// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package token

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func remoteServiceHandler(t *testing.T) http.Handler {
	_, key := generateJWK(t)

	m := http.NewServeMux()
	m.HandleFunc("/remote-token/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []interface{}{
				key,
			},
		}); err != nil {
			t.Fatal(err)
		}
	})
	m.HandleFunc("/remote-service/rotate", func(w http.ResponseWriter, r *http.Request) {
		jsonBody := make(map[string]interface{})
		if err := json.NewDecoder(r.Body).Decode(&jsonBody); err != nil {
			t.Fatalf("error in rotate request %v", err)
		}
		if _, ok := jsonBody["private_key"]; !ok {
			t.Error("rotate request has no private key")
		}
		if _, ok := jsonBody["jwks"]; !ok {
			t.Error("rotate request has no jwks")
		}
		w.WriteHeader(http.StatusOK)
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This matches every other route - we should not hit this one.
		t.Fatalf("Unknown route %s hit", r.URL.Path)
	})
	return m
}

func badHandler(t *testing.T) http.Handler {
	_, key := generateJWK(t)

	m := http.NewServeMux()
	m.HandleFunc("/remote-token/certs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []interface{}{
				key,
			},
		}); err != nil {
			t.Fatal(err)
		}
	})
	m.HandleFunc("/remote-service/rotate", func(w http.ResponseWriter, r *http.Request) {
		jsonBody := make(map[string]interface{})
		if err := json.NewDecoder(r.Body).Decode(&jsonBody); err != nil {
			t.Fatalf("error in rotate request %v", err)
		}
		if _, ok := jsonBody["private_key"]; !ok {
			t.Error("rotate request has no private key")
		}
		if _, ok := jsonBody["jwks"]; !ok {
			t.Error("rotate request has no jwks")
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This matches every other route - we should not hit this one.
		t.Fatalf("Unknown route %s hit", r.URL.Path)
	})
	return m
}

func TestTokenCreate(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := tokenResponse{
			Token: "/token/",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Fatalf("error: %v", err)
		}
	}))
	defer ts.Close()

	print := testutil.Printer("TestCreateToken")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "create", "--runtime", ts.URL, "--id", "/id/", "--secret", "/secret/"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"/token/"}

	print.Check(t, want)

	// bad runtime
	flags = []string{"token", "create", "--runtime", "dummy", "--id", "/id/", "--secret", "/secret/"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "creating token: Post \"dummy/remote-token/token\": unsupported protocol scheme")

	// missing runtime
	flags = []string{"token", "create", "--id", "/id/", "--secret", "/secret/"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "--runtime is required for hybrid or opdk (or --organization and --environment with --legacy)")
}

func TestTokenInspect(t *testing.T) {
	privateKey, key := generateJWK(t)

	jwksBuf, err := json.MarshalIndent(key, "", "")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	t.Logf("jwks: %s", jwksBuf)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write(jwksBuf)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
	}))
	defer ts.Close()

	print := testutil.Printer("TestInspectToken")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "inspect", "--runtime", ts.URL, "-v"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	token, err := generateJWT(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCmd.SetIn(strings.NewReader(token))

	if err = rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{`{
	"aud": [
		"remote-service-client"
	],
	"iss": "https://org-env.apigee.net/remote-token/token",
	"jti": "/id/",
	"access_token": "/token/",
	"api_product_list": [
		"/product/"
	],
	"application_name": "/appname/",
	"client_id": "/clientid/",
	"scope": "scope1 scope2"
}`,
		"\nverifying...",
		"valid token",
	}

	print.Check(t, want)

	flags = []string{"token", "inspect", "--runtime", "dummy", "-v"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "inspecting token: parsing jwt token: invalid jws message")
}

func TestTokenRotateCert(t *testing.T) {
	ts := httptest.NewServer(remoteServiceHandler(t))
	defer ts.Close()

	config := []byte(`tenant:
  internal_api: https://istioservices.apigee.net/edgemicro
  remote_service_api: https://org-env.apigee.net/remote-service
  org_name: hi
  env_name: test
  key: fake-key
  secret: fake-secret`)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	print := testutil.Printer("TestTokenRotateCert")

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "rotate-cert", "--config", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{"certificate successfully rotated"}

	print.Check(t, want)

	badServer := httptest.NewServer(badHandler(t))
	defer badServer.Close()

	// error on authentication error
	flags = []string{"token", "rotate-cert", "-o", "hi", "-e", "test", "--legacy"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, badServer.URL))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "authentication failed, check your key and secret")

	// error for invalid host
	flags = []string{"token", "rotate-cert", "-o", "hi", "-e", "test", "--legacy"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "no such host")

	// error for trying on hybrid
	rootArgs = &shared.RootArgs{}
	flags = []string{"token", "rotate-cert", "-o", "hi", "-e", "test", "-r", ts.URL}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "only valid for legacy or opdk")

	// error for missing flags
	flags = []string{"token", "rotate-cert", "-o", "hi", "-e", "test", "--legacy"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "required flag(s)")
}

func TestInspectTokenErrors(t *testing.T) {
	ts := httptest.NewServer(remoteServiceHandler(t))
	defer ts.Close()

	print := testutil.Printer("TestInspectTokenFunc")
	rootArgs := &shared.RootArgs{}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tk, err := generateJWT(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		token  token
		in     io.Reader
		errStr string
	}{
		{
			token: token{
				RootArgs: rootArgs,
				file:     "fake",
			},
			in:     os.Stdin,
			errStr: "opening file fake",
		},
		{
			token: token{
				RootArgs: rootArgs,
			},
			in:     strings.NewReader(""),
			errStr: "parsing jwt token",
		},
		{
			token: token{
				RootArgs: rootArgs,
			},
			in:     strings.NewReader(tk),
			errStr: "fetching certs",
		},
		{
			token: token{
				RootArgs: &shared.RootArgs{
					RemoteServiceProxyURL: fmt.Sprintf("%s/remote-service", ts.URL),
				},
			},
			in:     strings.NewReader(tk),
			errStr: "verifying cert",
		},
	}

	for _, tc := range testCases {
		tc := tc
		err := tc.token.inspectToken(tc.in, print.Printf)
		testutil.ErrorContains(t, err, tc.errStr)
	}

}

func testCmd(rootArgs *shared.RootArgs, printf shared.FormatFn, url string) *cobra.Command {
	c := Cmd(rootArgs, printf)

	defaultPersistentPreRun := c.PersistentPreRunE
	c.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := defaultPersistentPreRun(cmd, args); err != nil {
			return err
		}
		setTestUrls(rootArgs, url)
		return nil
	}

	return c
}

func setTestUrls(rootArgs *shared.RootArgs, url string) {
	rootArgs.RemoteServiceProxyURL = fmt.Sprintf("%s/remote-service", url)
}

func generateJWT(privateKey *rsa.PrivateKey) (string, error) {

	token := jwt.New()
	if err := token.Set(jwt.AudienceKey, "remote-service-client"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.JwtIDKey, "/id/"); err != nil {
		return "", err
	}
	if err := token.Set(jwt.IssuerKey, "https://org-env.apigee.net/remote-token/token"); err != nil {
		return "", err
	}
	if err := token.Set("access_token", "/token/"); err != nil {
		return "", err
	}
	if err := token.Set("client_id", "/clientid/"); err != nil {
		return "", err
	}
	if err := token.Set("application_name", "/appname/"); err != nil {
		return "", err
	}
	if err := token.Set("scope", "scope1 scope2"); err != nil {
		return "", err
	}
	if err := token.Set("api_product_list", []string{"/product/"}); err != nil {
		return "", err
	}
	payload, err := jwt.Sign(token, jwa.RS256, privateKey)

	return string(payload), err
}

func generateJWK(t *testing.T) (*rsa.PrivateKey, jwk.Key) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	key, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, "kid"); err != nil {
		t.Fatalf("error: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		t.Fatalf("error: %v", err)
	}

	return privateKey, key
}

func TestCreateInternalJWT(t *testing.T) {
	config := generateConfig(t)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	print := testutil.Printer("TestCreateInternalJWT")

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "internal", "--config", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	if len(print.Prints) != 1 {
		t.Errorf("want 1 output, got %d", len(print.Prints))
	}

	// missing config
	rootArgs = &shared.RootArgs{}
	flags = []string{"token", "internal", "-r", "dummy"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "required flag(s) \"config\" not set")

	// duration too long
	rootArgs = &shared.RootArgs{}
	flags = []string{"token", "internal", "--config", tmpFile.Name(), "--duration", "80m"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "JWT should not be valid for longer than 1 hour")
}

func generateConfig(t *testing.T) []byte {
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)

	privateKey, key := generateJWK(t)

	config := server.DefaultConfig()
	config.Tenant.RemoteServiceAPI = "https://RUNTIME/remote-service"
	config.Tenant.OrgName = "hi"
	config.Tenant.EnvName = "test"
	config.Analytics.FluentdEndpoint = "apigee-udca-hi-test-1q2w3e4r.apigee:20001"
	if err := yamlEncoder.Encode(config); err != nil {
		t.Fatal(err)
	}
	configYAML := yamlBuffer.String()
	data := map[string]string{"config.yaml": configYAML}

	configCRD := server.ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: server.Metadata{
			Name:      "apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: data,
	}

	yamlBuffer.Reset()
	yamlEncoder = yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	if err := yamlEncoder.Encode(configCRD); err != nil {
		t.Fatal(err)
	}

	privateKeyBytes := pem.EncodeToMemory(&pem.Block{Type: server.PEMKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	jwksBytes, _ := json.Marshal(&jwk.Set{
		Keys: []jwk.Key{key},
	})
	props := map[string]string{server.SecretPropsKIDKey: time.Now().Format(time.RFC3339)}
	propsBuf := new(bytes.Buffer)
	if err := server.WriteProperties(propsBuf, props); err != nil {
		t.Fatal(err)
	}

	secretData := map[string]string{
		server.SecretJWKSKey:    base64.StdEncoding.EncodeToString(jwksBytes),
		server.SecretPrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
		server.SecretPropsKey:   base64.StdEncoding.EncodeToString(propsBuf.Bytes()),
	}

	secretCRD := server.SecretCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "Opaque",
		Metadata: server.Metadata{
			Name:      "hi-test-policy-secret",
			Namespace: "apigee",
		},
		Data: secretData,
	}

	if err := yamlEncoder.Encode(secretCRD); err != nil {
		t.Fatal(err)
	}

	return yamlBuffer.Bytes()
}
