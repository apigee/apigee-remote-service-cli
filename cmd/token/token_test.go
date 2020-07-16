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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

func remoteServiceHandler(t *testing.T) http.Handler {
	_, key := generateJWK(t)

	m := http.NewServeMux()
	m.HandleFunc("/remote-service/certs", func(w http.ResponseWriter, r *http.Request) {
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
	"iss": "https://org-env.apigee.net/remote-service/token",
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
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"certificate successfully rotated"}

	print.Check(t, want)

	// a failing command for invalid host
	flags = []string{"token", "rotate-cert", "-o", "hi", "-e", "test"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("want error but got none")
	}
	if !testutil.ErrorContains(err, "no such host") {
		t.Fatalf("want no such host error, got %v", err)
	}

	// a failing command for trying on hybrid
	rootArgs = &shared.RootArgs{}
	flags = []string{"token", "rotate-cert", "-o", "hi", "-e", "test", "-r", ts.URL}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	if err == nil {
		t.Fatal("want error but got none")
	}
	if !testutil.ErrorContains(err, "only valid for legacy or opdk") {
		t.Fatalf("want only valid for legacy or opdk error, got %v", err)
	}
}

func TestInspectTokenFunc(t *testing.T) {
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
		if !testutil.ErrorContains(err, tc.errStr) {
			t.Errorf("want opening file err, got %v", err)
		}
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
	if err := token.Set(jwt.IssuerKey, "https://org-env.apigee.net/remote-service/token"); err != nil {
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
