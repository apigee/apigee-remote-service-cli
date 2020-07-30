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

func badHandler(t *testing.T) http.Handler {
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

	flags = []string{"token", "create", "--runtime", "dummy", "--id", "/id/", "--secret", "/secret/"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "creating token: Post \"dummy/remote-service/token\": unsupported protocol scheme")
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

func TestCreateInternalJWT(t *testing.T) {
	// TODO: Although the secret here is not really valuable, it's better to generate a valid temporary one later on
	config := []byte(`# Configuration for apigee-remote-service-envoy (platform: GCP)
# generated by apigee-remote-service-cli provision on 2020-07-29 19:04:19
apiVersion: v1
kind: ConfigMap
metadata:
  name: apigee-remote-service-envoy
  namespace: apigee
data:
  config.yaml: |
    tenant:
      remote_service_api: https://RUNTIME/remote-service
      org_name: hi
      env_name: test
    analytics:
      collection_interval: 10s
      fluentd_endpoint: apigee-udca-hi-test-1q2w3e4r.apigee:20001
      tls:
        ca_file: /opt/apigee/tls/ca.crt
        key_file: /opt/apigee/tls/tls.key
        cert_file: /opt/apigee/tls/tls.crt
---
apiVersion: v1
kind: Secret
metadata:
  name: hi-test-policy-secret
  namespace: apigee
type: Opaque
data:
  remote-service.crt: eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJhbGciOiJSUzI1NiIsImUiOiJBUUFCIiwia2lkIjoiMjAyMC0wNy0yOVQxOTowNDoxNFoiLCJuIjoidjNmcnBoZWVSdDA5OEtnek1MSlRsZ181ZWJIOURDREo3RFJwRktBZ09abVpvS3R1UHlNeGU0S2dXVnp4bmR1ZU5LbnpTMDROQ2o3M1EwTk9YcGdaVEFJX3lBOW1EVlVVTTRaREtDeUZhdkZjdmR3OERYVGo0emE1d2djTEp5ZmZYdjZOa05LWWNmS0ZKS1Zfbk9pUXJyN195LUphM2RXbnlPNXJnZVBlOGZvTnRxaXo3R1ZqbHllZkpxb3dha3NUUC02R25fMzFHZFdiQURkVkN0Y01vRThFd1BsOUJCLVpOcXRfVE1ENzV4MjZ3M1RLSHU1Tmx4dkkyU25vZ25lV3VRVG9NYkg4cTFORnpJUEdjN0hjdkhNWWRDc0JWelIya3pOdnBRcDE0ZFd1M2laMGRaelhUZ0t2TFp3OHI5cURYVF9qSERua29hd0tJbXhXVTVoSG9RIn1dfQ==
  remote-service.key: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBdjNmcnBoZWVSdDA5OEtnek1MSlRsZy81ZWJIOURDREo3RFJwRktBZ09abVpvS3R1ClB5TXhlNEtnV1Z6eG5kdWVOS256UzA0TkNqNzNRME5PWHBnWlRBSS95QTltRFZVVU00WkRLQ3lGYXZGY3ZkdzgKRFhUajR6YTV3Z2NMSnlmZlh2Nk5rTktZY2ZLRkpLVi9uT2lRcnI3L3krSmEzZFdueU81cmdlUGU4Zm9OdHFpego3R1ZqbHllZkpxb3dha3NUUCs2R24vMzFHZFdiQURkVkN0Y01vRThFd1BsOUJCK1pOcXQvVE1ENzV4MjZ3M1RLCkh1NU5seHZJMlNub2duZVd1UVRvTWJIOHExTkZ6SVBHYzdIY3ZITVlkQ3NCVnpSMmt6TnZwUXAxNGRXdTNpWjAKZFp6WFRnS3ZMWnc4cjlxRFhUL2pIRG5rb2F3S0lteFdVNWhIb1FJREFRQUJBb0lCQUFXamVITVp1dldIU20ydAo1bVFHdkdOczhRSGVkZjlIYityZTJFRmRQZFcwYWt2TEFLSW5YU3V2K3h6bW1jNzJTc0J1U05YczVJRnF2VWxqCjBBa0ZIYW1aWDF0NjZKeDM1dkpsZjlETkR0akpadHZJZ3BRNjN3TXY5MlI1WktDd2tlbHdRYWNFTEswZVlVRmwKQms4T29rUWpKOUZQUnpIRk92MjExOENwZjBWTTlNZ3N3bzIwWnVLVnFTdndvWnZYM1JzZlFNTjhGdkdvM0R4SApZMGdRYnZtVTFQUVZ1Sm5vR0c3c2ZYY3ZmS3BnRVdEOUVxem1uVCt3U0RhZlJPSDhhaTRhWm00S0hrRTdrWWdrCk0zeDlxZmRBenVQWVh3Y3hET2FGZzNDVGJoODU4R21NMmRJQnUydnQ2bU8wYzBPenk1SVhHUm9sOGQzSTgwUEEKejNDbVVnRUNnWUVBOFFFd3E3ZnRiUHhIQ1A3MEcwMlBDcXlaRFZ4MkQ4OGlrSE81OWVjRzFVeDZUdXlwNXh4Ywpsa05SSnpaYm44QVpXMmhyQTJzZ0FnTUd5Y01QdW9FVExVTlQ0U2UxV2twYTZma09Md2p6ZG1nNG1aZ041NzMwCklRSkZCL1NjdWJOSjlyU0xhT0pqOHdyYjJjZWdLVE1IbmZOUzRNSUdxcFUyTE1WUVhmVEVnYkVDZ1lFQXkyR3oKR0E5M25xb3hBQTZKQ3p2WHd6U1VYSVBoeFRtL1FodUhQdGtLY09SdjFMNy9wTStIUnY1ZlZUWmVlM2xzWlpVVApYdnE3TE1QbFFoVmdBK3lISkdxODVRWXpQblBVTGJSMDJGSHJjQVhkNUdDV3YvMkV3L3RCY2NJV1hSOXFtMUJ2ClcwL21NdFRoalVxTWh5R3d4VlJaV2tMN1ArdTQxN01OT0tRWk1QRUNnWUVBd09EMDlOazB1VDZHRTFzSVBqbXEKT3g2N053aENySkJYMTBmbkVqZ2RMZVFSRnMwdGhQc2IxbDUxdW00MGtmdUp6N0FYeFJxYytUODIxWTY1TGNoVApjcXdwbTA3T1F6NnkyQUl0S2ROK0ZjdC9VTjF5YzMrQXZGSTJzUkZCeFJVS0l0bUhvUjllWW9yVVBNMFpEeC81Ci9wMVlQT3pMclFYUjM2N2lqTzl4dldFQ2dZRUFveldUOHdyMmcyMHdSVXRrem84SFpxOGJIK0wxbXIvc3E3QkwKcURPa0hWUTBLaFhjTVBZWktPK1lzVmtnR1JZbjFwejdIbzAzQjRWc3hNdENjZU90ejV1WVduSFBUWjdGOXFlSgozTTVna1ZVajY5RlhLRnJaNEN3UktLa0lLVks4eWthU0ZrVFlCcEt2TGlOVkFsd1c3MFB4TUczd0VpdW4rZkRGCisxNDBtUUVDZ1lCb2JTNlR6S3dVb0dmejM1SUhaUmJuUjV0Z2kwcWJTUXJvb0E0VW5OTTY4RHVDZ2tBMy81a2MKVGxQME1FNG5KS1k1M21WNWtuTUZNM2gxREZTQlR2VDJEWVZUYWcyaWlPZGV6NWtSTVU5ZXdsajQrVnpGWW0xRAp5ektBeUVRMGlITXNFSW9ZaG1ZNmdETDlLaXVocUNoWnBjaEtYb3MvWUd3ZGpjZEpYcVd5Z3c9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
  remote-service.properties: a2lkPTIwMjAtMDctMjlUMdk6MDQ6MTRaCg==`)

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

	// missing config
	rootArgs = &shared.RootArgs{}
	flags = []string{"token", "internal", "--config", tmpFile.Name(), "--duration", "80m"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "JWT should not be valid for longer than 1 hour")
}
