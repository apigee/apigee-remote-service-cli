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
	"github.com/jarcoal/httpmock"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

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

	print := testutil.Printer("TestCreateToken")

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
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://org-env.apigee.net/remote-service/certs",
		httpmock.NewStringResponder(200, `{"keys":[{"alg":"RS256","e":"AQAB","kid":"2020-01-01T00:00:00-00:00","kty":"RSA","n":"old-fake-key"}]}`))

	httpmock.RegisterResponder("POST", "https://org-env.apigee.net/remote-service/rotate",
		httpmock.NewStringResponder(200, ""))

	config := []byte(`tenant:
  internal_api: https://istioservices.apigee.net/edgemicro
  remote_service_api: https://org-env.apigee.net/remote-service
  org_name: org
  env_name: env
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

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "rotate-cert", "--config", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"certificate successfully rotated"}

	print.Check(t, want)
}

func TestInspectTokenFunc(t *testing.T) {
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
	}

	for _, tc := range testCases {
		tc := tc
		err := tc.token.inspectToken(tc.in, print.Printf)
		if !testutil.ErrorContains(err, tc.errStr) {
			t.Errorf("want opening file err, got %v", err)
		}
	}

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
