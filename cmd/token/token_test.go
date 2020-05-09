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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
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
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	print := testutil.Printer("TestCreateToken:print")
	fatal := testutil.Printer("TestCreateToken:fatal")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "create", "--runtime", ts.URL, "--id", "/id/", "--secret", "/secret/"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf, fatal.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf, fatal.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{"/token/"}

	fatal.Check(t, nil)
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

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(key)
	}))
	defer ts.Close()

	print := testutil.Printer("TestCreateToken:print")
	fatal := testutil.Printer("TestCreateToken:fatal")

	rootArgs := &shared.RootArgs{}
	flags := []string{"token", "inspect", "--runtime", ts.URL, "-v"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf, fatal.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf, fatal.Printf))

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
	"iss": "https://theganyo1-eval-test.apigee.net/remote-service/token",
	"jti": "29e2320b-787c-4625-8599-acc5e05c68d0",
	"access_token": "8E7Az3ZgPHKrgzcQA54qAzXT3Z1G",
	"api_product_list": [
		"TestProduct"
	],
	"application_name": "61cd4d83-06b5-4270-a9ee-cf9255ef45c3",
	"client_id": "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H",
	"scope": "scope1 scope2"
}`,
		"\nverifying...",
		"token ok.",
	}

	fatal.Check(t, nil)
	print.Check(t, want)
}

func generateJWT(privateKey *rsa.PrivateKey) (string, error) {

	token := jwt.New()
	token.Set(jwt.AudienceKey, "remote-service-client")
	token.Set(jwt.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	token.Set(jwt.IssuerKey, "https://theganyo1-eval-test.apigee.net/remote-service/token")
	token.Set("access_token", "8E7Az3ZgPHKrgzcQA54qAzXT3Z1G")
	token.Set("client_id", "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H")
	token.Set("application_name", "61cd4d83-06b5-4270-a9ee-cf9255ef45c3")
	token.Set("scope", "scope1 scope2")
	token.Set("api_product_list", []string{"TestProduct"})
	payload, err := token.Sign(jwa.RS256, privateKey)

	return string(payload), err
}
