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

package shared

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

func testCertsServer(size int, t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		jwks := makeJWKS(size, t)
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Fatal(err)
		}
	}))
	return ts
}

func makeJWKS(size int, t *testing.T) jwk.Set {
	jwks := jwk.NewSet()
	for i := 0; i < size; i += 1 {
		keyID := time.Now().Format(time.RFC3339)
		privateKey, err := rsa.GenerateKey(rand.Reader, certKeyLength)
		if err != nil {
			t.Fatal(err)
		}

		var jwkKey jwk.Key
		if jwkKey, err = jwk.New(&privateKey.PublicKey); err != nil {
			t.Fatal(err)
		}
		if err = jwkKey.Set(jwk.KeyIDKey, keyID); err != nil {
			t.Fatal(err)
		}
		if err = jwkKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
			t.Fatal(err)
		}
		jwks.Add(jwkKey)
	}
	return jwks
}

func TestJWKSRotation(t *testing.T) {
	keySize := 5
	ts := testCertsServer(keySize, t)
	defer ts.Close()

	print := testutil.Printer("TestJWKSRotation")

	r := &RootArgs{
		RemoteServiceProxyURL: ts.URL,
		RemoteTokenProxyURL:   ts.URL,
	}
	truncate := 4
	_, _, jwksBytes, err := r.CreateJWKS(truncate, print.Printf)
	if err != nil {
		t.Errorf("want no error, got %v", err)
	}
	jwks := jwk.NewSet()
	err = json.Unmarshal(jwksBytes, jwks)
	if err != nil {
		t.Errorf("want no error, got %v", err)
	}
	if jwks.Len() != truncate {
		t.Errorf("want %d keys, got %d", truncate, jwks.Len())
	}
}

func TestFetchingOldJWKSError(t *testing.T) {
	print := testutil.Printer("TestFetchingOldJWKSError")

	r := &RootArgs{
		RemoteServiceProxyURL: "not a url",
		RemoteTokenProxyURL:   "not a url",
	}
	truncate := 2
	_, err := r.RotateJWKS(jwk.NewSet(), truncate)
	if err == nil {
		t.Error("want error got none")
	}
	_, _, jwks, err := r.CreateJWKS(truncate, print.Printf)
	if err == nil {
		t.Error("want error got none")
	}
	if jwks != nil {
		t.Error("returned jwks is not nil")
	}
}
