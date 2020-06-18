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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

const (
	certsURLFormat = "%s/certs" // RemoteServiceProxyURL
	certKeyLength  = 2048
)

// CreateJWKS returns keyID, private key, jwks, error
func (r *RootArgs) CreateJWKS(truncate int, verbosef FormatFn) (keyID string, pkBytes, jwksBytes []byte, err error) {
	jwkSet := &jwk.Set{}
	verbosef("retrieving existing certificates...")
	fail := func(err error, msg string) (string, []byte, []byte, error) {
		return "", nil, nil, errors.Wrap(err, msg)
	}

	if truncate > 1 { // if 1, just skip old stuff
		// get old jwks
		jwksURL := fmt.Sprintf(certsURLFormat, r.RemoteServiceProxyURL)
		jwkSet, err = jwk.FetchHTTP(jwksURL)
		if err != nil {
			return fail(err, "fetching jwks")
		}
		jwksBytes, err := json.Marshal(jwkSet)
		if err != nil {
			return fail(err, "marshalling JSON")
		}
		verbosef("old jkws...\n%s", string(jwksBytes))
	}

	// gen kid, key
	keyID = time.Now().Format(time.RFC3339)
	privateKey, err := rsa.GenerateKey(rand.Reader, certKeyLength)
	if err != nil {
		return fail(err, "generating key")
	}

	// update jwks with new key
	jwkKey, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		return fail(err, "generating jwks")
	}
	jwkKey.Set(jwk.KeyIDKey, keyID)
	jwkKey.Set(jwk.AlgorithmKey, jwa.RS256)

	jwkSet.Keys = append(jwkSet.Keys, jwkKey)

	// sort ascending and truncate
	sort.Sort(sort.Reverse(byKID(jwkSet.Keys)))
	if truncate > 0 {
		jwkSet.Keys = jwkSet.Keys[:truncate]
	}

	jwksBytes, err = json.Marshal(jwkSet)
	if err != nil {
		return fail(err, "marshalling JSON")
	}
	verbosef("new jkws...\n%s", string(jwksBytes))

	// get private key bytes
	pkBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	return keyID, pkBytes, jwksBytes, nil
}

type byKID []jwk.Key

func (a byKID) Len() int           { return len(a) }
func (a byKID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byKID) Less(i, j int) bool { return a[i].KeyID() < a[j].KeyID() }
