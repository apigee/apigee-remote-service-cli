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
	pemType        = "RSA PRIVATE KEY"
)

// CreateNewKey returns keyID, private key, jwks, error
func (r *RootArgs) CreateNewKey() (keyID string, privateKey *rsa.PrivateKey, jwks *jwk.Set, err error) {
	keyID = time.Now().Format(time.RFC3339)
	if privateKey, err = rsa.GenerateKey(rand.Reader, certKeyLength); err != nil {
		return
	}

	var jwkKey jwk.Key
	if jwkKey, err = jwk.New(&privateKey.PublicKey); err != nil {
		return
	}
	if err = jwkKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return
	}
	if err = jwkKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil {
		return
	}

	jwks = &jwk.Set{
		Keys: []jwk.Key{jwkKey},
	}
	return
}

// RotateJWKS returns a jwk.Set including passed keys and keys from existing endpoint,
// sorted by key ID and truncated per the truncate param.
func (r *RootArgs) RotateJWKS(jwks *jwk.Set, truncate int) (*jwk.Set, error) {

	keys := jwks.Keys

	if truncate > 1 { // if 1, just skip getting old
		var oldJWKS *jwk.Set
		var err error
		certsURL := fmt.Sprintf(certsURLFormat, r.RemoteServiceProxyURL)
		if oldJWKS, err = jwk.FetchHTTP(certsURL); err != nil {
			return nil, errors.Wrapf(err, "retrieving JWKs from: %s", certsURL)
		}
		keys = append(keys, oldJWKS.Keys...)
	}

	sort.Sort(sort.Reverse(byKID(keys)))
	if truncate > 0 && len(keys) > truncate {
		keys = keys[:truncate]
	}

	return &jwk.Set{Keys: keys}, nil
}

// CreateJWKS returns keyID, private key, jwks, error
func (r *RootArgs) CreateJWKS(truncate int, verbosef FormatFn) (keyID string, pkBytes, jwksBytes []byte, err error) {

	var privateKey *rsa.PrivateKey
	var jwks *jwk.Set
	if keyID, privateKey, jwks, err = r.CreateNewKey(); err != nil {
		return
	}

	if jwks, err = r.RotateJWKS(jwks, truncate); err != nil {
		return
	}

	if jwksBytes, err = json.Marshal(jwks); err != nil {
		return
	}
	verbosef("new jkws...\n%s", string(jwksBytes))

	pkBytes = pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return
}

type byKID []jwk.Key

func (a byKID) Len() int           { return len(a) }
func (a byKID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byKID) Less(i, j int) bool { return a[i].KeyID() < a[j].KeyID() }
