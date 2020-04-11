// Copyright 2018 Google LLC
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
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/apigee/apigee-remote-service-cli/cmd/provision"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	tokenURLFormat         = "%s/token"  // RemoteServiceProxyURL
	certsURLFormat         = "%s/certs"  // RemoteServiceProxyURL
	rotateURLFormat        = "%s/rotate" // RemoteServiceProxyURL
	clientCredentialsGrant = "client_credentials"
	policySecretNameFormat = "%s-%s-policy-secret"
	commonName             = "apigee-remote-service"
	orgName                = "Google LLC"

	// hybrid forces specific file extensions! https://docs.apigee.com/hybrid/v1.2/k8s-secrets
	jwksSecretKey       = "remote-service.crt" // obviously not a .crt, but hybrid will treat as blob
	keySecretKey        = "remote-service.key"
	kidSecretKey        = "remote-service.properties"
	kidSecretPropFormat = "kid=%s" // KID
)

type token struct {
	*shared.RootArgs
	clientID              string
	clientSecret          string
	file                  string
	keyID                 string
	certExpirationInYears int
	certKeyStrength       int
	namespace             string
	truncate              int
}

// Cmd returns base command
func Cmd(rootArgs *shared.RootArgs, printf, fatalf shared.FormatFn) *cobra.Command {
	t := &token{RootArgs: rootArgs}

	c := &cobra.Command{
		Use:   "token",
		Short: "JWT Token Utilities",
		Long:  "JWT Token Utilities",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootArgs.Resolve(true, true)
		},
	}

	c.AddCommand(cmdCreateToken(t, printf, fatalf))
	c.AddCommand(cmdInspectToken(t, printf, fatalf))
	c.AddCommand(cmdRotateCert(t, printf, fatalf))
	c.AddCommand(cmdCreateSecret(t, printf, fatalf))

	return c
}

func cmdCreateToken(t *token, printf, fatalf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new OAuth token",
		Long:  "Create a new OAuth token",
		Args:  cobra.NoArgs,

		Run: func(cmd *cobra.Command, _ []string) {
			_, err := t.createToken(printf, fatalf)
			if err != nil {
				fatalf("error creating token: %v", err)
			}
		},
	}

	c.Flags().StringVarP(&t.clientID, "id", "i", "", "client id")
	c.Flags().StringVarP(&t.clientSecret, "secret", "s", "", "client secret")

	c.MarkFlagRequired("id")
	c.MarkFlagRequired("secret")

	return c
}

func cmdInspectToken(t *token, printf, fatalf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a JWT token",
		Long:  "Inspect a JWT token",
		Args:  cobra.NoArgs,

		Run: func(cmd *cobra.Command, _ []string) {
			err := t.inspectToken(printf, fatalf)
			if err != nil {
				fatalf("error inspecting token: %v", err)
			}
		},
	}

	c.Flags().StringVarP(&t.file, "file", "f", "", "token file (default: use stdin)")

	return c
}

func cmdCreateSecret(t *token, printf, fatalf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "create-secret",
		Short: "create Kubernetes CRDs for JWT tokens (hybrid only)",
		Long:  "Creates a new Kubernetes Secret CRD for JWT tokens, maintains prior cert(s) for rotation.",
		Args:  cobra.NoArgs,

		Run: func(cmd *cobra.Command, _ []string) {
			if t.ServerConfig != nil {
				t.clientID = t.ServerConfig.Tenant.Key
				t.clientSecret = t.ServerConfig.Tenant.Secret
			}

			missingFlagNames := []string{}
			if t.clientID == "" {
				missingFlagNames = append(missingFlagNames, "key")
			}
			if t.clientSecret == "" {
				missingFlagNames = append(missingFlagNames, "secret")
			}
			if err := t.PrintMissingFlags(missingFlagNames); err != nil {
				fatalf(err.Error())
			}

			t.keyID = time.Now().Format(time.RFC3339)

			t.createSecret(printf, fatalf)
		},
	}

	c.Flags().IntVarP(&t.certExpirationInYears, "years", "", 1, "number of years before the cert expires")
	c.Flags().IntVarP(&t.certKeyStrength, "strength", "", 2048, "key strength")

	c.Flags().StringVarP(&t.clientID, "key", "k", "", "provision key")
	c.Flags().StringVarP(&t.clientSecret, "secret", "s", "", "provision secret")

	c.Flags().StringVarP(&t.namespace, "namespace", "n", "apigee", "emit Secret in the specified namespace")
	c.Flags().IntVarP(&t.truncate, "truncate", "", 2, "number of certs to keep in jwks")

	return c
}

func cmdRotateCert(t *token, printf, fatalf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "rotate-cert",
		Short: "rotate JWT certificate",
		Long:  "Deploys a new private and public key while maintaining the current public key for existing tokens.",
		Args:  cobra.NoArgs,

		Run: func(cmd *cobra.Command, _ []string) {
			if t.ServerConfig != nil {
				t.clientID = t.ServerConfig.Tenant.Key
				t.clientSecret = t.ServerConfig.Tenant.Secret
			}

			missingFlagNames := []string{}
			if t.clientID == "" {
				missingFlagNames = append(missingFlagNames, "key")
			}
			if t.clientSecret == "" {
				missingFlagNames = append(missingFlagNames, "secret")
			}
			if err := t.PrintMissingFlags(missingFlagNames); err != nil {
				fatalf(err.Error())
			}

			t.rotateCert(printf, fatalf)
		},
	}

	c.Flags().StringVarP(&t.keyID, "kid", "", "1", "new key id")
	c.Flags().IntVarP(&t.certExpirationInYears, "years", "", 1, "number of years before the cert expires")
	c.Flags().IntVarP(&t.certKeyStrength, "strength", "", 2048, "key strength")

	c.Flags().StringVarP(&t.clientID, "key", "k", "", "provision key")
	c.Flags().StringVarP(&t.clientSecret, "secret", "s", "", "provision secret")

	return c
}

func (t *token) createToken(printf, fatalf shared.FormatFn) (string, error) {
	tokenReq := &tokenRequest{
		ClientID:     t.clientID,
		ClientSecret: t.clientSecret,
		GrantType:    clientCredentialsGrant,
	}
	body := new(bytes.Buffer)
	json.NewEncoder(body).Encode(tokenReq)

	tokenURL := fmt.Sprintf(tokenURLFormat, t.RemoteServiceProxyURL)
	req, err := http.NewRequest(http.MethodPost, tokenURL, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var tokenRes tokenResponse
	resp, err := t.Client.Do(req, &tokenRes)
	if err != nil {
		return "", fmt.Errorf("error creating token: %v", err)
	}
	defer resp.Body.Close()

	printf(tokenRes.Token)
	return tokenRes.Token, nil
}

func (t *token) inspectToken(printf, fatalf shared.FormatFn) error {
	// Print JWT
	var file = os.Stdin
	if t.file != "" {
		var err error
		file, err = os.Open(t.file)
		if err != nil {
			fatalf("error opening file: %v", err)
		}
	}

	jwtBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return errors.Wrap(err, "error reading jwt token")
	}
	token, err := jwt.ParseBytes(jwtBytes)
	if err != nil {
		return errors.Wrap(err, "error parsing jwt token")
	}
	jsonBytes, err := token.MarshalJSON()
	if err != nil {
		return errors.Wrap(err, "error printing jwt token")
	}
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, jsonBytes, "", "\t")
	if err != nil {
		return errors.Wrap(err, "error printing jwt token")
	}
	printf(prettyJSON.String())

	// verify JWT
	printf("\nverifying...")

	url := fmt.Sprintf(certsURLFormat, t.RemoteServiceProxyURL)
	jwkSet, err := jwk.FetchHTTP(url)
	if err != nil {
		fatalf("error fetching certs: %v", err)
	}
	_, err = jws.VerifyWithJWKSet(jwtBytes, jwkSet, nil)
	if err != nil {
		fatalf("certificate error: %v", err)
	}
	err = token.Verify(
		jwt.WithAcceptableSkew(time.Minute),
	)
	if err != nil {
		fatalf("verification error: %v", err)
	}

	printf("token ok.")
	return nil
}

// rotateCert is called by `token rotate-cert`
func (t *token) rotateCert(printf, fatalf shared.FormatFn) {
	var verbosef = shared.NoPrintf
	if t.Verbose {
		verbosef = printf
	}

	verbosef("generating a new key and cert...")
	cert, privateKey, err := provision.GenKeyCert(t.certKeyStrength, t.certExpirationInYears)
	if err != nil {
		fatalf("error generating new cert: %v", err)
	}

	rotateReq := rotateRequest{
		PrivateKey:  privateKey,
		Certificate: cert,
		KeyID:       t.keyID,
	}

	verbosef("rotating certificate...")

	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(rotateReq)
	if err != nil {
		fatalf("encoding error: %v", err)
	}

	rotateURL := fmt.Sprintf(rotateURLFormat, t.RemoteServiceProxyURL)
	req, err := http.NewRequest(http.MethodPost, rotateURL, body)
	if err != nil {
		fatalf("unable to create request: %v", err)
	}
	req.SetBasicAuth(t.clientID, t.clientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := t.Client.Do(req, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			fatalf("authentication failed, check your key and secret")
		}
		fatalf("rotation request error: %v", err)
	}
	defer resp.Body.Close()

	verbosef("new certificate:\n%s", cert)
	verbosef("new private key:\n%s", privateKey)

	printf("certificate successfully rotated")
}

// createSecret is called by `token create-secret`
func (t *token) createSecret(printf, fatalf shared.FormatFn) {
	var verbosef = shared.NoPrintf
	if t.Verbose {
		verbosef = printf
	}

	jwkSet := &jwk.Set{}
	verbosef("retrieving existing certificates...")

	var err error
	if t.truncate > 1 { // if 1, just skip old stuff
		// old jwks
		jwksURL := fmt.Sprintf(certsURLFormat, t.RemoteServiceProxyURL)
		jwkSet, err = jwk.FetchHTTP(jwksURL)
		if err != nil {
			fatalf("fetch jwks: %v", err)
		}
		jwksBytes, err := json.Marshal(jwkSet)
		if err != nil {
			fatalf("marshal JSON: %v", err)
		}
		verbosef("old jkws...\n%s", string(jwksBytes))
	}

	t.keyID = time.Now().Format(time.RFC3339)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fatalf("generate key: %v", err)
	}

	// jwks
	key, err := jwk.New(&privateKey.PublicKey)
	if err != nil {
		fatalf("generate jwk: %v", err)
	}
	key.Set(jwk.KeyIDKey, t.keyID)
	key.Set(jwk.AlgorithmKey, jwa.RS256.String())

	jwkSet.Keys = append(jwkSet.Keys, key)

	// sort increasing and truncate
	sort.Sort(sort.Reverse(byKID(jwkSet.Keys)))
	if t.truncate > 0 {
		jwkSet.Keys = jwkSet.Keys[:t.truncate]
	}

	jwksBytes, err := json.Marshal(jwkSet)
	if err != nil {
		fatalf("marshal JSON: %v", err)
	}
	verbosef("new jkws...\n%s", string(jwksBytes))

	// private key
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	// kid
	kidProp := fmt.Sprintf(kidSecretPropFormat, t.keyID)

	// Secret CRD
	data := map[string]string{
		jwksSecretKey: base64.StdEncoding.EncodeToString(jwksBytes),
		keySecretKey:  base64.StdEncoding.EncodeToString(keyBytes),
		kidSecretKey:  base64.StdEncoding.EncodeToString([]byte(kidProp)),
	}

	crd := shared.KubernetesCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "Opaque",
		Metadata: shared.Metadata{
			Name:      fmt.Sprintf(policySecretNameFormat, t.Org, t.Env),
			Namespace: t.namespace,
		},
		Data: data,
	}

	// encode as YAML
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	err = yamlEncoder.Encode(crd)
	if err != nil {
		fatalf("encode: %v", err)
	}

	printf("# Secret for apigee-remote-service-envoy")
	printf("# generated by apigee-remote-service-cli provision on %s", time.Now().Format("2006-01-02 15:04:05"))
	printf(yamlBuffer.String())
}

type rotateRequest struct {
	PrivateKey  string `json:"private_key"`
	Certificate string `json:"certificate"`
	KeyID       string `json:"kid"`
}

type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

type tokenResponse struct {
	Token string `json:"token"`
}

type byKID []jwk.Key

func (a byKID) Len() int           { return len(a) }
func (a byKID) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byKID) Less(i, j int) bool { return a[i].KeyID() < a[j].KeyID() }
