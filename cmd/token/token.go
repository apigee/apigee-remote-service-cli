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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/apigee/apigee-remote-service-cli/shared"
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
	clientID     string
	clientSecret string
	file         string
	namespace    string
	truncate     int
}

// Cmd returns base command
func Cmd(rootArgs *shared.RootArgs, printf shared.FormatFn) *cobra.Command {
	t := &token{RootArgs: rootArgs}

	c := &cobra.Command{
		Use:   "token",
		Short: "JWT Token Utilities",
		Long:  "JWT Token Utilities",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootArgs.Resolve(true, true)
		},
	}

	c.AddCommand(cmdCreateToken(t, printf))
	c.AddCommand(cmdInspectToken(t, printf))
	c.AddCommand(cmdRotateCert(t, printf))
	c.AddCommand(cmdCreateSecret(t, printf))

	return c
}

func cmdCreateToken(t *token, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a new OAuth token",
		Long:  "Create a new OAuth token",
		Args:  cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {
			token, err := t.createToken(printf)
			if err != nil {
				return errors.Wrap(err, "creating token")
			}
			printf(token)
			return nil
		},
	}

	c.Flags().StringVarP(&t.clientID, "id", "i", "", "client id")
	c.Flags().StringVarP(&t.clientSecret, "secret", "s", "", "client secret")

	c.MarkFlagRequired("id")
	c.MarkFlagRequired("secret")

	return c
}

func cmdInspectToken(t *token, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a JWT token",
		Long:  "Inspect a JWT token",
		Args:  cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {
			err := t.inspectToken(cmd.InOrStdin(), printf)
			if err != nil {
				return errors.Wrap(err, "inspecting token")
			}
			return nil
		},
	}

	c.Flags().StringVarP(&t.file, "file", "f", "", "token file (default: use stdin)")

	return c
}

func cmdCreateSecret(t *token, printf shared.FormatFn) *cobra.Command {
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

			t.createSecret(printf)
		},
	}

	c.Flags().StringVarP(&t.namespace, "namespace", "n", "apigee", "emit Secret in the specified namespace")
	c.Flags().IntVarP(&t.truncate, "truncate", "", 2, "number of certs to keep in jwks")

	return c
}

func cmdRotateCert(t *token, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "rotate-cert",
		Short: "rotate JWT certificate (legacy or opdk)",
		Long:  "Deploys a new private and public key while maintaining the current public key for existing tokens (legacy or opdk).",
		Args:  cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {

			if t.IsGCPManaged {
				return fmt.Errorf("only valid for legacy or hybrid, use create-secret for hybrid")
			}

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
				return err
			}

			t.rotateCert(printf)
			return nil
		},
	}

	c.Flags().IntVarP(&t.truncate, "truncate", "", 2, "number of certs to keep in jwks")
	c.Flags().StringVarP(&t.clientID, "key", "k", "", "provision key")
	c.Flags().StringVarP(&t.clientSecret, "secret", "s", "", "provision secret")

	return c
}

func (t *token) createToken(printf shared.FormatFn) (string, error) {
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
		return "", errors.Wrap(err, "creating request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var tokenRes tokenResponse
	resp, err := t.Client.Do(req, &tokenRes)
	if err != nil {
		return "", errors.Wrap(err, "creating token")
	}
	defer resp.Body.Close()

	return tokenRes.Token, nil
}

func (t *token) inspectToken(in io.Reader, printf shared.FormatFn) error {
	var file = in
	if t.file != "" {
		var err error
		file, err = os.Open(t.file)
		if err != nil {
			return errors.Wrapf(err, "opening file %s", t.file)
		}
	}

	jwtBytes, err := ioutil.ReadAll(file)
	if err != nil {
		return errors.Wrap(err, "reading jwt token")
	}
	token, err := jwt.ParseBytes(jwtBytes)
	if err != nil {
		return errors.Wrap(err, "parsing jwt token")
	}
	buf, err := json.MarshalIndent(token, "", "\t")
	if err != nil {
		return errors.Wrap(err, "printing jwt token")
	}
	printf("%s", buf)

	// verify JWT
	printf("\nverifying...")

	url := fmt.Sprintf(certsURLFormat, t.RemoteServiceProxyURL)
	jwkSet, err := jwk.FetchHTTP(url)
	if err != nil {
		return errors.Wrap(err, "fetching certs")
	}
	if _, err = jws.VerifyWithJWKSet(jwtBytes, jwkSet, nil); err != nil {
		return errors.Wrap(err, "verifying cert")
	}
	if err := jwt.Verify(token, jwt.WithAcceptableSkew(time.Minute)); err != nil {
		printf("invalid token: %s", err)
		return nil
	}

	printf("valid token")
	return nil
}

// rotateCert is called by `token rotate-cert`
func (t *token) rotateCert(printf shared.FormatFn) error {
	var verbosef = shared.NoPrintf
	if t.Verbose {
		verbosef = printf
	}

	verbosef("generating key and jwks...")
	kid, keyBytes, jwksBytes, err := t.CreateJWKS(t.truncate, verbosef)
	if err != nil {
		return err
	}

	rotateReq := rotateRequest{
		PrivateKey: string(keyBytes),
		JWKS:       string(jwksBytes),
		KeyID:      kid,
	}

	verbosef("rotating certificate...")

	body := new(bytes.Buffer)
	err = json.NewEncoder(body).Encode(rotateReq)
	if err != nil {
		return errors.Wrap(err, "encoding")
	}

	rotateURL := fmt.Sprintf(rotateURLFormat, t.RemoteServiceProxyURL)
	req, err := http.NewRequest(http.MethodPost, rotateURL, body)
	if err != nil {
		return errors.Wrap(err, "creating request")
	}
	req.SetBasicAuth(t.clientID, t.clientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := t.Client.Do(req, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == 401 {
			return errors.Wrap(err, "authentication failed, check your key and secret")
		}
		return errors.Wrap(err, "rotating cert")
	}
	defer resp.Body.Close()

	verbosef("new private key:\n%s", string(keyBytes))
	verbosef("new jwks:\n%s", string(jwksBytes))

	printf("certificate successfully rotated")
	return nil
}

// createSecret is called by `token create-secret`
func (t *token) createSecret(printf shared.FormatFn) error {
	var verbosef = shared.NoPrintf
	if t.Verbose {
		verbosef = printf
	}

	kid, keyBytes, jwksBytes, err := t.CreateJWKS(t.truncate, verbosef)
	if err != nil {
		return err
	}

	// create CRD for secret
	kidProp := fmt.Sprintf(kidSecretPropFormat, kid)
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
		return errors.Wrap(err, "encoding YAML")
	}

	printf("# Secret for apigee-remote-service-envoy")
	printf("# generated by apigee-remote-service-cli provision on %s", time.Now().Format("2006-01-02 15:04:05"))
	printf(yamlBuffer.String())
	return nil
}

type rotateRequest struct {
	PrivateKey string `json:"private_key"`
	JWKS       string `json:"jwks"`
	KeyID      string `json:"kid"`
}

type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
}

type tokenResponse struct {
	Token string `json:"token"`
}
