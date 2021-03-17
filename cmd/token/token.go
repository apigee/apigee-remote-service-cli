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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	rotateURLFormat        = "%s/rotate" // RemoteServiceProxyURL
	clientCredentialsGrant = "client_credentials"
)

type token struct {
	*shared.RootArgs
	clientID            string
	clientSecret        string
	file                string
	truncate            int
	internalJWTDuration time.Duration
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

	c.PersistentFlags().BoolVarP(&rootArgs.IsLegacySaaS, "legacy", "", false,
		"Apigee SaaS (sets management and runtime URL)")
	c.PersistentFlags().BoolVarP(&rootArgs.IsOPDK, "opdk", "", false,
		"Apigee opdk")

	c.AddCommand(cmdCreateToken(t, printf))
	c.AddCommand(cmdInspectToken(t, printf))
	c.AddCommand(cmdRotateCert(t, printf))
	c.AddCommand(cmdCreateInternalJWT(t, printf))

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

	_ = c.MarkFlagRequired("id")
	_ = c.MarkFlagRequired("secret")

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

func cmdRotateCert(t *token, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "rotate-cert",
		Short: "rotate JWT certificate (legacy or opdk)",
		Long:  "Deploys a new private and public key while maintaining the current public key for existing tokens (legacy or opdk).",
		Args:  cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {

			if t.IsGCPManaged {
				return fmt.Errorf("only valid for legacy or opdk, use create-secret for hybrid")
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

			if err := t.rotateCert(printf); err != nil {
				return err
			}
			return nil
		},
	}

	c.Flags().IntVarP(&t.truncate, "truncate", "", 2, "number of certs to keep in jwks")
	c.Flags().StringVarP(&t.clientID, "key", "k", "", "provision key")
	c.Flags().StringVarP(&t.clientSecret, "secret", "s", "", "provision secret")

	return c
}

func cmdCreateInternalJWT(t *token, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "internal",
		Short: "Create a JWT token for authorizing remote-service API calls (hybrid only)",
		Long:  "Create a JWT token for authorizing remote-service API calls (hybrid only)",
		Args:  cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {
			if !t.IsGCPManaged {
				return fmt.Errorf("generating internal JWT only valid for hybrid")
			}
			if t.internalJWTDuration > 60*time.Minute {
				return fmt.Errorf("JWT should not be valid for longer than 1 hour")
			}

			token, err := t.createInternalJWT(printf)
			if err != nil {
				return errors.Wrap(err, "creating internal JWT")
			}
			printf(token)
			return nil
		},
	}

	// need to add this config flag here specifically to have it checked first
	c.Flags().StringVarP(&t.ConfigPath, "config", "c", "", "path to Apigee Remote Service config file")
	c.Flags().DurationVarP(&t.internalJWTDuration, "duration", "", 10*time.Minute, "valid time of the internal JWT from creation")
	_ = c.MarkFlagRequired("config")

	return c
}

func (t *token) createToken(printf shared.FormatFn) (string, error) {
	tokenReq := &tokenRequest{
		ClientID:     t.clientID,
		ClientSecret: t.clientSecret,
		GrantType:    clientCredentialsGrant,
	}
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(tokenReq); err != nil {
		return "", errors.Wrap(err, "creating request body")
	}

	tokenURL := t.GetTokenURL()
	req, err := http.NewRequest(http.MethodPost, tokenURL, body)
	if err != nil {
		return "", errors.Wrap(err, "creating request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	var tokenRes tokenResponse
	resp, err := t.ApigeeClient.Do(req, &tokenRes)
	if err != nil {
		return "", errors.Wrap(err, "creating token")
	}
	defer resp.Body.Close()

	return tokenRes.Token, nil
}

func (t *token) createInternalJWT(printf shared.FormatFn) (string, error) {
	if t.ServerConfig == nil {
		return "", fmt.Errorf("tenant not found. requires a valid config file")
	}
	token, err := server.NewToken(t.internalJWTDuration)
	if err != nil {
		return "", err
	}
	privateKey := t.ServerConfig.Tenant.PrivateKey
	kid := t.ServerConfig.Tenant.PrivateKeyID
	signed, err := server.SignJWT(token, jwa.RS256, privateKey, kid)
	if err != nil {
		return "", err
	}
	internalJWT := bytes.NewBuffer(signed).String()
	return internalJWT, nil
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

	jwtBytes, err := io.ReadAll(file)
	if err != nil {
		return errors.Wrap(err, "reading jwt token")
	}
	token, err := jwt.Parse(jwtBytes)
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

	url := t.GetCertsURL()
	jwkSet, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return errors.Wrap(err, "fetching certs")
	}
	if _, err = jws.VerifySet(jwtBytes, jwkSet); err != nil {
		return errors.Wrap(err, "verifying cert")
	}
	if err := jwt.Validate(token, jwt.WithAcceptableSkew(time.Minute)); err != nil {
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
		verbosef = shared.Errorf
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

	resp, err := t.ApigeeClient.Do(req, nil)
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
	Token string `json:"access_token"`
}
