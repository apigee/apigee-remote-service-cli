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

package provision

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"gopkg.in/yaml.v3"
)

const (
	fluentdInternalFormat        = "apigee-udca-%s-%s.%s:20001" // org, env, namespace
	fluentdInternalEncodedFormat = "apigee-udca-%s.%s:20001"    // org-env-sha, namespace

	defaultApigeeCAFile   = "/opt/apigee/tls/ca.crt"
	defaultApigeeCertFile = "/opt/apigee/tls/tls.crt"
	defaultApigeeKeyFile  = "/opt/apigee/tls/tls.key"

	propertysetPOSTURL = `/resourcefiles?name=%s&type=properties`
	propertysetPUTURL  = `/resourcefiles/properties/%s`

	policySecretNameFormat    = "%s-%s-policy-secret"
	analyticsSecretNameFormat = "%s-%s-analytics-secret"
)

func (p *provision) createConfig(cred *keySecret) *server.Config {
	config := &server.Config{
		Tenant: server.TenantConfig{
			InternalAPI:            p.InternalProxyURL,
			RemoteServiceAPI:       p.RemoteServiceProxyURL,
			OrgName:                p.Org,
			EnvName:                p.Env,
			AllowUnverifiedSSLCert: p.InsecureSkipVerify,
		},
	}

	if cred != nil {
		config.Tenant.Key = cred.Key
		config.Tenant.Secret = cred.Secret
	}

	if p.IsGCPManaged {
		config.Tenant.InternalAPI = "" // no internal API for GCP
		config.Analytics.CollectionInterval = 10 * time.Second

		config.Analytics.FluentdEndpoint = fmt.Sprintf(fluentdInternalFormat, p.Org, p.Env, p.Namespace)

		config.Analytics.TLS.CAFile = defaultApigeeCAFile
		config.Analytics.TLS.CertFile = defaultApigeeCertFile
		config.Analytics.TLS.KeyFile = defaultApigeeKeyFile
	}

	if p.IsOPDK {
		config.Analytics.LegacyEndpoint = true
	}

	return config
}

func (p *provision) printConfig(config *server.Config, printf shared.FormatFn, verifyErrors error, verbosef shared.FormatFn) error {
	// encode config
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	err := yamlEncoder.Encode(config)
	if err != nil {
		return err
	}
	configYAML := yamlBuffer.String()

	data := map[string]string{"config.yaml": configYAML}
	configCRD := server.ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: server.Metadata{
			Name:      "apigee-remote-service-envoy",
			Namespace: p.Namespace,
		},
		Data: data,
	}

	yamlBuffer.Reset()
	yamlEncoder = yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	err = yamlEncoder.Encode(configCRD)
	if err != nil {
		return err
	}

	// secrets for IsGCPManaged
	if p.IsGCPManaged {
		privateKeyBytes := pem.EncodeToMemory(&pem.Block{Type: server.PEMKeyType,
			Bytes: x509.MarshalPKCS1PrivateKey(config.Tenant.PrivateKey)})

		// create CRD for policy secret
		jwksBytes, err := json.Marshal(config.Tenant.JWKS)
		if err != nil {
			return err
		}

		props := map[string]string{server.SecretPropsKIDKey: config.Tenant.PrivateKeyID}
		propsBuf := new(bytes.Buffer)
		if err := server.WriteProperties(propsBuf, props); err != nil {
			return err
		}

		// encode policy secret
		secretData := map[string]string{
			server.SecretJWKSKey:    base64.StdEncoding.EncodeToString(jwksBytes),
			server.SecretPrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
			server.SecretPropsKey:   base64.StdEncoding.EncodeToString(propsBuf.Bytes()),
		}

		if p.isCloud() {
			if err := p.createSecretPropertyset(jwksBytes, privateKeyBytes, propsBuf.Bytes(), verbosef); err != nil {
				return err
			}
		}

		secretCRD := server.SecretCRD{
			APIVersion: "v1",
			Kind:       "Secret",
			Type:       "Opaque",
			Metadata: server.Metadata{
				Name:      fmt.Sprintf(policySecretNameFormat, p.Org, p.Env),
				Namespace: p.Namespace,
			},
			Data: secretData,
		}

		err = yamlEncoder.Encode(secretCRD)
		if err != nil {
			return err
		}

		// load analytics service account credentials
		if p.serviceAccount != "" {
			cred, err := ioutil.ReadFile(p.serviceAccount)
			if err != nil {
				return err
			}

			// encode service account credentials into secret
			secretData := map[string]string{
				server.ServiceAccount: base64.StdEncoding.EncodeToString(cred),
			}
			secretCRD := server.SecretCRD{
				APIVersion: "v1",
				Kind:       "Secret",
				Type:       "Opaque",
				Metadata: server.Metadata{
					Name:      fmt.Sprintf(analyticsSecretNameFormat, p.Org, p.Env),
					Namespace: p.Namespace,
				},
				Data: secretData,
			}

			err = yamlEncoder.Encode(secretCRD)
			if err != nil {
				return err
			}
		}
	}

	// TODO: Now that GCP can refer to NG SaaS, the naming needs some change.
	platform := "GCP"
	if p.IsLegacySaaS {
		platform = "SaaS"
	}
	if p.IsOPDK {
		platform = "OPDK"
	}

	printf("# Configuration for apigee-remote-service-envoy (platform: %s)", platform)
	printf("# generated by apigee-remote-service-cli provision on %s", time.Now().Format("2006-01-02 15:04:05"))
	if verifyErrors != nil {
		printf("# WARNING: verification of provision failed. May not be valid.")
	}
	printf(yamlBuffer.String())

	return nil
}

// checkRuntimeVersion gets the version of the hybrid runtime and change the fluentd endpoint when necessary
func (p *provision) checkRuntimeVersion(config *server.Config, client *http.Client, verbosef shared.FormatFn) (string, error) {
	targetURL := fmt.Sprintf("%s/version", p.RemoteServiceProxyURL)
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if res != nil {
		defer res.Body.Close()
	}
	jsonBody := make(map[string]string)
	if err := json.NewDecoder(res.Body).Decode(&jsonBody); err != nil {
		return "", err
	}
	version, ok := jsonBody["platform"]
	if !ok {
		return "", fmt.Errorf("response has no 'platform' field")
	}
	if version == "unknown" {
		verbosef("runtime version unknown")
	}

	return version, nil
}

func (p *provision) encodeUDCAEndpoint(config *server.Config, verbosef shared.FormatFn) {
	config.Analytics.FluentdEndpoint = fmt.Sprintf(fluentdInternalEncodedFormat, EnvScopeEncodedName(p.Org, p.Env), p.Namespace)
	verbosef("UDCA endpoint encoded")
}

// createSecretPropertyset creates an environment-scoped propertyset to store the secrets
func (p *provision) createSecretPropertyset(jwk []byte, privateKey []byte, props []byte, verbosef shared.FormatFn) error {
	m := map[string]string{
		"crt": string(jwk),
		"key": strings.ReplaceAll(string(privateKey), "\n", `\n`),
	}
	propsBuf := new(bytes.Buffer)
	if err := server.WriteProperties(propsBuf, m); err != nil {
		return err
	}
	props = append(props, propsBuf.Bytes()...)

	if p.rotate > 0 {
		req, err := p.ApigeeClient.NewRequest(http.MethodPut, fmt.Sprintf(propertysetPUTURL, "remote-service"), bytes.NewReader(props))
		if err != nil {
			return err
		}

		res, err := p.ApigeeClient.Do(req, nil)
		if res != nil {
			defer res.Body.Close()
		}
		return err
	}

	req, err := p.ApigeeClient.NewRequest(http.MethodPost, fmt.Sprintf(propertysetPOSTURL, "remote-service"), bytes.NewReader(props))
	if err != nil {
		return err
	}

	res, err := p.ApigeeClient.Do(req, nil)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		if res.StatusCode != http.StatusConflict {
			return err
		} else {
			verbosef("property set remote-service already exists")
		}
	}

	return nil
}

// shortName returns a substring with up to the first 15 characters of the input string
func shortName(s string) string {
	if len(s) < 16 {
		return s
	}
	return s[:15]
}

// shortSha returns a substring with the first 7 characters of a SHA for the input string
func shortSha(s string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(s))
	sha := fmt.Sprintf("%x", h.Sum(nil))
	return sha[:7]
}

// EnvScopeEncodedName returns the encoded resource name to avoid the 63 chars limit
func EnvScopeEncodedName(org, env string) string {
	sha := shortSha(fmt.Sprintf("%s:%s", org, env))
	return fmt.Sprintf("%s-%s-%s", shortName(org), shortName(env), sha)
}
