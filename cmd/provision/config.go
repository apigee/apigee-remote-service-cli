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
	propertysetPOSTURL = `/resourcefiles?name=%s&type=properties`
	propertysetPUTURL  = `/resourcefiles/properties/%s`

	policySecretNameFormat    = "%s-%s-policy-secret"
	analyticsSecretNameFormat = "%s-%s-analytics-secret"

	defaultResourceName = "apigee-remote-service-envoy"
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
			Name:      defaultResourceName,
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

	// encodes the policy secrets in GCP managed cases
	if p.policySecretData != nil {
		secretCRD := server.SecretCRD{
			APIVersion: "v1",
			Kind:       "Secret",
			Type:       "Opaque",
			Metadata: server.Metadata{
				Name:      fmt.Sprintf(policySecretNameFormat, p.Org, p.Env),
				Namespace: p.Namespace,
			},
			Data: p.policySecretData,
		}

		err = yamlEncoder.Encode(secretCRD)
		if err != nil {
			return err
		}
	}

	// encodes the service account credentials
	if p.analyticsSecretData != nil {
		secretCRD := server.SecretCRD{
			APIVersion: "v1",
			Kind:       "Secret",
			Type:       "Opaque",
			Metadata: server.Metadata{
				Name:      fmt.Sprintf(analyticsSecretNameFormat, p.Org, p.Env),
				Namespace: p.Namespace,
			},
			Data: p.analyticsSecretData,
		}

		err = yamlEncoder.Encode(secretCRD)
		if err != nil {
			return err
		}
	}

	if p.IsGCPManaged {
		// no need to check error as p.serviceAccountCRD() returns a static value
		_ = yamlEncoder.Encode(p.serviceAccountCRD())
	}

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

// createPolicySecretData creates the policySecretData to be encoded into the config file
// if the runtime type is CLOUD (NG SaaS), it creates the related property set in Apigee
func (p *provision) createPolicySecretData(config *server.Config, verbosef shared.FormatFn) error {
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
	p.policySecretData = map[string]string{
		server.SecretJWKSKey:    base64.StdEncoding.EncodeToString(jwksBytes),
		server.SecretPrivateKey: base64.StdEncoding.EncodeToString(privateKeyBytes),
		server.SecretPropsKey:   base64.StdEncoding.EncodeToString(propsBuf.Bytes()),
	}

	if p.isCloud() {
		err = p.createSecretPropertyset(jwksBytes, privateKeyBytes, propsBuf.Bytes(), verbosef)
	}

	return err
}

func (p *provision) createAnalyticsSecretData() error {
	// load analytics service account credentials
	cred, err := ioutil.ReadFile(p.analyticsServiceAccount)
	if err != nil {
		return err
	}

	// encode service account credentials into secret
	p.analyticsSecretData = map[string]string{
		server.ServiceAccount: base64.StdEncoding.EncodeToString(cred),
	}

	return nil
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

	// PUT request to rotate the remote-service propertyset
	if p.rotate > 0 {
		req, err := p.ApigeeClient.NewRequest(http.MethodPut, fmt.Sprintf(propertysetPUTURL, "remote-service"), bytes.NewReader(props))
		if err != nil {
			return err
		}

		res, err := p.ApigeeClient.Do(req, nil)
		if res != nil {
			defer res.Body.Close()
		}
		if err == nil { // returns if successful
			return nil
		}
		if res.StatusCode != http.StatusNotFound { // proceed to POST if 404 Not Found
			return err
		}
	}

	// otherwise try POST to avoid overwriting existing propertyset
	req, err := p.ApigeeClient.NewRequest(http.MethodPost, fmt.Sprintf(propertysetPOSTURL, "remote-service"), bytes.NewReader(props))
	if err != nil {
		return err
	}

	res, err := p.ApigeeClient.Do(req, nil)
	if res != nil {
		defer res.Body.Close()
	}
	// returns error even on 409 Conflict
	return err
}

func (p *provision) serviceAccountCRD() *ServiceAccountCRD {
	return &ServiceAccountCRD{
		APIVersion: "v1",
		Kind:       "ServiceAccount",
		Metadata: server.Metadata{
			Name:      defaultResourceName,
			Namespace: p.Namespace,
		},
	}
}

type ServiceAccountCRD struct {
	APIVersion string          `yaml:"apiVersion"`
	Kind       string          `yaml:"kind"`
	Metadata   server.Metadata `yaml:"metadata"`
}
