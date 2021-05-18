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
	"os"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/apigee/apigee-remote-service-cli/v2/testutil"
	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"gopkg.in/yaml.v3"
)

func TestConfigWithAnalyticsSecretFile(t *testing.T) {
	print := testutil.Printer("TestConfigWithAnalyticsSecretFile")

	r := &shared.RootArgs{
		Namespace:             "apigee",
		Org:                   "hi",
		Env:                   "test",
		IsGCPManaged:          true,
		InternalProxyURL:      "https://mock.com/internal",
		RemoteServiceProxyURL: "https://mock.com/remote-service",
	}

	tmpFile, err := os.CreateTemp("", "client_secret.json")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(fakeServiceAccount()); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	p := &provision{
		RootArgs:                r,
		analyticsServiceAccount: tmpFile.Name(),
	}

	cfg := p.createConfig(nil)

	keyID, privateKey, jwks, err := p.CreateNewKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tenant.PrivateKey = privateKey
	cfg.Tenant.PrivateKeyID = keyID
	cfg.Tenant.JWKS = jwks

	err = p.createPolicySecretData(cfg, print.Printf)
	if err != nil {
		t.Error(err)
	}

	err = p.createAnalyticsSecretData(cfg, print.Printf)
	if err != nil {
		t.Error(err)
	}

	err = p.printConfig(cfg, print.Printf, nil, print.Printf)
	if err != nil {
		t.Error(err)
	}

	if len(print.Prints) != 3 {
		t.Errorf("want 3 prints, got %d", len(print.Prints))
	}

	// test if the generated config has all three CRDs
	cfgBytes := []byte(print.Prints[2])
	configMap := &config.ConfigMapCRD{}
	secret := &config.SecretCRD{}
	serviceAccount := &config.ConfigMapCRD{}
	decoder := yaml.NewDecoder(bytes.NewReader(cfgBytes))
	if err := decoder.Decode(configMap); err != nil {
		t.Errorf("decoding ConfigMap error: %v", err)
	} else if configMap.Kind != "ConfigMap" {
		t.Errorf("ConfigMap has the wrong Kind: %q", configMap.Kind)
	}

	if err := decoder.Decode(secret); err != nil {
		t.Errorf("decoding policy Secret error: %v", err)
	} else if secret.Kind != "Secret" {
		t.Errorf("policy Secret has the wrong Kind: %q", secret.Kind)
	}

	if err := decoder.Decode(secret); err != nil {
		t.Errorf("decoding analytics Secret error: %v", err)
	} else if secret.Kind != "Secret" {
		t.Errorf("analytics Secret has the wrong Kind: %q", secret.Kind)
	}

	if err := decoder.Decode(serviceAccount); err != nil {
		t.Errorf("decoding ServiceAccount error: %v", err)
	} else if serviceAccount.Kind != "ServiceAccount" {
		t.Errorf("ServiceAccount has the wrong Kind: %q", serviceAccount.Kind)
	}
}

func TestConfigWithAnalyticsSecretInConfig(t *testing.T) {
	print := testutil.Printer("TestConfigWithAnalyticsSecretInConfig")

	r := &shared.RootArgs{
		Namespace:             "apigee",
		Org:                   "hi",
		Env:                   "test",
		IsGCPManaged:          true,
		InternalProxyURL:      "https://mock.com/internal",
		RemoteServiceProxyURL: "https://mock.com/remote-service",
	}

	p := &provision{
		RootArgs: r,
	}

	cfg := p.createConfig(nil)

	keyID, privateKey, jwks, err := p.CreateNewKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tenant.PrivateKey = privateKey
	cfg.Tenant.PrivateKeyID = keyID
	cfg.Tenant.JWKS = jwks
	cfg.Analytics.CredentialsJSON = fakeServiceAccount()

	err = p.createPolicySecretData(cfg, print.Printf)
	if err != nil {
		t.Error(err)
	}

	err = p.createAnalyticsSecretData(cfg, print.Printf)
	if err != nil {
		t.Error(err)
	}

	err = p.printConfig(cfg, print.Printf, nil, print.Printf)
	if err != nil {
		t.Error(err)
	}

	if len(print.Prints) != 3 {
		t.Errorf("want 3 prints, got %d", len(print.Prints))
	}

	// test if the generated config has all three CRDs
	cfgBytes := []byte(print.Prints[2])
	configMap := &config.ConfigMapCRD{}
	secret := &config.SecretCRD{}
	serviceAccount := &config.ConfigMapCRD{}
	decoder := yaml.NewDecoder(bytes.NewReader(cfgBytes))
	if err := decoder.Decode(configMap); err != nil {
		t.Errorf("decoding ConfigMap error: %v", err)
	} else if configMap.Kind != "ConfigMap" {
		t.Errorf("ConfigMap has the wrong Kind: %q", configMap.Kind)
	}

	if err := decoder.Decode(secret); err != nil {
		t.Errorf("decoding policy Secret error: %v", err)
	} else if secret.Kind != "Secret" {
		t.Errorf("policy Secret has the wrong Kind: %q", secret.Kind)
	}

	if err := decoder.Decode(secret); err != nil {
		t.Errorf("decoding analytics Secret error: %v", err)
	} else if secret.Kind != "Secret" {
		t.Errorf("analytics Secret has the wrong Kind: %q", secret.Kind)
	}

	if err := decoder.Decode(serviceAccount); err != nil {
		t.Errorf("decoding ServiceAccount error: %v", err)
	} else if serviceAccount.Kind != "ServiceAccount" {
		t.Errorf("ServiceAccount has the wrong Kind: %q", serviceAccount.Kind)
	}
}

func fakeServiceAccount() []byte {
	sa := []byte(`{
	"type": "service_account",
	"project_id": "hi",
	"private_key_id": "5a0ef8b44fe312a005ac6e6fe59e2e559b40bff3",
	"private_key": "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
	"client_email": "client@hi.iam.gserviceaccount.com",
	"client_id": "111111111111111111",
	"auth_uri": "https://mock.com/o/oauth2/auth",
	"token_uri": "https://mock.com/token",
	"auth_provider_x509_cert_url": "https://mock.com/oauth2/v1/certs",
	"client_x509_cert_url": "https://mock.com/robot/v1/metadata/x509/client%40hi.iam.gserviceaccount.com"
}`)
	return sa
}
