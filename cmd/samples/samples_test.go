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

package samples

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"gopkg.in/yaml.v3"
)

func TestFlagValidation(t *testing.T) {
	testSamples := [][]string{
		{"--template", "envoy-1.16", "--tag", "tag"},
		{"--template", "istio-1.7", "--host", "localhost"},
		{"--template", "istio-1.7", "--adapter-host", "targethost"},
		{"--template", "istio-1.7", "--tls", "tls-dir"},
		{"--template", "istio-0.9"},
	}

	wantedErrors := []string{
		"flag --tag should only be used for the istio template",
		"flags --adapter-host, --host or --tls should only be used for envoy templates",
		"flags --adapter-host, --host or --tls should only be used for envoy templates",
		"flags --adapter-host, --host or --tls should only be used for envoy templates",
		"template option: \"istio-0.9\" not found",
	}

	config := generateConfig(t, true, true)
	configFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := configFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(configFile.Name())

	for i, f := range testSamples {
		print := testutil.Printer("TestFlagValidation")
		rootArgs := &shared.RootArgs{}
		flags := []string{"samples", "create", "--config", configFile.Name()}
		flags = append(flags, f...)
		rootCmd := cmd.GetRootCmd(flags, print.Printf)
		shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

		err := rootCmd.Execute()
		testutil.ErrorContains(t, err, wantedErrors[i])
	}
}

func TestTemplatesListing(t *testing.T) {
	print := testutil.Printer("TemplatesListing")

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "templates"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Supported templates:",
		"  envoy-1.15",
		"  envoy-1.16",
		"  envoy-1.17",
		"  istio-1.7",
		"  istio-1.8",
	}

	print.CheckPrefix(t, want)
}

func TestSamplesParseConfigs(t *testing.T) {
	cfg := server.DefaultConfig()
	cfg.Tenant.RemoteServiceAPI = "http://runtime/remote-service"
	cfg.Tenant.OrgName = "hi"
	cfg.Tenant.EnvName = "test"
	cfg.Analytics.FluentdEndpoint = "fluentd"

	s := &samples{
		RootArgs: &shared.RootArgs{
			ServerConfig: cfg,
		},
		TargetService: targetService{},
		TLS:           tls{},
	}

	if err := s.parseConfig(); err != nil {
		t.Errorf("want no error, got %v", err)
	}
	if s.RuntimeTLS {
		t.Errorf("runtime TLS should not be true")
	}
	if s.RuntimePort != "80" {
		t.Errorf("want runtime port to be %q got %q", "80", s.RuntimePort)
	}
	if n := envScopeEncodedName("hi", "test"); n != s.EncodedName {
		t.Errorf("want encoded name to be %q got %q", n, s.EncodedName)
	}

	cfg.Analytics.CredentialsJSON = []byte("secret")
	if err := s.parseConfig(); err != nil {
		t.Errorf("want no error, got %v", err)
	}
	if s.EncodedName != "" {
		t.Errorf("want encoded name to be empty, got %q", s.EncodedName)
	}

	s.TLS.Dir = "dir"
	if err := s.parseConfig(); err != nil {
		t.Errorf("want no error, got %v", err)
	}
	if s.TLS.Key != "dir/tls.key" {
		t.Errorf("want tls key to be %q got %q", "dir/tls.key", s.TLS.Key)
	}
	if s.TLS.Crt != "dir/tls.crt" {
		t.Errorf("want tls cert to be %q got %q", "dir/tls.cert", s.TLS.Crt)
	}
}

func TestCreateEnvoyConfigs(t *testing.T) {
	print := testutil.Printer("TestCreateEnvoyConfigs")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, false, false)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	// make a fake tag
	shared.BuildInfo.Version = "v0.0.0-SNAPSHOT"

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "-t", "envoy-1.16", "--out", path.Join(tmpDir, "native"), "-c", tmpFile.Name(), "--tls", "./"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Generating envoy-1.16 configuration files...",
		"  generating envoy-config.yaml...",
		"Config files successfully generated.",
	}

	print.CheckPrefix(t, want)

	verifyNativeConfig(t, path.Join(tmpDir, "native/envoy-config.yaml"))
}

func TestCreateIstioConfigsWithHttpbin(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithHttpbin")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, false, false)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	// make a fake tag
	shared.BuildInfo.Version = "0.0.0-SNAPSHOT"

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--out", path.Join(tmpDir, "istio-samples"), "-c", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Generating istio-1.7 configuration files...",
		"  generating apigee-envoy-adapter.yaml...",
		"  generating envoyfilter-sidecar.yaml...",
		"  generating httpbin.yaml...",
		"  generating request-authentication.yaml...",
		"Config files successfully generated.",
		"Please enable istio sidecar injection on the default namespace before running kubectl apply on the directory with config files.",
	}

	print.CheckPrefix(t, want)
}

func TestCreateIstioConfigsWithoutHttpbin(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithoutHttpbin")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, true, false)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--out", path.Join(tmpDir, "istio-samples"), "-c", tmpFile.Name(), "-n", "target"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Generating istio-1.7 configuration files...",
		"  generating apigee-envoy-adapter.yaml...",
		"  generating envoyfilter-sidecar.yaml...",
		"  generating request-authentication.yaml...",
		"Config files successfully generated.",
		"Please enable istio sidecar injection on the default namespace before running kubectl apply on the directory with config files.",
	}

	print.CheckPrefix(t, want)
}

func TestCreateIstioConfigWithAnalyticsSecret(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithAnalyticsSecret")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, true, true)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--template", "istio-1.7", "--out", path.Join(tmpDir, "istio-samples"), "-c", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	verifyIstioConfig(t, path.Join(tmpDir, "istio-samples/apigee-envoy-adapter.yaml"))
}

func TestExistingDirectoryError(t *testing.T) {
	print := testutil.Printer("TestExistingDirectoryError")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, true, false)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	// existing directory with no overwrite
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--out", tmpDir, "-c", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "creating sample config files: output directory already exists")
}

func TestExistingDirectoryOverwrite(t *testing.T) {
	print := testutil.Printer("TestExistingDirectoryOverwrite")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, false, false)

	tmpFile, err := ioutil.TempFile("", "config.yaml")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err := tmpFile.Write(config); err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(tmpFile.Name())

	// existing directory with overwrite
	rootArgs := &shared.RootArgs{}

	flags := []string{"samples", "create", "-t", "envoy-1.16", "--out", tmpDir, "-c", tmpFile.Name(), "-f"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Overwriting the existing directory!",
		"Generating envoy-1.16 configuration files...",
		"  generating envoy-config.yaml...",
		"Config files successfully generated.",
	}

	print.CheckPrefix(t, want)
}

func TestLoadConfigError(t *testing.T) {
	print := testutil.Printer("TestLoadConfigError")

	tmpDir, err := ioutil.TempDir("", "samples")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// bad config file path
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--out", tmpDir, "-c", "badconfig"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "loading config yaml file: open badconfig: no such file or directory")
}

func TestGetTemplatesError(t *testing.T) {
	err := getTemplates("no such dir", "no such template")
	if err == nil {
		t.Fatal("want error got none")
	}
	testutil.ErrorContains(t, err, "restoring asset no such template: Asset no such template not found")
}

func TestShortName(t *testing.T) {
	longName := "asdfasdfasdfasdfasdf"
	if s := shortName(longName); s != longName[:15] {
		t.Errorf("want %q got %q", longName[:15], s)
	}
}

func generateConfig(t *testing.T, isGCPManaged bool, analyticsSecret bool) []byte {
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)

	config := server.DefaultConfig()
	if !isGCPManaged {
		config.Tenant.InternalAPI = server.LegacySaaSInternalBase
	}
	config.Tenant.RemoteServiceAPI = "https://RUNTIME:9001/remote-service"
	config.Tenant.OrgName = "hi"
	config.Tenant.EnvName = "test"
	config.Analytics.FluentdEndpoint = "apigee-udca-hi-test-1q2w3e4r.apigee:20001"
	if err := yamlEncoder.Encode(config); err != nil {
		t.Fatal(err)
	}
	configYAML := yamlBuffer.String()
	data := map[string]string{"config.yaml": configYAML}

	configCRD := server.ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: server.Metadata{
			Name:      "apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: data,
	}

	yamlBuffer.Reset()
	yamlEncoder = yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	if err := yamlEncoder.Encode(configCRD); err != nil {
		t.Fatal(err)
	}

	policySecretCRD := server.SecretCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: server.Metadata{
			Name:      "hi-test-policy-secret",
			Namespace: "apigee",
		},
		Data: map[string]string{},
	}
	if err := yamlEncoder.Encode(policySecretCRD); err != nil {
		t.Fatal(err)
	}

	if !analyticsSecret {
		return yamlBuffer.Bytes()
	}

	analyticsSecretCRD := server.SecretCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: server.Metadata{
			Name:      "hi-test-analytics-secret",
			Namespace: "apigee",
		},
		Data: map[string]string{
			"client_secret.json": fakeServiceAccount(),
		},
	}
	if err := yamlEncoder.Encode(analyticsSecretCRD); err != nil {
		t.Fatal(err)
	}

	return yamlBuffer.Bytes()
}

// verifyIstioConfig checks part of the envoy-config.yaml
// it checks if the runtime host if configured in the auth service
func verifyNativeConfig(t *testing.T, filename string) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(yamlFile))
	cfg := make(map[string]interface{})

	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}

	sr := cfg["static_resources"].(map[string]interface{})
	cls := sr["clusters"].([]interface{})
	for _, c := range cls {
		c := c.(map[string]interface{})
		if c["name"].(string) != "apigee-auth-service" {
			continue
		}
		ts := c["transport_socket"].(map[string]interface{})
		tc := ts["typed_config"].(map[string]interface{})
		if tc["sni"].(string) != "RUNTIME" {
			t.Errorf("runtime host not configured correctly, got %s want RUNTIME", ts["sni"].(string))
		}
	}
}

// verifyIstioConfig reads part of the apigee-envoy-adapter.yaml
// it checks if the secret names are correct when present
func verifyIstioConfig(t *testing.T, filename string) {
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(yamlFile))
	cfg := make(map[string]interface{})

	if err := decoder.Decode(&cfg); err != nil {
		t.Fatal(err)
	}

	spec := cfg["spec"].(map[string]interface{})
	tmpl := spec["template"].(map[string]interface{})
	spec = tmpl["spec"].(map[string]interface{})
	vols := spec["volumes"].([]interface{})
	for _, v := range vols {
		c := v.(map[string]interface{})
		if c["name"].(string) == "analytics-secret" {
			s := c["secret"].(map[string]interface{})
			name := s["secretName"].(string)
			if name != "hi-test-analytics-secret" {
				t.Errorf("secret name not correct, want 'hi-test-analytics-secret' got %s", name)
			}
		}
		if c["name"].(string) == "policy-secret" {
			s := c["secret"].(map[string]interface{})
			name := s["secretName"].(string)
			if name != "hi-test-policy-secret" {
				t.Errorf("secret name not correct, want 'hi-test-policy-secret' got %s", name)
			}
		}
	}
}

func fakeServiceAccount() string {
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
	return base64.StdEncoding.EncodeToString(sa)
}
