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

func TestCreateNativeConfigs(t *testing.T) {
	print := testutil.Printer("TestCreateNativeConfigs")

	tmpDir := "./native"
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
	flags := []string{"samples", "create", "-t", "native", "--out", "./native", "-c", tmpFile.Name(), "--tls", "./"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Generating native configuration files...",
		"  generating envoy-config.yaml...",
		"config files successfully generated.",
	}

	print.CheckPrefix(t, want)

	verifyNativeConfig(t, path.Join(tmpDir, "envoy-config.yaml"))
}

func TestCreateIstioConfigsWithHttpbin(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithHttpbin")

	tmpDir := "./istio-samples"
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
	flags := []string{"samples", "create", "--out", tmpDir, "-c", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Generating istio-1.6 configuration files...",
		"  generating apigee-envoy-adapter.yaml...",
		"  generating envoyfilter-sidecar.yaml...",
		"  generating httpbin.yaml...",
		"  generating request-authentication.yaml...",
		"config files successfully generated.",
		"Please enable istio sidecar injection on the default namespace before running kubectl apply on the directory with config files.",
	}

	print.CheckPrefix(t, want)
}

func TestCreateIstioConfigsWithoutHttpbin(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithoutHttpbin")

	tmpDir := "./istio-samples"
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
	flags := []string{"samples", "create", "--out", tmpDir, "-c", tmpFile.Name(), "-n", "target"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Generating istio-1.6 configuration files...",
		"  generating apigee-envoy-adapter.yaml...",
		"  generating envoyfilter-sidecar.yaml...",
		"  generating request-authentication.yaml...",
		"config files successfully generated.",
		"Please enable istio sidecar injection on the default namespace before running kubectl apply on the directory with config files.",
	}

	print.CheckPrefix(t, want)
}

func TestCreateIstioConfigWithAnalyticsSecret(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithAnalyticsSecret")

	tmpDir := "./istio-samples"
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
	flags := []string{"samples", "create", "--out", tmpDir, "-c", tmpFile.Name()}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	verifyIstioConfig(t, path.Join(tmpDir, "apigee-envoy-adapter.yaml"))
}

func TestExistingDirectoryError(t *testing.T) {
	print := testutil.Printer("TestExistingDirectoryError")

	tmpDir, err := ioutil.TempDir("./", "native")
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

	tmpDir, err := ioutil.TempDir("./", "native")
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

	flags := []string{"samples", "create", "-t", "native", "--out", tmpDir, "-c", tmpFile.Name(), "-f"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"Overwriting the existing directory!",
		"Generating native configuration files...",
		"  generating envoy-config.yaml...",
		"config files successfully generated.",
	}

	print.CheckPrefix(t, want)
}

func TestLoadConfigError(t *testing.T) {
	print := testutil.Printer("TestLoadConfigError")

	tmpDir := "./native"
	defer os.RemoveAll(tmpDir)

	// bad config file path
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--out", tmpDir, "-c", "badconfig"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "loading config yaml file: open badconfig: no such file or directory")
}

func generateConfig(t *testing.T, isGCPManaged bool, analyticsSecret bool) []byte {
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)

	config := server.DefaultConfig()
	if !isGCPManaged {
		config.Tenant.InternalAPI = server.LegacySaaSInternalBase
	}
	config.Tenant.RemoteServiceAPI = "https://RUNTIME/remote-service"
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
			"client_secret.json": "secret",
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
