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
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/templates"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"gopkg.in/yaml.v3"
)

func TestCreateNativeConfigs(t *testing.T) {
	print := testutil.Printer("TestCreateNativeConfigs")

	defer os.RemoveAll("./native")

	config := generateConfig(t, false)

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
}

func TestCreateIstioConfigsWithHttpbin(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigsWithHttpbin")

	tmpDir := "./istio-samples"
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, false)

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

	config := generateConfig(t, true)

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

func TestExistingDirectoryError(t *testing.T) {
	print := testutil.Printer("TestExistingDirectoryError")

	tmpDir, err := ioutil.TempDir("./", "native")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	config := generateConfig(t, true)

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

	config := generateConfig(t, false)

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

func generateConfig(t *testing.T, isGCPManaged bool) []byte {
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

	return yamlBuffer.Bytes()
}

func TestTemp(t *testing.T) {
	files, err := templates.AssetDir("native")
	if err != nil {
		t.Log(err)
	}
	for _, f := range files {
		t.Log(f)
	}
}
