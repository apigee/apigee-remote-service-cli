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
	"io/ioutil"
	"os"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
)

func TestCreateNativeConfigs(t *testing.T) {
	print := testutil.Printer("TestCreateNativeConfigs")

	tmpDir, err := ioutil.TempDir("./", "native")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--native", "--out-dir", tmpDir, "-r", "runtime", "--tls", "./"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"generating the configuration file for native envoy proxy...",
		"generating envoy-config.yaml...",
	}

	print.CheckPrefix(t, want)
}

func TestCreateIstioConfigs(t *testing.T) {
	print := testutil.Printer("TestCreateIstioConfigs")

	tmpDir := "./istio-samples"
	defer os.RemoveAll(tmpDir)

	// a good command
	rootArgs := &shared.RootArgs{}
	flags := []string{"samples", "create", "--out-dir", tmpDir, "-r", "runtime"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

	if err := rootCmd.Execute(); err != nil {
		t.Errorf("want no error: %v", err)
	}

	want := []string{
		"generating configuration files envoy as sidecars...",
		"generating envoyfilter-sidecar.yaml...",
		"generating request-authentication.yaml...",
		"generating apigee-envoy-adapter.yaml...",
	}

	print.CheckPrefix(t, want)
}
