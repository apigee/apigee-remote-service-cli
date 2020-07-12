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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/jarcoal/httpmock"
)

const (
	mockOrg           = "org"
	mockEnv           = "env"
	mockUser          = "user"
	mockPassword      = "password"
	mockRuntime       = "mock.runtime.com"
	mockRuntimeURL    = "https://mock.runtime.com"
	mockNamespace     = "namespace"
	mockToken         = "token"
	mockManagement    = "api.mock.apigee.com"
	mockManagementURL = "https://api.mock.apigee.com"

	legacyEdgeHost = "api.enterprise.apigee.com"
	legacyCredHost = "istioservices.apigee.net"

	hybridHost = "apigee.googleapis.com"

	internalProxyURL      = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/edgemicro-internal/deployments\z`
	internalProxyURLNoEnv = `=~^https://%s/v1/organizations/(\w+)/apis/edgemicro-internal\z`
	internalDeployURL     = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/edgemicro-internal/revisions/(\d+)/deployments\z`

	getDeployedURL      = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/remote-service/deployments\z`
	getDeployedURLNoEnv = `=~^https://%s/v1/organizations/(\w+)/apis/remote-service\z`
	deployURL           = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/apis/remote-service/revisions/(\d+)/deployments\z`
	deployURLNoEnv      = `=~^https://%s/v1/organizations/(\w+)/apis\z`
	cachesURLNoEnv      = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/caches\z`
	credentialURL       = `=~^https://%s/edgemicro/credential/organization/(\w+)/environment/(\w+)\z`
	kvmURL              = `=~^https://%s/v1/organizations/(\w+)/environments/(\w+)/keyvaluemaps\z`

	legacyRemoteServiceURL = `=~^https://%s-%s.apigee.net/remote-service/(\w+)\z`
	hybridRemoteServiceURL = `=~^https://%s/remote-service/(\w+)\z`
)

func TestVerifyRemoteServiceProxyTLS(t *testing.T) {

	count := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		count++
	}))

	// try without InsecureSkipVerify
	p := &provision{
		RootArgs: &shared.RootArgs{
			RuntimeBase:        ts.URL,
			Token:              "-",
			InsecureSkipVerify: false,
			IsLegacySaaS:       true,
		},
	}
	if err := p.Resolve(false, false); err != nil {
		t.Fatal(err)
	}
	client, err := p.createAuthorizedClient(p.createConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.verifyRemoteServiceProxy(client, shared.Printf); err == nil {
		t.Errorf("got nil error, want TLS failure")
	}

	// try with InsecureSkipVerify
	p.InsecureSkipVerify = true
	client, err = p.createAuthorizedClient(p.createConfig(nil))
	if err := p.Resolve(false, false); err != nil {
		t.Fatal(err)
	}

	if err := p.verifyRemoteServiceProxy(client, shared.Printf); err != nil {
		t.Errorf("unexpected: %v", err)
	}
	if count != 4 {
		t.Errorf("got %d, want %d", count, 4)
	}
}

func TestProvisionAll(t *testing.T) {
	activateMockServer()
	defer deactivateMockServer()

	testCases := []struct {
		name  string
		flags []string
	}{
		{
			name:  "TestProvisionLegacySaaS",
			flags: []string{"provision", "-o", mockOrg, "-e", mockEnv, "-u", mockUser, "-p", mockPassword, "--legacy"},
		},
		{
			name: "TestProvisionHybrid",
			flags: []string{"provision", "-o", mockOrg, "-e", mockEnv,
				"-r", mockRuntimeURL, "-n", mockNamespace, "-t", mockToken, "-v"},
		},
		{
			name:  "TestProvisionOPDK",
			flags: []string{"provision", "-o", mockOrg, "-e", mockEnv, "-u", mockUser, "-p", mockPassword, "-r", mockRuntimeURL, "-m", mockManagementURL, "--opdk"},
		},
	}

	for _, tc := range testCases {
		tc := tc
		print := testutil.Printer(tc.name)

		rootArgs := &shared.RootArgs{}
		rootCmd := cmd.GetRootCmd(tc.flags, print.Printf)
		shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))

		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("want no error: %v", err)
		}
	}
}

func activateMockServer() {
	httpmock.Activate()

	// legacy saas
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURL, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURLNoEnv, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURLNoEnv, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(cachesURLNoEnv, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURL, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(credentialURL, legacyCredHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(kvmURL, legacyEdgeHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(legacyRemoteServiceURL, mockOrg, mockEnv),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(legacyRemoteServiceURL, mockOrg, mockEnv),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))

	// hybrid
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURL, hybridHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURLNoEnv, hybridHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURLNoEnv, hybridHost),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURL, hybridHost),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))

	// OPDK
	httpmock.RegisterResponder("GET", fmt.Sprintf(internalProxyURL, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(internalProxyURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(internalDeployURL, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURL, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(getDeployedURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(cachesURLNoEnv, mockManagement),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(deployURL, mockManagement),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(credentialURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(kvmURL, mockManagement),
		httpmock.NewStringResponder(http.StatusCreated, "{}"))
	httpmock.RegisterResponder("GET", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
	httpmock.RegisterResponder("POST", fmt.Sprintf(hybridRemoteServiceURL, mockRuntime),
		httpmock.NewStringResponder(http.StatusAccepted, "{}"))
}

func deactivateMockServer() {
	httpmock.DeactivateAndReset()
}
