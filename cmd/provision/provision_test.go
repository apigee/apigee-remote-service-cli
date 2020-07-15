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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/apigee"
	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/spf13/cobra"
)

func TestVerifyRemoteServiceProxyTLS(t *testing.T) {

	count := 0
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte("{}")); err != nil {
			t.Fatalf("want no error %v", err)
		}
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
	if err != nil {
		t.Fatal(err)
	}
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

func testCmd(rootArgs *shared.RootArgs, printf shared.FormatFn, url string) *cobra.Command {
	c := Cmd(rootArgs, printf)

	defaultPersistentPreRun := c.PersistentPreRunE
	c.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := defaultPersistentPreRun(cmd, args); err != nil {
			return err
		}
		setTestUrls(rootArgs, url)
		return nil
	}

	return c
}

func setTestUrls(rootArgs *shared.RootArgs, url string) {
	rootArgs.RemoteServiceProxyURL = fmt.Sprintf("%s/remote-service", url)
	rootArgs.ManagementBase = url
	rootArgs.InternalProxyURL = url
	rootArgs.ClientOpts.MgmtURL = url
	rootArgs.ApigeeClient, _ = apigee.NewEdgeClient(rootArgs.ClientOpts)
}

func goodHandler(t *testing.T) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/remote-service/", func(w http.ResponseWriter, r *http.Request) {
		// w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	})
	m.HandleFunc("/v1/organizations/", func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.URL.Path)
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		case http.MethodPost:
			if strings.Contains(r.URL.Path, "apiproducts") {
				ap := apiProduct{}
				if err := json.NewDecoder(r.Body).Decode(&ap); err != nil {
					t.Fatalf("incorrect apiproduct %v", err)
				}
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
		}
	})
	m.HandleFunc("/credential/organization/", func(w http.ResponseWriter, r *http.Request) {
		t.Log(r.URL.Path)
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodPost:
			jsonBody := make(map[string]interface{})
			if err := json.NewDecoder(r.Body).Decode(&jsonBody); err != nil {
				t.Fatalf("error in generating credential request %v", err)
			}
			if _, ok := jsonBody["key"]; !ok {
				t.Error("generating credential request has no key")
			}
			if _, ok := jsonBody["secret"]; !ok {
				t.Error("generating credential request has no secret")
			}
			w.WriteHeader(http.StatusOK)
		}
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This matches every other route - we should not hit this one.
		t.Fatalf("Unknown route %s hit", r.URL.Path)
	})
	return m
}

func TestProvisionLegacySaaS(t *testing.T) {
	ts := httptest.NewServer(goodHandler(t))
	defer ts.Close()

	print := testutil.Printer("TestProvisionLegacySaaS")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "hi", "-e", "test", "-u", "me", "-p", "password", "--legacy"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}

func TestProvisionOPDK(t *testing.T) {
	ts := httptest.NewServer(goodHandler(t))
	defer ts.Close()

	print := testutil.Printer("TestProvisionHybrid")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "hi", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}

func TestProvisionHybrid(t *testing.T) {
	ts := httptest.NewServer(goodHandler(t))
	defer ts.Close()

	print := testutil.Printer("TestProvisionHybrid")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "hi", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "token", "-v"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}
