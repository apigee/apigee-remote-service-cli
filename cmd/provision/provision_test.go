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
	defer ts.Close()

	duration = 200
	interval = 100

	// try without InsecureSkipVerify
	p := &provision{
		RootArgs: &shared.RootArgs{
			RuntimeBase:        ts.URL,
			Token:              "-",
			InsecureSkipVerify: false,
			IsLegacySaaS:       true,
			Org:                "hi",
			Env:                "test",
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

func serveMux(t *testing.T) *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/v1/organizations/gcp/environments/test/apis/remote-service/deployments", func(w http.ResponseWriter, r *http.Request) {
		res := apigee.GCPDeployments{
			Deployments: []apigee.GCPDeployment{
				{
					Environment: "test",
					Name:        "remote-service",
					Revision:    "3",
				},
				{
					Environment: "test",
					Name:        "remote-service",
					Revision:    "2",
				},
				{
					Environment: "test",
					Name:        "remote-service",
					Revision:    "1",
				},
			},
		}
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		}
	})
	m.HandleFunc("/v1/organizations/gcp/apis/remote-service", func(w http.ResponseWriter, r *http.Request) {
		res := apigee.Proxy{
			Name:      "remote-service",
			Revisions: []apigee.Revision{3, 2, 1},
			MetaData: apigee.ProxyMetadata{
				LastModifiedBy: "gcp",
				CreatedBy:      "gcp",
			},
		}
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		}
	})
	m.HandleFunc("/v1/organizations/saas/environments/test/apis/remote-service/deployments", func(w http.ResponseWriter, r *http.Request) {
		res := apigee.EnvironmentDeployment{
			Name: "remote-service",
			Revision: []apigee.RevisionDeployment{
				{
					Number: 3,
					State:  "deployed",
				},
				{
					Number: 2,
					State:  "undeployed",
				},
				{
					Number: 1,
					State:  "undeployed",
				},
			},
		}
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		}
	})
	m.HandleFunc("/v1/organizations/saas/apis/remote-service", func(w http.ResponseWriter, r *http.Request) {
		res := apigee.Proxy{
			Name:      "remote-service",
			Revisions: []apigee.Revision{3, 2, 1},
			MetaData: apigee.ProxyMetadata{
				LastModifiedBy: "gcp",
				CreatedBy:      "gcp",
			},
		}
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		}
	})
	m.HandleFunc("/credential/organization/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		default:
			t.Fatalf("%s to %s not allowed", r.Method, r.URL.Path)
		case http.MethodPost:
			if strings.Contains(r.URL.Path, "nocred") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
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
	// internal proxy verification
	m.HandleFunc("/analytics/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "badinternal") {
			http.Error(w, "Not Found", http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	m.HandleFunc("/axpublisher/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "badinternal") {
			http.Error(w, "Not Found", http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})
	// catch-all handler for remote service proxy verification
	m.HandleFunc("/remote-service/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "version") {
			w.Header().Set("Content-Type", "application/json")
			res := map[string]string{
				"platform": "1.3.0",
			}
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	// catch-all handler for proxy management
	m.HandleFunc("/v1/organizations/", func(w http.ResponseWriter, r *http.Request) {
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
				if strings.Contains(r.URL.Path, "conflict") {
					w.WriteHeader(http.StatusConflict)
				} else if strings.Contains(r.URL.Path, "noapiprod") {
					w.WriteHeader(http.StatusForbidden)
				}
			} else if strings.Contains(r.URL.Path, "keyvaluemaps") {
				if strings.Contains(r.URL.Path, "conflictkvm") {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte("{}"))
				} else if strings.Contains(r.URL.Path, "nokvm") {
					w.WriteHeader(http.StatusForbidden)
				} else if strings.Contains(r.URL.Path, "badkvm") {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("{}"))
				} else {
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte("{}"))
				}
			} else if strings.Contains(r.URL.Path, "caches") {
				if strings.Contains(r.URL.Path, "conflictcache") {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte("{}"))
				} else if strings.Contains(r.URL.Path, "nocache") {
					w.WriteHeader(http.StatusForbidden)
				} else if strings.Contains(r.URL.Path, "badcache") {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("{}"))
				} else {
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte("{}"))
				}
			} else {
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte("{}"))
			}
		}
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// This matches every other route - we should not hit this one.
		t.Fatalf("Unknown route %s hit", r.URL.Path)
	})
	return m
}

func handler(t *testing.T) http.Handler {
	return serveMux(t)
}

func TestProvisionLegacySaaS(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestProvisionLegacySaaS")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "hi", "-e", "test", "-u", "me", "-p", "password", "--legacy"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	// force replacing existing proxies
	rootArgs = &shared.RootArgs{}
	flags = []string{"provision", "-o", "saas", "-e", "test", "-u", "me", "-p", "password", "-f", "--legacy"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{
		"# Configuration for apigee-remote-service-envoy (platform: SaaS)",
		"# generated by apigee-remote-service-cli provision on",
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: apigee-remote-service-envoy
  namespace: apigee
data:
  config.yaml:`,
		"",
		"",
		"",
	}

	print.CheckPrefix(t, want)

	// error on having rotate > 0 on saas
	rootArgs = &shared.RootArgs{}
	flags = []string{"provision", "-o", "saas", "-e", "test", "-u", "me", "-p", "password", "-f", "--legacy", "--rotate", "1"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "--rotate only valid for hybrid, use 'token rotate-cert' for others")
}

func TestProvisionOPDK(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestProvisionOPDK")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "opdk", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}

func TestProvisionHybrid(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	duration = 200
	interval = 100

	print := testutil.Printer("TestProvisionHybrid")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "gcp", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "token"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{
		"# Configuration for apigee-remote-service-envoy (platform: GCP)",
		"# generated by apigee-remote-service-cli provision on",
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: apigee-remote-service-envoy
  namespace: ns
data:
  config.yaml:`,
	}

	print.CheckPrefix(t, want)

	// force replacing existing proxies
	flags = []string{"provision", "-o", "gcp", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "token", "-f", "-v"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	// error on missing token
	flags = []string{"provision", "-o", "gcp", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "", "-f", "-v"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "--token is required for hybrid")
}

func TestInvalidRuntimeVersion(t *testing.T) {
	badHandler := func(t *testing.T) http.Handler {
		m := serveMux(t)
		m.HandleFunc("/remote-service/version", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		return m
	}

	ts := httptest.NewServer(badHandler(t))
	defer ts.Close()

	duration = 200
	interval = 100

	print := testutil.Printer("TestRuntimeVersion")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "gcp", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "token"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "Unable to get the runtime version: invalid character")
}

func TestMissingRuntimeVersion(t *testing.T) {
	badHandler := func(t *testing.T) http.Handler {
		m := serveMux(t)
		m.HandleFunc("/remote-service/version", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			res := map[string]string{
				"useless-field": "hello",
			}
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		})
		return m
	}

	ts := httptest.NewServer(badHandler(t))
	defer ts.Close()

	duration = 200
	interval = 100

	print := testutil.Printer("TestRuntimeVersion")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "gcp", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "token", "-v"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "Unable to get the runtime version: response has no 'platform' field")
}

func TestUnknownRuntimeVersion(t *testing.T) {
	badHandler := func(t *testing.T) http.Handler {
		m := serveMux(t)
		m.HandleFunc("/remote-service/version", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			res := map[string]string{
				"platform": "unknown",
			}
			if err := json.NewEncoder(w).Encode(res); err != nil {
				t.Fatalf("want no error %v", err)
			}
		})
		return m
	}

	ts := httptest.NewServer(badHandler(t))
	defer ts.Close()

	duration = 200
	interval = 100

	print := testutil.Printer("TestRuntimeVersion")

	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "gcp", "-e", "test", "-r", ts.URL, "-n", "ns", "-t", "token", "-v"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}

func TestAPIProductCreation(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestProvisionBadAPIProduct")

	// error on failing in creating api product
	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "noapiprod", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "creating remote-service API product")

	// product already exist
	flags = []string{"provision", "-o", "conflict", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{
		"# Configuration for apigee-remote-service-envoy (platform: OPDK)",
		"# generated by apigee-remote-service-cli provision on",
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: apigee-remote-service-envoy
  namespace: ns
data:
  config.yaml:`,
	}

	print.CheckPrefix(t, want)
}

func TestKVMCreation(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestKVMCreation")

	// error on failing in creating kvm
	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "nokvm", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "retrieving or creating kvm")

	// unexpected status code on creating kvm
	flags = []string{"provision", "-o", "badkvm", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "creating kvm remote-service, status code: 200")

	// kvm already exist
	flags = []string{"provision", "-o", "conflictkvm", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{
		"# Configuration for apigee-remote-service-envoy (platform: OPDK)",
		"# generated by apigee-remote-service-cli provision on",
		`apiVersion: v1
kind: ConfigMap
metadata:
  name: apigee-remote-service-envoy
  namespace: ns
data:
  config.yaml:`,
	}

	print.CheckPrefix(t, want)
}

func TestCacheCreation(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestCacheCreation")

	// error on failing in creating caches
	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "nocache", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "deploying internal proxy")

	// unexpected status code on creating caches
	flags = []string{"provision", "-o", "badcache", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err = rootCmd.Execute()
	testutil.ErrorContains(t, err, "creating cache remote-service, status code: 200")

	// caches already exist
	flags = []string{"provision", "-o", "conflictcache", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}

func TestCredentialsCreation(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestCredentialsCreation")

	// error on failing in creating credentials
	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "nocred", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	err := rootCmd.Execute()
	testutil.ErrorContains(t, err, "generating credential")
}

func TestInternalProxyVerification(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()

	print := testutil.Printer("TestInternalProxyVerification")

	// error on failing in verifying for opdk
	rootArgs := &shared.RootArgs{}
	flags := []string{"provision", "-o", "badinternal", "-e", "test", "-u", "me", "-p", "password", "-r", ts.URL, "-n", "ns", "-m", ts.URL, "--opdk"}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}

	// error on failing in verifying for legacy saas
	flags = []string{"provision", "-o", "badinternal", "-e", "test", "-u", "me", "-p", "password", "--legacy"}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, testCmd(rootArgs, print.Printf, ts.URL))

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("want no error: %v", err)
	}
}
