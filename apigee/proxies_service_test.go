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

package apigee

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/v2/testutil"
)

func proxyTestServer(t *testing.T) *httptest.Server {
	m := http.NewServeMux()

	proxy := Proxy{
		Name: "proxy-1",
	}

	// revs := []Revision{3, 2, 1}

	dep := EnvironmentDeployment{
		Revision: []RevisionDeployment{
			{
				Number: 3,
				State:  "deployed",
			},
			{
				Number: 2,
			},
			{
				Number: 1,
			},
		},
	}

	gcpDep := GCPDeployments{
		Deployments: []GCPDeployment{
			{
				Revision: "3",
			},
			{
				Revision: "2",
			},
			{
				Revision: "1s",
			},
		},
	}

	ctr := 0

	m.HandleFunc("/apis/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "proxy-notfound") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(proxy); err != nil {
				t.Fatalf("want no error %v", err)
			}
		case http.MethodPost:
			if strings.Contains(r.URL.Path, "proxy-notfound") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	m.HandleFunc("/apis/proxy-1/deployments/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(dep); err != nil {
				t.Fatalf("want no error %v", err)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	m.HandleFunc("/apis/proxy-gcp/deployments/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(gcpDep); err != nil {
				t.Fatalf("want no error %v", err)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	m.HandleFunc("/apis/proxy-none/deployments/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	m.HandleFunc("/apis/proxy-gcp/revisions/1/deployments", (func(w http.ResponseWriter, r *http.Request) {
		dep := GCPDeployment{
			Revision: "1",
		}
		switch ctr {
		case 0:
			dep.State = "PROGRESSING"
		case 1:
			dep.State = "READY"
		case 2:
			dep.State = "ERROR"
		case 3:
			dep.State = "UNKNOWN"
		}
		ctr++

		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(dep); err != nil {
				t.Fatalf("want no error %v", err)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return httptest.NewServer(m)
}

func TestGetProxy(t *testing.T) {
	ts := proxyTestServer(t)
	defer ts.Close()

	baseUrl, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &EdgeClient{
		client:     http.DefaultClient,
		BaseURLEnv: baseUrl,
		BaseURL:    baseUrl,
	}
	ps := &ProxiesServiceOp{
		client: client,
	}

	proxy, _, err := ps.Get("proxy-1")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
	if proxy.Name != "proxy-1" {
		t.Errorf("want proxy-1 got %s", proxy.Name)
	}

	_, _, err = ps.Get("proxy-notfound")
	if err == nil {
		t.Error("want error got none")
	}
}

func TestImportProxy(t *testing.T) {
	ts := proxyTestServer(t)
	defer ts.Close()

	baseUrl, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &EdgeClient{
		client:     http.DefaultClient,
		BaseURLEnv: baseUrl,
		BaseURL:    baseUrl,
	}
	ps := &ProxiesServiceOp{
		client: client,
	}

	proxiesPath := "../cmd/provision/proxies/"
	_, _, err = ps.Import("", proxiesPath+"remote-service-gcp/")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, _, err = ps.Import("", proxiesPath+"remote-service-gcp/apiproxy")
	testutil.ErrorContains(t, err, "while creating temp dir, error:")

	_, _, err = ps.Import("", proxiesPath+"remote-service-gcp/apiproxy/remote-service.xml")
	testutil.ErrorContains(t, err, "source must be a zipfile")

	ps.client.IsGCPManaged = true
	_, _, err = ps.Import("", proxiesPath+"remote-service-gcp/")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
}

func TestDeployProxy(t *testing.T) {
	ts := proxyTestServer(t)
	defer ts.Close()

	baseUrl, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &EdgeClient{
		client:     http.DefaultClient,
		BaseURLEnv: baseUrl,
		BaseURL:    baseUrl,
	}
	ps := &ProxiesServiceOp{
		client: client,
	}
	rev := Revision(1)

	_, _, err = ps.Deploy("proxy-1", "test", rev)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, _, err = ps.Deploy("proxy-notfound", "test", rev)
	testutil.ErrorContains(t, err, "403")
}

func TestUndeployProxy(t *testing.T) {
	ts := proxyTestServer(t)
	defer ts.Close()

	baseUrl, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &EdgeClient{
		client:     http.DefaultClient,
		BaseURLEnv: baseUrl,
		BaseURL:    baseUrl,
	}
	ps := &ProxiesServiceOp{
		client: client,
	}
	rev := Revision(1)

	_, _, err = ps.Undeploy("proxy-1", "test", rev)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, _, err = ps.Undeploy("proxy-notfound", "test", rev)
	testutil.ErrorContains(t, err, "403")

	ps.client.IsGCPManaged = true
	_, _, err = ps.Undeploy("proxy-1", "test", rev)
	testutil.ErrorContains(t, err, "405") // DELETE not allowed by test server
}

func TestGetProxyDeployment(t *testing.T) {
	ts := proxyTestServer(t)
	defer ts.Close()

	baseUrl, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &EdgeClient{
		client:     http.DefaultClient,
		BaseURLEnv: baseUrl,
		BaseURL:    baseUrl,
	}
	ps := &ProxiesServiceOp{
		client: client,
	}

	_, err = ps.GetDeployedRevision("proxy-1")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, err = ps.GetDeployedRevision("proxy-notfound")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, err = ps.GetDeployedRevision("proxy-none")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	ps.client.IsGCPManaged = true
	_, err = ps.GetDeployedRevision("proxy-1")
	testutil.ErrorContains(t, err, "not compatible with GCP Experience")
}

func TestGetGCPProxyDeployment(t *testing.T) {
	ts := proxyTestServer(t)
	defer ts.Close()

	baseUrl, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &EdgeClient{
		client:     http.DefaultClient,
		BaseURLEnv: baseUrl,
		BaseURL:    baseUrl,
		debug:      true,
	}
	ps := &ProxiesServiceOp{
		client: client,
	}

	_, err = ps.GetGCPDeployedRevision("proxy-gcp")
	testutil.ErrorContains(t, err, "only compatible with GCP Experience")

	ps.client.IsGCPManaged = true
	_, err = ps.GetGCPDeployedRevision("proxy-gcp")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, err = ps.GetGCPDeployedRevision("proxy-none")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}

	_, err = ps.GetGCPDeployedRevision("proxy-notfound")
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
}

func TestSmartFilter(t *testing.T) {
	strs := []string{
		"test",
		"test~",
		"#test",
		"test#",
		"#test#",
	}
	want := []bool{
		true,
		false,
		true,
		true,
		false,
	}

	for i, s := range strs {
		if smartFilter(s) != want[i] {
			t.Errorf("want %v for %s, got %v", want[i], s, !want[i])
		}
	}
}
