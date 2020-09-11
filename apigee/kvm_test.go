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
)

func kvmTestServer(t *testing.T) *httptest.Server {
	m := http.NewServeMux()

	kvm := KVM{
		Name: "kvm-1",
	}

	m.HandleFunc("/keyvaluemaps/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "kvm-2") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(kvm); err != nil {
				t.Fatalf("want no error %v", err)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	m.HandleFunc("/keyvaluemaps/kvm/entries/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "kvm-2") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(kvm); err != nil {
				t.Fatalf("want no error %v", err)
			}
		case http.MethodPost:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	return httptest.NewServer(m)
}

func TestGetKVM(t *testing.T) {
	ts := kvmTestServer(t)
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
	kvms := &KVMServiceOp{
		client: client,
	}

	kvm, _, err := kvms.Get("kvm-1")
	if err != nil {
		t.Error(err)
	}
	if kvm.Name != "kvm-1" {
		t.Errorf("want kvm-1 got %s", kvm.Name)
	}

	_, _, err = kvms.Get("kvm-2")
	if err == nil {
		t.Error("want error got none")
	}
}

func TestCreateKVM(t *testing.T) {
	ts := kvmTestServer(t)
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
	kvms := &KVMServiceOp{
		client: client,
	}

	kvm := KVM{
		Name: "kvm-1",
	}

	_, err = kvms.Create(kvm)
	if err != nil {
		t.Error(err)
	}
}

func TestGetValueKVM(t *testing.T) {
	kvm := &KVM{
		Name: "kvm",
		Entries: []Entry{
			Entry{
				Name:  "k1",
				Value: "v1",
			},
		},
	}

	v, ok := kvm.GetValue("k1")
	if !ok {
		t.Error("KVM should have entry k1")
	}
	if v != "v1" {
		t.Errorf("want v1 got %s", v)
	}

	_, ok = kvm.GetValue("k2")
	if ok {
		t.Error("KVM should not have entry k2")
	}
}

func TestUpdateEntryKVM(t *testing.T) {
	ts := kvmTestServer(t)
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
	kvms := &KVMServiceOp{
		client: client,
	}

	e := Entry{
		Name:  "k1",
		Value: "v1",
	}

	_, err = kvms.UpdateEntry("kvm", e)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
}

func TestAddEntryKVM(t *testing.T) {
	ts := kvmTestServer(t)
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
	kvms := &KVMServiceOp{
		client: client,
	}

	e := Entry{
		Name:  "k1",
		Value: "v1",
	}

	_, err = kvms.AddEntry("kvm", e)
	if err != nil {
		t.Errorf("want no error got %v", err)
	}
}
