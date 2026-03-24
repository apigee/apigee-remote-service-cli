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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func kvmTestServer(t *testing.T) *httptest.Server {
	m := http.NewServeMux()
	kvm := KVM{Name: "kvm-1"}

	// Handle both /keyvaluemaps and /keyvaluemaps/
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "kvm-2") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(kvm)
		case http.MethodPost:
			bodyBytes, _ := io.ReadAll(r.Body)
			// Trigger 500 error if name is error-trigger
			if strings.Contains(string(bodyBytes), "error-trigger") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(kvm)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}

	m.HandleFunc("/keyvaluemaps", handler)
	m.HandleFunc("/keyvaluemaps/", handler)
	m.HandleFunc("/keyvaluemaps/kvm/entries/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(kvm)
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
	baseUrl, _ := url.Parse(ts.URL)
	kvms := &KVMServiceOp{client: &EdgeClient{client: http.DefaultClient, BaseURLEnv: baseUrl, BaseURL: baseUrl}}
	kvm, _, err := kvms.Get("kvm-1")
	if err != nil || kvm.Name != "kvm-1" {
		t.Errorf("Get failed: %v", err)
	}
	_, _, err = kvms.Get("kvm-2")
	if err == nil {
		t.Error("want error got none")
	}
}

func TestCreateKVM(t *testing.T) {
	ts := kvmTestServer(t)
	defer ts.Close()
	baseUrl, _ := url.Parse(ts.URL)
	kvms := &KVMServiceOp{client: &EdgeClient{client: http.DefaultClient, BaseURLEnv: baseUrl, BaseURL: baseUrl}}
	_, err := kvms.Create(KVM{Name: "kvm-1"})
	if err != nil {
		t.Error(err)
	}
}

func TestGetValueKVM(t *testing.T) {
	kvm := &KVM{Entries: []Entry{{Name: "k1", Value: "v1"}}}
	if v, ok := kvm.GetValue("k1"); !ok || v != "v1" {
		t.Error("GetValue failed")
	}
	if _, ok := kvm.GetValue("k2"); ok {
		t.Error("GetValue should fail")
	}
}

func TestUpdateEntryKVM(t *testing.T) {
	ts := kvmTestServer(t)
	defer ts.Close()
	baseUrl, _ := url.Parse(ts.URL)
	kvms := &KVMServiceOp{client: &EdgeClient{client: http.DefaultClient, BaseURLEnv: baseUrl, BaseURL: baseUrl}}
	_, err := kvms.UpdateEntry("kvm", Entry{Name: "k1", Value: "v1"})
	if err != nil {
		t.Error(err)
	}
}

func TestAddEntryKVM(t *testing.T) {
	ts := kvmTestServer(t)
	defer ts.Close()
	baseUrl, _ := url.Parse(ts.URL)
	kvms := &KVMServiceOp{client: &EdgeClient{client: http.DefaultClient, BaseURLEnv: baseUrl, BaseURL: baseUrl}}
	_, err := kvms.AddEntry("kvm", Entry{Name: "k1", Value: "v1"})
	if err != nil {
		t.Error(err)
	}
}

func TestKVMErrorPaths(t *testing.T) {
	ts := kvmTestServer(t)
	defer ts.Close()
	baseUrl, _ := url.Parse(ts.URL)
	kvms := &KVMServiceOp{client: &EdgeClient{client: http.DefaultClient, BaseURLEnv: baseUrl, BaseURL: baseUrl}}

	// 1. NewRequest error
	_, _, err := kvms.Get("%%invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}

	// 2. Server Error (this should now pass)
	_, err = kvms.Create(KVM{Name: "error-trigger"})
	if err == nil {
		t.Error("expected server error")
	}
}

func TestKVM_FinalPrecisionHits(t *testing.T) {
	u, _ := url.Parse("http://localhost")
	kvms := &KVMServiceOp{
		client: &EdgeClient{
			client:     http.DefaultClient,
			BaseURL:    u,
			BaseURLEnv: u,
		},
	}

	// We use a control character \x7f (DEL) or a newline,
	// which are illegal in URL paths and force url.Parse to error out.
	illegalPath := "invalid\x7fpath"

	t.Run("CreateNewRequestError", func(t *testing.T) {
		// We give it a valid-looking URL that has a control character.
		// url.Parse might pass it, but ResolveReference or NewRequest will fail
		// when trying to join it with the relative "keyvaluemaps" path.
		badURL := &url.URL{Scheme: "http", Host: "localhost\n"}
		kvms.client.BaseURL = badURL

		_, err := kvms.Create(KVM{Name: "test"})
		if err == nil {
			t.Error("expected error for illegal BaseURL in Create")
		}

		// Restore for any subsequent tests
		kvms.client.BaseURL, _ = url.Parse("http://localhost")
	})

	t.Run("UpdateEntryNewRequestError", func(t *testing.T) {
		// Line 84: Hits the 'return nil, e' branch
		_, err := kvms.UpdateEntry("kvm", Entry{Name: illegalPath})
		if err == nil {
			t.Error("expected error for illegal entry name")
		}
	})

	t.Run("AddEntryNewRequestError", func(t *testing.T) {
		// Line 93: Hits the 'return nil, e' branch
		_, err := kvms.AddEntry(illegalPath, Entry{Name: "test"})
		if err == nil {
			t.Error("expected error for illegal KVM name in AddEntry")
		}
	})
}
