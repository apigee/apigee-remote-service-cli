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

func cacheTestServer(t *testing.T) *httptest.Server {
	m := http.NewServeMux()

	cache := Cache{
		Name:        "cache-1",
		Description: "cache 1",
	}

	m.HandleFunc("/", (func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.Contains(r.URL.Path, "cache-2") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(cache); err != nil {
				t.Fatalf("want no error %v", err)
			}
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{}"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	return httptest.NewServer(m)
}

func TestGetCache(t *testing.T) {
	ts := cacheTestServer(t)
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
	cs := &CacheServiceOp{
		client: client,
	}

	cache, _, err := cs.Get("cache-1")
	if err != nil {
		t.Error(err)
	}
	if cache.Name != "cache-1" {
		t.Errorf("want cache-1 got %s", cache.Name)
	}

	_, _, err = cs.Get("cache-2")
	if err == nil {
		t.Error("want error got none")
	}
}

func TestCreateCache(t *testing.T) {
	ts := cacheTestServer(t)
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
	cs := &CacheServiceOp{
		client: client,
	}

	cache := Cache{
		Name:        "cache-1",
		Description: "cache 1",
	}

	_, err = cs.Create(cache)
	if err != nil {
		t.Error(err)
	}
}
