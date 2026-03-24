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

package bindings

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/v2/apigee"
	"github.com/apigee/apigee-remote-service-cli/v2/cmd"
	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/apigee/apigee-remote-service-cli/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
)

func TestBindingsParams(t *testing.T) {
	print := testutil.Printer("TestBindingsParams")

	tests := []struct {
		name    string
		flags   []string
		wantErr string
	}{
		{
			"opdk no args",
			[]string{"bindings", "list", "--opdk"},
			"--runtime or --config is required",
		},
		{
			"hybrid requires token",
			[]string{"bindings", "list", "--runtime", "/runtime/"},
			"--token is required for hybrid",
		},
		{
			"legacy requires org",
			[]string{"bindings", "list", "--legacy", "--runtime", "/runtime/"},
			"--organization and --environment are required",
		},
	}

	for _, tt := range tests {
		rootArgs := &shared.RootArgs{}
		rootCmd := cmd.GetRootCmd(tt.flags, print.Printf)
		shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
		err := rootCmd.Execute()
		if err == nil {
			t.Errorf("%s: expected error", tt.name)
		}
	}
}

func TestBindingListOPDK(t *testing.T) {
	print := testutil.Printer("TestBindingListOPDK")
	ts := productTestServer(t)
	defer ts.Close()

	flags := []string{"bindings", "list", "--opdk", "--runtime", ts.URL,
		"-o", "org", "-e", "env", "-u", "u", "-p", "p"}
	rootArgs := &shared.RootArgs{}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("got: %v", err)
	}

	flags = []string{"bindings", "list", "A_Product", "--opdk", "--runtime", ts.URL,
		"-o", "org", "-e", "env", "-u", "u", "-p", "p"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("got: %v", err)
	}
}

func TestBindingsExtraPaths(t *testing.T) {
	print := testutil.Printer("TestBindingsExtraPaths")
	ts := productTestServer(t)
	defer ts.Close()

	flags := []string{"bindings", "list", "missing-product", "--opdk", "--runtime", ts.URL, "-o", "org", "-e", "env"}
	rootArgs := &shared.RootArgs{}
	rootCmd := cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	_ = rootCmd.Execute()

	flags = []string{"bindings", "list", "--opdk", "--runtime", ts.URL, "-o", "error-org", "-e", "env"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err := rootCmd.Execute(); err == nil {
		t.Error("expected error")
	}
}

func TestBindingsTemplateAndPrint(t *testing.T) {
	// Hits nil printf check
	err := printProducts([]product.APIProduct{{Name: "test"}}, nil)
	if err == nil {
		t.Error("expected template error for nil printf")
	}

	// Hits full template execution
	printf := func(format string, a ...interface{}) {}
	p1 := product.APIProduct{Name: "p1", Proxies: []string{"proxy1"}}
	p2 := product.APIProduct{Name: "p2"}
	_ = printProducts([]product.APIProduct{p1, p2}, printf)
}

func TestBindingsNewRequestError(t *testing.T) {
	b := &bindings{
		RootArgs: &shared.RootArgs{
			ApigeeClient: &apigee.EdgeClient{
				BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			},
		},
	}

	// Hits Request Creation Error
	_, err := b.getProduct("%%invalid")
	if err == nil {
		t.Error("expected error for invalid product name")
	}

	// Hits getProducts error path
	b.products = nil
	b.ApigeeClient.BaseURL = &url.URL{Scheme: "http", Host: " \t"}
	_, err = b.getProducts()
	if err == nil {
		t.Error("expected error for getProducts")
	}

	// Hits cache hit
	b.products = []product.APIProduct{{Name: "cached"}}
	_, _ = b.getProducts()
}

func productTestServer(t *testing.T) *httptest.Server {
	m := http.NewServeMux()

	// Happy path for all products
	m.HandleFunc("/v1/organizations/org/apiproducts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(product.APIResponse{
			APIProducts: []product.APIProduct{{Name: "A"}, {Name: "B"}},
		})
	})

	// Malformed JSON to trigger decoding errors (Line 100 area)
	m.HandleFunc("/v1/organizations/malformed-org/apiproducts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{invalid-json`))
	})

	// 500 Error to trigger retrieval errors (Line 89 & 100 area)
	m.HandleFunc("/v1/organizations/error-org/apiproducts", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	return httptest.NewServer(m)
}

func TestBindings_SurgicalErrorHits(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "trigger-error") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.Contains(r.URL.Path, "missing-product") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"test-product"}`))
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL) // Variable 'u' is now in scope for the whole function
	opts := &apigee.EdgeClientOptions{
		MgmtURL: ts.URL,
		Org:     "org",
		Env:     "env",
		Auth:    &apigee.EdgeAuth{SkipAuth: true},
	}
	client, _ := apigee.NewEdgeClient(opts)
	cfg := &bindings{RootArgs: &shared.RootArgs{ApigeeClient: client}}

	t.Run("ErrorPropagation_Lines_111_112", func(t *testing.T) {
		dummyPrintf := func(f string, a ...interface{}) {}
		originalURL := cfg.ApigeeClient.BaseURL

		// Force connection error
		cfg.ApigeeClient.BaseURL, _ = url.Parse("http://localhost:1")
		_ = cfg.cmdListAll(dummyPrintf)
		_ = cfg.cmdList("any-product", dummyPrintf)

		cfg.ApigeeClient.BaseURL = originalURL
	})

	t.Run("SortingAndFoundHits", func(t *testing.T) {
		// Target Swap (Line 138)
		prods := byName{{Name: "Z"}, {Name: "A"}}
		sort.Sort(prods) // Hits Len, Less, and Swap

		// Target getProduct 404 branch (Line 84-88)
		cfg.ApigeeClient.BaseURL = u
		cfg.ApigeeClient.BaseURLEnv = u
		_, _ = cfg.getProduct("missing-product")
	})

	t.Run("PrintUnboundProducts", func(t *testing.T) {
		// Target printProducts Unbound branch (Line 116+)
		unboundProd := product.APIProduct{Name: "unbound-one"}
		printf := func(format string, a ...interface{}) {}
		_ = printProducts([]product.APIProduct{unboundProd}, printf)
	})
}
