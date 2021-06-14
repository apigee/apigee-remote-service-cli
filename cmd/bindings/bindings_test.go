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
	"testing"

	"github.com/apigee/apigee-remote-service-cli/v2/cmd"
	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/apigee/apigee-remote-service-cli/v2/testutil"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/spf13/cobra"
)

func TestBindingsParams(t *testing.T) {
	var err error
	var flags []string
	var rootCmd *cobra.Command
	var rootArgs *shared.RootArgs
	var wantErr string
	print := testutil.Printer("TestBindingsParams")

	// opdk no args
	wantErr = "--runtime or --config is required and used as the management url if --management is not explicitly set for opdk"
	flags = []string{"bindings", "list", "--opdk"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("want %s, got: %v", wantErr, err)
	}

	// hybrid requires token
	wantErr = "--token is required for Apigee X/Hybrid"
	flags = []string{"bindings", "list", "--runtime", "/runtime/"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("want %s, got: %v", wantErr, err)
	}

	// legacy requires org & env
	wantErr = "--organization and --environment are required for legacy saas"
	flags = []string{"bindings", "list", "--legacy", "--runtime", "/runtime/"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("want %s, got: %v", wantErr, err)
	}
}
func TestBindingListOPDK(t *testing.T) {

	print := testutil.Printer("TestBindingListOPDK")
	ts := productTestServer(t)
	defer ts.Close()

	var err error
	var flags []string
	var rootCmd *cobra.Command
	var rootArgs *shared.RootArgs

	flags = []string{"bindings", "list", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	want := `
	API Products
	============
	Bound
	-----
	/product0/:
		Target (API) bindings:
			/api/
		Paths:
	/product2/:
		Target (API) bindings:
			/api/
		Paths:
	/product4/:
		Target (API) bindings:
			/api/
		Paths:
	/productOG/:
		Target (API) bindings:
			/api/
		Paths:
	
	Unbound
	-------
	/product/:
	/product1/:
	`
	print.CheckString(t, want)

	flags = []string{"bindings", "list", "/product2/", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	want = `
	API Products
	============
	Bound
	-----
	/product2/:
		Target (API) bindings:
			/api/
		Paths:
`
	print.CheckString(t, want)
}

func productTestServer(t *testing.T) *httptest.Server {

	prods := product.APIResponse{
		APIProducts: []product.APIProduct{
			{
				Name: "/product1/",
			},
			{
				Name: "/product/",
			},
			{
				Name: "/product2/",
				Attributes: []product.Attribute{
					{
						Name:  product.TargetsAttr,
						Value: "/api/",
					},
				},
				QuotaLimit: "null",
				Scopes:     []string{""},
			},
			{
				Name: "/product0/",
				Attributes: []product.Attribute{
					{
						Name:  product.TargetsAttr,
						Value: "/api/",
					},
				},
				QuotaLimit: "null",
				Scopes:     []string{""},
			},
			{
				Name:       "/productOG/",
				Attributes: []product.Attribute{},
				QuotaLimit: "",
				Scopes:     []string{""},
				OperationGroup: &product.OperationGroup{
					OperationConfigs: []product.OperationConfig{
						{
							APISource: "/api/",
							Operations: []product.Operation{
								{
									Resource: "/",
									Methods:  []string{"GET"},
								},
							},
						},
					},
				},
			},
			{
				Name: "/product4/",
				Attributes: []product.Attribute{
					{
						Name:  product.TargetsAttr,
						Value: "/api/",
					},
				},
				QuotaLimit: "null",
				Scopes:     []string{""},
			},
		},
	}

	m := http.NewServeMux()
	m.HandleFunc("/v1/organizations/org/apiproducts", (func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prods); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	m.HandleFunc("/v1/organizations/org/apiproducts/product1", (func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prods.APIProducts[0]); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	m.HandleFunc("/v1/organizations/org/apiproducts/product", (func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prods.APIProducts[1]); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	m.HandleFunc("/v1/organizations/org/apiproducts/product2", (func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prods.APIProducts[2]); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	m.HandleFunc("/v1/organizations/org/apiproducts/product/attributes", (func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prods.APIProducts[1]); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	m.HandleFunc("/v1/organizations/org/apiproducts/product2/attributes", (func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(prods.APIProducts[2]); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	return httptest.NewServer(m)
}
