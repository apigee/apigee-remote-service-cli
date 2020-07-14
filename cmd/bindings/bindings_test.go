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

	"github.com/apigee/apigee-remote-service-cli/cmd"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/spf13/cobra"
)

func TestBindingsParams(t *testing.T) {

	testBindingsParams(t, "list")
	testBindingsParams(t, "add", "/target/", "/product/")
	testBindingsParams(t, "remove", "/target/", "/product2/")
}

func TestBindingListOPDK(t *testing.T) {

	print := testutil.Printer("TestBindingListOPDK")
	ts := productTestServer()
	defer ts.Close()

	var err error
	var flags []string
	var rootCmd *cobra.Command
	var rootArgs *shared.RootArgs
	var wants []string

	flags = []string{"bindings", "list", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	wants = []string{
		"\nAPI Products\n============",
		"\nBound\n-----",
		"\n",
		"/product2/",
		":",
		"\n  Target bindings:",
		"\n    ",
		"/target/",
		"\n  Paths:",
		"\n\nUnbound\n-------",
		"\n",
		"/product/",
		":",
		"\n",
	}
	print.Check(t, wants)
}

func TestBindingAddOPDK(t *testing.T) {

	print := testutil.Printer("TestBindingAddOPDK")
	ts := productTestServer()
	defer ts.Close()

	var err error
	var flags []string
	var rootCmd *cobra.Command
	var rootArgs *shared.RootArgs
	var wants []string

	flags = []string{"bindings", "add", "/target/", "/product/", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	wants = []string{"product /product/ is now bound to: /target/"}
	print.Check(t, wants)

	flags = []string{"bindings", "add", "/target/", "/product2/", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	wants = []string{"target /target/ is already bound to /product2/"}
	print.Check(t, wants)
}

func TestBindingRemoveOPDK(t *testing.T) {

	print := testutil.Printer("TestBindingRemoveOPDK")
	ts := productTestServer()
	defer ts.Close()

	var err error
	var flags []string
	var rootCmd *cobra.Command
	var rootArgs *shared.RootArgs
	var wants []string

	flags = []string{"bindings", "remove", "/target/", "/product/", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	wants = []string{"target /target/ is not bound to /product/"}
	print.Check(t, wants)

	flags = []string{"bindings", "remove", "/target/", "/product2/", "--opdk", "--runtime", ts.URL,
		"-o", "/org/", "-e", "/env/", "-u", "/username/", "-p", "password"}
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	if err = rootCmd.Execute(); err != nil {
		t.Errorf("want no error, got: %v", err)
	}
	wants = []string{"product /product2/ is no longer bound to: /target/"}
	print.Check(t, wants)
}

func productTestServer() *httptest.Server {

	res := product.APIResponse{
		APIProducts: []product.APIProduct{
			{
				Name: "/product/",
			},
			{
				Name: "/product2/",
				Attributes: []product.Attribute{
					{
						Name:  product.TargetsAttr,
						Value: "/target/",
					},
				},
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			return
		}
	}))
}

func testBindingsParams(t *testing.T, args ...string) {
	var err error
	var flags []string
	var rootCmd *cobra.Command
	var rootArgs *shared.RootArgs
	print := testutil.Printer("TestBindingsParams")

	// hybrid no args
	wantErr := "--runtime is required for hybrid or opdk (or --organization and --environment with --legacy)"
	flags = []string{"bindings"}
	flags = append(flags, args...)
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("%v want %s, got: %v", args, wantErr, err)
	}

	// hybrid requires runtime
	wantErr = "--runtime is required for hybrid or opdk (or --organization and --environment with --legacy)"
	flags = []string{"bindings", "-o", "/org/", "-e", "/env/"}
	flags = append(flags, args...)
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("%v want %s, got: %v", args, wantErr, err)
	}

	// hybrid requires token
	wantErr = "--token is required for hybrid"
	flags = []string{"bindings", "--runtime", "/runtime/"}
	flags = append(flags, args...)
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("%v want %s, got: %v", args, wantErr, err)
	}

	// legacy requires org & env
	wantErr = "--organization and --environment are required"
	flags = []string{"bindings", "--legacy", "--runtime", "/runtime/"}
	flags = append(flags, args...)
	rootArgs = &shared.RootArgs{}
	rootCmd = cmd.GetRootCmd(flags, print.Printf)
	shared.AddCommandWithFlags(rootCmd, rootArgs, Cmd(rootArgs, print.Printf))
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Errorf("%v want %s, got: %v", args, wantErr, err)
	}
}
