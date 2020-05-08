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

package cmd

import (
	"os"
	"strings"
	"net/http"
	"net/http/httptest"
	"testing"
	"encoding/json"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
)

func TestForceHttp11(t *testing.T) {

	env := os.Getenv("GODEBUG")
	if !strings.Contains(env, "http2client=0") {
		t.Errorf("expected GODEBUG to include 'http2client=0' get %s", env)
	}
}

func TestVersion(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs := versionResponse{
			Version: "1.2.42",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(vs)
	}))
	defer ts.Close()

	shared.BuildInfo.Commit = "/commit/"
	shared.BuildInfo.Date = "/date/"
	shared.BuildInfo.Version = "/version/"

	// run without --runtime
	print := testutil.Printer("TestVersion:print:no runtime")
	fatal := testutil.Printer("TestVersion:fatal:no runtime")

	flags := []string{"version"}
	rootCmd := GetRootCmd(flags, print.Printf, fatal.Printf)

	err := rootCmd.Execute(); 
	if err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{
		"apigee-remote-service-cli version /version/ /date/ [/commit/]",
		"proxy version unknown (specify --hybrid-config OR --runtime to check)",
	}

	fatal.Check(t, nil)
	print.Check(t, want)

	// run with --runtime
	print = testutil.Printer("TestVersion:print:runtime")
	fatal = testutil.Printer("TestVersion:fatal:runtime")

	flags = []string{"version", "--runtime", ts.URL}
	rootCmd = GetRootCmd(flags, print.Printf, fatal.Printf)

	err = rootCmd.Execute(); 
	if err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want = []string{
		"apigee-remote-service-cli version /version/ /date/ [/commit/]",
		"remote-service proxy version: 1.2.42",
	}

	fatal.Check(t, nil)
	print.Check(t, want)

	// bad runtime url
	print = testutil.Printer("TestVersion:print:bad url")
	fatal = testutil.Printer("TestVersion:fatal:bad url")

	flags = []string{"version", "--runtime", "badurl"}
	rootCmd = GetRootCmd(flags, print.Printf, fatal.Printf)

	err = rootCmd.Execute(); 
	if err != nil {
		t.Fatalf("want no error: %v", err)
	}

	wantPrint := []string{
		"apigee-remote-service-cli version /version/ /date/ [/commit/]",
	}
	wantFatal := []string{
		`error getting proxy version: Get "badurl/remote-service/version": unsupported protocol scheme ""`,
	}

	fatal.Check(t, wantFatal)
	print.Check(t, wantPrint)
}
