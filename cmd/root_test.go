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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/testutil"
)

func TestVersion(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vs := versionResponse{
			Version: "1.2.42",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(vs); err != nil {
			t.Fatalf("want no error %v", err)
		}
	}))
	defer ts.Close()

	shared.BuildInfo.Commit = "/commit/"
	shared.BuildInfo.Date = "/date/"
	shared.BuildInfo.Version = "/version/"

	// run without --runtime
	print := testutil.Printer("TestVersion:no runtime")

	flags := []string{"version"}
	rootCmd := GetRootCmd(flags, print.Printf)

	err := rootCmd.Execute()
	if err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want := []string{
		"apigee-remote-service-cli version /version/ /date/ [/commit/]",
		"proxy version unknown (specify --hybrid-config OR --runtime to check)",
	}

	print.Check(t, want)

	// run with --runtime
	print = testutil.Printer("TestVersion:runtime")

	flags = []string{"version", "--runtime", ts.URL}
	rootCmd = GetRootCmd(flags, print.Printf)

	err = rootCmd.Execute()
	if err != nil {
		t.Fatalf("want no error: %v", err)
	}

	want = []string{
		"apigee-remote-service-cli version /version/ /date/ [/commit/]",
		"remote-service proxy version: 1.2.42",
	}

	print.Check(t, want)

	// bad runtime url
	print = testutil.Printer("TestVersion:bad url")

	flags = []string{"version", "--runtime", "badurl"}
	rootCmd = GetRootCmd(flags, print.Printf)

	wantErr := `error getting proxy version: Get "badurl/remote-service/version": unsupported protocol scheme ""`
	err = rootCmd.Execute()
	if err == nil || err.Error() != wantErr {
		t.Fatalf("want error: %v", wantErr)
	}

	wantPrint := []string{
		"apigee-remote-service-cli version /version/ /date/ [/commit/]",
	}

	print.Check(t, wantPrint)
}
