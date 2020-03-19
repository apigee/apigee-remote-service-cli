// Copyright 2018 Google LLC
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
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/apigee/apigee-remote-service-cli/cmd/bindings"
	"github.com/apigee/apigee-remote-service-cli/cmd/provision"
	"github.com/apigee/apigee-remote-service-cli/cmd/token"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/spf13/cobra"
)

func init() {
	// Apigee does not support http2 at present
	if !strings.Contains(os.Getenv("GODEBUG"), "http2client=0") {
		os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",http2client=0")
	}
}

// GetRootCmd returns the root of the cobra command-tree.
func GetRootCmd(args []string, printf, fatalf shared.FormatFn) *cobra.Command {
	rootArgs := &shared.RootArgs{}

	c := &cobra.Command{
		Use:   "apigee-remote-service-cli",
		Short: "Utility to work with Apigee Remote Service.",
		Long:  "This command lets you interact with Apigee Remote Service",
	}
	c.SetArgs(args)
	c.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	var addCommand = func(cmds ...*cobra.Command) {
		for _, subC := range cmds {
			// add general flags
			subC.PersistentFlags().StringVarP(&rootArgs.RuntimeBase, "runtime", "r",
				shared.DefaultRuntimeBase, "Apigee runtime base URL (required for hybrid)")
			subC.PersistentFlags().StringVarP(&rootArgs.ManagementBase, "management", "m",
				shared.DefaultManagementBase, "Apigee management base URL")
			subC.PersistentFlags().BoolVarP(&rootArgs.Verbose, "verbose", "v",
				false, "verbose output")
			subC.PersistentFlags().BoolVarP(&rootArgs.IsLegacySaaS, "legacy", "",
				false, "Apigee SaaS (sets management URL)")
			subC.PersistentFlags().BoolVarP(&rootArgs.IsOPDK, "opdk", "",
				false, "Apigee OPDK")

			subC.PersistentFlags().StringVarP(&rootArgs.Org, "org", "o",
				"", "Apigee organization name")
			subC.PersistentFlags().StringVarP(&rootArgs.Env, "env", "e",
				"", "Apigee environment name")
			subC.PersistentFlags().StringVarP(&rootArgs.Username, "username", "u",
				"", "Apigee username (legacy or OPDK)")
			subC.PersistentFlags().StringVarP(&rootArgs.Password, "password", "p",
				"", "Apigee password (legacy or OPDK)")
			subC.PersistentFlags().StringVarP(&rootArgs.Token, "token", "t",
				"", "Apigee OAuth or SAML token (hybrid)")

			subC.MarkPersistentFlagRequired("org")
			subC.MarkPersistentFlagRequired("env")

			c.AddCommand(subC)
		}
	}

	addCommand(provision.Cmd(rootArgs, printf, fatalf))
	addCommand(bindings.Cmd(rootArgs, printf, fatalf))
	addCommand(token.Cmd(rootArgs, printf, fatalf))

	c.AddCommand(version(rootArgs, printf, fatalf))

	return c
}

const versionAPIFormat = "%s/version" // internalProxyURL

func version(rootArgs *shared.RootArgs, printf, fatalf shared.FormatFn) *cobra.Command {
	subC := &cobra.Command{
		Use:   "version",
		Short: "Prints build version - specify org and env to include proxy version",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootArgs.Resolve(true)
		},
		Run: func(cmd *cobra.Command, args []string) {
			printf("apigee-remote-service-cli version %s %s [%s]",
				shared.BuildInfo.Version, shared.BuildInfo.Date, shared.BuildInfo.Commit)

			if rootArgs.RuntimeBase == "https://-.apigee.net" {
				return
			}

			// check proxy version
			versionURL := fmt.Sprintf(versionAPIFormat, rootArgs.RemoteServiceProxyURL)
			req, err := http.NewRequest(http.MethodGet, versionURL, nil)
			if err != nil {
				fatalf("error creating request: %v", err)
			}
			var version versionResponse
			resp, err := rootArgs.Client.Do(req, &version)
			if err != nil {
				fatalf("error getting proxy version: %v", err)
			}
			if err != nil {
				body, _ := ioutil.ReadAll(resp.Body)
				fatalf("error getting proxy version. response code: %d, body: %s", resp.StatusCode, string(body))
			}
			printf("remote-service proxy version: %v", version.Version)
		},
	}

	subC.PersistentFlags().StringVarP(&rootArgs.RuntimeBase, "runtime", "r",
		shared.DefaultRuntimeBase, "Apigee runtime base URL")

	subC.PersistentFlags().StringVarP(&rootArgs.Org, "org", "o",
		"", "Apigee organization name")
	subC.PersistentFlags().StringVarP(&rootArgs.Env, "env", "e",
		"", "Apigee environment name")

	return subC
}

type versionResponse struct {
	Version string `json:"version"`
}
