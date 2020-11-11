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

package shared

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/apigee/apigee-remote-service-cli/apigee"
	"github.com/apigee/apigee-remote-service-cli/testutil"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/spf13/cobra"
)

const (
	// GCPExperienceBase is the default management API URL for GCP Experience
	GCPExperienceBase = "https://apigee.googleapis.com"

	// LegacySaaSManagementBase is the default base for legacy SaaS management operations
	LegacySaaSManagementBase = "https://api.enterprise.apigee.com"

	// DefaultManagementBase is the base URL for GCE Experience management operations
	DefaultManagementBase = GCPExperienceBase

	// RuntimeBaseFormat is a format for base of the organization runtime URL (legacy SaaS and OPDK)
	RuntimeBaseFormat = "https://%s-%s.apigee.net"

	internalProxyURLFormat      = "%s://istioservices.%s/edgemicro" // runtime scheme, runtime domain (legacy SaaS and OPDK)
	internalProxyURLFormatOPDK  = "%s/edgemicro"                    // runtimeBase
	remoteServicePath           = "/remote-service"
	remoteServiceProxyURLFormat = "%s" + remoteServicePath // runtimeBase
)

// BuildInfoType holds version information
type BuildInfoType struct {
	Version string
	Commit  string
	Date    string
}

// BuildInfo is populated by main init()
var BuildInfo BuildInfoType

// RootArgs is the base struct to hold all command arguments
type RootArgs struct {
	RuntimeBase        string // "https://org-env.apigee.net"
	ManagementBase     string // "https://api.enterprise.apigee.com"
	Verbose            bool
	Org                string
	Env                string
	Username           string
	Password           string
	MFAToken           string
	Token              string
	NetrcPath          string
	IsOPDK             bool
	IsLegacySaaS       bool
	IsGCPManaged       bool
	ConfigPath         string
	InsecureSkipVerify bool
	Namespace          string

	ServerConfig *server.Config // config loaded from ConfigPath

	// the following is derived in Resolve()
	InternalProxyURL      string
	RemoteServiceProxyURL string
	ApigeeClient          *apigee.EdgeClient
	ClientOpts            *apigee.EdgeClientOptions
}

// AddCommandWithFlags adds to the root command with standard flags
func AddCommandWithFlags(c *cobra.Command, rootArgs *RootArgs, cmds ...*cobra.Command) {
	for _, subC := range cmds {
		subC.PersistentFlags().StringVarP(&rootArgs.RuntimeBase, "runtime", "r",
			"", "Apigee runtime base URL (required for hybrid or opdk)")

		subC.PersistentFlags().BoolVarP(&rootArgs.Verbose, "verbose", "v",
			false, "verbose output")

		subC.PersistentFlags().StringVarP(&rootArgs.Org, "organization", "o",
			"", "Apigee organization name")
		subC.PersistentFlags().StringVarP(&rootArgs.Env, "environment", "e",
			"", "Apigee environment name")

		subC.PersistentFlags().StringVarP(&rootArgs.ConfigPath, "config", "c",
			"", "path to Apigee Remote Service config file")

		subC.PersistentFlags().BoolVarP(&rootArgs.InsecureSkipVerify, "insecure", "",
			false, "allow insecure server connections when using SSL")

		c.AddCommand(subC)
	}
}

// Resolve is used to populate shared args, it's automatically called prior when creating the root command
func (r *RootArgs) Resolve(skipAuth, requireRuntime bool) error {

	if err := r.loadConfig(); err != nil {
		return err
	}

	if r.IsLegacySaaS && r.IsOPDK {
		return errors.New("--legacy and --opdk options are exclusive")
	}
	r.IsGCPManaged = !(r.IsLegacySaaS || r.IsOPDK)

	if r.ManagementBase == "" {
		r.ManagementBase = DefaultManagementBase
	}

	if r.ManagementBase == DefaultManagementBase {
		if r.IsLegacySaaS {
			r.ManagementBase = LegacySaaSManagementBase
		}
		if r.IsOPDK {
			if r.RuntimeBase == "" {
				return fmt.Errorf("--runtime or --config is required and used as the management url if --management is not explicitly set for opdk")
			}
			r.ManagementBase = r.RuntimeBase
		}
	}

	if r.IsLegacySaaS {
		if r.Org == "" || r.Env == "" {
			return fmt.Errorf("--organization and --environment are required for legacy saas")
		}
		if r.RuntimeBase == "" {
			r.RuntimeBase = fmt.Sprintf(RuntimeBaseFormat, r.Org, r.Env)
		}
	}

	if requireRuntime && r.RuntimeBase == "" {
		return errors.New("--runtime is required for hybrid or opdk (or --organization and --environment with --legacy)")
	}

	// calculate internal proxy URL from runtime URL for LegacySaaS or OPDK
	// note: GCPExperience doesn't have an internal proxy
	if r.IsOPDK {
		r.InternalProxyURL = fmt.Sprintf(internalProxyURLFormatOPDK, r.RuntimeBase)
	}
	if r.IsLegacySaaS {
		u, err := url.Parse(r.RuntimeBase)
		if err != nil {
			return err
		}
		domain := u.Host[strings.Index(u.Host, ".")+1:]
		r.InternalProxyURL = fmt.Sprintf(internalProxyURLFormat, u.Scheme, domain)
	}

	r.RemoteServiceProxyURL = fmt.Sprintf(remoteServiceProxyURLFormat, r.RuntimeBase)

	if r.IsGCPManaged && !skipAuth && r.Token == "" {
		return fmt.Errorf("--token is required for hybrid")
	}

	r.ClientOpts = &apigee.EdgeClientOptions{
		MgmtURL: r.ManagementBase,
		Org:     r.Org,
		Env:     r.Env,
		Auth: &apigee.EdgeAuth{
			NetrcPath:   r.NetrcPath,
			Username:    r.Username,
			Password:    r.Password,
			BearerToken: r.Token,
			MFAToken:    r.MFAToken,
			SkipAuth:    skipAuth,
		},
		GCPManaged:         r.IsGCPManaged,
		Debug:              r.Verbose,
		InsecureSkipVerify: r.InsecureSkipVerify,
	}

	var err error
	r.ApigeeClient, err = apigee.NewEdgeClient(r.ClientOpts)
	if err != nil {
		if strings.Contains(err.Error(), ".netrc") { // no .netrc and no auth
			baseURL, err := url.Parse(r.ManagementBase)
			if err != nil {
				return fmt.Errorf("unable to parse managementBase url %s: %v", r.ManagementBase, err)
			}
			return fmt.Errorf("no auth: must have username and password or a ~/.netrc entry for %s", baseURL.Host)
		}
		if strings.Contains(err.Error(), "oauth") { // OAuth failure
			return fmt.Errorf("error authorizing for OAuth token: %v", err)
		}
		return fmt.Errorf("error initializing Edge client: %v", err)
	}

	return nil
}

// FormatFn formats the supplied arguments according to the format string
// provided and executes some set of operations with the result.
type FormatFn func(format string, args ...interface{})

// Printf is a FormatFn that prints the formatted string to os.Stdout.
func Printf(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

// Errorf is a FormatFn that prints the formatted string to os.Stderr.
func Errorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// NoPrintf is a FormatFn that does nothing
func NoPrintf(format string, args ...interface{}) {
}

// FormatFnWriter bridges io.Writer to FormatFn
func FormatFnWriter(fn FormatFn) io.Writer {
	return &formatFnWriter{fn}
}

type formatFnWriter struct {
	formatFn FormatFn
}

func (w *formatFnWriter) Write(p []byte) (n int, err error) {
	if reflect.ValueOf(w.formatFn).Pointer() == reflect.ValueOf(Printf).Pointer() {
		fmt.Printf("%s", p)
	}
	if reflect.ValueOf(w.formatFn).Pointer() == reflect.ValueOf(Errorf).Pointer() {
		fmt.Fprintf(os.Stderr, "%s", p)
	}
	tp := testutil.TestPrint{}
	if reflect.ValueOf(w.formatFn).Pointer() == reflect.ValueOf(tp.Printf).Pointer() {
		w.formatFn("%s", p)
	}
	return len(p), nil
}

// OverrideEnv is subconfig of overrideConfig
type OverrideEnv struct {
	Name      string `yaml:"name"`
	HostAlias string `yaml:"hostAlias"`
}

func (r *RootArgs) loadConfig() error {
	if r.ConfigPath == "" {
		return nil
	}

	r.ServerConfig = &server.Config{}
	err := r.ServerConfig.Load(r.ConfigPath, "", "", false)
	if err != nil {
		return err
	}

	r.RuntimeBase = strings.Split(r.ServerConfig.Tenant.RemoteServiceAPI, remoteServicePath)[0]
	r.Org = r.ServerConfig.Tenant.OrgName
	r.Env = r.ServerConfig.Tenant.EnvName
	r.InsecureSkipVerify = r.ServerConfig.Tenant.AllowUnverifiedSSLCert
	r.Namespace = r.ServerConfig.Global.Namespace

	if r.ServerConfig.IsGCPManaged() {
		r.ManagementBase = GCPExperienceBase
		r.IsGCPManaged = true

		if r.ServerConfig.Tenant.PrivateKey == nil || r.ServerConfig.Tenant.PrivateKeyID == "" {
			return fmt.Errorf("Secret CRD not found in file: %s", r.ConfigPath)
		}
	}

	if r.ServerConfig.IsApigeeManaged() {
		r.ManagementBase = LegacySaaSManagementBase
		r.IsLegacySaaS = true
	}

	if r.ServerConfig.IsOPDK() {
		r.ManagementBase = r.RuntimeBase
		r.IsOPDK = true
	}

	return nil
}

// PrintMissingFlags will aggregate and print an error for the passed set of flags
func (r *RootArgs) PrintMissingFlags(missingFlagNames []string) error {
	if len(missingFlagNames) > 0 {
		return fmt.Errorf(`required flag(s) "%s" not set`, strings.Join(missingFlagNames, `", "`))
	}
	return nil
}
