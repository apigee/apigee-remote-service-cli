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

package samples

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/apigee/apigee-remote-service-cli/cmd/provision"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type samples struct {
	*shared.RootArgs
	isNative      bool
	outDir        string
	overwrite     bool
	RuntimeHost   string
	TargetService targetService
	TLS           tls
	EncodedName   string
}

type targetService struct {
	Name   string
	Host   string
	Prefix string
}

type tls struct {
	Dir string
	Key string
	Crt string
}

// Cmd returns base command
func Cmd(rootArgs *shared.RootArgs, printf shared.FormatFn) *cobra.Command {
	s := &samples{
		RootArgs:      rootArgs,
		TargetService: targetService{},
		TLS:           tls{},
	}

	c := &cobra.Command{
		Use:   "samples",
		Short: "Managing sample configuration files for remote-service deployment",
		Long:  `Managing sample configuration files for remote-service deployment`,
		Args:  cobra.NoArgs,
	}

	c.AddCommand(cmdCreateSampleConfig(s, printf))

	return c
}

func cmdCreateSampleConfig(s *samples, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "Create sample configuration files for native envoy or istio",
		Long: `Create sample configuration files for native envoy or istio. A valid config
yaml file generated through provisioning is required via --config/-c. Files will be in
the directory specified via --out (default ./samples).
In the case of native envoy, it takes the host of the target service, the desired name
for its cluster and optionally the path prefix for matching. It also sets custom SSL 
connection from the envoy to the remote-service cluster if a folder containing tls.key
and tls.crt is provided via --tls/-t.
In the case of istio where envoy proxy acts as sidecars, if the target is unspecified,
the httpbin example will be generated. Otherwise, users are responsible for preparing
files related to deployment of their target services.`,
		Args: cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {
			err := s.loadConfig()
			if err != nil {
				return errors.Wrap(err, "loading config yaml file")
			}
			return errors.Wrap(s.createSampleConfigs(printf), "creating sample config files")
		},
	}

	c.Flags().StringVarP(&s.ConfigPath, "config", "c", "", "Path to Apigee Remote Service config file")
	c.Flags().BoolVarP(&s.isNative, "native", "", false, "generate config for native envoy (otherwise assuming istio)")
	c.Flags().BoolVarP(&s.overwrite, "force", "f", false, "force overwriting existing directory")
	c.Flags().StringVarP(&s.outDir, "out", "", "./samples", "directory to create config files within")
	c.Flags().StringVarP(&s.TargetService.Name, "name", "n", "httpbin", "target service name")
	c.Flags().StringVarP(&s.TargetService.Host, "host", "", "httpbin.org", "target service host")
	c.Flags().StringVarP(&s.TargetService.Prefix, "prefix", "p", "/", "target service prefix")
	c.Flags().StringVarP(&s.TLS.Dir, "tls", "t", "", "directory for tls key and crt")

	_ = c.MarkFlagRequired("config")

	return c
}

func (s *samples) loadConfig() error {
	s.ServerConfig = &server.Config{}
	err := s.ServerConfig.Load(s.ConfigPath, "")
	if err != nil {
		return err
	}

	s.RuntimeBase = strings.Split(s.ServerConfig.Tenant.RemoteServiceAPI, "/remote-service")[0]
	url, err := url.Parse(s.RuntimeBase)
	if err != nil {
		return err
	}
	s.RuntimeHost = url.Hostname()
	s.Org = s.ServerConfig.Tenant.OrgName
	s.Env = s.ServerConfig.Tenant.EnvName
	s.Namespace = s.ServerConfig.Global.Namespace
	s.EncodedName = provision.EnvScopeEncodedName(s.Org, s.Env)

	return nil
}

func (s *samples) createSampleConfigs(printf shared.FormatFn) error {
	_, err := ioutil.ReadDir(s.outDir)
	if err != nil {
		if err := os.Mkdir(s.outDir, 0755); err != nil {
			return err
		}
	} else if s.overwrite {
		printf("overwriting the existing directory...")
	} else {
		return fmt.Errorf("output directory already exists")
	}
	if s.isNative {
		printf("generating the configuration file for native envoy proxy...")
		return s.createNativeConfig(printf)
	}
	printf("generating configuration files envoy as sidecars...")
	return s.createIstioConfig(printf)
}

func (s *samples) createNativeConfig(printf shared.FormatFn) error {
	tmpl, _ := template.New("envoy-config").Parse(nativeEnvoyConfig)
	f, err := os.OpenFile(path.Join(s.outDir, "envoy-config.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	if s.TLS.Dir != "" {
		s.TLS.Key = path.Join(s.TLS.Dir, "tls.key")
		s.TLS.Crt = path.Join(s.TLS.Dir, "tls.crt")
	}
	printf("generating envoy-config.yaml...")
	return tmpl.Execute(f, s)
}

func (s *samples) createIstioConfig(printf shared.FormatFn) error {
	err := s.createEnvoyFilter(printf)
	if err != nil {
		return err
	}
	err = s.createRequestAuthentication(printf)
	if err != nil {
		return err
	}
	err = s.createAdapterConfig(printf)
	if err != nil {
		return err
	}
	if s.TargetService.Name == "httpbin" {
		return s.createHttpbinConfig(printf)
	}
	return nil
}

func (s *samples) createEnvoyFilter(printf shared.FormatFn) error {
	tmpl, _ := template.New("envoyfilter-sidecar").Parse(envoyFilterSidecar)
	f, err := os.OpenFile(path.Join(s.outDir, "envoyfilter-sidecar.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("generating envoyfilter-sidecar.yaml...")
	return tmpl.Execute(f, s)
}

func (s *samples) createRequestAuthentication(printf shared.FormatFn) error {
	tmpl, _ := template.New("request-authentication").Parse(requestAuthentication)
	f, err := os.OpenFile(path.Join(s.outDir, "request-authentication.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("generating request-authentication.yaml...")
	return tmpl.Execute(f, s)
}

func (s *samples) createAdapterConfig(printf shared.FormatFn) error {
	tmpl, _ := template.New("apigee-envoy-adapter").Parse(adapterConfig)
	f, err := os.OpenFile(path.Join(s.outDir, "apigee-envoy-adapter.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("generating apigee-envoy-adapter.yaml...")
	return tmpl.Execute(f, s)
}

func (s *samples) createHttpbinConfig(printf shared.FormatFn) error {
	tmpl, _ := template.New("httpbin").Parse(httpbinConfig)
	f, err := os.OpenFile(path.Join(s.outDir, "httpbin.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("generating httpbin.yaml...")
	return tmpl.Execute(f, s)
}
