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
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"text/template"

	"github.com/apigee/apigee-remote-service-cli/cmd/provision"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type samples struct {
	*shared.RootArgs
	isNative      bool
	outDir        string
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
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootArgs.Resolve(true, true)
		},
	}

	c.AddCommand(cmdCreateSampleConfig(s, printf))

	return c
}

func cmdCreateSampleConfig(s *samples, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "Create sample configuration files for native envoy or istio",
		Long: `Create sample configuration files for native envoy or istio. A directory to
output the config files (default to ./samples) should be provided through --out-dir.
In the case of native envoy, it takes the host of the target service, the desired
cluster name for it and optionally the path prefix for matching should be provided.
It also sets up custom SSL connection from the envoy to the remote-service cluster if
a directory containing tls.key and tls.crt is provided.
In the case of istio where envoy proxy acts as sidecars, users are responsible for
preparing files related to deployment of the target services thus no information for it
is needed.`,
		Args: cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {
			url, _ := url.Parse(s.RuntimeBase)
			s.RuntimeHost = url.Hostname()
			return errors.Wrap(s.createSampleConfigs(printf), "creating sample config files")
		},
	}

	c.Flags().BoolVarP(&s.isNative, "native", "", false, "generating config for native envoy (otherwise istio by default)")
	c.Flags().StringVarP(&s.outDir, "out-dir", "", "samples", "directory to create config files within")
	c.Flags().StringVarP(&s.TargetService.Name, "name", "", "target-service-name", "target service name")
	c.Flags().StringVarP(&s.TargetService.Host, "host", "", "target-service-host", "target service host")
	c.Flags().StringVarP(&s.TargetService.Prefix, "prefix", "", "/", "target service prefix")
	c.Flags().StringVarP(&s.TLS.Dir, "tls", "", "", "directory for tls key and crt")

	return c
}

func (s *samples) createSampleConfigs(printf shared.FormatFn) error {
	_, err := ioutil.ReadDir(s.outDir)
	if err != nil {
		if err := os.Mkdir(s.outDir, 0755); err != nil {
			return err
		}
	}
	if s.isNative {
		printf("generating the configuration file for native envoy proxy...")
		return s.createNativeConfig(printf)
	}
	printf("generating configuration files envoy as sidecars...")
	return s.createIstioConfig(printf)
}

func (s *samples) createNativeConfig(printf shared.FormatFn) error {
	tmpl, err := template.New("native").Parse(nativeEnvoyConfig)
	if err != nil {
		return err
	}
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
	return s.createAdapterConfig(printf)
}

func (s *samples) createEnvoyFilter(printf shared.FormatFn) error {
	tmpl, err := template.New("native").Parse(envoyFilterSidecar)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path.Join(s.outDir, "envoyfilter-sidecar.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("generating envoyfilter-sidecar.yaml...")
	return tmpl.Execute(f, s)
}

func (s *samples) createRequestAuthentication(printf shared.FormatFn) error {
	tmpl, err := template.New("native").Parse(requestAuthentication)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path.Join(s.outDir, "request-authentication.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("generating request-authentication.yaml...")
	return tmpl.Execute(f, s)
}

func (s *samples) createAdapterConfig(printf shared.FormatFn) error {
	tmpl, err := template.New("native").Parse(adapterConfig)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path.Join(s.outDir, "apigee-envoy-adapter.yaml"), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	s.EncodedName = provision.EnvScopeEncodedName(s.Org, s.Env)
	printf("generating apigee-envoy-adapter.yaml...")
	return tmpl.Execute(f, s)
}
