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
	"github.com/apigee/apigee-remote-service-cli/templates"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type samples struct {
	*shared.RootArgs
	template      string
	outDir        string
	overwrite     bool
	RuntimeHost   string
	TargetService targetService
	TLS           tls
	EncodedName   string
}

type targetService struct {
	Name string
	Host string
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
		Short: "create sample configuration files for native envoy or istio",
		Long: `create sample configuration files for native envoy or istio. A valid config
yaml file generated through provisioning is required via --config/-c. Files will be in
the directory specified via --out (default ./samples).
In the case of native envoy, it takes the target service host and the desired name for
its cluster. It also sets custom SSL connection from the envoy to the remote-service 
cluster if a folder containing tls.key and tls.crt is provided via --tls.
In the case of istio where envoy proxy acts as sidecars, if the target is unspecified,
the httpbin example will be generated. Otherwise, users are responsible for preparing
files related to deployment of their target services.`,
		Args: cobra.NoArgs,

		RunE: func(cmd *cobra.Command, _ []string) error {
			err := s.loadConfig()
			if err != nil {
				return errors.Wrap(err, "loading config yaml file")
			}
			err = s.createSampleConfigs(printf)
			if err != nil {
				return errors.Wrap(err, "creating sample config files")
			}
			printf("config files successfully generated.")
			if s.template != "native" {
				printf("Please enable istio sidecar injection on the default namespace before running kubectl apply on the directory with config files.")
			}
			return nil
		},
	}

	c.Flags().StringVarP(&s.ConfigPath, "config", "c", "", "path to Apigee Remote Service config file")
	c.Flags().StringVarP(&s.template, "template", "t", "istio-1.6", "template name (options are istio-1.6, istio-1.7, native)")
	c.Flags().BoolVarP(&s.overwrite, "force", "f", false, "force overwriting existing directory")
	c.Flags().StringVarP(&s.outDir, "out", "", "./samples", "directory to create config files within")
	c.Flags().StringVarP(&s.TargetService.Name, "name", "n", "httpbin", "target service name")
	c.Flags().StringVarP(&s.TargetService.Host, "host", "", "httpbin.org", "target service host")
	c.Flags().StringVarP(&s.TLS.Dir, "tls", "", "", "directory for tls key and crt")

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

	if s.TLS.Dir != "" {
		s.TLS.Key = path.Join(s.TLS.Dir, "tls.key")
		s.TLS.Crt = path.Join(s.TLS.Dir, "tls.crt")
	}

	return nil
}

func (s *samples) createSampleConfigs(printf shared.FormatFn) error {
	_, err := ioutil.ReadDir(s.outDir)
	if err != nil {
		if err := os.Mkdir(s.outDir, 0755); err != nil {
			return err
		}
	} else if s.overwrite {
		printf("Overwriting the existing directory!")
	} else {
		return fmt.Errorf("output directory already exists")
	}
	printf("Generating %s configuration files...", s.template)
	return s.createConfig(s.template, printf)
}

func (s *samples) createConfig(templateDir string, printf shared.FormatFn) error {
	tempDir, err := ioutil.TempDir("", "apigee")
	if err != nil {
		return errors.Wrap(err, "creating temp dir")
	}
	defer os.RemoveAll(tempDir)

	err = getTemplates(tempDir, templateDir)
	if err != nil {
		return errors.Wrap(err, "getting templates")
	}
	path := path.Join(tempDir, templateDir)
	templates, err := ioutil.ReadDir(path)
	if err != nil {
		return errors.Wrap(err, "getting templates directory")
	}
	for _, f := range templates {
		if f.Name() == "httpbin.yaml" && s.TargetService.Name != "httpbin" {
			continue
		}
		err := s.createConfigYaml(path, f.Name(), printf)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *samples) createConfigYaml(dir string, name string, printf shared.FormatFn) error {
	tmpl, err := template.New(name).ParseFiles(path.Join(dir, name))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path.Join(s.outDir, name), os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	printf("  generating %s...", name)
	return tmpl.Execute(f, s)
}

// getTemplates unzips the templates to the tempDir/templates and returns the directory
func getTemplates(tempDir string, name string) error {
	if err := templates.RestoreAssets(tempDir, name); err != nil {
		return errors.Wrapf(err, "restoring asset %s", name)
	}
	return nil
}
