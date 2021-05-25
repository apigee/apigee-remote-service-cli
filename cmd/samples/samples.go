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
	"embed"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/apigee/apigee-remote-service-cli/v2/cmd"
	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const embedDir = "templates"

//go:embed "templates"
var embedded embed.FS

var (
	supportedTemplates = map[string]string{
		"envoy-1.15": "envoy-1.15",
		"envoy-1.16": "envoy-1.16",
		"envoy-1.17": "envoy-1.16",
		"envoy-1.18": "envoy-1.16",
		"istio-1.7":  "istio-1.7",
		"istio-1.8":  "istio-1.7",
		"istio-1.9":  "istio-1.9",
		"istio-1.10": "istio-1.9",
	}
)

type samples struct {
	*shared.RootArgs
	template        string
	templateDir     string
	outDir          string
	overwrite       bool
	JWTProviderKey  string
	RuntimeHost     string
	RuntimePort     string
	RuntimeTLS      bool
	AdapterHost     string
	TargetService   targetService
	TLS             tls
	ImageTag        string
	AnalyticsSecret bool // existence of sa credentials for analytics uploading
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
	c.AddCommand(cmdListTemplateOptions(printf))

	return c
}

func cmdListTemplateOptions(printf shared.FormatFn) *cobra.Command {
	return &cobra.Command{
		Use:   "templates",
		Short: "list available options for --template flag in \"samples create\" command",
		Long: `List available options for --template flag in "samples create" command.
Values outside those that are listed here will not be accepted.`,
		Args: cobra.NoArgs,

		Run: func(cmd *cobra.Command, _ []string) {
			printf("Supported templates:")
			keys := []string{}
			for k := range supportedTemplates {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				printf("  %s", k)
			}
		},
	}
}

func cmdCreateSampleConfig(s *samples, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "create",
		Short: "create sample configuration files for native envoy or istio",
		Long: `Create sample configuration files for native envoy or istio. A valid config
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
			var err error
			err = s.validateFieldsFromFlags(cmd)
			if err != nil {
				return errors.Wrap(err, "validating flags")
			}
			err = s.loadConfig()
			if err != nil {
				return errors.Wrap(err, "loading config yaml file")
			}
			err = s.checkVersionCompatibility()
			if err != nil {
				return errors.Wrap(err, "checking config file's compatibility with sample config")
			}
			err = s.createSampleConfigs(printf)
			if err != nil {
				return errors.Wrap(err, "creating sample config files")
			}
			printf("Config files successfully generated.")
			if strings.Contains(s.template, "istio") {
				printf("Please enable istio sidecar injection on the default namespace before running kubectl apply on the directory with config files.")
			}
			return nil
		},
	}

	c.Flags().StringVarP(&s.ConfigPath, "config", "c", "", "path to Apigee Remote Service config file")
	c.Flags().StringVarP(&s.template, "template", "t", "istio-1.9", "template name (run \"samples templates\" to see available options)")
	c.Flags().BoolVarP(&s.overwrite, "force", "f", false, "force overwriting existing directory")
	c.Flags().StringVarP(&s.outDir, "out", "", "./samples", "directory to create config files within")
	c.Flags().StringVarP(&s.TargetService.Name, "name", "n", "httpbin", "target service name")
	c.Flags().StringVarP(&s.TargetService.Host, "host", "", "httpbin.org", "target service host (envoy templates only)")
	c.Flags().StringVarP(&s.AdapterHost, "adapter-host", "", "localhost", "adapter host name (envoy templates only)")
	c.Flags().StringVarP(&s.TLS.Dir, "tls", "", "", "directory containing tls.key and tls.crt used for the adapter service (envoy templates only)")
	c.Flags().StringVarP(&s.ImageTag, "tag", "", getTagFromBuildVersion(), "version tag of the Envoy Adapter image (istio templates only)")

	_ = c.MarkFlagRequired("config")

	return c
}

func (s *samples) validateFieldsFromFlags(c *cobra.Command) error {
	dir, ok := supportedTemplates[s.template]
	if !ok {
		return fmt.Errorf("template option: %q not found; run samples templates to list available options", s.template)
	}
	s.templateDir = dir

	if strings.Contains(s.template, "envoy") || s.template == "native" {
		if c.Flags().Changed("tag") {
			return fmt.Errorf("flag --tag should only be used for the istio template")
		}
	} else {
		if c.Flags().Changed("adapter-host") || c.Flags().Changed("host") || c.Flags().Changed("tls") {
			return fmt.Errorf("flags --adapter-host, --host or --tls should only be used for envoy templates")
		}
	}

	return nil
}

func (s *samples) loadConfig() error {
	s.ServerConfig = &config.Config{}
	err := s.ServerConfig.Load(s.ConfigPath, "", "", false)
	if err != nil {
		return err
	}

	return s.parseConfig()
}

func (s *samples) parseConfig() error {
	s.RuntimeBase = strings.Split(s.ServerConfig.Tenant.RemoteServiceAPI, "/remote-service")[0]
	url, err := url.Parse(s.RuntimeBase)
	if err != nil {
		return err
	}
	s.RuntimeHost = url.Hostname()
	if url.Scheme == "https" {
		s.RuntimeTLS = true
		s.RuntimePort = "443"
	} else {
		s.RuntimeTLS = false
		s.RuntimePort = "80"
	}
	if url.Port() != "" {
		s.RuntimePort = url.Port()
	}
	s.Org = s.ServerConfig.Tenant.OrgName
	s.Env = s.ServerConfig.Tenant.EnvName
	s.Namespace = s.ServerConfig.Global.Namespace
	s.JWTProviderKey = s.ServerConfig.Auth.JWTProviderKey

	// handle configs for analytics-related credential
	if s.ServerConfig.IsGCPManaged() {
		s.IsGCPManaged = true
		if s.ServerConfig.Analytics.CredentialsJSON != nil {
			s.AnalyticsSecret = true
		}
	}

	if s.TLS.Dir != "" {
		s.TLS.Key = path.Join(s.TLS.Dir, "tls.key")
		s.TLS.Crt = path.Join(s.TLS.Dir, "tls.crt")
	}

	return nil
}

func (s *samples) checkVersionCompatibility() error {
	if (s.templateDir == "istio-1.7" || s.templateDir == "envoy-1.15") && !s.ServerConfig.Auth.AppendMetadataHeaders {
		return fmt.Errorf("specified Istio/Envoy version requires append_metadata_headers to be true in the given config")
	}
	return nil
}

func getTagFromBuildVersion() string {
	tag := shared.BuildInfo.Version
	if e := strings.Index(tag, "-SNAPSHOT"); e != -1 {
		tag = tag[:e]
	}
	if strings.HasPrefix(tag, "v") {
		return tag
	}
	return "v" + tag
}

func (s *samples) createSampleConfigs(printf shared.FormatFn) error {
	_, err := os.ReadDir(s.outDir)
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
	return s.createConfig(s.templateDir, printf)
}

func (s *samples) createConfig(templateDir string, printf shared.FormatFn) error {
	tempDir, err := os.MkdirTemp("", "apigee")
	if err != nil {
		return errors.Wrap(err, "creating temp dir")
	}
	defer os.RemoveAll(tempDir)

	err = getTemplates(tempDir, templateDir)
	if err != nil {
		return errors.Wrap(err, "getting templates")
	}
	path := path.Join(tempDir, embedDir, templateDir)
	templates, err := os.ReadDir(path)
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
	err = f.Truncate(0)
	if err != nil {
		return err
	}
	printf("  generating %s...", name)
	return tmpl.Execute(f, s)
}

// getTemplates retrieves the templates by name
func getTemplates(tempDir string, name string) error {
	embeddedPath := filepath.Join(embedDir, name)
	return cmd.CopyFromEmbedded(embedded, embeddedPath, tempDir)
}
