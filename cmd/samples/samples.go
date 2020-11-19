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
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"text/template"

	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-cli/templates"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var (
	supportedTemplates = map[string]string{
		"native":     "envoy-1.16", // deprecated
		"envoy-1.14": "envoy-1.16",
		"envoy-1.15": "envoy-1.16",
		"envoy-1.16": "envoy-1.16",
		"istio-1.5":  "istio-1.6",
		"istio-1.6":  "istio-1.6",
		"istio-1.7":  "istio-1.7",
	}
)

type samples struct {
	*shared.RootArgs
	template        string
	templateDir     string
	outDir          string
	overwrite       bool
	RuntimeHost     string
	RuntimePort     string
	RuntimeTLS      bool
	AdapterHost     string
	TargetService   targetService
	TLS             tls
	EncodedName     string
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
Values outside those that are listed here will not be accepted.
Note the "native" options has been deprecated.`,
		Args: cobra.NoArgs,

		Run: func(cmd *cobra.Command, _ []string) {
			printf("Supported templates (native is deprecated):")
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
			err = s.validateFieldsFromFlags()
			if err != nil {
				return errors.Wrap(err, "validating flags")
			}
			err = s.loadConfig()
			if err != nil {
				return errors.Wrap(err, "loading config yaml file")
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
	c.Flags().StringVarP(&s.template, "template", "t", "istio-1.6", "template name (run \"samples templates\" to see available options)")
	c.Flags().BoolVarP(&s.overwrite, "force", "f", false, "force overwriting existing directory")
	c.Flags().StringVarP(&s.outDir, "out", "", "./samples", "directory to create config files within")
	c.Flags().StringVarP(&s.TargetService.Name, "name", "n", "httpbin", "target service name")
	c.Flags().StringVarP(&s.TargetService.Host, "host", "", "", "target service host (envoy templates only)")
	c.Flags().StringVarP(&s.AdapterHost, "adapter-host", "", "", "adapter host name (envoy templates only)")
	c.Flags().StringVarP(&s.TLS.Dir, "tls", "", "", "directory containing tls.key and tls.crt used for the adapter service (envoy templates only)")
	c.Flags().StringVarP(&s.ImageTag, "tag", "", "", "version tag of the Envoy Adapter image (istio templates only)")

	_ = c.MarkFlagRequired("config")

	return c
}

func (s *samples) validateFieldsFromFlags() error {
	dir, ok := supportedTemplates[s.template]
	if !ok {
		return fmt.Errorf("template option: %q not found", s.template)
	}
	s.templateDir = dir

	if strings.Contains(s.template, "envoy") || s.template == "native" {
		if s.ImageTag != "" {
			return fmt.Errorf("flag --tag should only be used for the istio template")
		}
		if s.AdapterHost == "" {
			s.AdapterHost = "localhost"
		}
		if s.TargetService.Host == "" {
			s.TargetService.Host = "httpbin.org"
		}
	} else {
		if s.AdapterHost != "" || s.TargetService.Host != "" || s.TLS.Dir != "" {
			return fmt.Errorf("flags --adapter-host, --host or --tls should only be used for envoy templates")
		}
		if s.ImageTag == "" {
			s.ImageTag = getTagFromBuildVersion()
		}
	}

	return nil
}

func (s *samples) loadConfig() error {
	s.ServerConfig = &server.Config{}
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

	// handle configs for analytics-related credential
	if s.ServerConfig.IsGCPManaged() {
		s.IsGCPManaged = true
		if s.ServerConfig.Analytics.FluentdEndpoint != "" {
			s.EncodedName = envScopeEncodedName(s.Org, s.Env)
		}
		// SA credentials supersede the fluentd enpoint
		if s.ServerConfig.Analytics.CredentialsJSON != nil {
			s.AnalyticsSecret = true
			if s.EncodedName != "" {
				fmt.Fprintf(os.Stderr, "The fluentd endpoint is superseded with the given analytics service account.\n")
				s.EncodedName = ""
			}
		}
	}

	if s.TLS.Dir != "" {
		s.TLS.Key = path.Join(s.TLS.Dir, "tls.key")
		s.TLS.Crt = path.Join(s.TLS.Dir, "tls.crt")
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
	return s.createConfig(s.templateDir, printf)
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
	err = f.Truncate(0)
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

// shortName returns a substring with up to the first 15 characters of the input string
func shortName(s string) string {
	if len(s) < 16 {
		return s
	}
	return s[:15]
}

// shortSha returns a substring with the first 7 characters of a SHA for the input string
func shortSha(s string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(s))
	sha := fmt.Sprintf("%x", h.Sum(nil))
	return sha[:7]
}

// envScopeEncodedName returns the encoded resource name to avoid the 63 chars limit
func envScopeEncodedName(org, env string) string {
	sha := shortSha(fmt.Sprintf("%s:%s", org, env))
	return fmt.Sprintf("%s-%s-%s", shortName(org), shortName(env), sha)
}
