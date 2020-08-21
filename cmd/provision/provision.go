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

package provision

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
)

const (
	kvmName       = "remote-service"
	cacheName     = "remote-service"
	encryptKVM    = true
	authProxyName = "remote-service"

	remoteServiceProxyZip = "remote-service-gcp.zip"

	apiProductsPath = "apiproducts"

	certsURLFormat        = "%s/certs"        // RemoteServiceProxyURL
	productsURLFormat     = "%s/products"     // RemoteServiceProxyURL
	verifyAPIKeyURLFormat = "%s/verifyApiKey" // RemoteServiceProxyURL
	quotasURLFormat       = "%s/quotas"       // RemoteServiceProxyURL
)

// default durations for the proxy verification retry
var (
	duration time.Duration = 180 * time.Second
	interval time.Duration = 5 * time.Second
)

type provision struct {
	*shared.RootArgs
	forceProxyInstall bool
	virtualHosts      string
	rotate            int
}

// Cmd returns base command
func Cmd(rootArgs *shared.RootArgs, printf shared.FormatFn) *cobra.Command {
	p := &provision{RootArgs: rootArgs}

	c := &cobra.Command{
		Use:   "provision",
		Short: "Provision your Apigee environment for remote services",
		Long: `The provision command will set up your Apigee environment for remote services. This includes creating
and installing a remote-service kvm with certificates, creating credentials, and deploying a remote-service proxy
to your organization and environment.`,
		Args: cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := rootArgs.Resolve(false, true); err != nil {
				return err
			}
			if !p.IsGCPManaged && p.rotate > 0 {
				return fmt.Errorf(`--rotate only valid for hybrid, use 'token rotate-cert' for others`)
			}
			return nil
		},

		RunE: func(cmd *cobra.Command, _ []string) error {
			return p.run(printf)
		},
	}

	c.Flags().StringVarP(&rootArgs.ManagementBase, "management", "m",
		shared.DefaultManagementBase, "Apigee management base URL")
	c.Flags().BoolVarP(&rootArgs.IsLegacySaaS, "legacy", "", false,
		"Apigee SaaS (sets management and runtime URL)")
	c.Flags().BoolVarP(&rootArgs.IsOPDK, "opdk", "", false,
		"Apigee opdk")

	c.Flags().StringVarP(&rootArgs.Token, "token", "t", "",
		"Apigee OAuth or SAML token (hybrid only)")
	c.Flags().StringVarP(&rootArgs.Username, "username", "u", "",
		"Apigee username (legacy or OPDK only)")
	c.Flags().StringVarP(&rootArgs.Password, "password", "p", "",
		"Apigee password (legacy or OPDK only)")
	c.Flags().StringVarP(&rootArgs.MFAToken, "mfa", "", "",
		"Apigee password (legacy)")

	c.Flags().BoolVarP(&p.forceProxyInstall, "force-proxy-install", "f", false,
		"force new proxy install (upgrades proxy)")
	c.Flags().StringVarP(&p.virtualHosts, "virtual-hosts", "", "default,secure",
		"override proxy virtualHosts")
	c.Flags().StringVarP(&p.Namespace, "namespace", "n", "apigee",
		"emit configuration in the specified namespace")

	c.Flags().IntVarP(&p.rotate, "rotate", "", 0, "if n > 0, generate new private key and keep n public keys (hybrid only)")

	return c
}

func (p *provision) run(printf shared.FormatFn) error {

	var cred *keySecret

	var verbosef = shared.NoPrintf
	if p.Verbose {
		verbosef = shared.Errorf
	}

	tempDir, err := ioutil.TempDir("", "apigee")
	if err != nil {
		return errors.Wrap(err, "creating temp dir")
	}
	defer os.RemoveAll(tempDir)

	replaceVH := func(proxyDir string) error {
		proxiesFile := filepath.Join(proxyDir, "proxies", "default.xml")
		bytes, err := ioutil.ReadFile(proxiesFile)
		if err != nil {
			return errors.Wrapf(err, "reading file %s", proxiesFile)
		}
		newVH := ""
		for _, vh := range strings.Split(p.virtualHosts, ",") {
			if strings.TrimSpace(vh) != "" {
				newVH = newVH + fmt.Sprintf(virtualHostReplacementFmt, vh)
			}
		}
		// remove all "secure" virtualhost
		bytes = []byte(strings.ReplaceAll(string(bytes), virtualHostDeleteText, ""))
		// replace the "default" virtualhost
		bytes = []byte(strings.Replace(string(bytes), virtualHostReplaceText, newVH, 1))
		if err := ioutil.WriteFile(proxiesFile, bytes, 0); err != nil {
			return errors.Wrapf(err, "writing file %s", proxiesFile)
		}
		return nil
	}

	replaceInFile := func(file, old, new string) error {
		bytes, err := ioutil.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, "reading file %s", file)
		}
		bytes = []byte(strings.Replace(string(bytes), old, new, 1))
		if err := ioutil.WriteFile(file, bytes, 0); err != nil {
			return errors.Wrapf(err, "writing file %s", file)
		}
		return nil
	}

	// replace the version using the build info
	replaceVersion := func(proxyDir string) error {
		calloutFile := filepath.Join(proxyDir, "policies", "Send-Version.xml")
		oldValue := `"version":"{{version}}"`
		newValue := fmt.Sprintf(`"version":"%s"`, shared.BuildInfo.Version)
		if err := replaceInFile(calloutFile, oldValue, newValue); err != nil {
			return err
		}
		return nil
	}

	replaceVHAndAuthTarget := func(proxyDir string) error {
		if err := replaceVH(proxyDir); err != nil {
			return err
		}

		if err := replaceVersion(proxyDir); err != nil {
			return err
		}

		if p.IsOPDK {
			// OPDK must target local internal proxy
			authFile := filepath.Join(proxyDir, "policies", "Authenticate-Call.xml")
			oldTarget := "https://edgemicroservices.apigee.net"
			newTarget := p.RuntimeBase
			if err := replaceInFile(authFile, oldTarget, newTarget); err != nil {
				return err
			}

			// OPDK must have org.noncps = true for products callout
			calloutFile := filepath.Join(proxyDir, "policies", "JavaCallout.xml")
			oldValue := "</Properties>"
			newValue := `<Property name="org.noncps">true</Property>
			</Properties>`
			if err := replaceInFile(calloutFile, oldValue, newValue); err != nil {
				return err
			}
		}
		return nil
	}

	if p.IsOPDK {
		if err := p.deployInternalProxy(replaceVH, tempDir, verbosef); err != nil {
			return errors.Wrap(err, "deploying internal proxy")
		}
	}

	// input remote-service proxy
	var customizedProxy string
	if p.IsGCPManaged {
		customizedProxy, err = getCustomizedProxy(tempDir, remoteServiceProxyZip, replaceVersion)
	} else {
		customizedProxy, err = getCustomizedProxy(tempDir, legacyAuthProxyZip, replaceVHAndAuthTarget)
	}
	if err != nil {
		return err
	}

	if err := p.checkAndDeployProxy(authProxyName, customizedProxy, verbosef); err != nil {
		return errors.Wrapf(err, "deploying proxy %s", authProxyName)
	}

	// create API product
	if err := p.createAPIProduct(verbosef); err != nil {
		return errors.Wrapf(err, "creating remote-service API product")
	}

	if !p.IsGCPManaged {
		cred, err = p.createLegacyCredential(verbosef) // TODO: on missing or force new cred
		if err != nil {
			return errors.Wrapf(err, "generating credential")
		}

		if err := p.getOrCreateKVM(cred, verbosef); err != nil {
			return errors.Wrapf(err, "retrieving or creating kvm")
		}
	}

	config := p.ServerConfig
	if config == nil {
		config = p.createConfig(cred)
	}

	if p.IsGCPManaged && (config.Tenant.PrivateKey == nil || p.rotate > 0) {
		keyID, privateKey, jwks, err := p.CreateNewKey()
		if err != nil {
			return err
		}
		config.Tenant.PrivateKey = privateKey
		config.Tenant.PrivateKeyID = keyID

		if jwks, err = p.RotateJKWS(jwks, p.rotate); err != nil {
			return err
		}

		config.Tenant.JWKS = jwks
	}

	var verifyErrors error
	if p.IsGCPManaged {
		verifyErrors = p.verifyWithRetry(config, verbosef)
	} else {
		verifyErrors = p.verifyWithoutRetry(config, verbosef)
	}

	if err := p.printConfig(config, printf, verifyErrors); err != nil {
		return errors.Wrapf(err, "generating config")
	}

	if verifyErrors == nil {
		verbosef("provisioning verified OK")
	}

	return verifyErrors
}

func (p *provision) createAuthorizedClient(config *server.Config) (*http.Client, error) {

	// add authorization to transport
	tr := http.DefaultTransport
	if config.Tenant.AllowUnverifiedSSLCert {
		tr = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		}
	}

	tr, err := server.AuthorizationRoundTripper(config, tr)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   config.Tenant.ClientTimeout,
		Transport: tr,
	}, nil
}

func (p *provision) verifyWithRetry(config *server.Config, verbosef shared.FormatFn) error {
	var verifyErrors error
	timeout := time.After(duration)
	tick := time.Tick(interval)
	for {
		select {
		case <-timeout:
			if verifyErrors != nil {
				shared.Errorf("\nWARNING: Apigee may not be provisioned properly.")
				shared.Errorf("Unable to verify proxy endpoint(s). Errors:\n")
				for _, err := range multierr.Errors(verifyErrors) {
					if strings.Contains(err.Error(), "Unable to get the runtime version") {
						p.encodeUDCAEndpoint(config, verbosef)
					}
					shared.Errorf("  %s", err)
				}
				shared.Errorf("\n")
			}
			return verifyErrors
		case <-tick:
			verifyErrors = p.verify(config, verbosef)
			if verifyErrors == nil {
				return nil
			}
			verbosef("verifying proxies failed, trying again...")
		}
	}
}

func (p *provision) verifyWithoutRetry(config *server.Config, verbosef shared.FormatFn) error {
	verifyErrors := p.verify(config, verbosef)
	if verifyErrors != nil {
		shared.Errorf("\nWARNING: Apigee may not be provisioned properly.")
		shared.Errorf("Unable to verify proxy endpoint(s). Errors:\n")
		for _, err := range multierr.Errors(verifyErrors) {
			shared.Errorf("  %s", err)
		}
		shared.Errorf("\n")
	}
	return verifyErrors
}

func (p *provision) verify(config *server.Config, verbosef shared.FormatFn) error {

	client, err := p.createAuthorizedClient(config)
	if err != nil {
		return err
	}

	var verifyErrors error
	if p.IsLegacySaaS || p.IsOPDK {
		verbosef("verifying internal proxy...")
		verifyErrors = p.verifyInternalProxy(client, verbosef)
	}

	verbosef("verifying remote-service proxy...")
	verifyErrors = multierr.Combine(verifyErrors, p.verifyRemoteServiceProxy(client, verbosef))

	if p.IsGCPManaged {
		if version, err := p.checkRuntimeVersion(config, client, verbosef); err != nil {
			err = errors.Wrapf(err, "Unable to get the runtime version")
			verifyErrors = multierr.Combine(verifyErrors, err)
		} else if version >= "1.3.0" || version == "unknown" {
			p.encodeUDCAEndpoint(config, verbosef)
		}
	}

	return verifyErrors
}

// verify GET RemoteServiceProxyURL/certs
// verify GET RemoteServiceProxyURL/products
// verify POST RemoteServiceProxyURL/verifyApiKey
// verify POST RemoteServiceProxyURL/quotas
func (p *provision) verifyRemoteServiceProxy(client *http.Client, printf shared.FormatFn) error {

	verifyGET := func(targetURL string) error {
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			return errors.Wrapf(err, "creating request")
		}
		res, err := client.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
		return err
	}

	var res *http.Response
	var verifyErrors error
	certsURL := fmt.Sprintf(certsURLFormat, p.RemoteServiceProxyURL)
	err := verifyGET(certsURL)
	verifyErrors = multierr.Append(verifyErrors, err)

	productsURL := fmt.Sprintf(productsURLFormat, p.RemoteServiceProxyURL)
	err = verifyGET(productsURL)
	verifyErrors = multierr.Append(verifyErrors, err)

	verifyAPIKeyURL := fmt.Sprintf(verifyAPIKeyURLFormat, p.RemoteServiceProxyURL)
	req, err := http.NewRequest(http.MethodPost, verifyAPIKeyURL, strings.NewReader(`{ "apiKey": "x" }`))
	if err == nil {
		req.Header.Add("Content-Type", "application/json")
		res, err = client.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
	}
	if err != nil && (res == nil || res.StatusCode != 401) { // 401 is ok, we didn't use a valid api key
		verifyErrors = multierr.Append(verifyErrors, err)
	}

	quotasURL := fmt.Sprintf(quotasURLFormat, p.RemoteServiceProxyURL)
	req, err = http.NewRequest(http.MethodPost, quotasURL, strings.NewReader("{}"))
	if err == nil {
		req.Header.Add("Content-Type", "application/json")
		res, err = client.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
	}
	if err != nil {
		verifyErrors = multierr.Append(verifyErrors, err)
	}

	return verifyErrors
}

type keySecret struct {
	Key    string `json:"key"`
	Secret string `json:"secret"`
}
