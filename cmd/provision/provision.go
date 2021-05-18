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
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-cli/v2/apigee"
	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/apigee/apigee-remote-service-envoy/v2/config"
	"github.com/apigee/apigee-remote-service-envoy/v2/server"
	"github.com/apigee/apigee-remote-service-envoy/v2/util"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	kvmName        = "remote-service"
	cacheName      = "remote-service"
	encryptKVM     = true
	authProxyName  = "remote-service"
	tokenProxyName = "remote-token"

	remoteServiceProxy = "remote-service-gcp"
	remoteTokenProxy   = "remote-token-gcp"
)

// default durations for the proxy verification retry
var (
	duration time.Duration = 180 * time.Second
	interval time.Duration = 5 * time.Second
)

type provision struct {
	*shared.RootArgs
	forceProxyInstall       bool
	virtualHosts            string
	rotate                  int
	runtimeType             string
	analyticsServiceAccount string
	policySecretData        map[string]string
	analyticsSecretData     map[string]string
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
			if p.IsGCPManaged {
				err := p.retrieveRuntimeType()
				if err != nil {
					return errors.Wrapf(err, "getting runtime type")
				}
			}
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
		"Apigee OAuth or SAML token (overrides any other given credentials)")
	c.Flags().StringVarP(&rootArgs.Username, "username", "u", "",
		"Apigee username (legacy or opdk only)")
	c.Flags().StringVarP(&rootArgs.Password, "password", "p", "",
		"Apigee password (legacy or opdk only)")
	c.Flags().StringVarP(&rootArgs.MFAToken, "mfa", "", "",
		"Apigee multi-factor authorization token (legacy only)")

	c.Flags().StringVarP(&p.analyticsServiceAccount, "analytics-sa", "", "",
		"path to the service account json file (for GCP-managed analytics only)")

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

	tempDir, err := os.MkdirTemp("", "apigee")
	if err != nil {
		return errors.Wrap(err, "creating temp dir")
	}
	defer os.RemoveAll(tempDir)

	replaceVH := func(proxyDir string) error {
		proxiesFile := filepath.Join(proxyDir, "proxies", "default.xml")
		bytes, err := os.ReadFile(proxiesFile)
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
		if err := os.WriteFile(proxiesFile, bytes, 0); err != nil {
			return errors.Wrapf(err, "writing file %s", proxiesFile)
		}
		return nil
	}

	replaceInFile := func(file, old, new string) error {
		bytes, err := os.ReadFile(file)
		if err != nil {
			return errors.Wrapf(err, "reading file %s", file)
		}
		bytes = []byte(strings.Replace(string(bytes), old, new, 1))
		if err := os.WriteFile(file, bytes, 0); err != nil {
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

	// deploy remote-service proxy
	var customizedProxy string
	if p.IsGCPManaged {
		customizedProxy, err = getCustomizedProxy(tempDir, remoteServiceProxy, replaceVersion)
	} else {
		customizedProxy, err = getCustomizedProxy(tempDir, legacyServiceProxy, replaceVHAndAuthTarget)
	}
	if err != nil {
		return err
	}

	if err := p.checkAndDeployProxy(authProxyName, customizedProxy, p.forceProxyInstall, verbosef); err != nil {
		return errors.Wrapf(err, "deploying runtime proxy %s", authProxyName)
	}

	// Deploy remote-token proxy
	if p.IsGCPManaged {
		customizedProxy, err = getCustomizedProxy(tempDir, remoteTokenProxy, nil)
	} else {
		customizedProxy, err = getCustomizedProxy(tempDir, legacyTokenProxy, replaceVH)
	}
	if err != nil {
		return err
	}
	if err := p.checkAndDeployProxy(tokenProxyName, customizedProxy, false, verbosef); err != nil {
		return errors.Wrapf(err, "deploying token proxy %s", tokenProxyName)
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

	cfg := p.ServerConfig
	if cfg == nil {
		cfg = p.createConfig(cred)
	}

	if p.IsGCPManaged && (cfg.Tenant.PrivateKey == nil || p.rotate > 0) {
		var keyID string
		var privateKey *rsa.PrivateKey
		var jwks jwk.Set
		var err error

		if p.isCloud() { // attempt to fetch secrets from propertysets
			keyID, privateKey, jwks, err = p.policySecretsFromPropertyset()
		}
		if err != nil || privateKey == nil {
			verbosef("no existing policy secret, creating new ones")
			keyID, privateKey, jwks, err = p.CreateNewKey()
			if err != nil {
				return err
			}
		}
		cfg.Tenant.PrivateKey = privateKey
		cfg.Tenant.PrivateKeyID = keyID

		if jwks, err = p.RotateJWKS(jwks, p.rotate); err != nil {
			return err
		}

		cfg.Tenant.JWKS = jwks
	}

	var verifyErrors error
	if p.IsGCPManaged {
		verifyErrors = p.verifyWithRetry(cfg, verbosef)

		// creates the policy secrets if is GCP managed
		if err := p.createPolicySecretData(cfg, verbosef); err != nil {
			return errors.Wrapf(err, "creating policy secret data")
		}

		// create the analytics secrets if is GCP managed
		if err := p.createAnalyticsSecretData(cfg, verbosef); err != nil {
			return errors.Wrapf(err, "creating analytics secret data")
		}
		if len(p.analyticsSecretData) == 0 {
			shared.Errorf("\nWARNING: No analytics service account given via --analytics-sa or config.yaml.")
			shared.Errorf("\nIMPORTANT: Please make sure the application default credentials where the adapter is run are correctly configured.")
		}
	} else {
		verifyErrors = p.verifyWithoutRetry(cfg, verbosef)
	}

	if err := p.printConfig(cfg, printf, verifyErrors, verbosef); err != nil {
		return errors.Wrapf(err, "generating config")
	}

	if verifyErrors == nil {
		verbosef("provisioning verified OK")
	}

	// return possible errors if not hybrid
	if !p.IsGCPManaged || p.isCloud() {
		return verifyErrors
	}

	// output this warning for hybrid
	if p.rotate > 0 {
		shared.Errorf("\nIMPORTANT: Provisioned config with rotated secrets needs to be applied onto the k8s cluster to take effect.")
	} else {
		shared.Errorf("\nIMPORTANT: Provisioned config needs to be applied onto the k8s cluster to take effect.")
	}

	return verifyErrors
}

// retrieveRuntimeType fetches the organization information from the management base and extracts the runtime type
func (p *provision) retrieveRuntimeType() error {
	req, err := p.ApigeeClient.NewRequestNoEnv(http.MethodGet, "", nil)
	if err != nil {
		return err
	}

	org := &apigee.Organization{}
	if _, err := p.ApigeeClient.Do(req, org); err != nil {
		return err
	}
	p.runtimeType = org.RuntimeType

	return nil
}

// isCloud determines whether it is NG SaaS
func (p *provision) isCloud() bool {
	return p.IsGCPManaged && p.runtimeType == "CLOUD"
}

// policySecretsFromPropertyset retrieves the policy secret from the remote-service propertyset
// the returned values will be empty or nil if such propertyset does not exist or there is other error fetching it
func (p *provision) policySecretsFromPropertyset() (keyID string, privateKey *rsa.PrivateKey, jwks jwk.Set, err error) {
	req, err := p.ApigeeClient.NewRequest(http.MethodGet, fmt.Sprintf(propertysetGETOrPUTURL, "remote-service"), nil)
	if err != nil {
		return
	}

	buf := new(bytes.Buffer)
	_, err = p.ApigeeClient.Do(req, buf)
	if err != nil {
		return
	}

	// read the response into a map
	m, err := util.ReadProperties(buf)
	if err != nil {
		return
	}

	// extracts the jwks from the map
	jwksStr, ok := m["crt"]
	if !ok {
		err = fmt.Errorf("crt not found in remote-service propertyset")
		return
	}
	jwks = jwk.NewSet()
	err = json.Unmarshal([]byte(jwksStr), jwks)
	if err != nil {
		return
	}

	// extracts the private key from the map
	pkStr, ok := m["key"]
	if !ok {
		err = fmt.Errorf("key not found in remote-service propertyset")
		return
	}
	privateKey, err = util.LoadPrivateKey([]byte(strings.ReplaceAll(pkStr, `\n`, "\n")))
	if err != nil {
		return
	}

	// extracts the key id from the map
	keyID, ok = m[config.SecretPropsKIDKey]
	if !ok {
		err = fmt.Errorf("kid not found in remote-service propertyset")
		return
	}

	return
}

func (p *provision) createAuthorizedClient(cfg *config.Config) (*http.Client, error) {

	// add authorization to transport
	tr := http.DefaultTransport
	if cfg.Tenant.TLS.AllowUnverifiedSSLCert {
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

	tr, err := server.AuthorizationRoundTripper(cfg, tr)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Timeout:   cfg.Tenant.ClientTimeout,
		Transport: tr,
	}, nil
}

func (p *provision) verifyWithRetry(cfg *config.Config, verbosef shared.FormatFn) error {
	var verifyErrors error
	timeout := time.After(duration)
	tick := time.Tick(interval)
	for {
		select {
		case <-timeout:
			if verifyErrors != nil {
				shared.Errorf("\nWARNING: Apigee may not be provisioned properly.")
				shared.Errorf("Unable to verify proxy endpoint(s). Errors:\n")
				for _, err := range errorset.Errors(verifyErrors) {
					shared.Errorf("  %s", err)
				}
				shared.Errorf("\n")
			}
			return verifyErrors
		case <-tick:
			verifyErrors = p.verify(cfg, verbosef)
			if verifyErrors == nil {
				return nil
			}
			verbosef("verifying proxies failed, trying again...")
		}
	}
}

func (p *provision) verifyWithoutRetry(cfg *config.Config, verbosef shared.FormatFn) error {
	verifyErrors := p.verify(cfg, verbosef)
	if verifyErrors != nil {
		shared.Errorf("\nWARNING: Apigee may not be provisioned properly.")
		shared.Errorf("Unable to verify proxy endpoint(s). Errors:\n")
		for _, err := range errorset.Errors(verifyErrors) {
			shared.Errorf("  %s", err)
		}
		shared.Errorf("\n")
	}
	return verifyErrors
}

func (p *provision) verify(cfg *config.Config, verbosef shared.FormatFn) error {

	client, err := p.createAuthorizedClient(cfg)
	if err != nil {
		return err
	}

	var verifyErrors error
	if p.IsLegacySaaS || p.IsOPDK {
		verbosef("verifying internal proxy...")
		verifyErrors = p.verifyInternalProxy(client, verbosef)
	}

	verbosef("verifying remote-service proxy...")
	verifyErrors = errorset.Append(verifyErrors, p.verifyRemoteServiceProxy(client, verbosef))

	return verifyErrors
}

// verify GET /certs
// verify GET /products
// verify POST /verifyApiKey
// verify POST /quotas
func (p *provision) verifyRemoteServiceProxy(client *http.Client, printf shared.FormatFn) error {

	verifyGET := func(targetURL string) error {
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			return errors.Wrapf(err, "creating request")
		}
		res, err := client.Do(req)
		if res != nil {
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusInternalServerError && res.StatusCode != http.StatusUnauthorized {
				return fmt.Errorf("GET request to %q returns %d", targetURL, res.StatusCode)
			}
		}
		return err
	}

	var res *http.Response
	var verifyErrors error
	err := verifyGET(p.GetCertsURL())
	verifyErrors = errorset.Append(verifyErrors, err)

	err = verifyGET(p.GetProductsURL())
	verifyErrors = errorset.Append(verifyErrors, err)

	verifyAPIKeyURL := p.GetVerifyAPIKeyURL()
	req, err := http.NewRequest(http.MethodPost, verifyAPIKeyURL, strings.NewReader(`{ "apiKey": "x" }`))
	if err == nil {
		req.Header.Add("Content-Type", "application/json")
		res, err = client.Do(req)
		if res != nil {
			defer res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusInternalServerError { // 401 or 500 is ok, either the secret is not there or we didn't use a valid api key
				verifyErrors = errorset.Append(verifyErrors, fmt.Errorf("POST request to %q returns %d", verifyAPIKeyURL, res.StatusCode))
			}
		}
	}
	if err != nil {
		verifyErrors = errorset.Append(verifyErrors, err)
	}

	quotasURL := p.GetQuotasURL()
	req, err = http.NewRequest(http.MethodPost, quotasURL, strings.NewReader("{}"))
	if err == nil {
		req.Header.Add("Content-Type", "application/json")
		res, err = client.Do(req)
		if res != nil {
			defer res.Body.Close()
			if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusOK {
				verifyErrors = errorset.Append(verifyErrors, fmt.Errorf("POST request to %q returns %d", quotasURL, res.StatusCode))
			}
		}
	}
	if err != nil {
		verifyErrors = errorset.Append(verifyErrors, err)
	}

	return verifyErrors
}

type keySecret struct {
	Key    string `json:"key"`
	Secret string `json:"secret"`
}
