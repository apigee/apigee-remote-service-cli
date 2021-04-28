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

package provision

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/apigee/apigee-remote-service-cli/v2/apigee"
	"github.com/apigee/apigee-remote-service-cli/v2/cmd"
	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/pkg/errors"
)

const embedDir = "proxies"
const proxyTopDir = "apiproxy"

//go:embed "proxies"
var embedded embed.FS

type proxyModFunc func(name string) error

// returns path to customized proxy
// caller is responsible for deleting tempDir
func getCustomizedProxy(tempDir, proxyName string, modFunc proxyModFunc) (string, error) {

	embeddedPath := filepath.Join(embedDir, proxyName)
	extractDir, err := os.MkdirTemp(tempDir, "proxy")
	if err != nil {
		return "", errors.Wrap(err, "creating temp dir")
	}
	proxyBaseDir := filepath.Join(extractDir, embedDir, proxyName)

	if err := cmd.CopyFromEmbedded(embedded, embeddedPath, extractDir); err != nil {
		return "", err
	}

	if modFunc != nil {
		if err := modFunc(filepath.Join(proxyBaseDir, proxyTopDir)); err != nil {
			return "", errors.Wrap(err, "modFunc")
		}
	}

	return proxyBaseDir, nil
}

func (p *provision) checkAndDeployProxy(name, file string, forceInstall bool, printf shared.FormatFn) error {
	printf("checking if proxy %s deployment exists...", name)
	var oldRev *apigee.Revision
	var err error
	if p.IsGCPManaged {
		oldRev, err = p.ApigeeClient.Proxies.GetGCPDeployedRevision(name)
	} else {
		oldRev, err = p.ApigeeClient.Proxies.GetDeployedRevision(name)
	}
	if err != nil {
		return err
	}
	if oldRev != nil {
		if forceInstall {
			printf("replacing proxy %s revision %s in %s", name, oldRev, p.Env)
		} else {
			printf("proxy %s revision %s already deployed to %s", name, oldRev, p.Env)
			return nil
		}
	}

	printf("checking proxy %s status...", name)
	var resp *apigee.Response
	proxy, resp, err := p.ApigeeClient.Proxies.Get(name)
	if err != nil && (resp == nil || resp.StatusCode != 404) {
		return err
	}

	// importAndDeployProxy proxy
	var newRev apigee.Revision = 1
	var latestRev apigee.Revision = 0
	if proxy != nil && len(proxy.Revisions) > 0 {
		sort.Sort(apigee.RevisionSlice(proxy.Revisions))
		latestRev = proxy.Revisions[len(proxy.Revisions)-1]
		if forceInstall {
			// Always increment newRev if forceInstall is true
			// regardless of deployment status of the latestRev in the specified environment.
			newRev = latestRev + 1
		} else {
			// This is the case where proxy exists in the organization
			// but is not deployed to the specified environment.
			// If oldRev != nil, the whole function will not be invoked without forceInstall being true.
			newRev = latestRev
		}
		printf("proxy %s exists. highest revision is: %d", name, latestRev)
	}

	if newRev > latestRev { // only import if newRev is larger than the latest revision, 0 if not present, in the organization
		// create a new client to avoid dumping the proxy binary to stdout during Import
		noDebugClient := p.ApigeeClient
		if p.Verbose {
			opts := *p.ClientOpts
			opts.Debug = false
			var err error
			noDebugClient, err = apigee.NewEdgeClient(&opts)
			if err != nil {
				return err
			}
		}

		printf("creating new proxy %s revision: %d...", name, newRev)
		_, res, err := noDebugClient.Proxies.Import(name, file)
		if res != nil {
			defer res.Body.Close()
		}
		if err != nil {
			return errors.Wrapf(err, "importing proxy %s", name)
		}
	}

	if oldRev != nil && !p.IsGCPManaged { // it's not necessary to undeploy first with GCP
		printf("undeploying proxy %s revision %d on env %s...",
			name, oldRev, p.Env)
		_, res, err := p.ApigeeClient.Proxies.Undeploy(name, p.Env, *oldRev)
		if res != nil {
			defer res.Body.Close()
		}
		if err != nil {
			return errors.Wrapf(err, "undeploying proxy %s", name)
		}
	}

	if !p.IsGCPManaged {
		cache := apigee.Cache{
			Name: cacheName,
		}
		res, err := p.ApigeeClient.CacheService.Create(cache)
		if err != nil && (res == nil || res.StatusCode != http.StatusConflict) { // http.StatusConflict == already exists
			return err
		}
		if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusConflict {
			return fmt.Errorf("creating cache %s, status code: %v", cacheName, res.StatusCode)
		}
		if res.StatusCode == http.StatusConflict {
			printf("cache %s already exists", cacheName)
		} else {
			printf("cache %s created", cacheName)
		}
	}

	printf("deploying proxy %s revision %d to env %s...", name, newRev, p.Env)
	_, res, err := p.ApigeeClient.Proxies.Deploy(name, p.Env, newRev)
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return errors.Wrapf(err, "deploying proxy %s", name)
	}

	return nil
}
