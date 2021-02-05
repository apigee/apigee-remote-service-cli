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
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	rnd "math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-cli/apigee"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

const (
	legacyCredentialURLFormat = "%s/credential/organization/%s/environment/%s"  // InternalProxyURL, org, env
	analyticsURLFormat        = "%s/analytics/organization/%s/environment/%s"   // InternalProxyURL, org, env
	legacyAnalyticURLFormat   = "%s/axpublisher/organization/%s/environment/%s" // InternalProxyURL, org, env
	legacyServiceProxyZip     = "remote-service-legacy.zip"
	legacyTokenProxyZip       = "remote-token-legacy.zip"

	// virtualHost is only necessary for legacy
	virtualHostDeleteText     = "<VirtualHost>secure</VirtualHost>"
	virtualHostReplaceText    = "<VirtualHost>default</VirtualHost>"
	virtualHostReplacementFmt = "<VirtualHost>%s</VirtualHost>" // each virtualHost

	internalProxyName = "edgemicro-internal"
	internalProxyZip  = "internal.zip"
)

func (p *provision) deployInternalProxy(replaceVirtualHosts func(proxyDir string) error, tempDir string, verbosef shared.FormatFn) error {

	customizedZip, err := getCustomizedProxy(tempDir, internalProxyZip, func(proxyDir string) error {

		// change server locations
		calloutFile := filepath.Join(proxyDir, "policies", "Callout.xml")
		bytes, err := ioutil.ReadFile(calloutFile)
		if err != nil {
			return errors.Wrapf(err, "reading file %s", calloutFile)
		}
		var callout JavaCallout
		if err := xml.Unmarshal(bytes, &callout); err != nil {
			return errors.Wrapf(err, "unmarshalling %s", calloutFile)
		}
		setMgmtURL := false
		for i, cp := range callout.Properties {
			if cp.Name == "REGION_MAP" {
				callout.Properties[i].Value = fmt.Sprintf("DN=%s", p.RuntimeBase)
			}
			if cp.Name == "MGMT_URL_PREFIX" {
				setMgmtURL = true
				callout.Properties[i].Value = p.ManagementBase
			}
		}
		if !setMgmtURL {
			callout.Properties = append(callout.Properties,
				javaCalloutProperty{
					Name:  "MGMT_URL_PREFIX",
					Value: p.ManagementBase,
				})
		}

		writer, err := os.OpenFile(calloutFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0)
		if err != nil {
			return errors.Wrapf(err, "writing file %s", calloutFile)
		}
		if _, err := writer.WriteString(xml.Header); err != nil {
			return errors.Wrapf(err, "writing %s to file %s", xml.Header, calloutFile)
		}
		encoder := xml.NewEncoder(writer)
		encoder.Indent("", "  ")
		err = encoder.Encode(callout)
		if err != nil {
			return errors.Wrapf(err, "encoding xml to %s", calloutFile)
		}
		err = writer.Close()
		if err != nil {
			return errors.Wrapf(err, "closing file %s", calloutFile)
		}

		return replaceVirtualHosts(proxyDir)
	})
	if err != nil {
		return err
	}

	return p.checkAndDeployProxy(internalProxyName, customizedZip, p.forceProxyInstall, verbosef)
}

//check if the KVM exists, if it doesn't, create a new one and sets certs for JWT
func (p *provision) getOrCreateKVM(cred *keySecret, printf shared.FormatFn) error {

	kid, keyBytes, jwksBytes, err := p.CreateJWKS(1, printf)
	if err != nil {
		return err
	}

	kvm := apigee.KVM{
		Name:      kvmName,
		Encrypted: encryptKVM,
		Entries: []apigee.Entry{
			{
				Name:  "private_key",
				Value: string(keyBytes),
			},
			{
				Name:  "jwks",
				Value: string(jwksBytes),
			},
			{
				Name:  "kid",
				Value: kid,
			},
		},
	}

	resp, err := p.ApigeeClient.KVMService.Create(kvm)
	if err != nil && (resp == nil || resp.StatusCode != http.StatusConflict) { // http.StatusConflict == already exists
		return err
	}
	if resp.StatusCode == http.StatusConflict {
		printf("kvm %s already exists", kvmName)
		return nil
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("creating kvm %s, status code: %v", kvmName, resp.StatusCode)
	}
	printf("kvm %s created", kvmName)

	printf("new private key:\n%s", string(keyBytes))
	printf("new jwks:\n%s", string(jwksBytes))

	return nil
}

// hash for key and secret
func newHash() (string, error) {
	// use crypto seed
	var seed int64
	if err := binary.Read(rand.Reader, binary.BigEndian, &seed); err != nil {
		return "", err
	}
	rnd.Seed(seed)

	t := time.Now()
	h := sha256.New()
	if _, err := h.Write([]byte(t.String() + string(rune(rnd.Int())))); err != nil {
		return "", err
	}
	str := hex.EncodeToString(h.Sum(nil))
	return str, nil
}

func (p *provision) createLegacyCredential(printf shared.FormatFn) (*keySecret, error) {
	printf("creating credential...")

	key, err := newHash()
	if err != nil {
		return nil, err
	}
	secret, err := newHash()
	if err != nil {
		return nil, err
	}
	cred := &keySecret{
		Key:    key,
		Secret: secret,
	}

	credentialURL := fmt.Sprintf(legacyCredentialURLFormat, p.InternalProxyURL, p.Org, p.Env)

	req, err := p.ApigeeClient.NewRequest(http.MethodPost, credentialURL, cred)
	if err != nil {
		return nil, err
	}
	req.URL, err = url.Parse(credentialURL) // override client's munged URL
	if err != nil {
		return nil, err
	}

	_, err = p.ApigeeClient.Do(req, nil)
	if err != nil {
		return nil, err
	}
	printf("credential created")
	return cred, nil
}

// verify POST internalProxyURL/analytics/organization/%s/environment/%s
// verify POST internalProxyURL/quotas/organization/%s/environment/%s
func (p *provision) verifyInternalProxy(client *http.Client, printf shared.FormatFn) error {
	var verifyErrors error

	var req *http.Request
	var err error
	var res *http.Response
	if p.IsOPDK {
		analyticsURL := fmt.Sprintf(legacyAnalyticURLFormat, p.InternalProxyURL, p.Org, p.Env)
		req, err = http.NewRequest(http.MethodPost, analyticsURL, strings.NewReader("{}"))
	} else {
		analyticsURL := fmt.Sprintf(analyticsURLFormat, p.InternalProxyURL, p.Org, p.Env)
		req, err = http.NewRequest(http.MethodGet, analyticsURL, nil)
		q := req.URL.Query()
		q.Add("tenant", fmt.Sprintf("%s~%s", p.Org, p.Env))
		q.Add("relative_file_path", "fake")
		q.Add("file_content_type", "application/x-gzip")
		q.Add("encrypt", "true")
		req.URL.RawQuery = q.Encode()
	}
	if err == nil {
		res, err = client.Do(req)
		if res != nil {
			defer res.Body.Close()
		}
	}
	if (res != nil && res.StatusCode > 299) || err != nil {
		verifyErrors = multierr.Append(verifyErrors, err)
	}

	return verifyErrors
}

// JavaCallout must be capitalized to ensure correct generation
type JavaCallout struct {
	Name                                string `xml:"name,attr"`
	DisplayName, ClassName, ResourceURL string
	Properties                          []javaCalloutProperty `xml:"Properties>Property"`
}

type javaCalloutProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}
