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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/apigee/apigee-remote-service-envoy/testutil"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func TestAddCommandWithFlags(t *testing.T) {
	rootArgs := &RootArgs{}
	c := &cobra.Command{
		Use:   "test",
		Short: "Test",
		Long:  "Test Root Command",
		Args:  cobra.NoArgs,
	}
	subC := &cobra.Command{
		Use:   "test",
		Short: "Test",
		Long:  "Test Sub Command",
		Args:  cobra.NoArgs,
	}
	AddCommandWithFlags(c, rootArgs, subC)
	f := subC.PersistentFlags()
	flagNames := []string{
		"runtime",
		"verbose",
		"organization",
		"environment",
		"config",
		"insecure",
	}
	for _, n := range flagNames {
		if f.Lookup(n) == nil {
			t.Errorf("want flag %s added but not found", n)
		}
	}
}

func TestResolveWithConfig(t *testing.T) {
	var tf *os.File
	var err error
	var config string
	var configCRD *server.ConfigMapCRD
	var secretCRD *server.SecretCRD
	var configMapYAML string
	r := &RootArgs{}

	config = `
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  org_name: org
  env_name: env
analytics:
  fluentd_endpoint: apigee-udca-myorg-test.apigee.svc.cluster.local:20001`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r.ConfigPath = tf.Name()

	want := "--token is required for hybrid"
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}

	// add token
	r.Token = "token"
	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}

	config = `
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  internal_api: https://istioservices.apigee.net/edgemicro
  org_name: org
  env_name: env
analytics:
  fluentd_endpoint: apigee-udca-myorg-test.apigee.svc.cluster.local:20001`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r = &RootArgs{
		Token:      "token",
		ConfigPath: tf.Name(),
	}

	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}

	config = `
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  internal_api: https://opdk.apigee.net/edgemicro
  org_name: org
  env_name: env
analytics:
  fluentd_endpoint: apigee-udca-myorg-test.apigee.svc.cluster.local:20001`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r = &RootArgs{
		Token:      "token",
		ConfigPath: tf.Name(),
	}

	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
}

func TestResolveWithFlagOverride(t *testing.T) {
	var tf *os.File
	var err error
	var configCRD *server.ConfigMapCRD
	var secretCRD *server.SecretCRD
	var configMapYAML string
	var r *RootArgs
	var config string

	config = `
global:
  namespace: ns
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  org_name: org
  env_name: env
  allow_unverified_ssl_cert: false`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r = &RootArgs{
		Org:                "my-org",
		Env:                "my-env",
		Namespace:          "my-ns",
		InsecureSkipVerify: true,
		Token:              "token",
		ConfigPath:         tf.Name(),
	}

	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
	if r.Org != "my-org" {
		t.Errorf("want 'my-org', got '%s'", r.Org)
	}
	if r.Env != "my-env" {
		t.Errorf("want 'my-env', got '%s'", r.Env)
	}
	if r.Namespace != "my-ns" {
		t.Errorf("want 'my-ns', got '%s'", r.Namespace)
	}
	if !r.InsecureSkipVerify {
		t.Error("want InsecureSkipVerify to be true, got false")
	}

	config = `
global:
  namespace: ns
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  internal_api: https://istioservices.apigee.net/edgemicro
  org_name: org
  env_name: env`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r = &RootArgs{
		IsOPDK:     true,
		ConfigPath: tf.Name(),
		Token:      "token",
	}

	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
	if !r.IsOPDK {
		t.Error("want IsOPDK to be true, got false")
	}

	config = `
  global:
    namespace: ns
  tenant:
    remote_service_api: https://org-test.apigee.net/remote-service
    internal_api: https://opdk.apigee.net/edgemicro
    org_name: org
    env_name: env`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r = &RootArgs{
		IsLegacySaaS: true,
		ConfigPath:   tf.Name(),
		Token:        "token",
	}

	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
	if !r.IsLegacySaaS {
		t.Error("want IsLegacySaaS to be true, got false")
	}

	config = `
  global:
    namespace: ns
  tenant:
    remote_service_api: https://org-test.apigee.net/remote-service
    org_name: org
    env_name: env`
	configCRD = makeConfigCRD(config)
	secretCRD, err = makeSecretCRD()
	if err != nil {
		t.Fatal(err)
	}
	configMapYAML, err = makeYAML(configCRD, secretCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err = ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r = &RootArgs{
		IsLegacySaaS: true,
		ConfigPath:   tf.Name(),
		Token:        "token",
	}

	if err := r.Resolve(false, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
	if r.IsGCPManaged {
		t.Error("want IsGCPManaged to be false, got true")
	}
}

func TestResolveMissingSecret(t *testing.T) {
	const config = `
tenant:
  remote_service_api: https://org-test.apigee.net/remote-service
  org_name: org
  env_name: env
analytics:
  fluentd_endpoint: apigee-udca-myorg-test.apigee.svc.cluster.local:20001`
	configCRD := makeConfigCRD(config)
	configMapYAML, err := makeYAML(configCRD)
	if err != nil {
		t.Fatal(err)
	}

	tf, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tf.Name())
	if _, err := tf.WriteString(configMapYAML); err != nil {
		t.Fatal(err)
	}
	if err := tf.Close(); err != nil {
		t.Fatal(err)
	}
	r := &RootArgs{
		Token:      "token",
		ConfigPath: tf.Name(),
	}

	want := fmt.Sprintf("Secret CRD not found in file: %s", tf.Name())
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}
}

func TestResolveWithWrongConfigPath(t *testing.T) {
	r := &RootArgs{
		Token:      "token",
		ConfigPath: "no such file",
	}

	want := "open no such file: no such file or directory"
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}
}

func TestResolveWithoutConfig(t *testing.T) {
	r := &RootArgs{}
	var want string

	want = "--runtime is required for hybrid or opdk (or --organization and --environment with --legacy)"
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}

	r.IsLegacySaaS = true
	want = "--organization and --environment are required for legacy saas"
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}

	r.Org = "hi"
	r.Env = "test"
	if err := r.Resolve(true, true); err != nil {
		t.Errorf("want no error got %v", err)
	}

	r.IsOPDK = true
	want = "--legacy and --opdk options are exclusive"
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}

	r.IsLegacySaaS = false
	r.ManagementBase = "" // reset the management base
	r.RuntimeBase = ""    // reset the runtime base
	want = "--runtime or --config is required and used as the management url if --management is not explicitly set for opdk"
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}

	r.RuntimeBase = "runtime"
	if err := r.Resolve(true, true); err != nil {
		t.Errorf("want no error got %v", err)
	}
}

func TestResolveAuth(t *testing.T) {
	var r *RootArgs
	var want string

	r = &RootArgs{
		Org:            "hi",
		Env:            "test",
		RuntimeBase:    "www.runtime.com",
		ManagementBase: "www.mgmt.com",
		IsOPDK:         true,
	}

	want = "no auth: must have username and password or a ~/.netrc entry for "
	if err := r.Resolve(false, true); err == nil || err.Error() != want {
		t.Errorf("want %s got %v", want, err)
	}

	r = &RootArgs{
		Org:          "hi",
		Env:          "test",
		Username:     "me",
		Password:     "secret",
		IsLegacySaaS: true,
	}

	want = "error authorizing for OAuth token"
	if err := r.Resolve(false, true); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("want %s... got %v", want, err)
	}
}

func TestWrite(t *testing.T) {
	var w io.Writer
	b := []byte("test")

	w = FormatFnWriter(Printf)
	if _, err := w.Write(b); err != nil {
		t.Error(err)
	}

	w = FormatFnWriter(Errorf)
	if _, err := w.Write(b); err != nil {
		t.Error(err)
	}
}

func TestPrint(t *testing.T) {
	defaultStdout := os.Stdout
	defer func() {
		os.Stdout = defaultStdout
	}()
	r, w, _ := os.Pipe()
	os.Stdout = w

	Printf("test %s", "Printf")

	w.Close()
	out, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "test Printf\n" {
		t.Errorf("want test got %s", string(out))
	}

	defaultStderr := os.Stderr
	defer func() {
		os.Stderr = defaultStderr
	}()
	r, w, _ = os.Pipe()
	os.Stderr = w

	Errorf("test %s", "Errorf")

	w.Close()
	out, err = ioutil.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "test Errorf\n" {
		t.Errorf("want test got %s", string(out))
	}
}

func TestPrintMissingFlags(t *testing.T) {
	r := &RootArgs{}
	if err := r.PrintMissingFlags(nil); err != nil {
		t.Errorf("want no error got %v", err)
	}
	want := `required flag(s) "config" not set`
	if err := r.PrintMissingFlags([]string{"config"}); err == nil {
		t.Error("want error got none")
	} else if err.Error() != want {
		t.Errorf("want %s, got %v", want, err)
	}
}

func TestURLCreators(t *testing.T) {
	r := RootArgs{
		RuntimeBase: "runtime",
	}
	if err := r.Resolve(true, true); err != nil {
		t.Errorf("unexpected err: %v", err)
	}

	remoteServiceBase := "runtime" + remoteServicePath

	want := remoteServiceBase + "/products"
	got := r.GetProductsURL()
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}

	want = remoteServiceBase + "/verifyApiKey"
	got = r.GetVerifyAPIKeyURL()
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}

	want = remoteServiceBase + "/quotas"
	got = r.GetQuotasURL()
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}

	remoteTokenBase := "runtime" + remoteTokenPath

	want = remoteTokenBase + "/certs"
	got = r.GetCertsURL()
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}

	want = remoteTokenBase + "/token"
	got = r.GetTokenURL()
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}
}

func makeConfigCRD(config string) *server.ConfigMapCRD {
	data := map[string]string{"config.yaml": config}
	return &server.ConfigMapCRD{
		APIVersion: "v1",
		Kind:       "ConfigMap",
		Metadata: server.Metadata{
			Name:      "apigee-remote-service-envoy",
			Namespace: "apigee",
		},
		Data: data,
	}
}

func makeSecretCRD() (*server.SecretCRD, error) {
	kid := "my kid"
	privateKey, jwksBuf, err := testutil.GenerateKeyAndJWKs(kid)
	if err != nil {
		return nil, err
	}
	pkBytes := pem.EncodeToMemory(&pem.Block{Type: server.PEMKeyType, Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	props := map[string]string{server.SecretPropsKIDKey: kid}
	propsBuf := new(bytes.Buffer)
	if err := server.WriteProperties(propsBuf, props); err != nil {
		return nil, err
	}

	data := map[string]string{
		server.SecretJWKSKey:    base64.StdEncoding.EncodeToString(jwksBuf),
		server.SecretPrivateKey: base64.StdEncoding.EncodeToString(pkBytes),
		server.SecretPropsKey:   base64.StdEncoding.EncodeToString(propsBuf.Bytes()),
	}

	return &server.SecretCRD{
		APIVersion: "v1",
		Kind:       "Secret",
		Type:       "Opaque",
		Metadata: server.Metadata{
			Name:      "org-env-policy-secret",
			Namespace: "apigee",
		},
		Data: data,
	}, nil
}

func makeYAML(crds ...interface{}) (string, error) {
	var yamlBuffer bytes.Buffer
	yamlEncoder := yaml.NewEncoder(&yamlBuffer)
	yamlEncoder.SetIndent(2)
	for _, crd := range crds {
		if err := yamlEncoder.Encode(crd); err != nil {
			return "", err
		}
	}
	return yamlBuffer.String(), nil
}
