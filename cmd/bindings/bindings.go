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

package bindings

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/apigee/apigee-remote-service-cli/apigee"
	"github.com/apigee/apigee-remote-service-cli/shared"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
)

const (
	productsURLFormat     = "/apiproducts?expand=true"   // relative resource path to get API Products
	productURLFormat      = "/apiproducts/%s"            // relative resource path to get a specific API Product
	productAttrPathFormat = "/apiproducts/%s/attributes" // relative resource path to API Product attributes
	appURLFormat          = "/apps?expand=true"          // relative resource path to get Apps
)

type bindings struct {
	*shared.RootArgs
	products []product.APIProduct
}

// Cmd returns base command
func Cmd(rootArgs *shared.RootArgs, printf shared.FormatFn) *cobra.Command {
	cfg := &bindings{RootArgs: rootArgs}

	c := &cobra.Command{
		Use:   "bindings",
		Short: "Manage Apigee Product to Remote Target bindings",
		Long:  "Manage Apigee Product to Remote Target bindings.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return rootArgs.Resolve(false, false)
		},
	}

	c.PersistentFlags().BoolVarP(&rootArgs.IsLegacySaaS, "legacy", "", false,
		"Apigee SaaS (sets management and runtime URL)")
	c.PersistentFlags().BoolVarP(&rootArgs.IsOPDK, "opdk", "", false,
		"Apigee opdk")
	c.PersistentFlags().StringVarP(&rootArgs.Token, "token", "t", "",
		"Apigee OAuth or SAML token (hybrid only)")
	c.PersistentFlags().StringVarP(&rootArgs.Username, "username", "u", "",
		"Apigee username (legacy or OPDK only)")
	c.PersistentFlags().StringVarP(&rootArgs.Password, "password", "p", "",
		"Apigee password (legacy or OPDK only)")
	c.PersistentFlags().StringVarP(&rootArgs.MFAToken, "mfa", "", "",
		"Apigee password (legacy)")
	c.PersistentFlags().StringVarP(&rootArgs.ManagementBase, "management", "m",
		"", "Apigee management base URL")

	c.AddCommand(cmdBindingsList(cfg, printf))
	c.AddCommand(cmdBindingsAdd(cfg, printf))
	c.AddCommand(cmdBindingsRemove(cfg, printf))
	c.AddCommand(cmdBindingsVerify(cfg, printf))

	return c
}

func cmdBindingsList(b *bindings, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "list [product name (optional)]",
		Short: "List Apigee Products to Remote Target bindings",
		Long:  "List Apigee Products to Remote Target bindings",
		Args:  cobra.MaximumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return b.cmdListAll(printf)
			}
			return b.cmdList(args[0], printf)
		},
	}

	return c
}

func cmdBindingsAdd(b *bindings, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "add [target name] [product name]",
		Short: "Add Remote Target binding to Apigee Product",
		Long:  "Add Remote Target binding to Apigee Product",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			targetName := args[0]
			productName := args[1]
			p, err := b.getProduct(productName)
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			if p == nil {
				cmd.SilenceUsage = true
				return fmt.Errorf("invalid product name: %s", productName)
			}

			err = b.bindTarget(p, targetName, printf)
			if err != nil {
				return fmt.Errorf("%v", err)
			}
			return nil
		},
	}

	return c
}

func cmdBindingsRemove(b *bindings, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "remove [target name] [product name]",
		Short: "Remove target binding from Apigee Product",
		Long:  "Remove target binding from Apigee Product",
		Args:  cobra.ExactArgs(2),

		RunE: func(cmd *cobra.Command, args []string) error {
			targetName := args[0]
			productName := args[1]
			p, err := b.getProduct(productName)
			if err != nil {
				return err
			}
			if p == nil {
				printf("invalid product name: %s", productName)
				return nil
			}

			return b.unbindTarget(p, targetName, printf)
		},
	}

	return c
}

func cmdBindingsVerify(b *bindings, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "verify [product name (optional)]",
		Short: "Verify the bound Apigee products and the associated Apps also have remote-service product associated",
		Long:  "Verify the bound Apigee product (check all bound products if unspecified) and the associated Apps also have remote-service product associated",
		Args:  cobra.MaximumNArgs(1),

		RunE: func(cmd *cobra.Command, args []string) error {
			apps, err := b.getProductNameToAppMap()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				err = b.verifyAll(apps, printf)
				if err != nil {
					os.Exit(1)
				}
				return nil
			}
			p, err := b.getProduct(args[0])
			if err != nil {
				return err
			}
			err = b.verify(p, apps, printf)
			if err != nil {
				os.Exit(1)
			}
			return nil
		},
	}

	return c
}

func (b *bindings) getProduct(name string) (*product.APIProduct, error) {
	path := fmt.Sprintf(productURLFormat, name)
	req, err := b.ApigeeClient.NewRequestNoEnv(http.MethodGet, path, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}

	p := &product.APIProduct{}
	resp, err := b.ApigeeClient.Do(req, p)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			defer resp.Body.Close()
			return nil, nil
		}
		return nil, errors.Wrap(err, "retrieving products")
	}
	defer resp.Body.Close()

	return p, nil
}

func (b *bindings) getProducts() ([]product.APIProduct, error) {
	if b.products != nil {
		return b.products, nil
	}
	req, err := b.ApigeeClient.NewRequestNoEnv(http.MethodGet, productsURLFormat, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}

	var res product.APIResponse
	resp, err := b.ApigeeClient.Do(req, &res)
	if err != nil {
		return nil, errors.Wrap(err, "retrieving products")
	}
	defer resp.Body.Close()

	return res.APIProducts, nil
}

// getProductNameToAppMap returns a map of []App with the key being product names
func (b *bindings) getProductNameToAppMap() (map[string][]App, error) {
	req, err := b.ApigeeClient.NewRequestNoEnv(http.MethodGet, appURLFormat, nil)
	if err != nil {
		return nil, errors.Wrap(err, "creating request")
	}

	var res apigee.AppResponse
	resp, err := b.ApigeeClient.Do(req, &res)
	if err != nil {
		return nil, errors.Wrap(err, "retrieving products")
	}
	defer resp.Body.Close()

	appMap := make(map[string][]App)
	for _, app := range res.Apps {
		f := false
		for _, c := range app.Credentials {
			for _, p := range c.APIProducts {
				if p.Name == "remote-service" {
					f = true
				}
			}
		}
		a := App{
			name:             app.Name,
			hasRemoteService: f,
		}
		for _, c := range app.Credentials {
			for _, p := range c.APIProducts {
				appMap[p.Name] = append(appMap[p.Name], a)
			}
		}
	}

	return appMap, nil
}

func (b *bindings) cmdListAll(printf shared.FormatFn) error {
	products, err := b.getProducts()
	if err != nil {
		return err
	}
	return printProducts(products, printf)
}

func (b *bindings) cmdList(productName string, printf shared.FormatFn) error {
	p, err := b.getProduct(productName)
	if err != nil {
		return err
	}
	return printProducts([]product.APIProduct{*p}, printf)
}

func printProducts(products []product.APIProduct, printf shared.FormatFn) error {
	var bound, unbound []product.APIProduct
	for _, p := range products {
		// server returns empty scopes as array with a single empty string, remove for consistency
		if len(p.Scopes) == 1 && p.Scopes[0] == "" {
			p.Scopes = []string{}
		}
		// server may return empty quota field as "null"
		if p.QuotaLimit == "null" {
			p.QuotaLimit = ""
		}
		p.Targets = p.GetBoundTargets()
		if p.Targets == nil {
			unbound = append(unbound, p)
		} else {
			bound = append(bound, p)
		}
	}

	sort.Sort(byName(bound))
	sort.Sort(byName(unbound))
	data := struct {
		Bound   []product.APIProduct
		Unbound []product.APIProduct
	}{
		Bound:   bound,
		Unbound: unbound,
	}
	tmp := template.New("products")
	tmp.Funcs(template.FuncMap{
		"scopes": func(in []string) string { return strings.Join(in, ",") },
	})
	tmp, err := tmp.Parse(productsTemplate)
	if err != nil {
		return errors.Wrap(err, "creating template")
	}
	err = tmp.Execute(shared.FormatFnWriter(printf), data)
	if err != nil {
		return errors.Wrap(err, "executing template")
	}

	return nil
}

func (b *bindings) verifyAll(appMap map[string][]App, printf shared.FormatFn) error {
	products, err := b.getProducts()
	if err != nil {
		return err
	}
	var verifyErrors error
	for _, p := range products {
		if p.Name == "remote-service" { // no need to verify this reserved product
			continue
		}
		err = b.verify(&p, appMap, printf)
		if err != nil {
			verifyErrors = multierr.Append(verifyErrors, err)
		}
	}
	return verifyErrors
}

func (b *bindings) verify(p *product.APIProduct, appMap map[string][]App, printf shared.FormatFn) error {
	if p.GetBoundTargets() == nil {
		printf("Product %s is unbound to any target, no need to verify.", p.Name)
		return nil
	}
	apps, ok := appMap[p.Name]
	if !ok {
		printf("No app is found associated with product %s.", p.Name)
		return nil
	}
	printf("Verifying apps associated with product %s:", p.Name)
	for _, app := range apps {
		if !app.hasRemoteService {
			return fmt.Errorf("  app %s associated with product %s is not associated with remote-service product", app.name, p.Name)
		} else {
			printf("  app %s associated with product %s is verified", app.name, p.Name)
		}
	}
	return nil
}

func (b *bindings) bindTarget(p *product.APIProduct, target string, printf shared.FormatFn) error {
	boundTargets := p.GetBoundTargets()
	if _, ok := indexOf(boundTargets, target); ok {
		printf("target %s is already bound to %s", target, p.Name)
		return nil
	}
	if err := b.updateTargetBindings(p, append(boundTargets, target)); err != nil {
		return errors.Wrapf(err, "binding target %s to %s", target, p.Name)
	}
	printf("product %s is now bound to: %s", p.Name, target)
	return nil
}

func (b *bindings) unbindTarget(p *product.APIProduct, target string, printf shared.FormatFn) error {
	boundTargets := p.GetBoundTargets()
	i, ok := indexOf(boundTargets, target)
	if !ok {
		printf("target %s is not bound to %s", target, p.Name)
		return nil
	}
	boundTargets = append(boundTargets[:i], boundTargets[i+1:]...)
	if err := b.updateTargetBindings(p, boundTargets); err != nil {
		return errors.Wrapf(err, "removing target %s from %s", target, p.Name)
	}
	printf("product %s is no longer bound to: %s", p.Name, target)
	return nil
}

func (b *bindings) updateTargetBindings(p *product.APIProduct, bindings []string) error {
	bindingsString := strings.Join(bindings, ",")
	var attributes []product.Attribute
	for _, a := range p.Attributes {
		if a.Name != product.TargetsAttr {
			attributes = append(attributes, a)
		}
	}
	attributes = append(attributes, product.Attribute{
		Name:  product.TargetsAttr,
		Value: bindingsString,
	})
	newAttrs := attrUpdate{
		Attributes: attributes,
	}
	path := fmt.Sprintf(productAttrPathFormat, p.Name)
	req, err := b.ApigeeClient.NewRequestNoEnv(http.MethodPost, path, newAttrs)
	if err != nil {
		return err
	}
	var attrResult attrUpdate
	_, err = b.ApigeeClient.Do(req, &attrResult)
	return err
}

func indexOf(array []string, val string) (index int, exists bool) {
	index = -1
	for i, v := range array {
		if val == v {
			index = i
			exists = true
			break
		}
	}
	return
}

type attrUpdate struct {
	Attributes []product.Attribute `json:"attribute,omitempty"`
}

type byName []product.APIProduct

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name < a[j].Name }

type App struct {
	name             string
	hasRemoteService bool
}

const productsTemplate = `
{{- define "product"}}
{{.Name}}:
 {{- if .Scopes}}
  Scopes: {{scopes (.Scopes)}}
 {{- end}}
 {{- if .QuotaLimit}}
  Quota: {{.QuotaLimit}} requests every {{.QuotaInterval}} {{.QuotaTimeUnit}} 
 {{- end}}
 {{- if .Targets}}
  Target bindings:
  {{- range .Targets}}
    {{.}}
  {{- end}}
  Paths:
  {{- range .Resources}}
    {{.}}
  {{- end}}
 {{- end}}
{{- end}}
API Products
============          
{{- if .Bound}}
Bound
-----
 {{- range .Bound}}
 {{- template "product" .}}
 {{- end}}
{{- end}}
{{- if .Unbound}}

Unbound
-------
 {{- range .Unbound}}
 {{- template "product" .}}
 {{- end}}
{{- end}}
`
