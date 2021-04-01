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
	"sort"
	"strings"
	"text/template"

	"github.com/apigee/apigee-remote-service-cli/v2/shared"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

const (
	productsURLFormat = "/apiproducts?expand=true" // relative resource path to get API Products
	productURLFormat  = "/apiproducts/%s"          // relative resource path to get a specific API Product
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
		"Apigee OAuth or SAML token (overrides any other given credentials)")
	c.PersistentFlags().StringVarP(&rootArgs.Username, "username", "u", "",
		"Apigee username (legacy or opdk only)")
	c.PersistentFlags().StringVarP(&rootArgs.Password, "password", "p", "",
		"Apigee password (legacy or opdk only)")
	c.PersistentFlags().StringVarP(&rootArgs.MFAToken, "mfa", "", "",
		"Apigee multi-factor authorization token (legacy only)")
	c.PersistentFlags().StringVarP(&rootArgs.ManagementBase, "management", "m",
		"", "Apigee management base URL")

	c.AddCommand(cmdBindingsList(cfg, printf))

	return c
}

func cmdBindingsList(b *bindings, printf shared.FormatFn) *cobra.Command {
	c := &cobra.Command{
		Use:   "list [product name (optional)]",
		Short: "List Apigee Products to Remote Target (API) bindings",
		Long:  "List Apigee Products to Remote Target (API) bindings",
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

// getProduct queries the API product with the given name from Apigee
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

// getProducts queries all API products from Apigee
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

		p.APIs = p.GetBoundAPIs()
		if len(p.APIs) == 0 {
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

type byName []product.APIProduct

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name < a[j].Name }

const productsTemplate = `
{{- define "product"}}
{{.Name}}:
 {{- if .Scopes}}
  Scopes: {{scopes (.Scopes)}}
 {{- end}}
 {{- if .QuotaLimit}}
  Quota: {{.QuotaLimit}} requests every {{.QuotaInterval}} {{.QuotaTimeUnit}} 
 {{- end}}
 {{- if .APIs}}
  Target (API) bindings:
  {{- range .APIs}}
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
