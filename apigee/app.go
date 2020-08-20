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

package apigee

type Application struct {
	AppID       string          `json:"appId"`
	Attributes  interface{}     `json:"attributes,omitempty"`
	APIProducts []APIProductRef `json:"apiProducts,omitempty"`
	CallBackURL string          `json:"callbackUrl,omitempty"`
	Credentials []Credential    `json:"credentials,omitempty"`
	CompanyName string          `json:"companyName,omitempty"`
	DeveloperID string          `json:"developerId,omitempty"`
	Name        string          `json:"name"`
	Scopes      []string        `json:"scopes,omitempty"`
	Status      string          `json:"status,omitempty"`
}

type Credential struct {
	APIProducts []APIProductRef `json:"apiProducts,omitempty"`
}

type AppResponse struct {
	Apps []Application `json:"app,omitempty"`
}

type APIProductRef struct {
	Name   string `json:"apiproduct"`
	Status string `json:"status,omitempty"`
}
