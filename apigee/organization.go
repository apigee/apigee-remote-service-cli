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

type Organization struct {
	Name              string      `json:"name"`
	CreatedAt         string      `json:"createdAt,omitempty"`
	LastModifiedAt    string      `json:"lastModifiedAt,omitempty"`
	RuntimeType       string      `json:"runtimeType,omitempty"`
	SubscriptionType  string      `json:"subscriptionType,omitempty"`
	CACertificate     string      `json:"caCertificate,omitempty"`
	ProjectID         string      `json:"projectId"`
	AnalyticsRegion   string      `json:"analyticsRegion,omitempty"`
	AuthorizedNetwork string      `json:"authorizedNetwork,omitempty"`
	Environments      []string    `json:"environments,omitempty"`
	Properties        interface{} `json:"properties,omitempty"`
}
