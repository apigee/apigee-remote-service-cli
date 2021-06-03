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

if (context.getVariable('request.queryparam.filter-by-env') !== null) {
  context.setVariable('products.filter_by_env', context.getVariable('request.queryparam.filter-by-env'));
} else {
  // Default to the single-tenant case.
  context.setVariable('products.filter_by_env', "true");
}

if (context.getVariable('request.queryparam.attributes') !== null) {
  context.setVariable('products.attributes', context.getVariable('request.queryparam.attributes'));
} else {
  // Default to the remote service case
  context.setVariable('products.attributes', "apigee-remote-service-targets");
}

if (context.getVariable('request.queryparam.operation-config-types') !== null) {
  context.setVariable('products.operation_config_types', context.getVariable('request.queryparam.operation-config-types'));
} else {
  // Default to the remote service case
  context.setVariable('products.operation_config_types', "remoteservice");
}
