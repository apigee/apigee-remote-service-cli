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

var orgName = context.getVariable('apigee.edgemicro.organization');

context.setVariable('quota.identifier', orgName + '.' + request.body.asJSON.identifier);
context.setVariable("quota.allow",request.body.asJSON.allow);
context.setVariable("quota.interval",request.body.asJSON.interval);
context.setVariable("quota.unit",request.body.asJSON.timeUnit);
context.setVariable("quota.weight",request.body.asJSON.weight);
 
