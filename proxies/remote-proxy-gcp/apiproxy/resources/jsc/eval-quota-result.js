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

// ensures that in the response, used <= allowed
// and exceeded is a count of the excess of used > allow
// assumes that allow is set arbitrarily high in the actual policy
var used = context.getVariable("ratelimit.DistributedQuota.used.count")
var allowed = context.getVariable("quota.allow")
if (used > allowed) {
    var exceeded = used - allowed
    context.setVariable("quota.used", allowed)
    context.setVariable("quota.exceeded", exceeded.toFixed(0))
} else {
    var exceeded = 0
    context.setVariable("quota.used", used)
    context.setVariable("quota.exceeded", exceeded.toFixed(0))
}
