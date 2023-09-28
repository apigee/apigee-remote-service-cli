# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Set the "runtime_version" flow variable to a semver-style version made
by splitting APIGEE_DPCOLOR by "-" and concatenating the first three
segments that are digits. If this fails, the var is set to "unknown."
"""

import os


def make_semver(version_string):
    if not version_string:
        return "unknown"

    nums = []
    for segment in version_string.split("-"):
        try:
            int(segment)
            nums.append(segment)
        except ValueError:
            pass

    if len(nums) < 3:
        return "unknown"

    return ".".join(nums[:3])


dp_color = os.environ.get("APIGEE_DPCOLOR", "")
semver = make_semver(dp_color)
flow.setVariable("runtime_version", semver)
