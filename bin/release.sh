#!/usr/bin/env bash

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

# This script will build a new draft release on Github.
# use DRYRUN=1 to test build

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOTDIR="$(dirname "$SCRIPTPATH")"

if [[ `command -v bin/goreleaser` == "" ]]; then
  echo "goreleaser not found, installing..."
  (cd $ROOTDIR;
  curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | sh)
fi

DRYRUN_ARGS=""
if [[ "${DRYRUN}" == "1" ]]; then
  echo "Dry run, will not label or push to Github"
  DRYRUN_ARGS="--snapshot"
fi

cd "${ROOT_DIR}"
bin/goreleaser --rm-dist ${DRYRUN_ARGS}
