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

#
# If you change any templates:
# 1. run this script to generate templates.go 
# 2. run `go mod tidy` to remove the go-bindata dep from your mod and sum files
# 3. check in your changes
#

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOTDIR="$(dirname "$SCRIPTPATH")"

if [[ `command -v go-bindata` == "" ]]; then
  echo "go-bindata not installed, installing..."
  go get -u github.com/go-bindata/go-bindata/...
fi

TEMP_DIR=$(mktemp -d)
TEMPLATES_SOURCE_DIR="${ROOTDIR}/templates"
TEMPLATES_DIR="${TEMP_DIR}/templates"

if [ ! -d "${TEMPLATES_DIR}" ]; then
  mkdir -p "${TEMPLATES_DIR}"
fi


cp -r "${TEMPLATES_SOURCE_DIR}/native"    $TEMPLATES_DIR
cp -r "${TEMPLATES_SOURCE_DIR}/istio-1.6" $TEMPLATES_DIR
cp -r "${TEMPLATES_SOURCE_DIR}/istio-1.7" $TEMPLATES_DIR

# create resource
RESOURCE_FILE="${ROOTDIR}/templates/templates.go"
echo "building ${RESOURCE_FILE}"
cd ${TEMP_DIR}
echo $(ls "${TEMP_DIR}/templates")
go-bindata -nomemcopy -pkg "templates" -prefix "templates" -o "${RESOURCE_FILE}" templates/...

echo "done"