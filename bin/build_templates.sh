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
TEMPLATES_ZIP_DIR="${TEMP_DIR}/templates"
TEMPLATES_SOURCE_DIR="${ROOTDIR}/templates"

NATIVE_TEMPLATES_SRC="${TEMPLATES_SOURCE_DIR}/native"
ISTIO16_TEMPLATES_SRC="${TEMPLATES_SOURCE_DIR}/istio-1.6"
ISTIO17_TEMPLATES_SRC="${TEMPLATES_SOURCE_DIR}/istio-1.7"

if [ ! -d "${TEMPLATES_ZIP_DIR}" ]; then
  mkdir -p "${TEMPLATES_ZIP_DIR}"
fi

# native templates
ZIP=${TEMPLATES_ZIP_DIR}/native.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${TEMPLATES_SOURCE_DIR}"
zip -qr "${ZIP}" native

# istio-1.6 templates
ZIP=${TEMPLATES_ZIP_DIR}/istio-1.6.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${TEMPLATES_SOURCE_DIR}"
zip -qr "${ZIP}" istio-1.6

# istio-1.7 templates
ZIP=${TEMPLATES_ZIP_DIR}/istio-1.7.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${TEMPLATES_SOURCE_DIR}"
zip -qr "${ZIP}" istio-1.7

# create resource
RESOURCE_FILE="${ROOTDIR}/templates/templates.go"
echo "building ${RESOURCE_FILE}"
cd "${TEMP_DIR}"
go-bindata -nomemcopy -pkg "templates" -prefix "templates" -o "${RESOURCE_FILE}" templates

echo "done"