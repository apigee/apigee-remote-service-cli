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
# If you change any proxies:
# 1. ensure the returned version in the Send-Version.xml of the affected proxies is {{version}}"
# 2. run this script to generate proxies.go 
# 3. run `go mod tidy` to remove the go-bindata dep from your mod and sum files
# 4. check in your changes
#

SCRIPTPATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOTDIR="$(dirname "$SCRIPTPATH")"

if [[ `command -v go-bindata` == "" ]]; then
  echo "go-bindata not installed, installing..."
  go get -u github.com/go-bindata/go-bindata/...
fi

TEMP_DIR=$(mktemp -d)
PROXIES_ZIP_DIR="${TEMP_DIR}/proxies"
PROXIES_SOURCE_DIR="${ROOTDIR}/proxies"

LEGACY_REMOTE_PROXY_SRC="${PROXIES_SOURCE_DIR}/remote-service-legacy"
LEGACY_TOKEN_PROXY_SRC="${PROXIES_SOURCE_DIR}/remote-token-legacy"
INTERNAL_PROXY_SRC="${PROXIES_SOURCE_DIR}/internal-proxy"
GCP_REMOTE_PROXY_SRC="${PROXIES_SOURCE_DIR}/remote-service-gcp"
GCP_TOKEN_PROXY_SRC="${PROXIES_SOURCE_DIR}/remote-token-gcp"

if [ ! -d "${PROXIES_ZIP_DIR}" ]; then
  mkdir -p "${PROXIES_ZIP_DIR}"
fi

# legacy saas remote proxy
ZIP=${PROXIES_ZIP_DIR}/remote-service-legacy.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${LEGACY_REMOTE_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# legacy saas token proxy
ZIP=${PROXIES_ZIP_DIR}/remote-token-legacy.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${LEGACY_TOKEN_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# gcp remote proxy
ZIP=${PROXIES_ZIP_DIR}/remote-service-gcp.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${GCP_REMOTE_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# gcp token proxy
ZIP=${PROXIES_ZIP_DIR}/remote-token-gcp.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${GCP_TOKEN_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# internal proxy
ZIP=${PROXIES_ZIP_DIR}/internal.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${INTERNAL_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# create resource
RESOURCE_FILE="${ROOTDIR}/proxies/proxies.go"
echo "building ${RESOURCE_FILE}"
cd "${TEMP_DIR}"
go-bindata -nomemcopy -pkg "proxies" -prefix "proxies" -o "${RESOURCE_FILE}" proxies

echo "done"
