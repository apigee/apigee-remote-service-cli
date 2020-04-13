#!/usr/bin/env bash

#
# If you change any proxies:
# 1. update the returned version(s) in the Send-Version.xml of the affected proxies
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

LEGACY_REMOTE_PROXY_SRC="${PROXIES_SOURCE_DIR}/remote-proxy-legacy"
INTERNAL_PROXY_SRC="${PROXIES_SOURCE_DIR}/internal-proxy"
GCP_REMOTE_PROXY_SRC="${PROXIES_SOURCE_DIR}/remote-proxy-gcp"

if [ ! -d "${PROXIES_ZIP_DIR}" ]; then
  mkdir -p "${PROXIES_ZIP_DIR}"
fi

# legacy saas remote proxy
ZIP=${PROXIES_ZIP_DIR}/remote-service-legacy.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${LEGACY_REMOTE_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# gcp remote proxy
ZIP=${PROXIES_ZIP_DIR}/remote-service-gcp.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${GCP_REMOTE_PROXY_SRC}"
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
