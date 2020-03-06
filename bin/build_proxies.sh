#!/usr/bin/env bash

#
# If you change the proxies, you must run this and check in the generated proxies.go.
# Remember to update the returned proxy version(s).
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

LEGACY_AUTH_PROXY_SRC="${PROXIES_SOURCE_DIR}/auth-proxy-legacy"
INTERNAL_PROXY_SRC="${PROXIES_SOURCE_DIR}/internal-proxy"
HYBRID_AUTH_PROXY_SRC="${PROXIES_SOURCE_DIR}/auth-proxy-hybrid"

if [ ! -d "${PROXIES_ZIP_DIR}" ]; then
  mkdir -p "${PROXIES_ZIP_DIR}"
fi

# legacy saas auth proxy
ZIP=${PROXIES_ZIP_DIR}/istio-auth-legacy.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${LEGACY_AUTH_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# hybrid auth proxy
ZIP=${PROXIES_ZIP_DIR}/istio-auth-hybrid.zip
echo "building ${ZIP}"
rm -f "${ZIP}"
cd "${HYBRID_AUTH_PROXY_SRC}"
zip -qr "${ZIP}" apiproxy

# internal proxy
ZIP=${PROXIES_ZIP_DIR}/istio-internal.zip
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
