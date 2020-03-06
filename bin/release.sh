#!/usr/bin/env bash

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
