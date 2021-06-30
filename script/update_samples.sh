#!/usr/bin/env bash

set -ueo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
SAMPLES_REV="1.0"

TMP_DIR="${DIR}/../build"
SAMPLES_DIR="${DIR}/../samples"

cleanup() {
    rm -rf "${DIR}/../build/biscuit_spec"
}

trap "cleanup" ERR

# Clone and sync sample files from spec repo
if [ -d "${TMP_DIR}/biscuit_spec" ]; then
    cleanup
fi

git -C "${TMP_DIR}" clone https://github.com/CleverCloud/biscuit.git biscuit_spec
git -C "${TMP_DIR}/biscuit_spec" checkout "${SAMPLES_REV}"
rsync -prav --delete-before "${TMP_DIR}/biscuit_spec/samples/" "${SAMPLES_DIR}/data"

# extract keys from READMEs
for f in $(find "${SAMPLES_DIR}/data" -name README.md); do
    PRIVATE_KEY=$( grep "root secret key: " "${f}" | grep -oE "[a-fA-F0-9]{64}" | xxd -r -p )  || true
    PUBLIC_KEY=$( grep "root public key: " "${f}"  | grep -oE "[a-fA-F0-9]{64}" | xxd -r -p ) || true 
    KEY_DIR=$(dirname "${f}")
    if [ ! -z "${PRIVATE_KEY}" ]; then
        echo -n "${PRIVATE_KEY}" > "${KEY_DIR}/root_key"
    fi
    if [ ! -z "${PUBLIC_KEY}" ]; then
        echo -n "${PUBLIC_KEY}" > "${KEY_DIR}/root_key.pub"
    fi
done

cleanup
