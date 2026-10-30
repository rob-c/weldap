#!/usr/bin/env bash
# Test device CA: the production weldap-ca tool, run from the server image against testdir state.
#   ./device-ca.sh init | sign <csr> <device> | revoke <device> | crl | list
#   ./device-ca.sh rogue <name>      key + cert from a different, unregistered CA (negative tests)
# Signed device certificates are also copied to pki/devices/<device>.crt.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p .data/device-ca pki/device-ca-pub pki/devices pki/private
if [[ "${1:-}" == rogue ]]; then
    name="${2:?name}"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 30 \
        -subj "/CN=$name" -addext "extendedKeyUsage=clientAuth" \
        -keyout "pki/private/$name.key" -out "pki/devices/$name.crt" 2>/dev/null
    echo "rogue client cert: pki/devices/$name.crt"; exit 0
fi
args=("$@")
mounts=(-v "$PWD/.data/device-ca:/var/lib/weldap-ca" -v "$PWD/pki/device-ca-pub:/var/lib/weldap-publish")
if [[ "${1:-}" == sign ]]; then
    mounts+=(-v "$(cd "$(dirname "$2")" && pwd)/$(basename "$2"):/tmp/request.csr:ro"); args=(sign /tmp/request.csr "$3")
fi
out="$(docker run --rm --network none -u "$(id -u):$(id -g)" -e WELDAP_CA_NAME="/O=WELDAP/CN=WELDAP Device CA (test)" \
    "${mounts[@]}" --entrypoint /usr/local/bin/weldap-ca weldap-ca:latest "${args[@]}")"
if [[ "${1:-}" == sign ]]; then
    printf '%s\n' "$out" >"pki/devices/$3.crt"; chmod 644 "pki/devices/$3.crt"
    echo "registered $3: $(openssl x509 -in "pki/devices/$3.crt" -noout -serial -enddate | tr '\n' ' ')"
else
    printf '%s\n' "$out"
fi
