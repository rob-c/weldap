#!/usr/bin/env bash
# Test PKI. Creates:
#   pki/ca.crt                    test CA (the server uses it to verify 389 DS; clients never trust it)
#   pki/dirsrv.{crt,key}          389 DS LDAPS certificate for $LDAP_HOST (server-internal)
#   pki/weldap.{crt,key}          the WELDAP server's TLS certificate (clients pin its key: server-setup.sh)
# The device CA (client certificates for registered devices) is separate: see device-ca.sh.
# Existing certificates are kept; delete one to reissue it.
# Private keys go in pki/private/ (gitignored).
set -euo pipefail
cd "$(dirname "$0")"
LDAP_HOST="${LDAP_HOST:-ldap.example.test}"
WELDAP_HOST="${WELDAP_HOST:-weldap.example.test}"
mkdir -p pki/private
umask 077

[[ -f pki/private/ca.key ]] || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out pki/private/ca.key
[[ -f pki/ca.crt ]] || openssl req -x509 -new -key pki/private/ca.key -sha256 -days 825 \
    -subj "/CN=WELDAP Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out pki/ca.crt

issue() { # name cn
    local name="$1" cn="$2"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "pki/private/$name.key"
    openssl req -new -key "pki/private/$name.key" -subj "/CN=$cn" -out "pki/private/$name.csr"
    openssl x509 -req -in "pki/private/$name.csr" -CA pki/ca.crt -CAkey pki/private/ca.key \
        -CAcreateserial -days 397 -sha256 -out "pki/$name.crt" \
        -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n' "$cn")
    rm -f "pki/private/$name.csr"
}

[[ -f pki/dirsrv.crt ]] || issue dirsrv "$LDAP_HOST"
[[ -f pki/weldap.crt ]] || issue weldap "$WELDAP_HOST"

chmod 644 pki/*.crt
echo "PKI ready for $LDAP_HOST"
