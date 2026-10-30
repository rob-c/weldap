#!/usr/bin/env bash
# Start (and on first run, build) the local test environment: 389 DS (internal network only) + WELDAP server.
#   ./up.sh            start (WELDAP server on 127.0.0.1:16637; the VMs reach it as 10.0.2.2:16637)
#   ./up.sh reset      destroy the directory data and rebuild from seed.ldif
# Test user passwords are in .data/passwords (gitignored).
set -euo pipefail
cd "$(dirname "$0")"
SUFFIX="dc=example,dc=org"
mkdir -p .data
umask 077
randpw() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }

if [[ "${1:-}" == reset ]]; then
    docker compose down -v 2>/dev/null || true
    rm -f .data/passwords .data/dm_password .data/seeded
fi

[[ -f pki/ca.crt && -f pki/weldap.crt && -f pki/dirsrv.crt ]] || ./make-pki.sh
[[ -f pki/device-ca-pub/device-ca.crl ]] || ./device-ca.sh init   # the server needs the device CA and its CRL
export WELDAP_UID WELDAP_GID; WELDAP_UID="$(id -u)"; WELDAP_GID="$(id -g)"   # bind-mounted secrets are ours
[[ -s .data/dm_password ]] || randpw 24 >.data/dm_password
export DS_DM_PASSWORD; DS_DM_PASSWORD="$(cat .data/dm_password)"

docker compose up -d dirsrv

wait_ready() {
    for _ in $(seq 1 60); do
        docker exec weldap-test-dirsrv dsconf localhost backend suffix list >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "dirsrv did not start" >&2; exit 1
}
wait_ready

dsconf() { docker exec weldap-test-dirsrv dsconf localhost "$@"; }

if [[ ! -f .data/seeded ]]; then
    # TLS from our test PKI (the container imports /data/tls/* at start).
    docker exec weldap-test-dirsrv mkdir -p /data/tls/ca
    docker cp pki/dirsrv.crt weldap-test-dirsrv:/data/tls/server.crt
    docker cp pki/private/dirsrv.key weldap-test-dirsrv:/data/tls/server.key
    docker cp pki/ca.crt weldap-test-dirsrv:/data/tls/ca/ca.crt
    docker exec -u 0 weldap-test-dirsrv chown -R dirsrv:dirsrv /data/tls

    dsconf backend create --suffix "$SUFFIX" --be-name userroot 2>/dev/null || true
    dsconf plugin memberof enable
    dsconf plugin memberof set --scope "$SUFFIX"
    # LDAPS only, TLS 1.2+: SR-1 is enforced client-side too, but test against a server shaped like prod.
    dsconf security set --tls-protocol-min TLS1.2
    dsconf config replace nsslapd-require-secure-binds=on
    docker restart weldap-test-dirsrv >/dev/null
    wait_ready

    docker cp seed.ldif weldap-test-dirsrv:/tmp/seed.ldif
    docker exec weldap-test-dirsrv ldapadd -H ldapi://%2fdata%2frun%2fslapd-localhost.socket -Y EXTERNAL -f /tmp/seed.ldif >/dev/null
    : >.data/passwords
    for who in alice bob carol dave administrator; do
        pw="$(randpw 16)"
        docker exec weldap-test-dirsrv ldappasswd -H ldapi://%2fdata%2frun%2fslapd-localhost.socket -Y EXTERNAL \
            -s "$pw" "uid=$who,ou=people,$SUFFIX" >/dev/null 2>&1
        echo "$who $pw" >>.data/passwords
    done
    pw="$(randpw 24)"
    docker exec weldap-test-dirsrv ldappasswd -H ldapi://%2fdata%2frun%2fslapd-localhost.socket -Y EXTERNAL \
        -s "$pw" "cn=winlogin,ou=services,$SUFFIX" >/dev/null 2>&1
    echo "winlogin $pw" >>.data/passwords
    touch .data/seeded
fi

./server-setup.sh
docker compose up -d server
echo "WELDAP server on 127.0.0.1:16637 (VMs: 10.0.2.2:16637, trusted by key pin only)"
echo "test passwords: $(pwd)/.data/passwords"
