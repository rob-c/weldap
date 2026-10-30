#!/usr/bin/env bash
# Test server material in .data/server/ (all gitignored):
#   password-k1.key   HPKE private key (only the server reads it)    password-k1.pub  public key for clients
#   directory-service-password   the server's own read-only bind (cn=winlogin)
#   server.json       config, paths as seen inside the container
#   pin               SHA-256 of the server certificate's public key (base64): what clients trust
set -euo pipefail
cd "$(dirname "$0")"
umask 077
D=.data/server
mkdir -p "$D"
if [[ ! -f "$D/password-k1.key" ]]; then
    docker run --rm --network none -u "$(id -u):$(id -g)" -v "$PWD/$D:/out" weldap-server:latest \
        keygen --kid k1 --out /out/password-k1.key | sed -n 's/.*public=//p' >"$D/password-k1.pub"
fi
awk '$1 == "winlogin" { print $2 }' .data/passwords >"$D/directory-service-password"
openssl x509 -in pki/weldap.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary \
    | openssl base64 -A >"$D/pin"
S='dc=example,dc=org'
cat >"$D/server.json" <<JSON
{
  "listen": "0.0.0.0:8636",
  "server_cert": "/etc/weldap/tls/server.crt",
  "server_key": "/etc/weldap/tls/server.key",
  "device_ca": "/etc/weldap/device-ca/device-ca.crt",
  "device_crl": "/etc/weldap/device-ca/device-ca.crl",
  "password_keys": [{ "kid": "k1", "private_key": "/etc/weldap/secrets/password-k1.key" }],
  "directory": {
    "host": "ldap.example.test", "port": 3636, "server_name": "ldap.example.test", "ca": "/etc/weldap/tls/directory-ca.crt",
    "user_dn_template": "uid={0},ou=people,$S",
    "users_group": "cn=win-users,ou=groups,$S",
    "admins_group": "cn=win-admins,ou=groups,$S",
    "service_dn": "cn=winlogin,ou=services,$S",
    "service_password_file": "/etc/weldap/secrets/directory-service-password"
  }
}
JSON
echo "server ready: kid=k1 public=$(cat "$D/password-k1.pub") pin=$(cat "$D/pin")"
