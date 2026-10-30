# WELDAP server

The WELDAP server is the only thing WELDAP clients (Windows devices) ever talk to, and the only thing that talks
to the directory (389 DS). Everything LDAP-shaped lives here: DNs, groups, bind accounts, the directory's CA.
A client learns two flags per user, `user` and `admin`, and nothing else about the directory.

```
 client (Windows)                                    WELDAP server (this)                  directory
 ┌──────────────────────────────────┐   mTLS      ┌────────────────────────────┐  LDAPS   ┌──────────┐
 │ LogonUI: seals password (HPKE)   │ ──────────▶ │ weldap-server              │ ───────▶ │ 389 DS   │
 │ service: relays ciphertext,      │ device cert │  device CA + CRL check     │  bind as │          │
 │   trusts the server by key pin   │  required   │  opens password (mlocked)  │  the user│          │
 └──────────────────────────────────┘             │  binds, zeroes, answers    │          └──────────┘
                                                  └────────────────────────────┘
```

## What protects the password

| Where | Plaintext? | Why / how |
| --- | --- | --- |
| LogonUI (credential provider) | briefly | Windows collects it there. Sealed immediately (HPKE to the server's key), the field wiped, the UTF-8 copy in a `VirtualLock`ed page zeroed |
| named pipe, WELDAP service | never | the service relays ciphertext it cannot open |
| LSASS, SAM, disk | never | Windows logs on with the account's random local password; offline sign-in compares a PBKDF2 verifier |
| network | never | ciphertext inside mutual TLS; a TLS-terminating middlebox still sees only ciphertext |
| server | for one bind | decrypted into locked, non-dumpable memory, written straight into the LDAP bind request, zeroed before the reply is read |
| 389 DS / AD | yes | they check it: unavoidable with simple bind |
| logs, anywhere | never | the server has no debug mode; its only output is allow-listed JSON events; the secret type cannot be printed |

Tested, not assumed: `server/check.sh` (569 hermetic tests; every request path is checked for the password in the
audit output), `tests/server/run.sh` scrapes the running server's memory after logins (with a positive control),
`tests/acceptance/run.sh` scans the Windows service and LSASS and checks Windows rejects the user's password for
the local account.

## Hardening

- Image: AlmaLinux 9 micro with every executable deleted. Inside the container there is the server binary, glibc
  and configuration; no shell, coreutils, package manager or openssl for an intruder to use. The device CA tool
  is a separate image (`--target ca`) that never runs on the server's network.
- Process: `mlockall` (no swap), `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0` (no core dumps, no same-user ptrace),
  `no_new_privs`, `panic = abort`. Refuses to start if any of these fails.
- Container: read-only root, no capabilities at all (mlockall works through the memlock ulimit), unprivileged
  uid, `no-new-privileges`, memory/pid limits, secrets as read-only files.
- Network: one listening socket. TLS (rustls, no logging feature) 1.2/1.3 with forward-secret AEAD suites only;
  client certificates from the device CA only, revocation mandatory (unknown status refused, expired CRL = nobody
  in), CRL reloaded when the file changes; no session tickets or resumption.
- Connections: at most 8 at a time per source address; the TLS handshake must finish within 5 s and the request
  arrive within 10 s after it, so neither unauthenticated nor registered peers can hold the connection slots.
- Requests: one per connection, 16 KiB cap, strict JSON (unknown and duplicate fields rejected), UUN
  `^[a-z0-9]{1,20}$`, timestamp window, replay cache, 5 failures per user per 5 min, 30 requests per device per
  minute; `status` takes at most 100 UUNs and answers only for the UUNs asked.
- LDAP: minimal client in the server itself (simple bind, base search); the directory's certificate verified.
- Clients hold no directory credential: membership (FR-12) is read with the server's own read-only account.

## Running it

```sh
docker build -t weldap-server server/ && docker build --target ca -t weldap-ca server/
docker compose -f server/compose.yaml run --rm ca init                      # device CA, once
docker run --rm --network none -v /etc/weldap/secrets:/out weldap-server keygen --kid k1 --out /out/password-k1.key
#   -> prints the public key: the MSI's SERVERKEY (and SERVERKEYID=k1)
openssl x509 -in /etc/weldap/tls/server.crt -noout -pubkey | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -binary | openssl base64 -A                     # the MSI's SERVERPINS
docker compose -f server/compose.yaml up -d server
```

Clients trust the server by the pin of its TLS key, not by a CA: renewing the certificate with the same key needs
nothing on the clients; a new key needs its pin added to `SERVERPINS` (a list) before the switch.

Rotation of the password key: add `k2` to `password_keys` (newest first), roll the MSI property out, remove `k1`
once no device uses it. Rotation of the device CA: publish both CA certificates in `device-ca.crt` and both CRLs in
`device-ca.crl` during the overlap, and give the new CA a different name (`WELDAP_CA_NAME`): a CRL is matched to
its CA by name, so two CAs with the same name lock out the devices of one of them.

## Registering and cutting off devices

1. Device (SYSTEM): `installer/fleet/register-device.ps1 -NewRequest` → CSR; key in the TPM when there is one,
   never exportable.
2. Admin: check the request came from a managed device (Fleet's identity), then
   `docker compose run --rm ca sign /requests/<device>.csr <device>` (subject forced to `CN=<device>`, 90 days).
3. Device: `register-device.ps1 -Accept <cert>` (names it `WELDAP device`, which is what the service presents).
   The device does not trust the device CA (it cannot be abused to impersonate servers to it).

Cut off: `docker compose run --rm ca revoke <device>`; the server picks up the new CRL on the next connection.
Run `ca crl` at least weekly (the CRL lives 7 days; an expired CRL locks every device out of online sign-in).

## Known limits

- The server sees the password for the length of one bind: protect its host like the directory.
- Unauthenticated peers still reach the TLS handshake (rustls); keep the image patched.
- A registered device can ask `status` about any UUN (100 at a time, 30 requests a minute) and so learn who is a
  user or admin; it learns nothing else, and every request is logged with the device's name.
- The server container has outbound network (Docker needs a non-internal network to publish a port); restrict
  egress on the host to the directory where the platform allows.
- A stolen, powered-off laptop allows offline guessing against the PBKDF2 verifier: BitLocker, short
  `MaxOfflineDays`, and `OfflineMaxFailures` (10, then online sign-in required) limit it.
- 389 DS sees the server's address, not the device's: correlate with the server's `auth` events (device, uun).
