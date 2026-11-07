# Deploying WELDAP against your own directory

This is the end-to-end recipe: check that your LDAP directory fits, stand up the WELDAP server next to it, prove it
works before any Windows device is involved, then roll out the MSI and register devices. Every command here was run
against a 389 DS directory (the shape of `testdir/`) with the production container settings.

For what each device setting means see `docs/CONFIGURATION.md`; for the server's design and hardening see
`server/README.md`; for how the pieces fit together see `docs/ARCHITECTURE.md`.

```
 Windows devices  --mTLS, TCP 636-->  WELDAP server (Docker)  --LDAPS-->  your directory
 (MSI + device cert)                  (the only LDAP client)              (unchanged)
```

## 1. Check your directory fits

These are hard requirements of the current server code. Check them before anything else.

| Requirement | Detail |
| --- | --- |
| **LDAPS only** | TLS from the first byte (usually port 636). No StartTLS, no plain 389. The server verifies the directory's certificate against a CA file and a configured name. |
| **One DN pattern for every user** | e.g. `uid={0},ou=people,dc=example,dc=org` — `{0}` is the username. Users spread across several OUs are not supported. |
| **`uid` equals the username** | The server reads the user's entry with a base search on that DN filtered by `(uid=<username>)`. |
| **`memberOf` on the user entry** | It must list the *users* group and (for local admins) the *admins* group. Groups are matched by exact DN, ignoring case and spaces around `,` and `=`. Nested groups count only if your directory writes them into `memberOf`. |
| **Usernames: `^[a-z0-9]{1,20}$`** | Lowercase letters and digits, at most 20. People must type their username in lowercase at the tile; names such as `j.smith` or `jsmith-adm` are refused. |
| **Read access** | A user, once bound, can read their own `uid` and `memberOf`. A **read-only service account** can read `uid` and `memberOf` of all users (used for the hourly reconciliation). |
| **Simple bind over TLS** | Wrong password must return result 49; locked/disabled accounts return 19, 50 or 53 (reported as `denied`). |

Directory flavours:

| Directory | Fits? |
| --- | --- |
| 389 DS / Red Hat Directory Server | Yes, with the memberOf plugin enabled (and a fixup run for existing members). |
| FreeIPA | Should fit: DN pattern `uid={0},cn=users,cn=accounts,dc=…`, groups `cn=<group>,cn=groups,cn=accounts,dc=…`. |
| OpenLDAP | Yes, with the `memberof` overlay (direct memberships only). |
| Active Directory | **No, not as-is.** AD DNs are `CN=<display name>,…` and `uid` is normally empty; the server's lookup would need to bind by UPN and search by `sAMAccountName`. |

## 2. Collect these values

| Value | Example | Goes into |
| --- | --- | --- |
| Directory host and LDAPS port | `ldap.example.org`, `636` | `server.json` `directory.host` / `port` |
| Name on the directory's TLS certificate | `ldap.example.org` | `directory.server_name` |
| CA certificate (PEM) that issued the directory's certificate | `ldap-ca.pem` | `/etc/weldap/tls/directory-ca.crt` |
| User DN pattern | `uid={0},ou=people,dc=example,dc=org` | `directory.user_dn_template` |
| Users group DN (may sign in) | `cn=weldap-users,ou=groups,dc=example,dc=org` | `directory.users_group` |
| Admins group DN (local Administrators) | `cn=weldap-admins,ou=groups,dc=example,dc=org` | `directory.admins_group` |
| Read-only service account DN and password | `cn=weldap-server,ou=services,dc=example,dc=org` | `directory.service_dn`, `/etc/weldap/secrets/directory-service-password` |
| Name devices will use for the WELDAP server | `weldap.example.org` (or an IP) | MSI `SERVERHOST` |

Network and time:

- Devices must reach the WELDAP server on **TCP 636** (or the port you publish). Allow it from device networks only.
- The WELDAP server must reach the directory on its LDAPS port. Restrict the host's other egress where you can.
- Server and device clocks must agree within **120 s** (`max_clock_skew_seconds`): use NTP on both.

## 3. Build the images

On the server host, from a checkout of this repository (a Linux host with Docker and the Compose plugin):

```sh
docker build -t weldap-server server/ && docker build --target ca -t weldap-ca server/
```

Images are built for the machine that builds them. To build on an Apple Silicon Mac for an x86-64 server, use
`docker buildx build --platform linux/amd64 …` for both images, then
`docker save weldap-server weldap-ca | ssh <host> docker load`. Tagged releases also publish
`ghcr.io/rob-c/weldap-server` (`linux/amd64`; pull it by digest, see `docs/RELEASING.md`). The CA image is
always built locally.

## 4. Lay out `/etc/weldap`

The container runs as uid **10001**, so everything it reads must be readable by that uid.

```sh
sudo install -d -m 0755 /etc/weldap /etc/weldap/tls
sudo install -d -o 10001 -g 10001 -m 0700 /etc/weldap/secrets
```

**The server's TLS identity.** Self-signed is fine: devices trust the server by the pin of its key, nothing else.
It **must be an end-entity certificate (`CA:FALSE`)**: a plain `openssl req -x509` produces a CA certificate, which
TLS clients refuse as a server identity.

```sh
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
  -subj "/CN=weldap.example.org" -addext "subjectAltName=DNS:weldap.example.org" \
  -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=serverAuth" \
  -keyout /etc/weldap/tls/server.key -out /etc/weldap/tls/server.crt
sudo chown 10001:10001 /etc/weldap/tls/server.key && sudo chmod 0400 /etc/weldap/tls/server.key

# The pin: the MSI's SERVERPINS
openssl x509 -in /etc/weldap/tls/server.crt -noout -pubkey | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | openssl base64 -A
```

Keep this key. Renewing the certificate with the **same key** needs nothing on the devices; a **new key** needs its
pin added to `SERVERPINS` on every device before you switch.

**The directory's CA:**

```sh
sudo cp ldap-ca.pem /etc/weldap/tls/directory-ca.crt
```

**The password key** (HPKE, P-256). The private half never leaves the server; the public half goes to every device.

```sh
docker run --rm --network none -v /etc/weldap/secrets:/out weldap-server keygen --kid k1 --out /out/password-k1.key
# prints:  kid=k1 public=<base64>     -> the MSI's SERVERKEY (and SERVERKEYID=k1)
```

**The service account's password** (read from the terminal, so it stays out of shell history):

```sh
read -rs PW && printf '%s' "$PW" | sudo tee /etc/weldap/secrets/directory-service-password >/dev/null; unset PW
sudo chown 10001:10001 /etc/weldap/secrets/directory-service-password
sudo chmod 0400 /etc/weldap/secrets/directory-service-password
```

## 5. Write `server.json`

Start from `server/server.example.json` (`sudo cp server/server.example.json /etc/weldap/server.json`), keep only
the `k1` key, and fill in the `directory` block with the values from step 2:

```json
{
  "listen": "0.0.0.0:8636",
  "server_cert": "/etc/weldap/tls/server.crt",
  "server_key": "/etc/weldap/tls/server.key",
  "device_ca": "/etc/weldap/device-ca/device-ca.crt",
  "device_crl": "/etc/weldap/device-ca/device-ca.crl",
  "password_keys": [{ "kid": "k1", "private_key": "/etc/weldap/secrets/password-k1.key" }],
  "directory": {
    "host": "ldap.example.org", "port": 636, "server_name": "ldap.example.org",
    "ca": "/etc/weldap/tls/directory-ca.crt",
    "user_dn_template": "uid={0},ou=people,dc=example,dc=org",
    "users_group": "cn=weldap-users,ou=groups,dc=example,dc=org",
    "admins_group": "cn=weldap-admins,ou=groups,dc=example,dc=org",
    "service_dn": "cn=weldap-server,ou=services,dc=example,dc=org",
    "service_password_file": "/etc/weldap/secrets/directory-service-password",
    "timeout_seconds": 5
  },
  "max_connections": 64,
  "max_clock_skew_seconds": 120
}
```

The paths are as seen **inside** the container (the mounts in `server/compose.yaml`); leave them and `listen` as
they are. Unknown or misspelt fields are rejected at start-up.

## 6. Create the device CA and start the server

1. In `server/compose.yaml`, set `WELDAP_CA_NAME` on the `ca` service to your organisation, e.g.
   `"/O=Example University/CN=WELDAP Device CA"`.
2. If port 636 is already taken on this host (for example it is your LDAP server), change `"636:8636"` under
   `ports` to another host port and pass that port to the MSI as `SERVERPORT`.
3. Create the CA, then start the server:

```sh
docker compose -f server/compose.yaml run --rm -T ca init        # once: CA key + certificate + first CRL
docker compose -f server/compose.yaml up -d server
docker compose -f server/compose.yaml logs server                # expect {"event":"started"} then {"event":"listening"}
```

Always use the same `server/compose.yaml` (the same directory): Compose names the CA's volumes after it.

## 7. Smoke-test it before touching Windows

`weldap-probe` (in the test image) does exactly what a device does on the wire: mutual TLS with a device
certificate, the password sealed to the server's key. Register a throwaway "device" and sign in as a real user:

```sh
docker build --target test -t weldap-server:test server/   # the runtime image plus the probe; never deploy this one
mkdir -p server/requests smoke
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out smoke/dev.key
openssl req -new -key smoke/dev.key -subj /CN=smoke-test -out server/requests/smoke-test.csr
docker compose -f server/compose.yaml run --rm -T ca sign /requests/smoke-test.csr smoke-test > smoke/dev.crt
cp /etc/weldap/tls/server.crt smoke/
read -rs PW && printf '%s' "$PW" > smoke/pw; unset PW          # a real user's password

probe() { docker run --rm --network host -u "$(id -u):$(id -g)" -v "$PWD/smoke:/w:ro" \
  --entrypoint /usr/local/bin/weldap-probe weldap-server:test "$1" --server 127.0.0.1:636 \
  --name weldap.example.org --ca /w/server.crt --cert /w/dev.crt --key /w/dev.key "${@:2}"; }

probe auth --kid k1 --pub '<SERVERKEY>' --uun <username> --password-file /w/pw   # the sign-in path
probe status --uuns <user1>,<user2>                                             # the service-account path
```

`--name` is the name in the server certificate's SAN (the probe checks it; devices check only the pin).

| Probe result | Meaning |
| --- | --- |
| `"result":"ok","user":true` | Working. `"admin":true` too if the user is in the admins group. |
| `"result":"ok","user":false` | The password is right, but `users_group` is not in the user's `memberOf`: check the group DN and the memberOf plugin/overlay. |
| `"result":"invalid"` | Wrong password, or `user_dn_template` does not produce the user's real DN. |
| `"result":"denied"` | The directory refused the account (locked, disabled, password policy). |
| `"result":"unavailable"` | The server cannot reach the directory: network, port, or a TLS failure (`directory.ca` or `server_name` wrong). Devices treat this as offline. |
| `"result":"error"` | See the `reason` in `docker compose -f server/compose.yaml logs server`: `self_read` (bound, but cannot read its own entry: ACL, or `uid` ≠ username), `service_bind` (service account DN/password), `unseal` (wrong `--pub`), `stale_or_future` (clock skew). |
| `refused: …` (TLS) | Device certificate not from this CA, or revoked; or the server certificate is a CA certificate (see step 4). |

Then clean up: `docker compose -f server/compose.yaml run --rm -T ca revoke smoke-test` and `rm -rf smoke` (it
holds a password).

## 8. Roll out to devices

**Build the MSI** (see the README): `vm/build-in-vm.sh` → `out/msi/Weldap-{x64,arm64}.msi`. To brand the logon
tile, build with `WELDAP_TILE_IMAGE=<square png/jpg/bmp>` (`docs/CONFIGURATION.md` §3). For production, sign the
binaries and MSI (`docs/CONFIGURATION.md` §6).

**Install** (as administrator; the four server values are required). `Weldap-x64.msi` goes on x64 Windows,
`Weldap-arm64.msi` on ARM64 Windows (the x64 MSI refuses to install on ARM64):

```powershell
msiexec /i Weldap-x64.msi /qn /norestart /l*v C:\Windows\Temp\weldap-install.log `
  SERVERHOST=weldap.example.org `
  SERVERPINS=<pin from step 4> `
  SERVERKEY=<public key from step 4> `
  SERVERKEYID=k1 `
  EXCLUDEDACCOUNTS="administrator,<your local backup admins>"
# add SERVERPORT=<port> if you did not publish 636
```

`SERVERHOST` can be a DNS name or an IP; it is not checked against the certificate (the pin is the trust).
Exclude any local account the tile must never touch, and consider the `WELDAP-ForceLocal` group for break-glass
admins (`docs/CONFIGURATION.md` §4).

**Register each device** (the private key is created on the device and never leaves it; in the TPM when there is
one):

1. On the device, as SYSTEM or an administrator:
   `installer\fleet\register-device.ps1 -NewRequest` → prints the path of `<COMPUTERNAME>.csr`.
2. Copy the CSR to the server host as `server/requests/<device>.csr`, check it really came from a managed device,
   and sign it (the certificate's subject is forced to `CN=<device>`):
   `docker compose -f server/compose.yaml run --rm -T ca sign /requests/<device>.csr <device> > <device>.crt`
3. Copy `<device>.crt` back and run `installer\fleet\register-device.ps1 -Accept <device>.crt`. The service
   restarts and presents it.

Until a device is registered the server will not talk to it, and sign-in falls back to offline (which on a fresh
install means no WELDAP sign-in yet). Optionally apply the lockout policy with
`installer\fleet\set-lockout-policy.ps1`.

**Moving an existing device to a new server:** uninstall the MSI and install it again with the new values (an
uninstall deletes all of `HKLM\SOFTWARE\WELDAP`, offline verifiers and hand-set policies included, so each user
signs in online once), or change `ServerHost`/`ServerPort`/`ServerPins`/`ServerKey`/`ServerKeyId` under
`HKLM\SOFTWARE\WELDAP` and `Restart-Service Weldap`; then register it with the new device CA. A certificate from
another CA is refused.

## 9. Operate

| Task | How | When |
| --- | --- | --- |
| **Refresh the CRL** | `docker compose -f server/compose.yaml run --rm -T ca crl` (cron) | **At least weekly.** The CRL is valid 7 days; if it expires, every device loses online sign-in. |
| Renew device certificates | re-run step 8's registration (`-NewRequest` … `-Accept`) | Before 90 days (`WELDAP_DEVICE_DAYS`) |
| Cut a device off | `docker compose -f server/compose.yaml run --rm -T ca revoke <device>` | Lost/retired device; takes effect on its next connection |
| List devices | `docker compose -f server/compose.yaml run --rm -T ca list` | Any time |
| Upgrade devices | `msiexec /i Weldap-<arch>.msi /qn /norestart /l*v <log>`, no properties: settings, local passwords, offline verifiers and hand-set policies are kept (`docs/CONFIGURATION.md` §2) | Each new build; any rebuild upgrades in place |
| Back up | the `weldap-ca` volume (CA key + database) and `/etc/weldap/secrets` | After `init` and after each registration |
| Rotate the password key | add `k2` to `password_keys` (newest first), roll `SERVERKEY`/`SERVERKEYID` out, remove `k1` once unused | As policy requires (`server/README.md`) |
| Watch | `docker compose -f server/compose.yaml logs server`: one JSON line per event, with device and username, never a password | Ongoing |

Security notes:

- The WELDAP server holds each password for the length of one LDAP bind: protect its host like the directory.
- Publish its port to device networks only; keep the image patched.
- A registered device can ask which usernames are users or admins (rate-limited, logged by device name). Revoke
  devices you no longer manage.
