# WELDAP — Requirements

WELDAP (Windows Enterprise LDAP) builds implicit trust in an LDAP directory into a Windows device: a
pGina-style logon that checks the user's password against the directory and creates or maintains a matching
local account, without Windows ever learning the directory password.

There are exactly two parties on the network:

- **client** — the Windows side: a native credential provider (in LogonUI) and a SYSTEM service, talking over a
  local named pipe. The client seals the password inside LogonUI and sends it to the server; it knows nothing
  about LDAP, DNs or groups, and learns only two flags per user.
- **server** — a small Rust service in a container. It is the only thing clients reach and the only LDAP client
  of the directory (389 Directory Server, or any LDAP server that accepts simple binds over LDAPS).

This document is the authoritative requirements list. The wire formats are in
`client/Weldap.Shared/PROTOCOL.md`; the operational detail is in `server/README.md` and the top-level
`README.md`. Requirement IDs (FR-\*, SR-\*) are referenced directly from code comments.

## Scope

**Must do**

- Offer a WELDAP sign-in tile on the logon and unlock screens of Windows 10 22H2 and Windows 11 23H2+
  (Pro/Enterprise/Education), on x64 and ARM64.
- Authenticate a typed username (UUN) and password against the directory, and authorise by group membership.
- Create and maintain a local account matching an authorised user; keep it in step with the directory.
- Allow sign-in while the server/directory is unreachable, from a previously verified password.
- Install, upgrade and remove silently by MSI.

**Must not do**

- Let Windows, its logs, LSASS, the SAM, disk, the registry or the network ever hold the user's directory
  password in a recoverable form.
- Touch any local account that WELDAP did not create (nothing outside the `WELDAP-Managed` group).
- Put directory credentials, DNs, group names or LDAP code on the device.
- Open any listening network port on the device, or expose anything to the network beyond the server's one TLS
  port.
- Delete user profiles automatically.

## Login flow

**Online.** The credential provider collects the UUN and password, seals the password (HPKE) to the server's
key and computes an offline verifier, and sends both to the service over the pipe (never the password itself).
The service relays the sealed password to the server over mutual TLS. The server opens it in locked memory,
binds to the directory as the user (LDAPS simple bind), reads the user's own membership, and answers with two
flags (`user`, `admin`). A successful bind is proof the password is correct. The service then creates or
updates the local account and hands the credential provider the account's random local password, which Windows
logs on with. A definite "no" (bad password, not a member, excluded, an unexpected directory result, a service
error) denies the sign-in with a short message. The server's answer always wins when there is one.

**Offline.** When there is *no answer* (server unreachable, TLS refused because the device is unregistered or
revoked, connect timeout, or the server cannot reach the directory), the service compares the offline verifier
the credential provider computed against the one stored at the last successful online sign-in, in constant
time, and on a match returns the local password. Offline sign-in is allowed only for a managed, enabled account
before its expiry date, and stops after `OfflineMaxFailures` consecutive wrong offline attempts until the next
online sign-in. Excluded and non-managed names are refused offline too.

## Functional requirements

| ID | Requirement |
| --- | --- |
| FR-1 | Provide a WELDAP tile on the logon and unlock screens of Windows 10 22H2 and Windows 11 23H2+ (Pro/Enterprise/Education), x64 and ARM64. |
| FR-2 | Authenticate by relaying the sealed password to the server, which performs an LDAPS simple bind as the user; a successful bind is proof the password is correct. |
| FR-3 | Authorise by the user's own `memberOf`: membership of the users group is required to sign in; the admins group grants local Administrators. |
| FR-4 | Create a local account named exactly the UUN when it does not exist; add it to `WELDAP-Managed` and `Users`. |
| FR-5 | On every successful authentication: enable the account, set its expiry to today + `MaxOfflineDays`, store the offline verifier, and keep its random local password (generated once; never expires, user cannot change). The local password is never the user's password. |
| FR-6 | Add the account to Administrators when in the admins group; remove it when not. Never change Administrators for accounts outside `WELDAP-Managed`. |
| FR-7 | Refuse the sign-in if the UUN matches an existing local account not in `WELDAP-Managed` (no takeover of existing accounts). |
| FR-8 | Refuse sign-ins for excluded names (Administrator, Guest, DefaultAccount, WDAGUtilityAccount, the break-glass account, and anything in `ExcludedAccounts`). |
| FR-9 | Fail closed online: an invalid result, not-authorised, an unexpected directory result or a service crash = deny with a short tile message. No answer at all (unreachable, TLS failure, connect timeout) = the offline path (FR-15), never an online allow. |
| FR-10 | Leave the stock Windows password tile available for excluded and break-glass accounts. |
| FR-11 | Disable the "change password" scenario for the WELDAP tile. |
| FR-12 | Every hour and at service start, reconcile managed accounts with the server: ask only about the accounts this device manages; the server answers two flags per UUN. Disable accounts no longer users; match Administrators to the admin flag. A failed or partial read changes nothing. Never delete profiles. |
| FR-13 | Write a Windows Application-log event for every allow, deny and account change: UUN, result, reason. Never the password. |
| FR-14 | Be installable, upgradable and removable silently by MSI; removal leaves local accounts and profiles in place. |
| FR-15 | Offline sign-in (see Login flow): verifier comparison for a managed, enabled, unexpired account, subject to `OfflineMaxFailures`; excluded and non-managed names still refused. |
| FR-16 | Build and ship x64 and ARM64: the credential provider DLL natively for each (LogonUI loads only native DLLs), the service per runtime, one MSI per architecture. |

## Device trust

Every online connection is mutually authenticated TLS to one WELDAP server in front of the directory. The
client never speaks LDAP; it sends the sealed password and asks two questions. The client trusts the server by
the pinned SHA-256 of the server's TLS public key alone (no CA, no name check), so no certificate authority can
stand in for it. The server admits only client certificates from the WELDAP device CA that are not on its CRL.
Device keys are generated on the device, non-exportable, in the TPM where available.

Every online sign-in therefore needs two independent proofs: the device's key (the TLS handshake at the server)
and the user's password (the simple bind at the directory). Neither alone grants an online sign-in. Cutting a
device off is a certificate revocation; blocking the server only forces the offline path, which grants nothing
the offline path does not already allow.

## Password handling

The password is handled on the assumption that every component except the server may be inspected by an
attacker: memory, logs, the pipe, disk, the network.

| Where | Plaintext? | How |
| --- | --- | --- |
| LogonUI (credential provider) | briefly | Windows collects it; sealed at once with HPKE (RFC 9180: DHKEM P-256, HKDF-SHA256, AES-256-GCM) to the server's key, AAD binding key id, user, scenario, timestamp and request id. The field is wiped; the UTF-8 copy sits in a locked page and is zeroed. |
| named pipe, service | never | the service relays ciphertext it cannot open. |
| LSASS, SAM, disk | never | Windows logs on with the account's random local password; offline sign-in compares a PBKDF2 verifier. |
| network | never | ciphertext inside mutual TLS. |
| server | for one bind | opened into locked, non-dumpable memory, written into the LDAP bind request, zeroed before the reply is read. |
| directory | yes | it checks the password: unavoidable with simple bind. |
| logs, anywhere | never | the server has no debug mode; its only output is allow-listed events; the secret type cannot be printed. |

## Security requirements

| ID | Requirement |
| --- | --- |
| SR-1 | LDAPS only (the server→directory hop): no plain LDAP, no StartTLS fallback, TLS 1.2+. |
| SR-2 | The client trusts the server by a pinned SHA-256 of its TLS public key (`ServerPins`), not by a CA or hostname; any mismatch = no answer (offline). The server verifies the directory's certificate against its configured CA. |
| SR-3 | Validate the UUN with `^[a-z0-9]{1,20}$` before it is used anywhere. Reject empty passwords (an empty-password bind is an anonymous bind). |
| SR-4 | The credential provider contains no network, LDAP or account code: only UI, the pipe client, the logon serialization, and the sealing of the password (CNG only). |
| SR-5 | The pipe accepts local SYSTEM clients only (remote rejected, NETWORK denied), one request per connection, size-limited, in a strict fixed binary schema; anything malformed is dropped with no reply. The credential provider checks the pipe server is SYSTEM before sending; the service owns the pipe name for its whole lifetime (one instance). |
| SR-6 | Passwords and verifiers live only in memory for one request; buffers are zeroed after use (`SecureZeroMemory` in C++, pinned/cleared `byte[]`/`char[]` in C#). No password in logs, events, crash dumps or the registry. |
| SR-7 | Only accounts in `WELDAP-Managed` are ever created, changed, enabled or disabled. |
| SR-8 | Rate limit: after 5 failed sign-ins for one UUN within 5 minutes, deny that UUN locally for 5 minutes without contacting the server (protects the directory account from lockout). The server enforces the same independently. |
| SR-9 | Per-account secrets on the device (local password, offline verifier) are machine-scope DPAPI blobs in `HKLM\SOFTWARE\WELDAP\Secret`, a key with a protected DACL for SYSTEM only; the service refuses to start if anyone else can read it. The device holds no directory credential. |
| SR-10 | DLL and service binaries ship with no debug symbols; the service verifies the registered credential-provider DLL against a build-time pinned hash and checks its config key is writable only by SYSTEM/Administrators, refusing to run otherwise. |
| SR-11 | Build with compiler/linker hardening (Control Flow Guard, CET shadow stack on x64, high-entropy ASLR, DEP, `/GS`, `/sdl`, static CRT; `/analyze` clean) and no third-party runtime dependency beyond the self-contained .NET runtime. |
| SR-12 | A crash in the credential provider must never block the stock password tile (it stays registered; tested with the provider DLL deliberately failing). |
| SR-13 | Offline password guessing is limited by the Windows account-lockout policy and `OfflineMaxFailures`, and every offline sign-in is logged (FR-13). |
| SR-14 | Device trust: every online connection presents the device's registered certificate (newest valid `LocalMachine\My` certificate named "WELDAP device", with its private key). The server accepts only non-revoked certificates from the WELDAP device CA. Device keys are non-exportable, TPM-backed where available. |
| SR-15 | The server is the only LDAP client of the directory. It reads membership with its own read-only account, whose password exists only on the server host. No secret is shared between devices; no device holds a directory credential. |
| SR-16 | Device certificates live at most 90 days. The device CA's CRL is published at least weekly and the server reloads it; a revocation takes effect at the device's next connection (an expired CRL fails closed). |
| SR-17 | The device CA issues only device certificates, never server certificates; the server trusts no other CA for clients, and devices never trust the device CA. |
| SR-18 | The password is sealed in the credential provider (HPKE to the server's key, AAD binding key id, user, scenario, timestamp and request id) before it leaves LogonUI. Only the server can open it; the server refuses requests more than 120 s off its clock and request ids it has already seen. |
| SR-19 | The password is never logged, at any level or debug setting. The server has no debug mode; its only output is allow-listed events; its secret type has no printable form. |
| SR-20 | Plaintext exists only in LogonUI (until sealed) and in the server (for one bind), in locked memory (VirtualLock / mlockall), zeroed after use. The server is not dumpable, has core dumps disabled, and refuses to start if memory cannot be locked. |
| SR-21 | Windows never receives the user's password: managed accounts have a random local password only the service knows, used for the logon serialization. Offline sign-in compares a PBKDF2-HMAC-SHA256 verifier (600 000 iterations, per-machine-and-user salt) in constant time. |
| SR-22 | The server runs as an unprivileged user in a read-only container with no capabilities, no new privileges, an image with no shell or other executables, and secrets as read-only files. The device CA key is never in the serving container. |

## Configuration

All device settings live under `HKLM\SOFTWARE\WELDAP`, writable only by SYSTEM and Administrators, written by the
MSI.

| Value | Type | Meaning |
| --- | --- | --- |
| `ServerHost` | string | address of the WELDAP server |
| `ServerPort` | DWORD | server port (default 636) |
| `ServerPins` | multi-string | base64 SHA-256 of the server's TLS public key — the only server trust (required) |
| `ServerKey` | string | base64 P-256 public key the credential provider seals to |
| `ServerKeyId` | string | key id naming `ServerKey` (e.g. `k1`) |
| `ExcludedAccounts` | multi-string | extra names the tile refuses (besides the built-ins and break-glass) |
| `MaxOfflineDays` | DWORD | account expiry set at each online sign-in (default 180; 0 disables offline sign-in) |
| `OfflineMaxFailures` | DWORD | consecutive wrong offline attempts before offline sign-in stops (default 10) |
| `TileLabel` | string | the tile's label (default "WELDAP sign-in") |
| `ProviderHash` | string | SHA-256 the MSI pins for the credential-provider DLL (anti-tamper; SR-10) |

The managed group (`WELDAP-Managed`), the connect/request timeouts and the reconcile interval are fixed in code,
not configurable. The device certificate is the newest valid `LocalMachine\My` certificate named "WELDAP
device", installed by `installer/fleet/register-device.ps1`.

## Server side

The server is an AlmaLinux 9 micro container (`server/`) with every executable removed — no shell, coreutils,
package manager or openssl — running as an unprivileged user with no Linux capabilities. It reads its HPKE
password key(s), its device CA + CRL, its TLS certificate/key, and a read-only directory service account from
files, and exposes one TLS port. The device CA is a separate, offline tool (`weldap-ca`, its own image) that
never runs on the serving host's network. Operational detail is in `server/README.md`.

## Development and test

Develop on a Mac or Linux host; test the Windows parts in disposable VMs (see `README.md`). The gates:

- `tests/quality.sh` — paranoia lint, code-size budget, shellcheck, the client and server gates, and the
  credential provider's import allow-list.
- `client/check.sh` — C# build with warnings as errors, format, tests; `Weldap.Core` at 100% lines and branches.
- `server/check.sh` — Rust `unsafe` confinement, rustfmt, clippy at pedantic with warnings as errors, tests, and
  100% lines and regions (in Docker).
- `tests/server/run.sh` — the server in Docker: device trust, sealed auth, replay, throttling, revocation,
  network surface, TLS, process hardening, hostile-network resilience, and no secret in logs or memory.
- `tests/acceptance/run.sh <vm>` — end to end on a real Windows VM: sealed sign-in, offline, cleanup, device
  trust, pin trust, anti-tamper, pipe fuzzing, the client's network surface, and memory scans of the service and
  LSASS.
- `tests/cp-harness` — the credential provider's own sealing and pipe code, built and self-tested in the VM.

## Acceptance

A build is acceptable when all gates pass, and on real Windows (x64 and ARM64):

- An authorised user signs in through the tile; the local account is created/updated; Windows does **not** accept
  the user's directory password for the local account (it has a different, random one).
- A non-member is denied; an excluded or non-managed name is refused; the stock tile still rejects the directory
  password.
- With the server or directory unreachable, a previously verified user signs in offline; offline lockout and
  expiry hold.
- Removing a user from the directory disables the account at the next reconcile; re-adding re-enables it.
- A revoked or unregistered device gets no online answer (falls to offline); a tampered or repointed credential
  provider makes the service refuse to start.
- The user's directory password appears nowhere: not in the registry, not in the service's memory, and not in
  LSASS (on systems where LSASS is readable).

## Out of scope / known limits

- RDP and Remote Assistance are out of scope; the tile targets interactive console logon and unlock.
- The server sees the password for the duration of one bind: its host is protected like the directory.
- A stolen, powered-off device allows offline guessing against the PBKDF2 verifier; BitLocker, a short
  `MaxOfflineDays` and `OfflineMaxFailures` limit it.
- A registered device can ask the server whether any username is a user or admin (rate-limited, logged); it
  learns nothing else.
