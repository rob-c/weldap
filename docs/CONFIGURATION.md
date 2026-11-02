# WELDAP configuration and operation

This is the operator's guide: how to install WELDAP on a device, every setting it reads and what each one does,
how the local-account model behaves, the `weldapadm` management tool, and the code-signing / anti-tamper setup.

If you want *how the code fits together* or *the exact bytes on the wire*, read `docs/ARCHITECTURE.md` and
`client/Weldap.Shared/PROTOCOL.md` instead; for the authoritative requirements, `docs/REQUIREMENTS.md`. This
document assumes you have an MSI (`vm/build-in-vm.sh` → `out/msi/Weldap-{x64,arm64}.msi`) and a running WELDAP
server with a device CA.

## 1. How it works, in one page

WELDAP signs a user into Windows with their **directory** password, without that password ever living on the
device. A user types their university username (UUN) and password into the WELDAP tile; the credential provider
**seals** the password (HPKE) inside LogonUI and hands the sealed blob to the SYSTEM service over a local pipe;
the service forwards it, over mutual TLS, to the one WELDAP server, which opens it in locked memory, binds to
the directory as that user, and replies with just two booleans — `user` (may sign in) and `admin` (is a local
administrator). The device never learns anything else about the directory, and Windows logs the user on with a
**random local password** it generates, never the directory one.

Three consequences shape everything an operator does:

- **The device is configured, not joined.** All device-side policy lives in one registry key,
  `HKLM\SOFTWARE\WELDAP`, locked to SYSTEM + Administrators. There is no domain, no GPO, no LDAP config on the
  device — just the server's address, how to recognise it, and a few local-account policies.
- **Each directory user gets a local account.** On first successful online sign-in the service creates a local
  account named after the UUN, puts it in the `WELDAP-Managed` group, and gives it that random password. From
  then on the account is "managed": WELDAP owns its enabled/disabled state, its admin membership, and its
  offline verifier.
- **It keeps working offline.** The last successful online sign-in leaves behind a one-way *offline verifier*
  (PBKDF2, machine- and user-bound) so the user can still log on when the server is unreachable, up to a
  configurable age.

## 2. Installing

The MSI is **deployment-neutral**: it ships the binaries and creates the config key, but the server's address
and keys come from the `msiexec` command line (put a site's real values in a wrapper script —
`installer/fleet/` is the place for them). A minimal install:

```powershell
msiexec /i Weldap-x64.msi /qn `
  SERVERHOST=weldap.example.org `
  SERVERPINS=<base64 SHA-256 of the server's TLS SubjectPublicKeyInfo> `
  SERVERKEY=<base64 HPKE P-256 public key> `
  SERVERKEYID=k1 `
  EXCLUDEDACCOUNTS="administrator,breakglass"
```

`SERVERHOST`, `SERVERPINS`, `SERVERKEY` and `SERVERKEYID` are **required** — the installer refuses without them.
Everything else has a default (see the table below). Uninstall removes the binaries, the service, the provider
registration and the config key; it deliberately leaves local accounts, the `WELDAP-Managed` group and user
profiles in place.

After install, the device still needs its **own identity**: a per-device client certificate. Run, on the device:

```powershell
installer/fleet/register-device.ps1        # generates a device key + CSR, you accept it at the device CA
installer/fleet/set-lockout-policy.ps1      # optional: account-lockout policy
```

The newest currently-valid certificate named `"WELDAP device"` in `LocalMachine\My`, with its private key, is
the one the service presents. Until a certificate is registered the server will not trust the device and
sign-in falls back to offline (which, on a fresh install with no verifier yet, means no WELDAP sign-in — expected
until registration completes).

## 3. Every setting: `HKLM\SOFTWARE\WELDAP`

All device policy is here. The key is created by the MSI with an ACL of **owner Administrators; full control
SYSTEM + Administrators; read-only for Users** (SR-10) — the service *refuses to start* if anyone else can write
it. Per-account secrets live in the `Secret` subkey, readable by SYSTEM only.

| Value | Type | Default | MSI property | Meaning |
| --- | --- | --- | --- | --- |
| `ServerHost` | REG_SZ | — (required) | `SERVERHOST` | The WELDAP server's address; also sent as the TLS server name. |
| `ServerPort` | REG_DWORD | `636` | `SERVERPORT` | TCP port of the WELDAP server. |
| `ServerPins` | REG_MULTI_SZ | — (required) | `SERVERPINS` | Base64 SHA-256 of the server certificate's SubjectPublicKeyInfo. **This is the only server trust** — no CA, no hostname check. List several to rotate keys. |
| `ServerKey` | REG_SZ | — (required) | `SERVERKEY` | The server's **public** HPKE password key (P-256), base64. |
| `ServerKeyId` | REG_SZ | — (required) | `SERVERKEYID` | Identifier of that key (e.g. `k1`); lets the server roll its key pair. |
| `ExcludedAccounts` | REG_MULTI_SZ | `administrator` | `EXCLUDEDACCOUNTS` | Names the WELDAP tile always refuses and reconciliation never touches, on top of the built-ins. |
| `MaxOfflineDays` | REG_DWORD | `180` | `MAXOFFLINEDAYS` | How long an offline verifier stays usable after the last online sign-in. `0`–`3650`. |
| `OfflineMaxFailures` | REG_DWORD | `10` | `OFFLINEMAXFAILURES` | Consecutive wrong offline passwords before offline sign-in locks until the next online one. `1`–`100`. |
| `TileLabel` | REG_SZ | `WELDAP sign-in` | `TILELABEL` | The text under the WELDAP tile. |
| `AdoptPreexisting` | REG_DWORD | `1` (on) | — | Allow taking over a pre-existing local account that shares a directory user's name, after the user consents. See §4. |
| `LockdownEnforce` | REG_DWORD | `0` (off) | — | Arm the lockdown: actually disable local accounts unknown to the directory. Off = **dry run** (reported only). See §4. |
| `IdleDisableDays` | REG_DWORD | `30` | — | Disable a managed account with no interactive logon for this many days. `0` = never. `0`–`3650`. |
| `ProviderHash` / `ServiceHash` / `AdminHash` | REG_SZ | set by MSI | — | Anti-tamper pins; see §6. Do not edit by hand. |

**Built-in exclusions** are always refused regardless of `ExcludedAccounts`: `administrator`, `guest`,
`defaultaccount`, `wdagutilityaccount`.

**Changing a setting after install.** The three `*Hash` values and the server identity come from the MSI; the
local-account policies (`AdoptPreexisting`, `LockdownEnforce`, `IdleDisableDays`) are plain DWORDs you can set
with an elevated `reg.exe` (or, for lockdown, `weldapadm lockdown arm|disarm`):

```powershell
reg add HKLM\SOFTWARE\WELDAP /v IdleDisableDays /t REG_DWORD /d 45 /f
```

The service reads its settings **once at startup**, so restart it for any change to take effect:

```powershell
Restart-Service Weldap
```

A value that fails validation (bad port, a pin that is not a base64 SHA-256, a malformed host) makes the service
refuse to start — fail-closed, by design.

## 4. The local-account model

Every local account on the device falls into exactly one class, and WELDAP treats each differently. `weldapadm
list` shows the class of every account.

| Class | What it is | WELDAP's behaviour |
| --- | --- | --- |
| **managed** | In `WELDAP-Managed`; holds a random local password the user never learns. Created on first online sign-in, or by adopting a pre-existing account. | Fully owned: enabled/disabled, admin membership and the offline verifier all follow the directory. Idle-disabled after `IdleDisableDays`. |
| **force-local** | In `WELDAP-ForceLocal`. Your **trusted backup** accounts — a break-glass admin and the built-in Administrator belong here. | Never adopted, never disabled, never idle-reaped, never touched by lockdown. Always works locally. |
| **excluded** | Name is in `ExcludedAccounts` or the built-in list. | The tile refuses it; reconciliation ignores it. |
| **unclassified** | Any other local account (not managed, not force-local, not excluded). | Left alone normally; a **lockdown** candidate (see below). |

### Adoption (`AdoptPreexisting`)
If a directory user signs in and a local account already exists with that name but is **not** managed, WELDAP
offers to *adopt* it rather than silently taking it over. The user sees a "continue, or log out" consent
prompt; on continue, and only after the directory confirms the password, the account is moved into
`WELDAP-Managed`, its local password reset to a fresh random one (its old password stops working), and admin
membership synced. Set `AdoptPreexisting=0` to refuse pre-existing accounts outright instead.

A **force-local** account is never adopted — it is refused at the tile so the backup account's known password
keeps working.

### Idle disable (`IdleDisableDays`)
A managed account with no interactive logon for `IdleDisableDays` days is disabled and its offline verifier
cleared. This is reversible: the user's next *online* sign-in re-enables it. This is distinct from
`MaxOfflineDays` (how long the offline verifier itself is accepted). Set `IdleDisableDays=0` to never idle-reap.

### Lockdown (`LockdownEnforce`)
Lockdown is how you converge a device onto "only directory-known accounts, plus the backups." During hourly
reconciliation WELDAP asks the server about each candidate:

- **Dry run** (`LockdownEnforce=0`, the default): every unclassified account that the directory does **not**
  know is written to the event log as a `WouldDisable` — so you can see what *would* happen without changing
  anything.
- **Armed** (`LockdownEnforce=1`): those same accounts are actually disabled.

Force-local and excluded accounts are exempt in both modes. **Roll it out dry-run first, read the events, seed
your backups into `WELDAP-ForceLocal`, then arm it.**

### The last-admin guard
WELDAP will never disable the last remaining enabled local administrator, whatever the policy says — idle,
lockdown or a removed directory user. The attempt is logged (`DisableSkipped`) and the account stays enabled.
This is the safety net behind "there is always a backup admin that works", but you should still keep a real
force-local break-glass admin rather than relying on it.

### Offline sign-in
When the server is unreachable the service verifies the typed password against the offline verifier saved at the
last online sign-in (PBKDF2-HMAC-SHA256, 600 000 iterations, salted with the machine GUID and the UUN). It is
accepted for up to `MaxOfflineDays` and locks after `OfflineMaxFailures` wrong tries until the next online
sign-in. The plaintext password is never stored — only this one-way verifier.

## 5. `weldapadm` — the local account manager

`weldapadm.exe` ships beside the service (in `C:\Program Files\WELDAP`) and is the supported way to inspect and
repair the local-account state. It talks to the local accounts directly, **never over the service's pipe or the
network**, so it adds no attack surface — and it must run **elevated** (local administrator). Every mutating
verb is one the service itself performs, so its effects match the login/reconcile paths exactly.

```
weldapadm list                      all local accounts and how WELDAP classifies them
weldapadm show <name>               details for one account (class, enabled, admin, managed, force-local, expiry, last logon)
weldapadm adopt <name>              bring a pre-existing account under WELDAP management
weldapadm force-local <name>        protect an account as a backup (always works locally)
weldapadm force-local <name> --off  stop protecting it
weldapadm enable  <name>            re-enable a managed account (e.g. one idle-disabled)
weldapadm disable <name>            disable a managed account
weldapadm set-admin <name> on|off   grant or revoke local admin on a managed account
weldapadm lockdown [status|arm|disarm]  show or set lockdown enforcement
```

Typical first-run hardening of a device:

```powershell
weldapadm force-local breakglass     # your emergency admin always works locally
weldapadm force-local Administrator  # keep the built-in admin as a backup too
weldapadm lockdown status            # review policy
weldapadm lockdown                   # (dry run) then read the WouldDisable events before arming
weldapadm lockdown arm               # enforce once you've confirmed the backups are in place
```

`weldapadm lockdown arm|disarm` writes `LockdownEnforce`; restart the service for the running reconciler to pick
it up. If settings can't be read (a half-configured machine) the account verbs still work, so you can always
inspect and repair — only the "excluded" marking and the policy summary are unavailable.

## 6. Code signing and anti-tamper

Anti-tamper is defence in depth on top of the trust model (pipe = SYSTEM-only, server = key-pinned mutual TLS).
Two independent mechanisms:

1. **Authenticode signatures** on the binaries and the MSI, enforced by Windows.
2. **Integrity pins**: at build time the MSI records the SHA-256 of each shipped binary into
   `HKLM\SOFTWARE\WELDAP\{ProviderHash, ServiceHash, AdminHash}` (SYSTEM-only). At startup the service hashes
   the on-disk binaries and refuses to run on any mismatch — a swapped, patched or repointed provider, service
   or admin tool fails closed. The provider check also verifies the registered CLSID's `InprocServer32` points
   at the install folder, so Windows can't be steered to load a different DLL. `ProviderHash` and `ServiceHash`
   are required once pinned; `AdminHash` is optional (the tool may be absent).

> Obfuscation (symbol renaming) is a *reverse-engineering cost*, not tamper resistance. Signing + the integrity
> pins + OS enforcement are what actually stop tampering; treat any obfuscation as a secondary nuisance layer,
> never as the control.

Signing is **off by default** — an unsigned build is a valid dev build, exactly as an unset `ProviderHash` means
"not pinned." To produce a signed MSI, set one of these in the build VM before `vm/build-in-vm.sh` runs
`vm/provision/build-msi.ps1`:

| Variable | Meaning |
| --- | --- |
| `WELDAP_SIGN_THUMBPRINT` | SHA-1 thumbprint of a code-signing cert in `Cert:\*\My`. |
| `WELDAP_SIGN_PFX` (+ `WELDAP_SIGN_PFX_PASSWORD`) | Path to a PFX file and its password. |
| `WELDAP_SIGN_TIMESTAMP_URL` | RFC-3161 timestamp server (default: DigiCert). |

The build **signs each binary first, then pins the hash of the signed bytes**, then builds and signs the MSI —
so the service's check matches what shipped, and a patched binary fails both the signature and the pin. For
production use an OV/EV code-signing certificate; a self-signed certificate is fine for validating the pipeline
in a test VM (install its public cert into the device's Trusted Publishers / Root for Windows to honour the
signature). See `docs/RELEASING.md` for the release flow.

## 7. Troubleshooting

- **Where the logs are.** The service logs to the Windows **Application** event log under the source `WELDAP`
  (the MSI registers it). `weldapadm list` / `show` give the current account state. The password is never logged
  at any level, by design — don't go looking for it.
- **The service won't start.** It fails closed on: a missing or mis-ACL'd config key (SR-10), an invalid setting
  (bad port/host/pin), or an anti-tamper mismatch. The event log says which. Check
  `Get-Service Weldap` and the latest `WELDAP` events:
  ```powershell
  Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -eq WELDAP
  ```
- **Sign-in falls back to offline when the server is up.** Usually the device certificate (not registered,
  expired, or revoked) or a pin mismatch (the server rotated its TLS key and `ServerPins` wasn't updated). Both
  fail closed to offline rather than trusting the wrong peer.
- **An account got disabled unexpectedly.** Check `weldapadm show <name>` and the event log for `Idle`,
  `Lockdown` or `RemovedFromUsers`. Re-enable a managed account with `weldapadm enable <name>` (an online
  sign-in also re-enables). If it's a backup you didn't want touched, make it force-local.
- **Lockdown disabled too much.** It won't have, if you ran dry-run first: disarm (`weldapadm lockdown disarm`),
  re-enable what you need, seed `WELDAP-ForceLocal`, and re-arm.

## See also

- `docs/ARCHITECTURE.md` — how the code fits together, the trust model, the data flow.
- `client/Weldap.Shared/PROTOCOL.md` — the exact bytes on the pipe and the server wire.
- `docs/REQUIREMENTS.md` — the authoritative FR-*/SR-* requirements.
- `docs/RELEASING.md` — building and releasing a signed MSI.
- `SECURITY.md` — the threat model and how to report a vulnerability.
