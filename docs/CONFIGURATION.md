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
`installer/fleet/` is the place for them). Install `Weldap-x64.msi` on x64 Windows and `Weldap-arm64.msi` on ARM64
Windows (LogonUI loads only a native provider; the x64 MSI refuses to install on ARM64). A minimal install:

```powershell
msiexec /i Weldap-x64.msi /qn /norestart /l*v C:\Windows\Temp\weldap-install.log `
  SERVERHOST=weldap.example.org `
  SERVERPINS=<base64 SHA-256 of the server's TLS SubjectPublicKeyInfo> `
  SERVERKEY=<base64 HPKE P-256 public key> `
  SERVERKEYID=k1 `
  EXCLUDEDACCOUNTS="administrator,breakglass"
```

`SERVERHOST`, `SERVERPINS`, `SERVERKEY` and `SERVERKEYID` are **required** — the installer refuses without them.
Everything else has a default (see the table below). Install as an administrator or SYSTEM (every deployment
tool does): no property is `Secure`, so a standard user can never hand settings to the per-machine install (a
repair started by one cannot point the device at another server). Uninstall (Programs and Features, or `msiexec /x` with the
installed MSI or its product code, plus `/qn /norestart`) removes the binaries, the service, the provider
registration and all of `HKLM\SOFTWARE\WELDAP` (settings, the `Secret` subkey with local passwords and offline
verifiers, and the policy values set by hand); it deliberately leaves local accounts, the `WELDAP-Managed` group
and user profiles in place. Managed accounts then keep random passwords nobody knows: reset one with
`net user <name> *` (as an administrator) if it must be used locally. The purge runs only once the uninstall has
succeeded (a cancelled or failed uninstall leaves WELDAP and its state as they were).

Losing the `Secret` subkey (an uninstall, the one-off upgrade from 0.1.0) costs more than offline sign-in: at each
user's next online sign-in WELDAP sets a new local password, and Windows treats that as an administrator's
password *reset*, so that user's DPAPI-protected data (Credential Manager, EFS keys, passwords saved in browsers)
becomes unreadable. Moving a device to another server is therefore a settings change (below), not a reinstall.

**Upgrade and repair.** Run the new MSI the same way; no properties are needed:

```powershell
msiexec /i Weldap-x64.msi /qn /norestart /l*v C:\Windows\Temp\weldap-upgrade.log
```

- A newer build upgrades an installed copy in place, as one transaction: if the new install fails, the old one is
  rolled back. A rebuild of the same version does too; an *older* build is refused (dev builds are stamped
  `<major>.<minor>.<days since 2026-01-01>`, see `docs/RELEASING.md`), so a stale MSI can never replace a newer one.
- Every setting is remembered from the registry on upgrade and repair; a property given on the command line wins.
- Per-device state — the `Secret` subkey and the policy values set by hand (`AdoptPreexisting`, `LockdownEnforce`,
  `IdleDisableDays`) — is kept. (Upgrading *from 0.1.0* loses it once, because 0.1.0's own uninstall deletes the
  key: users sign in online once, and hand-set policies must be set again.)
- The installed provider DLL is named `WeldapCredentialProvider-<first 12 hex of its SHA-256>.dll`, so an upgrade
  while LogonUI holds the old DLL (a PC at the logon screen) writes the new one beside it instead of deferring to a
  reboot.
- Programs and Features offers Repair and Uninstall, not Change. A repair from the command line rewrites the
  registry (provider registration, pins, settings) from the remembered settings, puts back any missing or older
  file, and touches no per-device state. Use the MSI that is installed:

  ```powershell
  msiexec /i Weldap-x64.msi /qn /norestart REINSTALL=ALL REINSTALLMODE=omus
  ```

  Not `msiexec /f…`: in that form `/norestart` is not applied, and Windows Installer restarts the PC when it needs
  to. And not mode `a` (`amus`, "every file, whatever its version"): it overwrites `WeldapService.exe` a few
  milliseconds after stopping the service, while the process is still exiting, so the file is replaced at a reboot
  instead (exit 3010). To replace a damaged binary, upgrade to a newer build (or uninstall and reinstall, which
  loses per-device state; see above).

**Changing a setting** (a new server, a rotated key or pin). Running the *installed* MSI again with new properties
does nothing (it is already installed), and a repair ignores command-line properties. Either set the value in the
registry and restart the service (`reg add HKLM\SOFTWARE\WELDAP /v ServerKeyId /t REG_SZ /d k2 /f`, then
`Restart-Service Weldap`), or reinstall in place with the new values, which keeps everything else. Use the MSI
that is installed (a different build refuses `REINSTALL`; to change settings while upgrading, run the new MSI
normally with the properties):

```powershell
msiexec /i Weldap-x64.msi /qn /norestart REINSTALL=ALL REINSTALLMODE=omus SERVERKEY=<new key> SERVERKEYID=k2
```

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
| `ServerPort` | number | `636` | `SERVERPORT` | TCP port of the WELDAP server. |
| `ServerPins` | list | — (required) | `SERVERPINS` | Base64 SHA-256 of the server certificate's SubjectPublicKeyInfo. **This is the only server trust** — no CA, no hostname check. List several to rotate keys. |
| `ServerKey` | REG_SZ | — (required) | `SERVERKEY` | The server's **public** HPKE password key: base64 of the 65-byte uncompressed P-256 point. |
| `ServerKeyId` | REG_SZ | — (required) | `SERVERKEYID` | Identifier of that key (e.g. `k1`; 1–32 of `[a-z0-9-]`); lets the server roll its key pair. |
| `ExcludedAccounts` | list | `administrator` | `EXCLUDEDACCOUNTS` | Names the WELDAP tile always refuses and reconciliation never touches, on top of the built-ins. |
| `MaxOfflineDays` | number | `180` | `MAXOFFLINEDAYS` | How long an offline verifier stays usable after the last online sign-in. `0`–`3650`. Lowering it is not retroactive: an account's expiry is stamped at each online sign-in. |
| `OfflineMaxFailures` | number | `10` | `OFFLINEMAXFAILURES` | Consecutive wrong offline passwords before offline sign-in locks until the next online one. `1`–`100`. |
| `TileLabel` | REG_SZ | `WELDAP sign-in` | `TILELABEL` | The text under the WELDAP tile. |
| `AdoptPreexisting` | number | `1` (on) | — | Allow taking over a pre-existing local account that shares a directory user's name, after the user consents. See §4. |
| `LockdownEnforce` | number | `0` (off) | — | Arm the lockdown: actually disable local accounts unknown to the directory. Off = **dry run** (reported only). See §4. |
| `IdleDisableDays` | number | `30` | — | Disable a managed account with no interactive logon for this many days. `0` = never. `0`–`3650`. |
| `ProviderHash` / `ServiceHash` / `AdminHash` | REG_SZ | set by MSI | — | Anti-tamper pins; see §6. Do not edit by hand. |

**Types.** A *number* is a REG_DWORD or decimal digits in a REG_SZ (any other form means the default; the day and
failure counts are clamped to their ranges, a port out of range stops the service). A *list* is a REG_MULTI_SZ or
one REG_SZ separated by `,` or `;`. The MSI writes both as REG_SZ (`"636"`, `"pinA,pinB"`); a value carried over
from an earlier install keeps its type.

**Built-in exclusions** are always refused regardless of `ExcludedAccounts`: `administrator`, `guest`,
`defaultaccount`, `wdagutilityaccount`. The built-in accounts themselves are also recognised by SID (RIDs 500,
501, 503, 504), so a renamed or localised Administrator, Guest, DefaultAccount or WDAGUtilityAccount is protected
too.

**The tile picture** is not a setting: it is compiled into the credential-provider DLL (so the anti-tamper pin
covers it too) and chosen at build time. Give the build any square PNG, JPEG, GIF or BMP of 64–1024 px; it is
normalised to a 192×192 24-bit bitmap (no alpha — transparency is flattened onto black) and LogonUI shows it
cropped to a circle, so keep the subject inside the inscribed circle.

```sh
WELDAP_TILE_IMAGE=~/branding/logo.png vm/build-in-vm.sh     # from the Mac: both providers and both MSIs
```
```powershell
client\Weldap.CredentialProvider\build.ps1 -TileImage C:\branding\logo.png   # or in the build VM directly
```

Unset, the build uses `client/Weldap.CredentialProvider/art/tile.bmp` (a collider event display), which
`art/make-tile.py` regenerates; the label beside the picture is the run-time `TileLabel` above.

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

A value that fails validation (bad port, a pin that is not a base64 SHA-256, a malformed host, a `ServerKey` that
is not a P-256 point, a bad `ServerKeyId`) makes the service refuse to start — fail-closed, by design. It logs a
critical event and stays stopped: fix the value, then `Start-Service Weldap`.

## 4. The local-account model

Every local account on the device falls into exactly one class, and WELDAP treats each differently. `weldapadm
list` shows the class of every account (the first that applies, in the order built-in, excluded, force-local,
managed). Account names are handled lower case, as Windows compares them case-insensitively: a pre-existing
`Alice` is the user `alice` for adoption, reconciliation and lockdown.

| Class | What it is | WELDAP's behaviour |
| --- | --- | --- |
| **managed** | In `WELDAP-Managed`; holds a random local password the user never learns. Created on first online sign-in, or by adopting a pre-existing account. | Fully owned: enabled/disabled, admin membership and the offline verifier all follow the directory; WELDAP keeps its local password. Idle-disabled after `IdleDisableDays`. |
| **built-in** | Administrator, Guest, DefaultAccount, WDAGUtilityAccount, recognised by SID (renamed or localised ones too). | Never signed in by the tile, adopted, disabled or reconciled. |
| **force-local** | In `WELDAP-ForceLocal`. Your **trusted backup** accounts — a break-glass admin belongs here. | Refused by the tile (even if also managed), never adopted, never disabled, never idle-reaped, never touched by lockdown or reconciliation. Always works locally. |
| **excluded** | Name is in `ExcludedAccounts` or the built-in list. | The tile refuses it; reconciliation ignores it. |
| **unclassified** | Any other local account (not managed, not force-local, not excluded). | Left alone normally; a **lockdown** candidate (see below). |

Every online sign-in re-applies the stored local password to the account, so one whose password was reset by hand
converges back. A stored local password that is not one WELDAP generated (32 characters of its alphabet) is treated
as missing: replaced at the next online sign-in, offline sign-in refused until then.

### Adoption (`AdoptPreexisting`)
If a directory user signs in and a local account already exists with that name but is **not** managed, WELDAP
offers to *adopt* it rather than silently taking it over. Only after the server confirms the password and that
the name is a WELDAP user does the tile show the warning and a **Continue** box; nothing has changed yet. Tick it
and sign in again (with the password) to consent; changing the username to another name or leaving the tile
withdraws the offer, and the consent only ever applies to the name the warning was shown for.
On consent the account is moved into `WELDAP-Managed`, given a fresh random local password (its old password stops
working; a password stored for an earlier account of the same name is never reused), and admin membership synced.
Set `AdoptPreexisting=0` to refuse pre-existing accounts outright instead.

A **force-local** or **built-in** account is never adopted — it is refused at the tile so the backup account's
known password keeps working.

### Idle disable (`IdleDisableDays`)
A managed account with no interactive logon for `IdleDisableDays` days is disabled and its offline verifier
cleared. This is reversible: the user's next *online* sign-in re-enables it. This is distinct from
`MaxOfflineDays` (how long the offline verifier itself is accepted). Set `IdleDisableDays=0` to never idle-reap.

Idleness is measured against the clock **and** the most recent logon of any account on the device, so a clock
stepped forward, or a device left off for a month (its only user back from holiday), does not idle-disable
everyone. An account that has never logged on is never idle-disabled.

### Lockdown (`LockdownEnforce`)
Lockdown is how you converge a device onto "only directory-known accounts, plus the backups." At service start and
hourly, reconciliation asks the server about every candidate whose name can be a UUN (one that cannot, such as
`j.smith`, is unknown to the directory by definition):

- **Dry run** (`LockdownEnforce=0`, the default): every enabled unclassified account that the directory does
  **not** know is written to the event log as a `WouldDisable` (event 1212, Warning) — so you can see what *would*
  happen without changing anything.
- **Armed** (`LockdownEnforce=1`): those same accounts are actually disabled.

An unclassified account whose name the directory knows is left alone (it is adopted at that user's next sign-in).
Built-in, force-local and excluded accounts are exempt in both modes. An account lockdown disabled is not
WELDAP-managed, so re-enable it with Windows' own tools: `net user <name> /active:yes`. **Roll it out dry-run
first, read the events, seed your backups into `WELDAP-ForceLocal`, then arm it.**

### The last-admin guard
WELDAP will never disable **or demote** the last remaining enabled local administrator, whatever the policy says,
on every path: the hourly reconcile (a removed directory user, idle, lockdown), an online sign-in that says "not a
user" or "not admin", and `weldapadm disable` / `set-admin off`. The service logs a Warning (`DisableSkipped`,
event 1213, or `DemotionSkipped`, event 1214) and the account stays as it is; `weldapadm` refuses with an error. A
removed user's offline verifier is still forgotten when the guard keeps the account enabled. This is the safety net
behind "there is always a backup admin that works", but you should still keep a real force-local break-glass admin
rather than relying on it.

### Offline sign-in
When the server is unreachable the service verifies the typed password against the offline verifier saved at the
last online sign-in (PBKDF2-HMAC-SHA256, 600 000 iterations, salted with the machine GUID and the UUN). It is
only for managed accounts (never a pre-existing unmanaged one), accepted for up to `MaxOfflineDays`, and locks
after `OfflineMaxFailures` wrong tries until the next online sign-in. The plaintext password is never stored —
only this one-way verifier.

## 5. `weldapadm` — the local account manager

`weldapadm.exe` ships beside the service (in `C:\Program Files\WELDAP`) and is the supported way to inspect and
repair the local-account state. It talks to the local accounts directly, **never over the service's pipe or the
network**, so it adds no attack surface — and it must run **elevated** (local administrator). Every mutating
verb is one the service itself performs, under the same guards (managed accounts only; protected accounts never;
the last enabled local admin never disabled or demoted).

```
weldapadm list                      all local accounts and how WELDAP classifies them
weldapadm show <name>               details for one account (class, enabled, admin, managed, force-local, expiry, last logon)
weldapadm adopt <name>              bring a pre-existing account under WELDAP management
weldapadm force-local <name>        protect an account as a backup (always works locally)
weldapadm force-local <name> --off  stop protecting it
weldapadm enable  <name>            re-enable a managed account (e.g. one idle-disabled)
weldapadm disable <name>            disable a managed account (until its next online sign-in)
weldapadm set-admin <name> on|off   grant or revoke local admin on a managed account (until the next reconcile)
weldapadm lockdown [status|arm|disarm]  show or set lockdown enforcement (no argument = status)
```

- **Changes to managed accounts are temporary:** they last until the service next follows the directory (an
  online sign-in, the hourly reconcile). `ExcludedAccounts` is the durable way to keep someone out.
- **`adopt`** refuses when settings are unavailable, for a name that cannot be a UUN, an excluded name, a protected
  account (force-local or built-in) and one already managed. It does not reset the password: the account's old
  password works until the user's first online sign-in. From then on it follows the directory — if the name is not
  a WELDAP user, the next reconcile disables it.
- **`disable`** and **`set-admin … off`** refuse to act on the last enabled local administrator.
- **`force-local`** takes only `<name>` or `<name> --off`.
- Any failure is an `error:` message and exit code 2 (an unknown verb or a malformed argument prints the usage,
  exit code 1).

Typical first-run hardening of a device:

```powershell
weldapadm force-local breakglass     # your emergency admin always works locally
weldapadm force-local Administrator  # keep the built-in admin as a backup too
weldapadm lockdown                   # review policy (same as: weldapadm lockdown status)
# dry run: read the WouldDisable events (1212) from the next reconcile before arming
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'WELDAP'; Id = 1212 }
weldapadm lockdown arm               # enforce once you've confirmed the backups are in place
```

`weldapadm lockdown arm|disarm` writes `LockdownEnforce`; restart the service for the running reconciler to pick
it up. If settings can't be read (a half-configured machine) the account verbs still work, so you can always
inspect and repair — only the "excluded" marking, the policy summary and `adopt` are unavailable.

## 6. Code signing and anti-tamper

Anti-tamper is defence in depth on top of the trust model (pipe = SYSTEM-only, server = key-pinned mutual TLS).
Two independent mechanisms:

1. **Authenticode signatures** on the binaries and the MSI, enforced by Windows.
2. **Integrity pins**: at build time the MSI records the SHA-256 of each shipped binary into
   `HKLM\SOFTWARE\WELDAP\{ProviderHash, ServiceHash, AdminHash}` (writable by SYSTEM and Administrators only, like
   the rest of the key: an administrator can replace any binary anyway, so the pins guard against everyone else).
   At startup the service hashes
   the on-disk binaries and refuses to run on any mismatch — a swapped, patched or repointed provider, service
   or admin tool fails closed. The provider check also verifies the registered CLSID's `InprocServer32` points
   at the install folder, so Windows can't be steered to load a different DLL. `ProviderHash` and `ServiceHash`
   are required once pinned; `AdminHash` is optional (the tool may be absent).

> Obfuscation (symbol renaming) is a *reverse-engineering cost*, not tamper resistance. Signing + the integrity
> pins + OS enforcement are what actually stop tampering; treat any obfuscation as a secondary nuisance layer,
> never as the control.

Signing is **off by default** — an unsigned build is a valid dev build, exactly as an unset `ProviderHash` means
"not pinned." To produce a signed MSI, set one of these **on the host** before running `vm/build-in-vm.sh`; it
forwards them into the build VM session, where `vm/provision/build-msi.ps1` uses them:

| Variable | Meaning |
| --- | --- |
| `WELDAP_SIGN_THUMBPRINT` | SHA-1 thumbprint of a code-signing cert in the build VM's `Cert:\LocalMachine\My`. |
| `WELDAP_SIGN_PFX` (+ `WELDAP_SIGN_PFX_PASSWORD`) | Path (in the build VM) to a PFX file and its password. |
| `WELDAP_SIGN_TIMESTAMP_URL` | RFC-3161 timestamp server (default: DigiCert). |

The build runs as SYSTEM, so a thumbprint cert must live in the **Local Machine** store (`Cert:\LocalMachine\My`),
not a per-user store — the tooling signs with `signtool /sm` to match. The build **signs each binary first, then
pins the SHA-256 of the signed bytes**, then builds and signs the MSI, so the service's check matches exactly
what shipped and a patched binary fails both the signature and the pin.

For production use an OV/EV code-signing certificate. For validating the pipeline in a test VM a self-signed
certificate is fine — create and trust one **in the build VM**:

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=WELDAP dev code signing' `
    -KeyAlgorithm RSA -KeyLength 3072 -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(3)
# so Windows honours the signature locally (test VM only):
foreach ($s in 'Root', 'TrustedPublisher') {
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($s, 'LocalMachine')
    $store.Open('ReadWrite'); $store.Add($cert); $store.Close()
}
$cert.Thumbprint   # use as WELDAP_SIGN_THUMBPRINT
```

After a signed build, verify the pins match the signed binaries (the service checks the same hashes at startup):
`Get-FileHash` each of `WeldapService.exe` / `weldapadm.exe` and the provider DLL — installed as
`WeldapCredentialProvider-<first 12 hex of its SHA-256>.dll`, the file the CLSID's `InprocServer32` points at:

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Classes\CLSID\{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}\InprocServer32').'(default)'
```

— and compare to `HKLM\SOFTWARE\WELDAP\{ServiceHash,AdminHash,ProviderHash}`. See `docs/RELEASING.md` for the
release flow.

## 7. Troubleshooting

- **Where the logs are.** The service logs to the Windows **Application** event log under the source `WELDAP`
  (the MSI registers it): audit events 1000–1400 (one per allow, deny and account change; 1214 `DemotionSkipped`
  and 1213 `DisableSkipped` mean the last-admin guard fired) and service events 1500–1512 (1500 refused to start,
  1501 stopping on a fault, 1502 integrity status at start, 1503 cleanup failed, 1510–1512 pipe problems).
  `weldapadm list` / `show` give the current account state. The password is never logged at any level, by
  design — don't go looking for it.
- **The service won't start.** It fails closed on: a missing or mis-ACL'd config key (SR-10), an invalid setting
  (bad port/host/pin, `ServerKey`, `ServerKeyId`), or an anti-tamper mismatch. It logs a critical event saying
  which and stays stopped (restarting would not change anything): fix the cause, then `Start-Service Weldap`.
  Check `Get-Service Weldap` and the latest `WELDAP` events:
  ```powershell
  Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -eq WELDAP
  ```
  Once running, any fault makes the service exit with code 1 and the Service Control Manager restarts it 5 s
  later (the MSI sets the failure actions to apply to non-crash failures too). If another process holds the pipe
  name, the service logs it and retries with backoff rather than exiting.
- **Sign-in falls back to offline when the server is up.** Usually the device certificate (not registered,
  expired, or revoked) or a pin mismatch (the server rotated its TLS key and `ServerPins` wasn't updated). Both
  fail closed to offline rather than trusting the wrong peer. A server slower than the 9 s round-trip budget
  falls back to offline too.
- **The tile says "This PC's account is out of step with WELDAP".** Windows rejected the local password the
  service supplied: the account was changed outside WELDAP (password reset by hand, restored from a backup). The
  next online sign-in re-applies the stored password; if it persists, check the event log for account errors.
- **An account got disabled unexpectedly.** Check `weldapadm show <name>` and the event log for `Idle`,
  `Lockdown` or `RemovedFromUsers`. Re-enable a managed account with `weldapadm enable <name>` (an online
  sign-in also re-enables); an unmanaged one lockdown disabled with `net user <name> /active:yes`. If it's a backup
  you didn't want touched, make it force-local.
- **Lockdown disabled too much.** It won't have, if you ran dry-run first: disarm (`weldapadm lockdown disarm`),
  re-enable what you need (`net user <name> /active:yes`), seed `WELDAP-ForceLocal`, and re-arm.

### Recovery: the WELDAP tile breaks LogonUI
Sign in with a local administrator — the break-glass / force-local account, or the standard Windows password tile
— or boot to Safe Mode. Then either uninstall the product (`msiexec /x` with the installed MSI or its product
code), or delete the provider's registration so LogonUI no longer loads it:

```powershell
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}" /f
```

After an uninstall, managed accounts keep random passwords nobody knows: reset one with `net user <name> *` (as
an administrator) if it must be used locally.

## See also

- `docs/ARCHITECTURE.md` — how the code fits together, the trust model, the data flow.
- `client/Weldap.Shared/PROTOCOL.md` — the exact bytes on the pipe and the server wire.
- `docs/REQUIREMENTS.md` — the authoritative FR-*/SR-* requirements.
- `docs/RELEASING.md` — building and releasing a signed MSI.
- `SECURITY.md` — the threat model and how to report a vulnerability.
