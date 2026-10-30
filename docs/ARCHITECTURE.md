# WELDAP architecture

This is the map for someone reading, maintaining, or extending the code. It covers how the pieces fit, where
each responsibility lives, the trust and data flow, and the invariants that must not be broken. It is the *why*
and the *shape*; the companions are:

- `client/Weldap.Shared/PROTOCOL.md` — the exact bytes on each wire (pipe v3 and server v1).
- `docs/REQUIREMENTS.md` — the authoritative functional (FR-*) and security (SR-*) requirements.
- `SECURITY.md` — the threat model and how to report a vulnerability.
- `README.md` — building, the test VMs, and running the gates; `CONTRIBUTING.md` — the gate workflow.

## 1. The shape: two parties, one secret

WELDAP logs a user into Windows using their directory password, without that password ever living on the
device. There are exactly **two parties on the network**, and they are the two top-level directories:

- **`client/`** — the Windows device. It seals the password and learns, per user, two booleans: `user`
  (may sign in) and `admin` (is a local administrator). It knows nothing about LDAP, DNs, or groups.
- **`server/`** — a Rust service in an AlmaLinux 9 container. It is the only thing clients talk to and the
  only LDAP client of the directory. It opens the sealed password, binds as the user, and answers.

The design goal everything else serves: **the smallest possible surface that ever touches the password, and
the password never readable anywhere it need not be.** 389 Directory Server knowledge is confined entirely to
the server; the client/server link is a single mutually-authenticated TLS socket.

```
   Windows device (client/)                                    container (server/)        directory
  ┌───────────────────────────────────────────┐              ┌──────────────────┐       ┌──────────┐
  │ LogonUI                      SYSTEM service │              │  weldap-server   │       │  389 DS  │
  │ ┌───────────────┐  pipe v3   ┌────────────┐ │  server v1   │                  │ LDAPS │          │
  │ │ credential     │ (binary,  │ Weldap      │ │  (JSON over  │ opens sealed pw  │ bind  │ user's   │
  │ │ provider (C++) │──SYSTEM──▶│ .Service    │─┼──mutual TLS─▶│ in locked mem,   │──────▶│ entry +  │
  │ │ seals password │  only)    │ (C#, thin   │ │  device cert │ binds as user,   │       │ groups   │
  │ │ with HPKE      │           │ Windows     │ │  + key pin)  │ returns 2 flags  │       │          │
  │ └───────────────┘           │ shell)      │ │              │                  │       │          │
  │   password sealed here;      │ + Weldap   │ │              └──────────────────┘       └──────────┘
  │   Windows logs on with a     │   .Core    │ │               the ONLY LDAP client; 389 DS has no
  │   random LOCAL password      └────────────┘ │               published port and no route out
  └───────────────────────────────────────────┘
```

## 2. Trust model

Three independent trust decisions, each fail-closed:

| Boundary | Who trusts whom, and how |
| --- | --- |
| **Pipe** (provider ↔ service) | Both ends require the other process token to be SYSTEM (`S-1-5-18`); the pipe DACL allows SYSTEM and denies NETWORK, rejects remote clients, and is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` so the name can't be squatted. |
| **Client → server** | Mutual TLS. The client authenticates with a per-device certificate; the server authenticates to the client **by a SHA-256 pin of its certificate's SubjectPublicKeyInfo** (`ServerMessages.Pin`), *not* by a CA or hostname — a rogue CA or middlebox cannot impersonate it. |
| **Server → device** | The server verifies each device certificate against the device CA **and a mandatory CRL**; an expired or missing CRL fails closed (no client is trusted). |

Plus **anti-tamper** (defence in depth, `Weldap.Service/IntegrityGuard.cs`): before serving, the service checks
that the credential-provider DLL Windows will actually load (the registered CLSID's `InprocServer32`) sits in
the install folder and matches a SHA-256 the MSI pinned at build time. A swapped or repointed provider makes
the service refuse to start.

**The password's life:** typed into the tile → sealed in LogonUI → crosses the pipe sealed → crosses the
network sealed → opened only inside the server's locked memory → used for one LDAP bind → gone. Windows itself
logs the user on with a *random local password* it generates; the directory password never becomes a Windows
credential. It is never logged at any level (enforced mechanically by `tests/lint/paranoia.sh`).

## 3. Data flow

### Online sign-in
1. The user types their username (UUN) and password into the WELDAP tile.
2. The **credential provider** (`WeldapSeal.cpp`) seals the password with HPKE (RFC 9180 base mode,
   DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, info `"WELDAP password v1"`). The AAD binds the
   ciphertext to the key id, UUN, scenario (`logon`/`unlock`), timestamp, and a random request id, so it
   cannot be replayed or retargeted. It also computes the **offline verifier** (see below).
3. `WeldapClient.cpp` frames a **pipe v3** request (fixed binary layout) and sends it over the SYSTEM-only
   named pipe to the service.
4. **`Weldap.Service`** (`PipeServer` → `LoginHandler`) connects to the server over mutual TLS (pinned) and
   forwards a **server v1** request (`{op:"auth", uun, kid, enc, ct, ts, rid, scenario}`, JSON, 4-byte
   big-endian length frame).
5. The **server** opens the sealed password into `mlock`ed memory (`seal.rs` → `secret.rs`), binds to 389 DS
   as the user (`ldap.rs`, a minimal hand-written BER client), reads the user's group membership
   (`directory.rs`), and replies `{result:"ok", user:bool, admin:bool}`.
6. The service applies the flags (`Reconciler`/`LocalAccounts`): create or update the local account, set its
   admin membership, mark it WELDAP-managed, and hand LogonUI a fresh random local password to actually log on.

### Offline sign-in
When the server is unreachable, the service verifies the typed password against the **offline verifier** stored
at last successful online logon: PBKDF2-HMAC-SHA256, 600 000 iterations, 32 bytes, salt =
`SHA-256("WELDAP-offline-v1\n" + MachineGuid + "\n" + uun)`. The verifier binds to the machine and user, has a
configurable max age (default 180 days) and a lockout after repeated failures. The plaintext password is never
stored — only this one-way verifier.

### Reconciliation
Hourly (and after each online logon) the service asks the server, via the `status` op, only about *its own*
managed accounts (≤ `MAX_STATUS_UUNS` UUNs) — never a directory dump. Users removed upstream are disabled
locally and their offline verifier cleared; admin status is synced.

## 4. Component map

### Credential provider — `client/Weldap.CredentialProvider/` (C++, in LogonUI)
Largest and most sensitive component; runs inside `LogonUI`, handles the plaintext password, derived from
Microsoft's MIT credential-provider sample.

| File | Responsibility |
| --- | --- |
| `Dll.cpp`, `WeldapProvider.*` | COM entry points, the provider, usage-scenario gating (only `CPUS_LOGON`/`CPUS_UNLOCK_WORKSTATION`). |
| `WeldapCredential.*` | The tile: fields, `GetSerialization`, password capture and zeroing. |
| `WeldapSeal.*` | HPKE sealing (hand-rolled over BCrypt) and the PBKDF2 offline verifier; all secret-buffer zeroing. |
| `WeldapClient.*` | The pipe v3 codec and the pipe client (`WeldapAuthenticateEx`). |
| `helpers.*` | Sample-derived field/serialization helpers (mostly inherited boilerplate). |

### Service — `client/Weldap.Service/` + `client/Weldap.Core/` (C#, .NET 10)
Split so the logic is testable off-Windows:

- **`Weldap.Core`** — platform-neutral login logic, held to **100% line and branch coverage**. Protocol codecs
  (`Protocol.cs`, `ServerMessages.cs`, `ServerTransport.cs`), settings/validation (`Settings.cs`),
  the decision logic (`LoginHandler.cs`, `Reconciler.cs`, `RateLimiter.cs`), audit formatting, and the
  abstractions (`Abstractions.cs`) the Windows shell implements. **No Windows APIs here.**
- **`Weldap.Service`** — the thin Windows shell: the named pipe (`PipeServer.cs`), the socket + pinned TLS
  (`ServerClient.cs`), SAM local accounts (`LocalAccounts.cs`, `Native.cs`), the DPAPI secret store
  (`SecretStore.cs`), the registry config and its ACL checks (`RegistrySettings.cs`), the event log
  (`EventLogAudit.cs`), the anti-tamper guard (`IntegrityGuard.cs`), and the host (`Program.cs`). Exercised
  only by the on-VM acceptance suite — it has no host-runnable unit tests, and `client/check.sh` lists its
  files so that gap is explicit, not hidden.

### Server — `server/src/` (Rust, AlmaLinux 9)
The only LDAP client; the only network-reachable service.

| File | Responsibility |
| --- | --- |
| `main.rs` | Process entry, config/key loading, startup. |
| `server.rs` | Connection handling, the per-request `handle()`, rate/slot limits, request parsing, `auth`/`status`. |
| `seal.rs` | HPKE open (and the test-only sealer); the crypto suite definition. |
| `secret.rs` | `SecretBuf`: `mlock`ed, zero-on-drop memory for opened passwords (the only `unsafe`, with `hardening.rs`). |
| `ldap.rs` | Minimal hand-written BER LDAP client (bind, base-object search). |
| `directory.rs` | The `Directory` trait and `LdapDirectory`: membership → `{user, admin}` decision. |
| `tls.rs` | Server TLS config, device-CA + CRL verification, hot reload (fail-closed). |
| `config.rs`, `audit.rs`, `hardening.rs` | Config parsing; JSON audit sink (dependency-free); process hardening (mlockall, no-dump, drop capabilities). |
| `bin/weldap-probe.rs` | Test client: seals exactly as the C++ provider does, for host tests and C++↔Rust interop checks. |

## 5. Load-bearing invariants

Break one of these and something important fails silently. They are the first things to check in review.

- **The password never reaches a log, at any level.** `tests/lint/paranoia.sh` enforces it mechanically across
  all three languages; do not work around it.
- **Every secret buffer is zeroed.** In `WeldapSeal.cpp` the end-of-function wipe list is the invariant the
  whole design rests on: every buffer holding secret or key-derived material is wiped; the public ones are
  deliberately left. **Any new intermediate that touches the password or key material must join that list.** On
  the server, secrets live only in `SecretBuf` (mlocked, zero-on-drop).
- **The three protocol copies must agree.** Pipe/seal constants exist in C++ (`WeldapProtocol.h`,
  `WeldapSeal.h`), C# (`Protocol.cs`), and Rust (`seal.rs`, `server.rs`). `tests/surface/protocol-consistency.py`
  fails the build if they drift — change a constant in one place and update the others.
- **UUN/device-name charset ⊆ `audit::is_identifier`.** `server::valid_uun` and `server::cert_device_name`
  accept a subset of what `audit::is_identifier` allows, so every accepted name logs verbatim rather than as
  `"?"`. Widening one requires widening `is_identifier` to match (the predicate is duplicated because `audit`
  is deliberately dependency-free).
- **`LoginReply.Mode` is meaningful only when `Result == Ok`.** Deny/Error replies always report `Online` and
  the mode byte is not sent.
- **Fail closed, always.** A lock poisoned, a CRL expired, a config ACL too broad, a TLS integrity failure — each
  denies or drops rather than degrading. The server treats a malformed frame as "no reply at all".
- **No networking in the credential provider.** The DLL's import table is checked against an allow-list
  (`tests/surface/pe-imports.py`); it must never link a networking library into LogonUI.

## 6. Build and validate topology

What can be checked where — this is why some changes validate on a laptop and others need a VM:

| Layer | Builds / validates on | Gate |
| --- | --- | --- |
| `Weldap.Core` (C#) | Mac/Linux host | `tests/quality.sh client` — build (warnings=errors), format, **100/100** coverage |
| Server (Rust) | Docker (distro Rust + distro LLVM) | `tests/quality.sh server` — clippy pedantic, tests, **100/100**; `deny` for the supply chain |
| Lints / surface | host | `paranoia`, `budget`, `protocol`, `shellcheck`, `imports` (see `tests/quality.sh`) |
| `Weldap.Service` (C#) | compiles on host; **behaviour only in a VM** | the on-VM acceptance suite (`tests/acceptance/run.sh`) |
| Credential provider (C++) | **MSVC in vm1 only** | the 620-check harness + `tests/acceptance/run.sh` |

CI (`.github/workflows/ci.yml`) runs everything in the first three rows on every push/PR. The Windows-only rows
need the QEMU VMs in `vm/` (see `README.md`).

## 7. Extending it safely

A short "if you change X, also do Y":

- **Change a wire constant or field** → update all three language copies and `PROTOCOL.md`; the `protocol` gate
  will otherwise fail. Re-run `tests/acceptance/run.sh` for C++↔Rust interop.
- **Add a secret/intermediate buffer in sealing** → add it to the `WeldapSeal.cpp` zero list; prefer `SecretBuf`
  on the server.
- **Touch the server's dependency graph** → `cargo-deny` gates it; a new licence or advisory fails CI. Keep the
  surface minimal (the `hpke` `nistp` feature already pulls unused NIST curves that LTO strips).
- **Add logging** anywhere near the password path → expect the `paranoia` gate to scrutinise it; never format a
  secret into a message.
- **Add a P/Invoke, a network call, or a provider import** → it will be scrutinised; the provider import
  allow-list is a hard wall.
- **Loosen a name/charset rule** → keep `valid_uun`/`cert_device_name` within `audit::is_identifier`.
- **Change the credential provider** → it only builds under MSVC in vm1; validate with the harness and
  acceptance before relying on it. Comment-only changes are safe to land from the host.
