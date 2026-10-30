```
 __        _______ _     ____    _    ____
 \ \      / / ____| |   |  _ \  / \  |  _ \
  \ \ /\ / /|  _| | |   | | | |/ _ \ | |_) |
   \ V  V / | |___| |___| |_| / ___ \|  __/
    \_/\_/  |_____|_____|____/_/   \_\_|

   Windows Enterprise LDAP
   [ client ]==( sealed )==>[ server ]-- 389
```

# WELDAP – Windows Enterprise LDAP

[![CI](https://github.com/rob-c/weldap/actions/workflows/ci.yml/badge.svg)](https://github.com/rob-c/weldap/actions/workflows/ci.yml)

Builds implicit trust in an LDAP directory into a Windows device: a pGina-style logon (native credential
provider + C# service over a named pipe) that checks the user's password and creates or updates a matching
local account. There are exactly two parties on the network:

- **client** (`client/`): the Windows side. It seals the password (HPKE) inside LogonUI to the server's key and
  talks to nothing but the WELDAP server, over mutual TLS with a per-device key, trusting the server by its key pin
  alone. It knows nothing about LDAP, 389 DS, DNs or groups: per user it learns two flags, `user` and `admin`.
  Windows itself never sees the user's password; it logs on with a random local password.
- **server** (`server/`): a Rust service in an AlmaLinux 9 container, the only thing clients reach and the only
  LDAP client of the directory. It opens the sealed password in locked memory, binds as the user, and answers.

New to the code? Start with `docs/ARCHITECTURE.md`. See also `client/Weldap.Shared/PROTOCOL.md`,
`server/README.md` and `docs/REQUIREMENTS.md`. It targets 389
Directory Server (and any LDAP directory that accepts simple binds over LDAPS).

## Layout

| Path | What |
| --- | --- |
| `client/` | `Weldap.CredentialProvider` (C++: tile, binary pipe client, HPKE sealing), `Weldap.Service` + `Weldap.Core` (C# .NET 10), `Weldap.Shared` (protocols) |
| `server/` | WELDAP server (Rust, AlmaLinux 9 image): device mTLS + CRL, opens sealed passwords, the only LDAP code; `weldap-ca` device CA tool; production compose file |
| `installer/` | WiX MSI per arch; `fleet/`: device registration, lockout policy |
| `testdir/` | Local test environment: 389 DS on an internal-only network + the WELDAP server |
| `tests/` | `quality.sh` (every gate), unit tests, credential-provider harness, server and acceptance suites, surface checks |
| `vm/` | Headless QEMU test VMs on Apple Silicon: unattended install, provisioning, control script |
| `docs/` | `ARCHITECTURE.md` (how the code fits together — start here), `REQUIREMENTS.md` (the authoritative requirements), `logo.txt` |

## Test VMs

| VM | OS / arch | Runs as | Use |
| --- | --- | --- | --- |
| `weldap-win11-arm64` (vm1) | Windows 11 Pro ARM64 | native (QEMU + Hypervisor.framework) | build machine (MSVC x64+ARM64, .NET 10 SDK) and daily test loop |
| `weldap-win10-x64` (vm2) | Windows 10 Pro 22H2 x64 | QEMU full emulation (TCG), ~5–10x slower | x64 check runs |

The real x64 pilot laptop covers Windows 11 x64.

Needs Homebrew `qemu` (firmware from `/opt/homebrew/share/qemu`). Each VM lives in `vm/vms/<name>/`
(disk, UEFI vars, control sockets, log). UTM was dropped after it stopped starting VMs while the
display kept reconfiguring; QEMU runs with no display at all. vm1 uses QEMU's own GICv3 with an ITS
(`kernel-irqchip=off`): with Apple's in-kernel vGIC Windows gets no MSIs and all I/O crawls.

1. Download the ISOs (English (United States)) into `vm/iso/`:
   - `Win11_ARM64.iso` from https://www.microsoft.com/software-download/windows11arm64
   - `Win10_x64.iso` from https://www.microsoft.com/software-download/windows10ISO
2. Build each VM (unattended; vm1 about 20 min plus the build tools, vm2 a couple of hours under emulation):
   ```sh
   vm/vmctl.sh up vm1
   vm/vmctl.sh up vm2
   ```
   Each ends at the logon screen with a `clean-os` snapshot. Watch progress with `vm/vmctl.sh screen vm1`
   (writes a PNG).
3. Break-glass admin: user `breakglass`, password from `vm/vmctl.sh password vm1`.

Day to day:

```sh
vm/vmctl.sh ps vm1 'Get-WinEvent -LogName Application -MaxEvents 20'   # run PowerShell as SYSTEM
vm/vmctl.sh push vm1 out/msi/Weldap-arm64.msi 'C:\ProgramData\WELDAP-Provision\Weldap.msi'
vm/vmctl.sh screen vm1 /tmp/s.png                                         # screenshot
vm/vmctl.sh keys vm1 'password' --enter                                     # type at the logon screen
vm/vmctl.sh snap vm1 before-cp-test                                         # shuts down first
vm/vmctl.sh restore vm1 clean-os                                            # VM must be stopped
vm/vmctl.sh start|stop|kill|status vm1
```

**Network surface of the VMs:** the Windows Firewall blocks all inbound traffic on every profile, including
allow rules, and RDP and Remote Assistance are off. The NIC is QEMU user-mode NAT: outbound only,
nothing on the LAN or the Mac can connect in. QEMU has no VNC, SPICE or monitor port; the host
controls it through QMP and the guest agent (virtio-serial) on unix sockets in `vm/vms/<name>/`
(mode 700). There is no clipboard or folder sharing. A broken credential provider can't lock the
host out, because the agent doesn't go through LogonUI.

## Build and test

```sh
make quality                        # every host gate (wraps tests/quality.sh); non-zero on any failure
tests/quality.sh <gate>...          # run named gates only (CI does this): paranoia budget protocol
                                    #   shellcheck client server deny imports; --fast for the quick three
./build.sh                          # C# unit tests, then publish the service for win-x64 and win-arm64 to out/
vm/build-in-vm.sh                   # in vm1: credential provider x64 + ARM64 and both MSIs -> out/msi
docker build -t weldap-server server/ && docker build --target test -t weldap-server:test server/
tests/server/run.sh                 # server in Docker: device trust, sealed auth, replay, throttling, revocation,
                                    #   network surface, TLS, process hardening, no secret in logs or memory
tests/acceptance/run.sh vm1         # end to end on a VM: sealed sign-in, offline, cleanup, device trust, pin trust,
                                    #   pipe fuzzing, client surface, memory scans
tests/acceptance/register-vm.sh vm1 [--revoke]   # register (or revoke) a VM with the test device CA
```

`run.sh` installs the service with `install-dev.ps1`, registers the VM's device key, and drives the credential
provider's own sealing code (`tests/cp-harness`, built in the VM) against the real pipe. It stops the server or
the directory for the offline cases and edits group membership for the cleanup cases. The harness self-test
(`WeldapClientTest.exe selftest`) covers the pipe codec, PBKDF2 known answers and HPKE; its `seal` mode is checked
against the server's HPKE with `weldap-probe open`.

`installer/fleet/` has the per-device steps: `register-device.ps1` (device key + CSR, accept the certificate) and
`set-lockout-policy.ps1`.

## Hardening and assurance

- **Coverage:** `Weldap.Core` (the client's platform-neutral logic) is at 100% of lines and 100% of branches
  (1467 tests); the Rust server is at 100% of lines and 100% of regions (598 tests). Both gates fail below 100.
  The client's Windows-only P/Invoke files (SAM, DPAPI, the pipe, the registry ACLs, the socket/TLS open) have no
  host-runnable logic; `client/check.sh` lists them explicitly as covered only by the acceptance suite, so the
  gap is named rather than hidden. The credential provider's own code is exercised by its 620-check harness.
- **No debug symbols shipped:** the service publishes with no PDB (`build.sh` fails on a stray one), the provider
  DLL emits no PDB, and the Rust binary is stripped. The server runs in an AlmaLinux 9 micro image with every
  executable removed — no shell, coreutils, package manager or openssl.
- **Compiler/linker hardening:** the provider keeps Control Flow Guard, CET shadow stack (x64), high-entropy
  ASLR, DEP, `/GS`, `/sdl` and a static CRT, and builds clean under `/analyze`; Spectre `/Qspectre` is a
  one-flag opt-in (`-p:SpectreMitigation=Spectre`, needs the VC Spectre libraries). The server drops every Linux
  capability, is non-dumpable, locks all memory, and `panic = abort`.
- **Anti-tamper:** at startup the service resolves the credential-provider DLL Windows will load (the registered
  CLSID's `InprocServer32`), requires it to sit in the install folder, and checks its SHA-256 against a hash the
  MSI pinned at build time (`HKLM\SOFTWARE\WELDAP\ProviderHash`, SYSTEM-only). A swapped or repointed provider
  makes the service refuse to start. Validated on the real MSI and in the acceptance suite.
- **Hostile networking:** every exchange has bounded connect, handshake and request deadlines on both ends, and
  TCP keepalive, so a black-holing firewall, a switch that truncates or reorders, an MTU hole, a half-open
  connection or a slow-loris peer all become a clean offline fall-back (client) or a dropped connection (server),
  never a hang or a crash. TLS integrity turns any injected or corrupted bytes into a dropped connection; the
  client trusts the server by key pin, so a middlebox or a rogue CA cannot impersonate it. Both the server's
  Docker suite and the Core transport tests drive these cases explicitly.
- **Supply chain and reproducibility:** the Rust crates (`Cargo.lock`) and NuGet packages
  (`packages.lock.json`, restored in locked mode under CI) are pinned with content hashes, the server's Docker
  base images are pinned by digest, and GitHub Actions are pinned by commit SHA. `cargo-deny` gates the server's
  dependency graph on every push — advisories (RustSec), licences (an explicit allow-list), bans and sources —
  and Dependabot keeps all of these current, each bump re-gated by CI. The accepted-advisory list in
  `server/deny.toml` is empty; any future exception must carry a dated rationale and a revisit condition there.

## Continuous integration

`.github/workflows/ci.yml` runs the host gates — lint, client (C# 100/100), server (Rust 100/100) and
cargo-deny — on every push and pull request, each job calling `tests/quality.sh` with the same gate names you
run locally, so the green badge above means exactly what `make quality` means on your machine. The Windows-only
build and the end-to-end acceptance run stay in the VMs (they need MSVC and a real LogonUI) and are not part of
hosted CI.

## Test directory

```sh
testdir/up.sh          # first run: test PKI, device CA, 389 DS, seed users, server; later runs: start
testdir/up.sh reset    # rebuild the directory from seed.ldif
testdir/device-ca.sh init|sign|revoke|crl|list|rogue   # test device CA (the production weldap-ca tool)
```

Only the WELDAP server is published: `127.0.0.1:16637` (VMs: `10.0.2.2:16637`, the QEMU NAT gateway). 389 DS has
no published port and sits on an internal Docker network with no route out; only the server reaches it. The VMs
trust nothing from the test PKI: they pin the server's key (`testdir/.data/server/pin`). The server's password
key, directory secret and config are in `testdir/.data/server/` (`server-setup.sh`).

| User | Groups | Expected |
| --- | --- | --- |
| alice | win-users | allowed, standard user |
| bob | win-users, win-admins | allowed, local admin |
| carol | – | denied (has an entry, not authorised) |
| dave | win-users | cleanup tests (remove from win-users → disabled) |
| administrator | win-users | excluded name: WELDAP tile refuses |

Passwords are in `testdir/.data/passwords`. The `winlogin` service account (the server's own) is read-only.

The directory is shaped like production: LDAPS only, TLS 1.2+, simple binds refused without TLS, self-read ACI.

## License

MIT (see `LICENSE`). The Windows credential provider derives from Microsoft's MIT-licensed
credential-provider sample, and the design is inspired by pGina; see `THIRD-PARTY-NOTICES.md`.
Security reports: see `SECURITY.md`. Contributing: see `CONTRIBUTING.md`.
