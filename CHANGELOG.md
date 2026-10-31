# Changelog

All notable changes to WELDAP are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-10-31

First public release — a pGina-style Windows logon that authenticates a user against an LDAP directory
without the password ever living on the device.

### Added
- **Credential provider** (C++, in LogonUI): seals the typed password with HPKE (RFC 9180 base mode,
  DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM) and computes a machine- and user-bound PBKDF2
  offline verifier.
- **Windows service** (C#/.NET 10): a SYSTEM-only named-pipe server that talks to the WELDAP server over
  mutual TLS (per-device certificate; server trusted by public-key pin) and creates or updates the local
  account, logging the user on with a random local password.
- **WELDAP server** (Rust, AlmaLinux 9 container): the only LDAP client of the directory; opens sealed
  passwords in locked memory, binds as the user, and returns two flags — `user` and `admin`.
- **Offline sign-in** against the PBKDF2 verifier, with a configurable maximum age and a failure lockout.
- **Reconciliation**: the device asks the server only about its own managed accounts; upstream removals
  disable the local account and clear its verifier.

### Security & hardening
- 100% line+branch coverage of the platform-neutral client logic; 100% line+region coverage of the server.
- Device trust by mutual TLS with a mandatory CRL (fails closed); server trust by SHA-256 public-key pin;
  startup anti-tamper check that the registered provider DLL matches the MSI-pinned hash.
- Stripped binaries, no shipped debug symbols, a shell-less runtime image, CFG/CET/ASLR/DEP and `/analyze`
  on the provider, every Linux capability dropped, `mlockall`, `panic = abort`.
- The password never reaches a log at any level (enforced by a lint); secrets are zeroed and the server
  holds them only in locked memory.
- Hostile-network resilience: bounded connect/handshake/request deadlines and TCP keepalive on both ends,
  so a black-holing or truncating middlebox becomes a clean offline fall-back or a dropped connection.

### Supply chain & tooling
- GitHub Actions CI running the full host gate set (lint, client, server, cargo-deny) on every push and PR.
- `cargo-deny` (advisories, licences, bans, sources); Docker base images pinned by digest; NuGet lock files
  restored in locked mode under CI; Dependabot across Cargo, NuGet, Actions and Docker.
- `tests/quality.sh` gate runner, a cross-language protocol-constant consistency check, a PE import
  allow-list for the provider, the no-secret-in-logs lint, and per-component code-size budgets.
- `docs/ARCHITECTURE.md` maintainer guide; a `Makefile` and a dev container for the local loop.

[Unreleased]: https://github.com/rob-c/weldap/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rob-c/weldap/releases/tag/v0.1.0
