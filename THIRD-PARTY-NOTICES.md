# Third-party notices

WELDAP is distributed under the MIT License (see `LICENSE`). It builds on, and is
inspired by, the following work.

## Microsoft credential provider sample (MIT)

The Windows credential provider in `client/Weldap.CredentialProvider/` is derived from
Microsoft's V2 credential-provider sample (the "CredentialProvider" / `SampleV2CredentialProvider`
sample), which Microsoft publishes under the MIT License. Files such as `helpers.cpp`, `helpers.h`,
`guid.*`, `common.h` and `Dll.cpp` retain structure and helper routines from that sample; the
WELDAP-specific tile, sealing and pipe logic is new.

    Copyright (c) Microsoft Corporation. All rights reserved.
    Licensed under the MIT License.

## pGina (Apache License 2.0) — design inspiration

WELDAP's overall approach — a Windows logon that authenticates against an external directory and
provisions a matching local account — is inspired by pGina (https://github.com/pgina/pgina),
which is licensed under the Apache License 2.0. No pGina source code is used in WELDAP; only the
general design idea is shared.

## Build / runtime dependencies

- The server (`server/`) links the Rust crates listed in `server/Cargo.toml` / `server/Cargo.lock`
  (notably `rustls`, `hpke`, `x509-parser`, `serde`), each under its own permissive licence
  (MIT / Apache-2.0 / ISC). Run `cargo license` or see each crate's repository for details.
- The client service targets .NET and references `Microsoft.Extensions.Hosting.WindowsServices`
  (MIT).
- The test environment uses the `389ds/dirsrv` and `almalinux` container images, which carry their
  own licences and are not redistributed as part of this repository.
