# Contributing to WELDAP

Thanks for your interest. WELDAP is a Windows logon component that handles passwords, so the bar
for changes is high: everything is gated, and the gates must stay green.

## Ground rules

- **Correctness and clarity over cleverness.** Match the style of the surrounding code.
- **No secret ever reaches a log, at any level.** The `tests/lint/paranoia.sh` lint enforces this
  mechanically; do not work around it.
- **Keep the attack surface small.** New network endpoints, new P/Invoke, new dependencies, or new
  logging in the credential provider will be scrutinised. The credential-provider DLL's imports are
  checked against an allow-list (`tests/surface/pe-imports.py`) — it must never link a networking
  library.
- **Tests come with the change.** Coverage gates are 100% lines/branches for `Weldap.Core` and 100%
  lines/regions for the server; new code is expected to hold that line.

## Layout

See the "Layout" table in `README.md`. In brief: `client/` is the Windows side (C++ credential
provider + C# service), `server/` is the Rust server, `installer/` is the WiX MSI, `testdir/` is a
local 389 DS + server for tests, `tests/` holds the suites and gates, `vm/` drives the test VMs.

## Running the gates

On a Mac or Linux host (no Windows needed for the server and the client logic):

```sh
tests/quality.sh         # paranoia lint, code-size budget, shellcheck, client gate, server gate, PE imports
client/check.sh          # C# build (warnings = errors), format, tests, Weldap.Core 100/100 coverage
server/check.sh          # Rust: unsafe confinement, rustfmt, clippy pedantic, tests, 100/100 coverage (in Docker)
```

The Windows-only parts (credential provider, MSI, end-to-end sign-in) are built and tested in the
QEMU VMs described in `README.md` (`vm/build-in-vm.sh`, `tests/acceptance/run.sh`,
`tests/server/run.sh`). You do not need them for most changes to `Weldap.Core` or the server.

## Pull requests

- Keep PRs focused. Explain the security reasoning for anything touching the password path.
- Run the gates locally first. CI (when present) runs the same ones.
- By contributing you agree your contribution is licensed under the project's MIT License.

## Security

Do not report vulnerabilities in public issues or PRs — see `SECURITY.md`.
