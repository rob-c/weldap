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

Everything here runs on a Mac or Linux host — no Windows, no VMs — and needs only the .NET 10 SDK,
Docker and Python 3. `make` wraps the scripts; `make help` lists the targets:

```sh
make quality             # every host gate (run this before a PR)
make fast                # quick gates only: paranoia, budget, protocol (no build, no Docker)
make client              # C#: build (warnings = errors), format, tests, Weldap.Core 100/100 coverage
make server              # Rust: unsafe confinement, rustfmt, clippy pedantic, tests, 100/100 coverage (Docker)
make deny                # cargo-deny: advisories, licences, bans, sources of the server's dependencies (Docker)
```

Under the hood these call `tests/quality.sh`, which takes gate names so a local run and CI run the
identical check — `tests/quality.sh <gate>...` where a gate is one of `paranoia budget protocol
shellcheck client server deny imports`. The `protocol` gate checks that the wire constants agree across
the C++, C# and Rust copies; the `imports` gate inspects the built provider DLL (and skips cleanly when
it is absent, e.g. in CI).

If you use VS Code / Dev Containers, the `.devcontainer/` here provisions the SDK, Docker and Python
for you, so `make quality` works on first boot.

The Windows-only parts (credential provider, MSI, end-to-end sign-in) are built and tested in the
QEMU VMs described in `README.md` (`vm/build-in-vm.sh`, `tests/acceptance/run.sh`,
`tests/server/run.sh`). You do not need them for most changes to `Weldap.Core` or the server.

## Continuous integration

`.github/workflows/ci.yml` runs the host gates — `lint`, `client`, `server` and `supply-chain`
(cargo-deny) — on every push and pull request, each job calling `tests/quality.sh` with the same gate
names you run locally. CI restores NuGet packages in locked mode (`packages.lock.json`), so a
dependency change must be committed with its refreshed lock file. Dependabot keeps the Cargo, NuGet,
GitHub Actions and Docker base-image versions current; its PRs go through the same gates.

## Pull requests

- Keep PRs focused. Explain the security reasoning for anything touching the password path.
- Run `make quality` locally first; CI runs the same gates.
- By contributing you agree your contribution is licensed under the project's MIT License.

## Security

Do not report vulnerabilities in public issues or PRs — see `SECURITY.md`.
