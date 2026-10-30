#!/usr/bin/env bash
# Every quality gate that runs on a Mac/Linux host (no Windows, no VMs), in one place -- so a local run and CI
# run the exact same checks. Exits non-zero if any selected gate fails; prints a PASS/FAIL/SKIP summary.
#
#   tests/quality.sh                 run every host gate (the default set below)
#   tests/quality.sh --fast          quick gates only: no build, no Docker heavy lifting
#   tests/quality.sh <gate>...        run only the named gates (CI runs them as separate, parallel jobs)
#
# Gates (bullets keep shellcheck from reading a gate name as one of its own directives):
#   - paranoia    no secret can reach a log, at any level          (tests/lint/paranoia.sh)
#   - budget      per-component code-size budget                   (tests/lint/budget.py)
#   - protocol    pipe/seal constants agree across C++/C#/Rust     (tests/surface/protocol-consistency.py)
#   - shellcheck  every shell script, pinned linter, in Docker
#   - client      C#: build (warnings=errors), format, tests, Weldap.Core 100/100 coverage  (client/check.sh)
#   - server      Rust: unsafe confinement, fmt, clippy pedantic, tests, 100/100 coverage   (server/check.sh, Docker)
#   - deny        cargo-deny: advisories, licences, bans, sources of the server's deps (Docker; needs network)
#   - imports     the credential-provider DLL links no networking library (needs out/provider-*; SKIP if absent)
#
# `deny` is defined but not in the default set (it needs the network for the advisory DB); CI runs it as its own
# job, and you can run it locally with `tests/quality.sh deny`. The Windows-only checks (MSVC /analyze, the C++
# harness, end-to-end acceptance, the MSI) run in the VMs -- see README.md.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DEFAULT=(paranoia budget protocol shellcheck client server imports)
QUICK=(paranoia budget protocol)
KNOWN="paranoia budget protocol shellcheck client server deny imports"

selected=()
for arg in "$@"; do
    case "$arg" in
        --fast) selected+=("${QUICK[@]}") ;;
        -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
        paranoia|budget|protocol|shellcheck|client|server|deny|imports) selected+=("$arg") ;;
        *) echo "unknown gate '$arg' (known: $KNOWN)" >&2; exit 2 ;;
    esac
done
[ ${#selected[@]} -eq 0 ] && selected=("${DEFAULT[@]}")

# --- gate implementations -------------------------------------------------------------------------------------

gate_paranoia() { tests/lint/paranoia.sh; }
gate_budget()   { python3 -I tests/lint/budget.py; }
gate_protocol() { python3 -I tests/surface/protocol-consistency.py; }
gate_client()   { client/check.sh; }
gate_server()   { server/check.sh; }

gate_shellcheck() {
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(find . -name '*.sh' -not -path './vm/cache/*' -not -path './vm/vms/*' \
        -not -path './out/*' -not -path '*/target/*' | sort)
    docker run --rm -v "$PWD:/mnt:ro" -w /mnt koalaman/shellcheck:v0.10.0 -x -S warning -f gcc "${files[@]}" server/weldap-ca
}

# The provider DLL is a Windows build artefact (vm/build-in-vm.sh). If it is not present there is nothing to
# inspect, so SKIP rather than fail -- a host or CI runner without the Windows build still passes cleanly. When
# the DLL *is* present it is checked strictly: it must not link any networking library into LogonUI.
gate_imports() {
    local dll found=0
    for dll in out/provider-x64/WeldapCredentialProvider.dll out/provider-ARM64/WeldapCredentialProvider.dll; do
        [[ -f "$dll" ]] || continue
        found=1
        python3 -I tests/surface/pe-imports.py "$dll" || return 1
    done
    ((found)) || { echo "no provider DLL in out/ (build with vm/build-in-vm.sh) -- nothing to check"; return 3; }
}

# cargo-deny against the server's locked dependency graph, in a pinned Rust container. The installed binary is
# cached in a named volume so only the first run pays for the build.
gate_deny() {
    docker run --rm -v "$REPO/server:/src:ro" -w /src -v weldap-cargo-deny:/usr/local/cargo \
        rust:1.99-bookworm bash -c '
            set -euo pipefail
            want=0.20.2
            have="$(cargo-deny --version 2>/dev/null | cut -d" " -f2 || true)"
            [ "$have" = "$want" ] || cargo install cargo-deny --version "$want" --locked --force
            cargo deny --manifest-path Cargo.toml check advisories bans licenses sources
        '
}

# --- run ------------------------------------------------------------------------------------------------------

results=()
for name in "${selected[@]}"; do
    echo; echo "######## $name"
    rc=0
    "gate_$name" || rc=$?
    case $rc in
        0) results+=("PASS  $name") ;;
        3) results+=("SKIP  $name") ;;
        *) results+=("FAIL  $name") ;;
    esac
done

echo; echo "######## summary"
printf '%s\n' "${results[@]}"
! printf '%s\n' "${results[@]}" | grep -q '^FAIL'
