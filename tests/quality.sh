#!/usr/bin/env bash
# Every quality gate that runs on the Mac, in one go. Exits non-zero if any gate fails; prints a summary.
#   tests/quality.sh            all gates
#   tests/quality.sh --fast     skip the coverage-instrumented runs (client and server still build and test)
# Gates: paranoia lint, code-size budget, shellcheck, client (C#: build, format, analyzers, tests, coverage),
# server (Rust: fmt, clippy pedantic, tests, coverage, unsafe confinement), and the credential provider's
# import table (no networking DLL may ever be linked into LogonUI). Windows-only checks (MSVC /analyze, the
# C++ harness, acceptance) run in the VMs: see README.md.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
export FAST="${1:-}"
results=()

gate() {   # gate <name> <command...>
    local name="$1"; shift
    echo; echo "######## $name"
    if "$@"; then results+=("PASS  $name"); else results+=("FAIL  $name"); fi
}

shellcheck_all() {
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(find . -name '*.sh' -not -path './vm/cache/*' -not -path './vm/vms/*' \
        -not -path './out/*' -not -path '*/target/*' | sort)
    docker run --rm -v "$PWD:/mnt:ro" -w /mnt koalaman/shellcheck:v0.10.0 -x -S warning -f gcc "${files[@]}" server/weldap-ca
}

pe_imports() {
    local dll found=0
    for dll in out/provider-x64/WeldapCredentialProvider.dll out/provider-ARM64/WeldapCredentialProvider.dll; do
        [[ -f "$dll" ]] || continue
        found=1
        python3 tests/surface/pe-imports.py "$dll" || return 1
    done
    ((found)) || { echo "no provider DLL in out/ (run vm/build-in-vm.sh)"; return 1; }
}

gate "paranoia lint"                 tests/lint/paranoia.sh
gate "code-size budget"              python3 tests/lint/budget.py
gate "shellcheck"                    shellcheck_all
gate "client (C#)"                   client/check.sh
gate "server (Rust)"                 server/check.sh
gate "credential provider imports"   pe_imports

echo; echo "######## summary"
printf '%s\n' "${results[@]}"
! printf '%s\n' "${results[@]}" | grep -q '^FAIL'
