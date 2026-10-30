#!/usr/bin/env bash
# Code-quality gate for the C# client (macOS/Linux host; bash 3.2 compatible). Exits non-zero on any failure:
#   1. Weldap.Core (AnalysisLevel latest-all), Weldap.Service (Windows target, built here too) and the tests
#      build with zero warnings (TreatWarningsAsErrors in Directory.Build.props, -warnaserror here as well).
#   2. dotnet format --verify-no-changes (/.editorconfig) on all three projects.
#   3. The unit tests pass, and Weldap.Core coverage is at least MIN_LINE % of lines and MIN_BRANCH % of branches.
# All platform-neutral login logic lives in Weldap.Core and is held to 100/100 here. Weldap.Service is the thin
# Windows shell (P/Invoke, sockets/TLS open, registry, event log, named pipe); it has no host-runnable unit tests
# and is exercised only by the on-VM acceptance suite (tests/acceptance/run.sh). This script lists those files so
# the gap is explicit, not hidden.
# Usage: client/check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
command -v dotnet >/dev/null || export PATH="$HOME/.dotnet:$PATH"

MIN_LINE=100
MIN_BRANCH=100
CORE=client/Weldap.Core/Weldap.Core.csproj
SERVICE=client/Weldap.Service/Weldap.Service.csproj
TESTS=tests/Weldap.Core.Tests/Weldap.Core.Tests.csproj

step() { printf '\n== %s\n' "$*"; }

results=$(mktemp -d "${TMPDIR:-/tmp}/weldap-check.XXXXXX")
trap 'rm -rf "$results"' EXIT

step "build (warnings are errors)"
for project in "$CORE" "$SERVICE" "$TESTS"; do
    dotnet build "$project" -c Release --no-incremental -warnaserror --nologo -v q
done

step "format"
for project in "$CORE" "$SERVICE" "$TESTS"; do
    dotnet format "$project" --verify-no-changes --no-restore
done

step "test + coverage"
dotnet test "$TESTS" -c Release --no-build --nologo \
    --settings tests/Weldap.Core.Tests/coverage.runsettings \
    --collect:"XPlat Code Coverage" --results-directory "$results"

report=$(find "$results" -name coverage.cobertura.xml | head -n 1)
[[ -n "$report" ]] || { echo "error: no coverage report produced" >&2; exit 1; }

step "coverage thresholds (Weldap.Core: lines >= $MIN_LINE %, branches >= $MIN_BRANCH %)"
python3 -I - "$report" "$MIN_LINE" "$MIN_BRANCH" <<'PY'
import sys
import xml.etree.ElementTree as ET

report, min_line, min_branch = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
packages = [p for p in ET.parse(report).getroot().iter("package") if p.get("name") == "Weldap.Core"]
if len(packages) != 1:
    sys.exit("error: Weldap.Core not found exactly once in the coverage report")
line = 100 * float(packages[0].get("line-rate"))
branch = 100 * float(packages[0].get("branch-rate"))
print(f"Weldap.Core: lines {line:.2f} %, branches {branch:.2f} %")
failed = [f"{name} coverage {got:.2f} % < {want:g} %"
          for name, got, want in (("line", line, min_line), ("branch", branch, min_branch)) if got < want]
for f in failed:
    print(f"error: {f}", file=sys.stderr)
sys.exit(1 if failed else 0)
PY

step "Weldap.Service: Windows-only, covered by the acceptance suite (tests/acceptance/run.sh) only"
# Everything host-runnable is in Weldap.Core (100/100 above). These files touch Windows APIs that cannot run on
# the macOS/Linux host, so they have no unit tests here; the on-VM acceptance suite exercises them end to end.
for f in client/Weldap.Service/*.cs; do
    printf '      %s\n' "$f"
done

step "all checks passed"
