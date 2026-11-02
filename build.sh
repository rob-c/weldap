#!/usr/bin/env bash
# Host-side build (macOS or Linux): unit tests, then the service for both Windows architectures
# into out/. The credential provider and the MSIs need MSVC/WiX and
# are built in vm1 (client/Weldap.CredentialProvider/build.ps1, installer/Weldap.wixproj).
#   ./build.sh            test + publish
#   ./build.sh --no-test  publish only
set -euo pipefail
cd "$(dirname "$0")"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
command -v dotnet >/dev/null || export PATH="$HOME/.dotnet:$PATH"

[[ "${1:-}" == --no-test ]] || dotnet test tests/Weldap.Core.Tests -c Release --nologo -v q

for rid in win-x64 win-arm64; do
    for project in Weldap.Service Weldap.Admin; do
        out="out/$([[ $project == Weldap.Service ]] && echo service || echo admin)-$rid"
        rm -rf "$out"
        dotnet publish "client/$project" -c Release -r "$rid" -o "$out" --nologo -v q
        # Ship no debug symbols: drop PDBs from referenced projects (Weldap.Core keeps its PDB only at build/test
        # time, for coverage). The MSI harvests the exe explicitly, never a PDB; this keeps the staging clean too.
        find "$out" -name '*.pdb' -delete
    done
done
# The MSI and install-dev.ps1 both expect the event-log message DLL beside the service exe.
for rid in win-x64 win-arm64; do
    [[ -f "out/service-$rid/System.Diagnostics.EventLog.Messages.dll" ]] \
        || { echo "error: out/service-$rid is missing System.Diagnostics.EventLog.Messages.dll" >&2; exit 1; }
    # Ship no debug symbols: a .pdb in the published output is a build error.
    pdbs="$(find "out/service-$rid" "out/admin-$rid" -name '*.pdb')"
    [[ -z "$pdbs" ]] || { echo "error: debug symbols in published output:" >&2; echo "$pdbs" >&2; exit 1; }
done
ls -l out/service-*/ out/admin-*/
