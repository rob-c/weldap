#!/usr/bin/env bash
# Build the Windows-only parts in vm1 and bring them back:
#   vm/build-in-vm.sh            -> out/msi/Weldap-{x64,arm64}.msi, out/provider-{x64,ARM64}/WeldapCredentialProvider.dll
# Publishes the service on the host first (./build.sh --no-test), copies the sources in as a zip
# over the guest agent, runs vm/provision/build-msi.ps1 there as SYSTEM, then pulls the results.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
VM=vm1
G='C:\src\windev'

# SKIP_PUBLISH=1 reuses out/service-* as they are (e.g. while an acceptance run is reading them).
[[ -n "${SKIP_PUBLISH:-}" ]] || ./build.sh --no-test >/dev/null
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
zip -qr "$work/src.zip" client installer tests/cp-harness vm/provision/build-msi.ps1 global.json Directory.Build.props \
    out/service-win-x64 out/service-win-arm64 out/admin-win-x64 out/admin-win-arm64 \
    -x '*/bin/*' '*/obj/*' 'client/Weldap.CredentialProvider/out/*' '*.DS_Store'
# WELDAP_TILE_IMAGE (a host path) swaps the picture on the logon tile: shipped beside the sources and handed to the
# provider build (build.ps1 -TileImage checks and normalises it). Unset = the default, art/tile.bmp.
if [[ -n "${WELDAP_TILE_IMAGE:-}" ]]; then
    [[ -f "$WELDAP_TILE_IMAGE" ]] || { echo "WELDAP_TILE_IMAGE: no such file: $WELDAP_TILE_IMAGE" >&2; exit 1; }
    mkdir -p "$work/branding"
    cp "$WELDAP_TILE_IMAGE" "$work/branding/tile-image"
    (cd "$work" && zip -qr src.zip branding)
fi

vm/vmctl.sh ps "$VM" "Remove-Item -Recurse -Force '$G' -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path '$G' | Out-Null" >/dev/null
vm/vmctl.sh push "$VM" "$work/src.zip" "$G\\src.zip"
vm/vmctl.sh ps "$VM" "Expand-Archive -Force '$G\\src.zip' '$G'; Remove-Item '$G\\src.zip'" >/dev/null

# Pass any WELDAP_SIGN_* set on the host into the guest session so build-msi.ps1 signs the binaries and the MSI
# (and pins over the signed bytes). Unset = unsigned dev build, exactly as build-msi.ps1 documents.
sign_prelude=""
for v in WELDAP_SIGN_THUMBPRINT WELDAP_SIGN_PFX WELDAP_SIGN_PFX_PASSWORD WELDAP_SIGN_TIMESTAMP_URL; do
    if [[ -n "${!v:-}" ]]; then
        val="${!v//\'/\'\'}" # single-quote the value for PowerShell, doubling any embedded quote
        sign_prelude+="\$env:$v='$val'; "
    fi
done
[[ -z "${WELDAP_TILE_IMAGE:-}" ]] || sign_prelude+="\$env:WELDAP_TILE_IMAGE='$G\\branding\\tile-image'; "
GUEST_TIMEOUT=2400 vm/vmctl.sh ps "$VM" "$sign_prelude& '$G\\vm\\provision\\build-msi.ps1' -Root '$G'"

mkdir -p out/msi out/provider-x64 out/provider-ARM64
for f in Weldap-x64.msi Weldap-arm64.msi; do
    vm/vmctl.sh pull "$VM" "$G\\artifacts\\$f" "out/msi/$f"
done
for p in x64 ARM64; do
    vm/vmctl.sh pull "$VM" "$G\\artifacts\\provider-$p\\WeldapCredentialProvider.dll" "out/provider-$p/WeldapCredentialProvider.dll"
done
ls -l out/msi out/provider-*
