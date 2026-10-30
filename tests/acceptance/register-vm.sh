#!/usr/bin/env bash
# Register a test VM for WELDAP device trust, playing Fleet and the device CA:
#   tests/acceptance/register-vm.sh <vm1|vm2>             key + CSR in the guest -> signed by the test device CA
#                                                          (weldap-ca) -> certificate installed in the guest
#   tests/acceptance/register-vm.sh <vm1|vm2> --revoke    revoke its certificate (new CRL; the server reloads it)
# The private key is generated in the guest and never leaves it; only the CSR and certificate move. Devices hold
# no directory credentials at all: only the server talks to the directory.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
VM="${1:?usage: register-vm.sh <vm1|vm2> [--revoke]}"
R='C:\ProgramData\WELDAP\registration'
vps() { vm/vmctl.sh ps "$VM" "$1"; }

dev="$(vps '$env:COMPUTERNAME.ToLowerInvariant()' | tr -d '\r\n')"
[[ "$dev" =~ ^[a-z0-9-]+$ ]] || { echo "could not read the guest's computer name ($dev)" >&2; exit 1; }

if [[ "${2:-}" == --revoke ]]; then
    testdir/device-ca.sh revoke "$dev"
    exit 0
fi

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
vps "New-Item -ItemType Directory -Force -Path '$R' | Out-Null" >/dev/null
vm/vmctl.sh push "$VM" installer/fleet/register-device.ps1 "$R\\register-device.ps1"
out="$(vps "& '$R\\register-device.ps1' -NewRequest" | tr -d '\r')"
echo "guest: $out"
csr="$(sed -n 's/^csr=\([^ ]*\) .*/\1/p' <<<"$out")"
[[ -n "$csr" ]] || { echo "no CSR from the guest" >&2; exit 1; }
vm/vmctl.sh pull "$VM" "$csr" "$work/device.csr"
testdir/device-ca.sh sign "$work/device.csr" "$dev"
vm/vmctl.sh push "$VM" "testdir/pki/devices/$dev.crt" "$R\\$dev.crt"
vps "& '$R\\register-device.ps1' -Accept '$R\\$dev.crt'" | tr -d '\r'
echo "registered $dev"
