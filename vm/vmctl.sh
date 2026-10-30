#!/usr/bin/env bash
# Host-side control for the WELDAP sign-in test VMs (headless QEMU on Apple Silicon).
#
#   vm/vmctl.sh iso      <vm1|vm2>          render autounattend + build the provision ISO
#   vm/vmctl.sh create   <vm1|vm2>          blank disk + UEFI vars in vm/vms/<name>/
#   vm/vmctl.sh up       <vm1|vm2>          iso + create + start + wait for provisioning + snapshot "clean-os"
#   vm/vmctl.sh provision <vm1|vm2>         resume "up" on an existing VM (wait, build tools, snapshot)
#   vm/vmctl.sh start|stop|kill|status <vm1|vm2>
#   vm/vmctl.sh wait     <vm1|vm2> [file]   wait until the guest agent answers and [file] exists in the guest
#   vm/vmctl.sh exec     <vm1|vm2> <script> run vm/provision/<script>.ps1 in the guest as SYSTEM
#   vm/vmctl.sh ps       <vm1|vm2> <cmd>    run a PowerShell one-liner in the guest as SYSTEM
#   vm/vmctl.sh push     <vm1|vm2> <local> <guest-path>
#   vm/vmctl.sh pull     <vm1|vm2> <guest-path> <local>
#   vm/vmctl.sh screen   <vm1|vm2> [out.png] screenshot of the guest display
#   vm/vmctl.sh keys     <vm1|vm2> <text> [--enter] [--us]  type on the guest keyboard
#   vm/vmctl.sh click    <vm1|vm2> <x> <y>  left-click at a pixel of the last screenshot
#   vm/vmctl.sh snap     <vm1|vm2> <name>   shut down + disk snapshot (VM left stopped)
#   vm/vmctl.sh restore  <vm1|vm2> <name>   (VM must be stopped)
#   vm/vmctl.sh snaps    <vm1|vm2>          list snapshots
#   vm/vmctl.sh password <vm1|vm2>          print the break-glass password
#
# No listening ports anywhere: QEMU has no VNC/SPICE/monitor port, the control channels are
# unix sockets in vm/vms/<name>/ (mode 700), and the guest NIC is user-mode NAT (outbound only).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
# shellcheck source=config.env
source "${VM_CONFIG:-vm/config.env}"
FW=/opt/homebrew/share/qemu

die() { echo "error: $*" >&2; exit 1; }

load_vm() {
    case "${1:-}" in
        vm1|"$VM1_NAME") P=VM1 ;;
        vm2|"$VM2_NAME") P=VM2 ;;
        *) die "unknown VM '${1:-}' (use vm1 or vm2)" ;;
    esac
    for k in NAME ARCH ISO EDITION COMPUTER MEMORY CPUS DISK BUILD_TOOLS UI_LANGUAGE; do
        eval "$k=\"\${${P}_${k}}\""
    done
    SECRET="vm/.secrets/$NAME.breakglass"
    PROV_ISO="$REPO/vm/build/$NAME-provision.iso"
    DIR="$REPO/vm/vms/$NAME"
    QMP="$DIR/qmp.sock"
    QGA="$DIR/qga.sock"
}

qctl() { python3 -I "$REPO/vm/qctl.py" "$@"; }

breakglass_password() {
    if [[ ! -s "$SECRET" ]]; then
        umask 077
        # 20 random alphanumerics + a fixed tail so it satisfies any complexity policy.
        printf '%s-Pp9\n' "$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-20)" >"$SECRET"
    fi
    tr -d '\n' <"$SECRET"
}

cmd_iso() {
    [[ -s "$GUEST_TOOLS_ISO" ]] || curl -fL -o "$GUEST_TOOLS_ISO" "$GUEST_TOOLS_URL"
    local arch drv_arch drv_os stage mnt pw
    if [[ "$ARCH" == aarch64 ]]; then arch=arm64; drv_arch=ARM64; else arch=amd64; drv_arch=amd64; fi
    if [[ "$EDITION" == *"Windows 11"* ]]; then drv_os=w11; else drv_os=w10; fi
    pw="$(breakglass_password)"
    stage="$REPO/vm/build/$NAME-stage"
    mnt="$REPO/vm/build/$NAME-gt"
    rm -rf "$stage"; mkdir -p "$stage" "$mnt"

    hdiutil attach -nobrowse -readonly -mountpoint "$mnt" "$GUEST_TOOLS_ISO" >/dev/null 2>&1 \
        || die "could not attach $GUEST_TOOLS_ISO"
    cp "$mnt"/utm-guest-tools-*.exe "$stage/"
    mkdir -p "$stage/Drivers"
    for d in NetKVM vioserial viostor viorng Balloon; do
        mkdir -p "$stage/Drivers/$d/$drv_os"
        cp -R "$mnt/Drivers/$d/$drv_os/$drv_arch" "$stage/Drivers/$d/$drv_os/"
    done
    hdiutil detach "$mnt" >/dev/null 2>&1 || true
    rmdir "$mnt" 2>/dev/null || true
    cp vm/provision/provision.ps1 "$stage/"

    sed -e "s|@@ARCH@@|$arch|g" \
        -e "s|@@DRV_ARCH@@|$drv_arch|g" \
        -e "s|@@DRV_OS@@|$drv_os|g" \
        -e "s|@@EDITION@@|$EDITION|g" \
        -e "s|@@COMPUTER@@|$COMPUTER|g" \
        -e "s|@@UI_LANGUAGE@@|$UI_LANGUAGE|g" \
        -e "s|@@INPUT_LOCALE@@|$INPUT_LOCALE|g" \
        -e "s|@@USER_LOCALE@@|$USER_LOCALE|g" \
        -e "s|@@TIME_ZONE@@|$TIME_ZONE|g" \
        -e "s|@@BREAKGLASS_USER@@|$BREAKGLASS_USER|g" \
        -e "s|@@BREAKGLASS_PASSWORD@@|$pw|g" \
        vm/autounattend.xml.tmpl >"$stage/Autounattend.xml"
    chmod 600 "$stage/Autounattend.xml"
    grep -q '@@' "$stage/Autounattend.xml" && die "unrendered placeholder in Autounattend.xml"

    rm -f "$PROV_ISO"
    hdiutil makehybrid -quiet -iso -joliet -default-volume-name WELDAPPROV -o "$PROV_ISO" "$stage"
    chmod 600 "$PROV_ISO"
    rm -rf "$stage"
    echo "built $PROV_ISO"
}

cmd_create() {
    [[ -s "$ISO" ]] || die "missing Windows ISO: $REPO/$ISO"
    [[ -s "$PROV_ISO" ]] || cmd_iso
    [[ -e "$DIR/disk.qcow2" ]] && die "VM $NAME already exists ($DIR); remove it first"
    mkdir -p "$DIR/snapshots"; chmod 700 "$DIR"
    if [[ "$ARCH" == aarch64 ]]; then
        cp "$FW/edk2-arm-vars.fd" "$DIR/vars.fd"
    else
        cp "$FW/edk2-i386-vars.fd" "$DIR/vars.fd"
    fi
    qemu-img create -q -f qcow2 "$DIR/disk.qcow2" "${DISK}M"
    echo "created $DIR"
}

is_running() {
    [[ -f "$DIR/qemu.pid" ]] && kill -0 "$(cat "$DIR/qemu.pid")" 2>/dev/null
}

cmd_status() { if is_running; then echo running; elif [[ -e "$DIR/disk.qcow2" ]]; then echo stopped; else echo absent; fi; }

cmd_start() {
    is_running && { echo "$NAME already running"; return 0; }
    [[ -e "$DIR/disk.qcow2" ]] || die "$NAME not created"
    local -a q
    # p2/p3=8: with the default 4 ports QEMU chains a 12 Mbit/s USB 1.1 hub onto the last one, and a
    # CD behind it reads at ~1 MB/s. Disk first, then the Windows ISO: a blank disk falls through to Setup, an installed one boots.
    # (CD first makes the firmware rewrite BootOrder on every boot and lose Windows Boot Manager.)
    if [[ "$ARCH" == aarch64 ]]; then
        # QEMU's own GICv3 + ITS, not Apple's in-kernel vGIC: that has no ITS, so Windows gets no MSIs
        # and only sees finished I/O on its 15.6 ms clock tick (~3 MB/s from CD, everything slow).
        # shellcheck disable=SC2054  # commas separate QEMU sub-options, not array elements
        q=(qemu-system-aarch64 -M virt,highmem=on,gic-version=3,its=on,msi=its -accel hvf,kernel-irqchip=off -cpu host
           -drive "if=pflash,format=raw,readonly=on,file=$FW/edk2-aarch64-code.fd"
           -device ramfb
           -device qemu-xhci,id=xhci,p2=8,p3=8 -device usb-kbd -device usb-tablet
           -drive "if=none,id=cd0,media=cdrom,readonly=on,file=$REPO/$ISO" -device usb-storage,drive=cd0,bootindex=1
           -drive "if=none,id=cd1,media=cdrom,readonly=on,file=$PROV_ISO" -device usb-storage,drive=cd1)
    else
        # shellcheck disable=SC2054  # commas separate QEMU sub-options, not array elements
        q=(qemu-system-x86_64 -M q35 -accel tcg,thread=multi,tb-size=1024 -cpu max
           -drive "if=pflash,format=raw,readonly=on,file=$FW/edk2-x86_64-code.fd"
           -vga std
           -device qemu-xhci,id=xhci,p2=8,p3=8 -device usb-kbd -device usb-tablet
           -drive "if=none,id=cd0,media=cdrom,readonly=on,file=$REPO/$ISO" -device ide-cd,drive=cd0,bus=ide.0,bootindex=1
           -drive "if=none,id=cd1,media=cdrom,readonly=on,file=$PROV_ISO" -device ide-cd,drive=cd1,bus=ide.1)
    fi
    # shellcheck disable=SC2054  # commas separate QEMU sub-options, not array elements
    q+=(-name "$NAME" -smp "$CPUS" -m "$MEMORY" -rtc base=localtime
        -drive "if=pflash,format=raw,file=$DIR/vars.fd"
        -drive "if=none,id=hd0,format=qcow2,discard=unmap,file=$DIR/disk.qcow2" -device nvme,drive=hd0,serial=ppe0,bootindex=0
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile=
        -device virtio-serial-pci
        -chardev "socket,id=qga0,path=$QGA,server=on,wait=off"
        -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0
        -qmp "unix:$QMP,server=on,wait=off"
        -display none -pidfile "$DIR/qemu.pid")
    # Debug hook, e.g. QEMU_EXTRA='-no-reboot -action shutdown=pause' freezes the last screen.
    # shellcheck disable=SC2206
    [[ -n "${QEMU_EXTRA:-}" ]] && q+=($QEMU_EXTRA)
    rm -f "$QMP" "$QGA"
    nohup "${q[@]}" >"$DIR/qemu.log" 2>&1 </dev/null &
    for _ in $(seq 1 30); do
        [[ -S "$QMP" ]] && is_running && { echo "$NAME started (log $DIR/qemu.log)"; return 0; }
        sleep 1
    done
    cat "$DIR/qemu.log" >&2
    die "$NAME did not start"
}

# Clean shutdown via ACPI; waits up to 5 min. `kill` is the hard stop.
cmd_stop() {
    is_running || return 0
    qctl qmp "$QMP" system_powerdown >/dev/null || true
    local deadline=$((SECONDS + 300))
    while is_running; do
        ((SECONDS < deadline)) || die "$NAME did not shut down (vm/vmctl.sh kill $NAME to force)"
        sleep 3
    done
    echo "$NAME stopped"
}

cmd_kill() {
    is_running || return 0
    qctl qmp "$QMP" quit >/dev/null 2>&1 || kill "$(cat "$DIR/qemu.pid")"
    sleep 2
    echo "$NAME killed"
}

# Windows ISOs wait ~5 s for "Press any key to boot from CD"; keep pressing through that window.
# The key is "z", not space: WinPE is up within seconds under hvf, and space (or Enter, or a
# button's mnemonic) would hit the focused Cancel button on Setup's progress screen.
press_to_boot() {
    for _ in $(seq 1 25); do
        qctl qmp "$QMP" send-key '{"keys":[{"type":"qcode","data":"z"}]}' >/dev/null 2>&1 || true
        sleep 1
    done
}

# Run a PowerShell command in the guest as SYSTEM via the guest agent; prints stdout,
# prints stderr to stderr, returns the guest exit code (1 if the agent is unreachable).
# The command travels as -EncodedCommand, so quoting needs no care.
guest_ps() {
    local enc raw code
    enc="$(printf '%s' "\$ProgressPreference = 'SilentlyContinue'; $1" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n')"
    raw="$(qctl qga "$QGA" exec "${GUEST_TIMEOUT:-600}" powershell.exe \
        -NoProfile -NonInteractive -OutputFormat Text -ExecutionPolicy Bypass -EncodedCommand "$enc" 2>&1)" || {
        echo "guest agent error: $raw" >&2; return 1; }
    code="${raw%%$'\n'*}"
    raw="${raw#*$'\n'}"
    printf '%s' "${raw%%$'\n'--WELDAP-STDERR--*}" | tr -d '\r'
    local err="${raw#*--WELDAP-STDERR--}"
    # PowerShell serialises errors as CLIXML on a redirected stderr: print just the error text.
    if [[ "$err" == *"#< CLIXML"* ]]; then
        err="$(printf '%s' "$err" | python3 -I -c 'import re,sys,html; t=sys.stdin.read(); print("".join(html.unescape(m) for m in re.findall(r"<S S=\"Error\">(.*?)</S>", t, re.S)).replace("_x000D__x000A_", "\n").rstrip())')"
    fi
    [[ -n "${err//[$'\r\n ']/}" ]] && printf '%s\n' "$err" | tr -d '\r' >&2
    [[ "$code" =~ ^[0-9]+$ ]] || return 1
    return "$code"
}

# True only if the guest agent answers and the PowerShell condition is true.
guest_test() {
    qctl qga "$QGA" ping >/dev/null 2>&1 || return 1
    GUEST_TIMEOUT=60 guest_ps "if ($1) { exit 0 } else { exit 3 }" >/dev/null 2>&1
}

cmd_wait() {
    local file="${1:-}" deadline=$((SECONDS + ${WAIT_TIMEOUT:-7200}))
    echo "waiting for $NAME guest agent${file:+ and $file}..."
    while ((SECONDS < deadline)); do
        is_running || die "$NAME is not running"
        local cond='$true' msg='agent up'
        [[ -n "$file" ]] && { cond="Test-Path '$file'"; msg="found $file"; }
        if guest_test "$cond"; then
            echo "$msg"; return 0
        fi
        sleep 30
    done
    die "timed out waiting for $NAME"
}

# The provision ISO is rebuilt only when its inputs changed (parallel `up`s then don't race on hdiutil).
iso_stale() {
    local f
    [[ -s "$PROV_ISO" ]] || return 0
    for f in vm/autounattend.xml.tmpl vm/provision/provision.ps1 vm/config.env "$GUEST_TOOLS_ISO" "$SECRET"; do
        [[ "$f" -nt "$PROV_ISO" ]] && return 0
    done
    return 1
}

cmd_up() {
    if iso_stale; then cmd_iso; fi
    cmd_create
    cmd_start
    press_to_boot
    echo "Windows setup is unattended; watch it with: vm/vmctl.sh screen $NAME"
    cmd_provision
}

# Everything after the VM is booted; safe to re-run on an existing VM.
cmd_provision() {
    cmd_wait 'C:\ProgramData\WELDAP-Provision\done.txt'
    # Provisioning reboots the guest; wait for the agent to come back at the logon screen.
    sleep 60
    cmd_wait
    if [[ "$BUILD_TOOLS" == 1 ]] && ! guest_test "Test-Path 'C:\ProgramData\WELDAP-Provision\build-tools.done'"; then
        cmd_exec_bg build-tools
        cmd_wait 'C:\ProgramData\WELDAP-Provision\build-tools.done'
    fi
    cmd_snap clean-os
    cmd_start
    echo "$NAME ready; snapshot 'clean-os' taken, VM restarted"
}

# Offline internal qcow2 snapshot plus a copy of the UEFI variables. Leaves the VM stopped.
cmd_snap() {
    cmd_stop
    qemu-img snapshot -d "$1" "$DIR/disk.qcow2" 2>/dev/null || true
    qemu-img snapshot -c "$1" "$DIR/disk.qcow2"
    cp "$DIR/vars.fd" "$DIR/snapshots/$1.vars"
    echo "snapshot $1 taken"
}

cmd_restore() {
    is_running && die "$NAME is running; stop it first"
    qemu-img snapshot -a "$1" "$DIR/disk.qcow2"
    [[ -f "$DIR/snapshots/$1.vars" ]] && cp "$DIR/snapshots/$1.vars" "$DIR/vars.fd"
    echo "restored $1"
}

cmd_screen() {
    local out="${1:-$REPO/vm/build/$NAME-screen.png}"
    mkdir -p "$(dirname "$out")"
    qctl qmp "$QMP" screendump "{\"filename\":\"$out\",\"format\":\"png\"}" >/dev/null
    echo "$out"
}

cmd_push() { qctl qga "$QGA" push "$1" "$2"; }
cmd_pull() { qctl qga "$QGA" pull "$1" "$2"; }

push_script() {
    local script="vm/provision/$1.ps1"
    [[ -f "$script" ]] || die "no such script: $script"
    guest_ps "New-Item -ItemType Directory -Force -Path 'C:\\ProgramData\\WELDAP-Provision' | Out-Null" >/dev/null \
        || die "guest agent not available on $NAME"
    cmd_push "$script" "C:\\ProgramData\\WELDAP-Provision\\$1.ps1"
}

cmd_exec() {
    push_script "$1"
    guest_ps "& 'C:\\ProgramData\\WELDAP-Provision\\$1.ps1'"
}

# Long-running scripts (installers): start detached so the agent call returns at once.
cmd_exec_bg() {
    push_script "$1"
    guest_ps "Start-Process powershell.exe -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\\ProgramData\\WELDAP-Provision\\$1.ps1'" \
        || die "could not start $1 on $NAME"
}

sub="${1:-}"; shift || true
[[ -n "$sub" && "$sub" != -h && "$sub" != help ]] || { sed -n '2,26p' "$0"; exit 1; }
load_vm "${1:-}"; shift || true
case "$sub" in
    iso)      cmd_iso ;;
    create)   cmd_create ;;
    up)       cmd_up ;;
    provision) cmd_provision ;;
    start)    cmd_start ;;
    stop)     cmd_stop ;;
    kill)     cmd_kill ;;
    status)   cmd_status ;;
    wait)     cmd_wait "${1:-}" ;;
    exec)     cmd_exec "${1:?script name}" ;;
    ps)       guest_ps "${1:?command}" ;;
    push)     cmd_push "${1:?local}" "${2:?guest path}" ;;
    pull)     cmd_pull "${1:?guest path}" "${2:?local}" ;;
    screen)   cmd_screen "${1:-}" ;;
    keys)     qctl keys "$QMP" "${1:?text}" "${@:2}" ;;
    click)    qctl click "$QMP" "${1:?x}" "${2:?y}" ;;
    snap)     cmd_snap "${1:?name}" ;;
    restore)  cmd_restore "${1:?name}" ;;
    snaps)    qemu-img snapshot -l -U "$DIR/disk.qcow2" ;;
    password) breakglass_password; echo ;;
    *) sed -n '2,25p' "$0"; exit 1 ;;
esac
