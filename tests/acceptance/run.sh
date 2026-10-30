#!/usr/bin/env bash
# WELDAP end-to-end acceptance on a test VM, driven from the Mac:
#   tests/acceptance/run.sh <vm1|vm2> [--no-install]
# Client (VM): registered device certificate, WELDAP service (install-dev.ps1) and the credential provider's own
# sealing code (WeldapClientTest.exe, built from WeldapClient.cpp + WeldapSeal.cpp) talking to the real pipe.
# Server: testdir's WELDAP server + 389 DS. Offline cases stop the server or the directory.
# The password goes in sealed; the suite then checks that the device never had it: Windows rejects it for the
# local account, the secrets at rest are DPAPI blobs without it, and the service's and LSASS's memory lack it.
# It also checks the client's surface: no listening ports, a SYSTEM-only local pipe that drops anything malformed,
# and a server trusted by its key pin alone.
# Needs: testdir/up.sh, ./build.sh, and the harness built in the VM (vm/build-in-vm.sh, tests/cp-harness/build.ps1).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"
VM="${1:?usage: run.sh <vm1|vm2> [--no-install]}"
case "$VM" in vm1) RID=win-arm64 ;; vm2) RID=win-x64 ;; *) echo "vm1 or vm2" >&2; exit 2 ;; esac
INSTALL=1; [[ "${2:-}" == --no-install ]] && INSTALL=0
G='C:\ProgramData\WELDAP-Test'
SUFFIX='dc=example,dc=org'
PUB="$(cat testdir/.data/server/password-k1.pub)"
PIN="$(cat testdir/.data/server/pin)"
PASS=0; FAIL=0; FAILED=()

vps() { vm/vmctl.sh ps "$VM" "$1"; }
# Setup steps (not checks): retried, because guest PowerShell can fall over under full x86 emulation.
vrun() { for _ in 1 2 3; do vps "$1" >/dev/null 2>&1 && return 0; sleep 10; done; echo "setup step failed: ${1:0:60}" >&2; return 1; }
# Like vrun, for an external helper command (device registration): retry under the emulated VM's transient hiccups.
vretry() { local i; for i in 1 2 3; do "$@" && return 0; echo "retry $i: $*" >&2; sleep 10; done; echo "step failed: $*" >&2; return 1; }
ldapi() { docker exec -i weldap-test-dirsrv "$@" -H ldapi://%2fdata%2frun%2fslapd-localhost.socket -Y EXTERNAL -Q; }

check() {   # check <name> <expected-substring> <actual>
    if [[ "$3" == *"$2"* ]]; then
        PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"
    else
        FAIL=$((FAIL + 1)); FAILED+=("$1"); printf 'FAIL  %s\n      want: %s\n      got:  %s\n' "$1" "$2" "$3"
    fi
}

# login <uun> <password-key> [scenario]: the tile's code path (seal + pipe), password via stdin.
login() {
    vps "\$p = (Get-Content '$G\\passwords' | Where-Object { \$_ -like '$2 *' } | Select-Object -First 1)
         \$pw = if (\$p) { \$p.Substring(\$p.IndexOf(' ') + 1) } else { '' }
         \$pw | & '$G\\WeldapClientTest.exe' call '${3:-logon}' '$1' -" 2>&1 | tr -d '\r' | tr '\n' ' '
}

account() {  # "enabled=<bool> admin=<bool> managed=<bool> expires_days=<n>" or "absent"
    vps "\$u = Get-LocalUser -Name '$1' -ErrorAction SilentlyContinue
         if (-not \$u) { 'absent'; exit }
         \$adm = [bool](Get-LocalGroupMember -SID S-1-5-32-544 | Where-Object { \$_.Name -like '*\\$1' })
         \$mgd = [bool](Get-LocalGroupMember -Name 'WELDAP-Managed' -ErrorAction SilentlyContinue | Where-Object { \$_.Name -like '*\\$1' })
         \$d = if (\$u.AccountExpires) { [int]((\$u.AccountExpires - (Get-Date)).TotalDays) } else { 'never' }
         \"enabled=\$(\$u.Enabled) admin=\$adm managed=\$mgd expires_days=\$d\"" 2>&1 | tr -d '\r' | tail -1
}

# localcheck <uun> <password-key>: does Windows itself accept that password for the local account?
localcheck() {
    vps "Add-Type -Namespace P -Name L -MemberDefinition '[DllImport(\"advapi32.dll\", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool LogonUser(string u, string d, string p, int t, int v, out System.IntPtr h);'
         \$p = (Get-Content '$G\\passwords' | Where-Object { \$_ -like '$2 *' } | Select-Object -First 1)
         \$h = [IntPtr]::Zero
         if ([P.L]::LogonUser('$1', '.', \$p.Substring(\$p.IndexOf(' ') + 1), 3, 0, [ref]\$h)) { 'accepted' } else { 'rejected' }" 2>&1 | tr -d '\r' | tail -1
}

wait_dir() {
    for _ in $(seq 1 60); do
        docker exec weldap-test-dirsrv dsconf localhost backend suffix list >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "directory did not come back" >&2; exit 1
}
trap 'docker start weldap-test-dirsrv weldap-test-server >/dev/null 2>&1 || true' EXIT

if ((INSTALL)); then
    echo "== install ($RID)"
    work="$(mktemp -d)"
    cp -R "out/service-$RID" "$work/service"
    cp client/Weldap.Service/install-dev.ps1 tests/acceptance/memscan.ps1 tests/acceptance/pipe.ps1 "$work/"
    (cd "$work" && zip -qr bundle.zip service install-dev.ps1 memscan.ps1 pipe.ps1)
    { cat testdir/.data/passwords; echo "wrong NotThePassword-1"; } >"$work/passwords"
    vps "Remove-Item -Recurse -Force '$G' -ErrorAction SilentlyContinue
         New-Item -ItemType Directory -Force -Path '$G' | Out-Null
         icacls '$G' /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null" >/dev/null
    vm/vmctl.sh push "$VM" "$work/bundle.zip" "$G\\bundle.zip"
    vm/vmctl.sh push "$VM" "$work/passwords" "$G\\passwords"
    rm -rf "$work"
    # Clean slate: sign test users out, remove their accounts and secrets from earlier runs, any old MSI.
    vps "Expand-Archive -Force '$G\\bundle.zip' '$G'
         Copy-Item 'C:\\src\\windev\\tests\\cp-harness\\out\\WeldapClientTest.exe' '$G\\'
         Get-Package -Name WELDAP -ErrorAction SilentlyContinue | Uninstall-Package -Force -ErrorAction SilentlyContinue | Out-Null
         foreach (\$s in (quser 2>\$null | Select-Object -Skip 1)) { if (\$s -match '^\\s*>?(alice|bob|carol|dave)\\s+\\S*\\s+(\\d+)') { logoff \$Matches[2] } }
         Start-Sleep 3
         foreach (\$u in 'alice','bob','carol','dave') { Remove-LocalUser -Name \$u -ErrorAction SilentlyContinue }
         Remove-Item -Recurse -Force 'HKLM:\\SOFTWARE\\WELDAP\\Secret\\Accounts' -ErrorAction SilentlyContinue
         # Pin-only server trust: nothing from the test PKI is trusted, and no name resolution is needed.
         Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { \$_.Subject -eq 'CN=WELDAP Test CA' } | Remove-Item
         \$h = \"\$env:SystemRoot\\System32\\drivers\\etc\\hosts\"
         Set-Content \$h -Encoding ascii -Value (Get-Content \$h | Where-Object { \$_ -notmatch '\\.ppe\\.test' })
         & '$G\\install-dev.ps1' -Source '$G\\service' -ServerKey '$PUB' -ServerPin '$PIN' -ServerKeyId k1" | tr -d '\r' | grep -E 'Running|Stopped|rror' || true
    vretry tests/acceptance/register-vm.sh "$VM" | tail -1
fi

echo "== online (sealed in the tile's code, opened only by the server)"
check "alice: right password -> ok, online"            'result=ok mode=online local_password_chars=32' "$(login alice alice)"
check "alice: account created, standard user"          'enabled=True admin=False managed=True' "$(account alice)"
a="$(account alice)"; d="${a##*expires_days=}"
check "alice: expiry ~180 days out"                    'yes' "$([[ "$d" =~ ^(179|180)$ ]] && echo yes || echo "$d")"
check "alice: Windows does NOT know her real password" 'rejected' "$(localcheck alice alice)"
check "bob: admin -> ok"                          'result=ok' "$(login bob bob)"
check "bob: local admin"                               'admin=True managed=True' "$(account bob)"
check "carol: not a user -> deny"                    'result=deny' "$(login carol carol)"
check "carol: no account created"                      'absent' "$(account carol)"
check "alice: wrong password -> deny"                  'result=deny' "$(login alice wrong)"
check "administrator: excluded"                        'standard Windows sign-in' "$(login administrator administrator)"
check "breakglass: excluded"                           'standard Windows sign-in' "$(login breakglass wrong)"
check "unknown user -> deny"                           'result=deny' "$(login zed wrong)"
check "unlock scenario -> ok"                          'result=ok mode=online' "$(login alice alice unlock)"

echo "== client surface: no ports, one SYSTEM-only local pipe that drops anything malformed"
SVCPID="(Get-CimInstance Win32_Service -Filter \"Name='Weldap'\").ProcessId"
check "service: no listening TCP port"                 'listen=0' "$(vps "'listen=' + @(Get-NetTCPConnection -OwningProcess ($SVCPID) -State Listen -ErrorAction SilentlyContinue).Count" 2>&1 | tr -d '\r' | tail -1)"
check "service: no UDP endpoint"                       'udp=0' "$(vps "'udp=' + @(Get-NetUDPEndpoint -OwningProcess ($SVCPID) -ErrorAction SilentlyContinue).Count" 2>&1 | tr -d '\r' | tail -1)"
check "no firewall rule opened for WELDAP"             'rules=0' "$(vps "'rules=' + @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { \$_.DisplayName -like '*WELDAP*' -or \$_.DisplayName -like '*Weldap*' }).Count" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: owner SYSTEM, SYSTEM only, network denied" 'O:SYD:P(D;;FA;;;NU)(A;;FA;;;SY)' "$(vps "& '$G\\pipe.ps1' sddl" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: refused through the network redirector"  'refused' "$(vps "& '$G\\pipe.ps1' remote" 2>&1 | tr -d '\r' | tail -1)"
ls_out="$(vps "\$d = 'C:\\ProgramData\\WELDAP-Test-ls'; New-Item -ItemType Directory -Force \$d | Out-Null
     icacls \$d /grant 'NT AUTHORITY\\LOCAL SERVICE:(OI)(CI)M' | Out-Null
     Copy-Item '$G\\pipe.ps1' \$d -Force; Remove-Item \"\$d\\out.txt\" -ErrorAction SilentlyContinue
     \$a = New-ScheduledTaskAction -Execute powershell.exe -Argument \"-NoProfile -ExecutionPolicy Bypass -Command & '\$d\\pipe.ps1' open | Set-Content '\$d\\out.txt'\"
     \$p = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\LOCAL SERVICE' -LogonType ServiceAccount
     Register-ScheduledTask -TaskName WeldapPipeProbe -Action \$a -Principal \$p -Force | Out-Null
     Start-ScheduledTask WeldapPipeProbe
     for (\$i = 0; \$i -lt 60 -and -not (Test-Path \"\$d\\out.txt\"); \$i++) { Start-Sleep 1 }
     Start-Sleep 1; Unregister-ScheduledTask WeldapPipeProbe -Confirm:\$false
     Get-Content \"\$d\\out.txt\"" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: a non-SYSTEM process cannot even open it" 'refused' "$ls_out"
check "pipe: previous (v2 JSON) request dropped, no reply" 'replies=0' "$(vps "& '$G\\pipe.ps1' frames -Kind v2json" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: zero-length frame dropped"                'replies=0' "$(vps "& '$G\\pipe.ps1' frames -Kind zero" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: oversize length prefix dropped"           'replies=0' "$(vps "& '$G\\pipe.ps1' frames -Kind oversize" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: 40 truncated v3 headers dropped"          'sent=40 replies=0 refused=0' "$(GUEST_TIMEOUT=600 vps "& '$G\\pipe.ps1' frames -Kind truncated -Count 40 -Seed 7" 2>&1 | tr -d '\r' | tail -1)"
check "pipe: 200 random frames dropped"                'sent=200 replies=0 refused=0' "$(GUEST_TIMEOUT=900 vps "& '$G\\pipe.ps1' frames -Kind random -Count 200 -Seed 11" 2>&1 | tr -d '\r' | tail -1)"
check "service: still running after the fuzzing"       'Running' "$(vps '(Get-Service Weldap).Status' 2>&1 | tr -d '\r' | tail -1)"
check "and still signs people in"                      'result=ok mode=online' "$(login alice alice)"

echo "== C++ sealer -> Rust opener (the only pair that ever shares a secret)"
seal_out="$(vps "& '$G\\WeldapClientTest.exe' seal '$PUB' 'WELDAP-auth-v1\\nk1\\nalice\\nlogon\\n1793320000\\nAAAAAAAAAAAAAAAAAAAAAA==' 'interop-Secret-1'" 2>&1 | tr -d '\r')"
enc="$(sed -n 's/^enc=//p' <<<"$seal_out")"; ct="$(sed -n 's/^ct=//p' <<<"$seal_out")"; hex="$(sed -n 's/^aad_hex=//p' <<<"$seal_out")"
probe_open() { docker run --rm --network none -u "$(id -u):$(id -g)" -v "$REPO/testdir/.data/server:/k:ro" \
    --entrypoint /usr/local/bin/weldap-probe weldap-server:test open --key /k/password-k1.key --enc "$1" --ct "$2" --aad-hex "$3" 2>&1 | tail -1; }
flip_last() { local x="$1" c="${1: -1}"; [[ "$c" == f ]] && echo "${x%?}e" || echo "${x%?}f"; }
check "C++-sealed password opens with the server's key" 'opened 16 bytes: interop-Secret-1' "$(probe_open "$enc" "$ct" "$hex")"
check "... but not with one AAD byte changed"          'open failed' "$(probe_open "$enc" "$ct" "$(flip_last "$hex")")"
ct_hex="$(base64 -d <<<"$ct" | xxd -p | tr -d '\n')"; ct_bad="$(flip_last "$ct_hex" | xxd -r -p | base64)"
check "... nor with one ciphertext bit changed"        'open failed' "$(probe_open "$enc" "$ct_bad" "$hex")"

echo "== secrets at rest (SYSTEM-only key, DPAPI blobs, no plaintext)"
check "Secret key: SYSTEM only"                        'system-only' "$(vps "\$a = Get-Acl 'HKLM:\\SOFTWARE\\WELDAP\\Secret'; \$o = @(\$a.Access | Where-Object { \$_.IdentityReference -ne 'NT AUTHORITY\\SYSTEM' }); if (\$a.AreAccessRulesProtected -and \$o.Count -eq 0) { 'system-only' } else { 'also: ' + ((\$o | ForEach-Object { \$_.IdentityReference }) -join ',') }" 2>&1 | tr -d '\r' | tail -1)"
check "alice: local password + verifier stored as blobs" 'blobs' "$(vps "\$k = Get-ItemProperty 'HKLM:\\SOFTWARE\\WELDAP\\Secret\\Accounts\\alice'; if (\$k.LocalPassword.Length -gt 100 -and \$k.Verifier.Length -gt 100) { 'blobs' } else { 'missing' }" 2>&1 | tr -d '\r' | tail -1)"
check "no user password anywhere in WELDAP's registry" 'clean' "$(vps "\$pw = (Get-Content '$G\\passwords' | ForEach-Object { \$_.Split(' ')[1] })
     \$found = 0
     Get-ChildItem -Recurse 'HKLM:\\SOFTWARE\\WELDAP' | ForEach-Object { Get-ItemProperty \$_.PSPath } | ForEach-Object {
         foreach (\$prop in \$_.PSObject.Properties) { \$v = \$prop.Value; if (\$v -is [byte[]]) { \$v = [Text.Encoding]::Unicode.GetString(\$v) + [Text.Encoding]::UTF8.GetString(\$v) }
             foreach (\$x in \$pw) { if (\$x -and \"\$v\".Contains(\$x)) { \$found++ } } } }
     if (\$found) { \"found \$found\" } else { 'clean' }" 2>&1 | tr -d '\r' | tail -1)"

echo "== rate limit (dave)"
for _ in 1 2 3 4 5; do login dave wrong >/dev/null || true; done
check "dave: 6th try with the right password -> locked" 'Too many failed' "$(login dave dave)"

echo "== offline: server down"
docker stop weldap-test-server >/dev/null
check "alice: right password -> ok, offline"           'result=ok mode=offline local_password_chars=32' "$(login alice alice)"
check "alice: wrong password offline -> deny"          'result=deny' "$(login alice wrong)"
check "carol: never signed in here -> deny"            'signed in to this PC before' "$(login carol carol)"
vrun "Set-ItemProperty HKLM:\\SOFTWARE\\WELDAP -Name OfflineMaxFailures -Value 3 -Type DWord; Restart-Service Weldap"
for _ in 1 2 3; do login alice wrong >/dev/null || true; done
check "alice: 3 offline failures -> locked, even with the right password" 'Too many failed offline' "$(login alice alice)"
docker start weldap-test-server >/dev/null; sleep 3
check "alice: online again -> ok, unlocks offline"     'result=ok mode=online' "$(login alice alice)"
docker stop weldap-test-server >/dev/null
check "alice: offline works again"                     'result=ok mode=offline' "$(login alice alice)"
docker start weldap-test-server >/dev/null; sleep 3
vrun "Remove-ItemProperty HKLM:\\SOFTWARE\\WELDAP -Name OfflineMaxFailures -ErrorAction SilentlyContinue; Restart-Service Weldap"

echo "== offline: server up, directory behind it down"
docker stop weldap-test-dirsrv >/dev/null
check "alice: server says unavailable -> offline"      'result=ok mode=offline' "$(login alice alice)"
docker start weldap-test-dirsrv >/dev/null; wait_dir

echo "== cleanup (the device asks only about its own accounts; the server reads the directory)"
printf 'dn: cn=win-admins,ou=groups,%s\nchangetype: modify\ndelete: member\nmember: uid=bob,ou=people,%s\n\ndn: cn=win-users,ou=groups,%s\nchangetype: modify\ndelete: member\nmember: uid=alice,ou=people,%s\n' \
    "$SUFFIX" "$SUFFIX" "$SUFFIX" "$SUFFIX" | ldapi ldapmodify >/dev/null
vps "Restart-Service Weldap; Start-Sleep -Seconds 10" >/dev/null   # the reconciler runs at start
check "bob: demoted to standard user"                  'enabled=True admin=False' "$(account bob)"
check "alice: disabled"                                'enabled=False' "$(account alice)"
check "alice: disabled -> deny"                        'result=deny' "$(login alice alice)"
printf 'dn: cn=win-admins,ou=groups,%s\nchangetype: modify\nadd: member\nmember: uid=bob,ou=people,%s\n\ndn: cn=win-users,ou=groups,%s\nchangetype: modify\nadd: member\nmember: uid=alice,ou=people,%s\n' \
    "$SUFFIX" "$SUFFIX" "$SUFFIX" "$SUFFIX" | ldapi ldapmodify >/dev/null
check "alice: back in win-users -> ok, re-enabled"     'result=ok mode=online' "$(login alice alice)"
check "alice: enabled again"                           'enabled=True' "$(account alice)"
check "bob: re-promoted on next login"                 'admin=True' "$(login bob bob >/dev/null; account bob)"
docker stop weldap-test-server >/dev/null
vrun "Restart-Service Weldap; Start-Sleep -Seconds 15"
check "cleanup with the server down changes nothing"   'enabled=True admin=True' "$(account bob)"
docker start weldap-test-server >/dev/null; sleep 3

echo "== device trust"
check "registered device: online"                      'result=ok mode=online' "$(login alice alice)"
vretry tests/acceptance/register-vm.sh "$VM" --revoke >/dev/null
last_event() { vps "(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='WELDAP'; Id=1400} -MaxEvents 1).Message" 2>&1 | tr -d '\r' | tail -1; }
check "revoked device: no online answer -> offline"    'result=ok mode=offline' "$(login alice alice)"
check "revoked device: logged as unreachable"          'event=ServerUnreachable' "$(last_event)"
check "revoked device: never-seen user still refused"  'signed in to this PC before' "$(login carol carol)"
vrun "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object { \$_.FriendlyName -eq 'WELDAP device' } | Remove-Item"
check "no device certificate: offline"                 'result=ok mode=offline' "$(login alice alice)"
check "no device certificate: says why"                'device-cert: this device is not registered' "$(last_event)"
vretry tests/acceptance/register-vm.sh "$VM" >/dev/null
check "re-registered device: online again"             'result=ok mode=online' "$(login alice alice)"

echo "== server trust is the pin, and the config cannot be loosened"
check "test CA not trusted anywhere on the device"     'absent' "$(vps "if (Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { \$_.Subject -eq 'CN=WELDAP Test CA' }) { 'present' } else { 'absent' }" 2>&1 | tr -d '\r' | tail -1)"
vrun "Set-ItemProperty HKLM:\\SOFTWARE\\WELDAP -Name ServerPins -Value @('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') -Type MultiString; Restart-Service Weldap"
check "wrong pin: the real server is not trusted -> offline" 'result=ok mode=offline' "$(login alice alice)"
check "wrong pin: logged as such"                      'server key does not match the pin' "$(last_event)"
vrun "Remove-ItemProperty HKLM:\\SOFTWARE\\WELDAP -Name ServerPins; Restart-Service Weldap -ErrorAction SilentlyContinue; Start-Sleep 3"
check "no pin at all: service refuses to start"        'Stopped' "$(vps '(Get-Service Weldap).Status' 2>&1 | tr -d '\r' | tail -1)"
check "service down: the tile says so"                 'status=SERVICE_UNAVAILABLE' "$(login alice alice)"
vrun "Set-ItemProperty HKLM:\\SOFTWARE\\WELDAP -Name ServerPins -Value @('$PIN') -Type MultiString
      \$a = Get-Acl HKLM:\\SOFTWARE\\WELDAP
      \$a.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule('BUILTIN\\Users', 'SetValue', 'Allow')))
      Set-Acl HKLM:\\SOFTWARE\\WELDAP \$a; Restart-Service Weldap -ErrorAction SilentlyContinue; Start-Sleep 3"
check "config writable by Users: service refuses to start (SR-10)" 'Stopped' "$(vps '(Get-Service Weldap).Status' 2>&1 | tr -d '\r' | tail -1)"
vrun "\$a = Get-Acl HKLM:\\SOFTWARE\\WELDAP
      \$a.RemoveAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule('BUILTIN\\Users', 'SetValue', 'Allow'))) | Out-Null
      Set-Acl HKLM:\\SOFTWARE\\WELDAP \$a; Start-Service Weldap; Start-Sleep 3"
check "config restored: service back, online"          'result=ok mode=online' "$(login alice alice)"

echo "== anti-tamper: the service refuses a provider DLL that is not the pinned one"
CLSID='HKLM:\\SOFTWARE\\Classes\\CLSID\\{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}\\InprocServer32'
# Register a bogus provider DLL outside the install folder and pin a hash it cannot match, then restart.
vrun "New-Item -Path '$CLSID' -Force | Out-Null
      Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\WELDAP' -Name ProviderHash -Value ('a' * 64)
      Set-Item -Path '$CLSID' -Value 'C:\\Windows\\System32\\notepad.exe'
      Restart-Service Weldap -ErrorAction SilentlyContinue; Start-Sleep 3"
check "tampered provider: service refuses to start"   'Stopped' "$(vps '(Get-Service Weldap).Status' 2>&1 | tr -d '\r' | tail -1)"
check "tampered provider: logged as a tamper, not a crash" 'outside the install folder' "$(vps "(((Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='WELDAP'} -MaxEvents 6 -ErrorAction SilentlyContinue).Message) -join ' ') -replace '\r?\n',' '" 2>&1 | tr -d '\r' | tail -1)"
# Clean up: drop the bogus registration and the pin, restart.
vrun "Remove-Item -Path 'HKLM:\\SOFTWARE\\Classes\\CLSID\\{E239AAAB-FFFD-4525-A894-1B9D6314B1CB}' -Recurse -Force -ErrorAction SilentlyContinue
      Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\WELDAP' -Name ProviderHash -ErrorAction SilentlyContinue
      Start-Service Weldap; Start-Sleep 3"
check "pin removed: service back, online"             'result=ok mode=online' "$(login alice alice)"

echo "== the device never held the user password in memory"
for u in alice bob; do login "$u" "$u" >/dev/null; done
vrun "Get-Content '$G\\passwords' | ForEach-Object { \$_.Split(' ')[1] } | Set-Content '$G\\secrets'"
svc="$(GUEST_TIMEOUT=900 vps "& '$G\\memscan.ps1' -ProcessName WeldapService -SecretsFile '$G\\secrets' -Control 'WELDAP-Managed'" 2>&1 | tr -d '\r' | tail -1)"
echo "      WeldapService: $svc"
check "service memory: no user password"          ', 0 hits' "$svc"
check "service memory: control string found (scan is real)" 'control found' "$svc"
ppl="$(vps "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').RunAsPPL" 2>/dev/null | tr -d '\r\n' || true)"
if [[ "$ppl" =~ ^[12]$ ]]; then
    # LSA protection on: not even SYSTEM can read LSASS (nor can credential-dumping tools). The evidence is the
    # LogonUser check above: Windows does not know the user's password.
    echo "SKIP  LSASS memory: LSASS runs as a protected process (RunAsPPL=$ppl), cannot be read"
else
    lsa="$(GUEST_TIMEOUT=900 vps "& '$G\\memscan.ps1' -ProcessName lsass -SecretsFile '$G\\secrets' -Control 'NT AUTHORITY'" 2>&1 | tr -d '\r' | tail -1 || true)"
    echo "      lsass: $lsa"
    if [[ "$lsa" == unreadable* ]]; then
        echo "SKIP  LSASS memory: $lsa"
    else
        check "LSASS memory: no user password"    ', 0 hits' "$lsa"
        check "LSASS memory: control string found"     'control found' "$lsa"
    fi
fi

echo
echo "passed $PASS, failed $FAIL"
((FAIL == 0)) || { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
