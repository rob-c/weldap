#!/usr/bin/env bash
# WELDAP server tests from the host: the probe (weldap-server:test image) plays a client on the compose
# network. Covers device trust, sealed-password auth, binding/replay/staleness, status, throttling, malformed
# input, revocation -- and that no test password ever appears in the server's output or memory.
#   tests/server/run.sh            (needs testdir/up.sh)
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO/testdir"
PASS=0; FAIL=0; FAILED=()
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
umask 077
NET=testdir_front
PUB="$(cat .data/server/password-k1.pub)"

check() {
    if [[ "$3" == *"$2"* ]]; then PASS=$((PASS + 1)); printf 'PASS  %s\n' "$1"
    else FAIL=$((FAIL + 1)); FAILED+=("$1"); printf 'FAIL  %s\n      want: %s\n      got:  %s\n' "$1" "$2" "$3"; fi
}

# probe <device> <cmd> [args...]: device "none" = no client certificate.
probe() {
    local dev="$1"; shift
    local certargs=()
    [[ "$dev" != none ]] && certargs=(--cert "/w/$dev.crt" --key "/w/$dev.key")
    docker run --rm --network "$NET" -v "$work:/w:ro" --entrypoint /usr/local/bin/weldap-probe weldap-server:test \
        "$1" --server weldap-test-server:8636 --name weldap.example.test --ca /w/ca.crt ${certargs[@]+"${certargs[@]}"} "${@:2}" 2>&1 | tail -2
}
auth() { # auth <device> <uun> <password-key> [extra probe args]
    awk -v u="$3" '$1 == u { print $2 }' .data/passwords >"$work/pw-$3"
    [[ -s "$work/pw-$3" ]] || echo "NotThePassword-1" >"$work/pw-$3"
    probe "$1" auth --kid k1 --pub "$PUB" --uun "$2" --password-file "/w/pw-$3" "${@:4}"
}

cp pki/ca.crt "$work/ca.crt"
for dev in gwtest-dev gwtest-revoked gwtest-other gwtest-busy; do
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$work/$dev.key" 2>/dev/null
    openssl req -new -key "$work/$dev.key" -subj "/CN=whatever" -out "$work/$dev.csr"
    ./device-ca.sh sign "$work/$dev.csr" "$dev" >/dev/null
    cp "pki/devices/$dev.crt" "$work/$dev.crt"
done
./device-ca.sh rogue gwtest-rogue >/dev/null
cp pki/devices/gwtest-rogue.crt pki/private/gwtest-rogue.key "$work/"
chmod 644 "$work"/*
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "== device trust"
check "no client certificate: refused"       'refused'  "$(auth none alice alice)"
check "unregistered CA: refused"             'refused'  "$(auth gwtest-rogue alice alice)"
check "registered device: alice ok, member"  '"result":"ok","user":true,"admin":false' "$(auth gwtest-dev alice alice)"

echo "== sealed password"
check "bob: admin"                           '"user":true,"admin":true' "$(auth gwtest-dev bob bob)"
check "carol: ok but not a member"           '"user":false' "$(auth gwtest-dev carol carol)"
check "wrong password: invalid"              '"result":"invalid"' "$(auth gwtest-dev alice wrong)"
check "unknown user: invalid"                '"result":"invalid"' "$(auth gwtest-dev zed wrong)"
check "replayed request: refused"            '"result":"error"' "$(auth gwtest-dev alice alice --replay | tail -1)"
check "stale timestamp: refused"             '"result":"error"' "$(auth gwtest-dev alice alice --skew -600)"
check "future timestamp: refused"            '"result":"error"' "$(auth gwtest-dev alice alice --skew 600)"
check "unknown key id: refused"              '"result":"error"' "$(auth gwtest-dev alice alice --other-kid k9)"
check "malformed request: no reply"          'refused' "$(probe gwtest-dev raw --body '{"op":"auth","v":1,"uun":"alice","x":1}')"
check "bad uun: refused"                     '"result":"error"' "$(probe gwtest-dev raw --body '{"op":"auth","v":1,"uun":"Alice","scenario":"logon","kid":"k1","enc":"","ct":"","ts":0,"rid":""}')"

echo "== status (server's own read-only identity; clients hold none, and learn only about UUNs they ask for)"
g="$(probe gwtest-dev status --uuns alice,bob,carol,zed)"
check "status: users among those asked"      '"users":["alice","bob"]' "$g"
check "status: admins among those asked"     '"admins":["bob"]' "$g"
check "status: nobody else listed"           '"users":["alice"],"admins":[]' "$(probe gwtest-dev status --uuns alice)"

echo "== throttling"
for _ in 1 2 3 4 5; do auth gwtest-dev dave wrong >/dev/null; done
check "dave: 6th attempt throttled even with the right password" '"result":"throttled"' "$(auth gwtest-dev dave dave)"

echo "== revocation"
check "before revocation: ok"                '"result":"ok"' "$(auth gwtest-revoked alice alice)"
./device-ca.sh revoke gwtest-revoked >/dev/null
check "after revocation: refused"            'refused' "$(auth gwtest-revoked alice alice)"
check "other devices unaffected"             '"result":"ok"' "$(auth gwtest-other alice alice)"

echo "== per-device rate limit (30 requests a minute)"
for _ in $(seq 1 30); do probe gwtest-busy status --uuns alice >/dev/null; done
check "31st request from one device: throttled" '"result":"throttled"' "$(probe gwtest-busy status --uuns alice)"

echo "== network surface"
ports="$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{$p}}={{range $b}}{{.HostIp}}:{{.HostPort}}{{end}} {{end}}' weldap-test-server)"
check "server: one published port, loopback only"   '8636/tcp=127.0.0.1:16637 ' "$ports"
check "server: nothing else published"              '1' "$(wc -w <<<"$ports" | tr -d ' ')"
check "389 DS: no published port"                   'none' "$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' weldap-test-dirsrv | grep -q . && echo some || echo none)"
check "389 DS network: internal (no route out)"     'true' "$(docker network inspect -f '{{.Internal}}' testdir_directory)"
check "389 DS: only the server shares its network"  'weldap-test-dirsrv weldap-test-server' "$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' testdir_directory | tr ' ' '\n' | sort | xargs)"
# (127.0.0.11 is Docker's embedded DNS resolver, which dockerd places in every container's network namespace.)
listen="$(docker run --rm --network container:weldap-test-server busybox:latest netstat -ltnu 2>/dev/null | awk 'NR > 2 && $4 !~ /^127\.0\.0\.11:/ { print $1, $4 }' | sort | xargs)"
check "server: exactly one listening socket (tcp 8636)" 'tcp 0.0.0.0:8636' "$listen"
check "server: no UDP, nothing else listening"      '2' "$(wc -w <<<"$listen" | tr -d ' ')"
dsip="$(docker inspect -f '{{(index .NetworkSettings.Networks "testdir_directory").IPAddress}}' weldap-test-dirsrv)"
check "front network: 389 DS name does not resolve"  'unreachable' "$(docker run --rm --network testdir_front busybox:latest sh -c 'nc -w 3 ldap.example.test 3636 </dev/null 2>/dev/null && echo reachable || echo unreachable')"
check "front network: 389 DS address not routable"   'unreachable' "$(docker run --rm --network testdir_front busybox:latest sh -c "nc -w 3 $dsip 3636 </dev/null 2>/dev/null && echo reachable || echo unreachable")"

echo "== TLS: the only thing an unregistered peer can reach"
ossl() { docker run --rm --network testdir_front -v "$work:/w:ro" --entrypoint openssl weldap-ca:latest s_client \
    -connect weldap-test-server:8636 -servername weldap.example.test -CAfile /w/ca.crt "$@" </dev/null 2>&1; }
check "TLS 1.0 refused"                             'no peer certificate' "$(ossl -tls1 -cipher 'DEFAULT:@SECLEVEL=0' || true)"
check "TLS 1.1 refused"                             'no peer certificate' "$(ossl -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0' || true)"
check "TLS 1.2 non-forward-secret cipher refused"   'no peer certificate' "$(ossl -tls1_2 -cipher 'AES128-SHA:AES256-GCM-SHA384' || true)"
cas="$(ossl -tls1_3 -cert /w/gwtest-dev.crt -key /w/gwtest-dev.key | sed -n '/Acceptable client certificate CA names/,/Requested Signature/p' | grep -v 'Acceptable\|Requested' | xargs)"
check "client CAs offered: the device CA only"      'O=WELDAP, CN=WELDAP Device CA (test)' "$(sed 's/ = /=/g' <<<"$cas")"
check "client CAs offered: nothing else"            '1' "$(ossl -tls1_3 -cert /w/gwtest-dev.crt -key /w/gwtest-dev.key | sed -n '/Acceptable client certificate CA names/,/Requested Signature/p' | grep -c 'CN')"
check "no session tickets (no resumption state)"    'tickets=0' "tickets=$(ossl -tls1_3 -cert /w/gwtest-dev.crt -key /w/gwtest-dev.key | grep -c 'Post-Handshake New Session Ticket' || true)"
check "no client certificate: refused in the handshake" 'alert' "$(ossl -tls1_2 || true)"
raw() { python3 - "$1" "$2" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", 16637), timeout=30)
payload = sys.argv[1].encode().decode("unicode_escape").encode("latin-1")
mode = sys.argv[2]
t = time.time()
if payload: s.sendall(payload)
data = b""
try:
    while True:
        b = s.recv(4096)
        if not b: break
        data += b
except Exception as e:
    print("error", type(e).__name__)
print("bytes=%d http=%s secs=%d" % (len(data), b"HTTP" in data, time.time() - t))
PY
}
check "plain HTTP: no HTTP answer, closed"          'http=False' "$(raw 'GET / HTTP/1.0\r\n\r\n' x)"
check "random bytes: closed"                        'http=False' "$(raw '\x16\x03\x01\x00\x05hello' x)"
idle="$(raw '' idle)"
check "idle peer: dropped by the server"            'bytes=0' "$idle"
check "idle peer: within the I/O timeout"           'yes' "$(s="${idle##*secs=}"; ((s <= 12)) && echo yes || echo "$s s")"

echo "== server process hardening"
st="$(docker run --rm --pid container:weldap-test-server --cap-drop ALL --cap-add SYS_PTRACE -u 0 busybox:latest sh -c 'cat /proc/1/status')"
field() { awk -v f="$1:" '$1 == f { $1 = ""; print substr($0, 2) }' <<<"$st"; }
check "not root"                                    'nonroot' "$( [[ "$(field Uid | awk '{print $1}')" != 0 ]] && echo nonroot || echo root)"
check "no capabilities at all (effective)"          '0000000000000000' "$(field CapEff)"
check "no capabilities at all (bounding set)"       '0000000000000000' "$(field CapBnd)"
check "no_new_privs"                                '1' "$(field NoNewPrivs)"
check "seccomp filter on"                           '2' "$(field Seccomp)"
check "all memory locked (mlockall)"                'locked' "$(v="$(field VmLck | awk '{print $1}')"; ((v > 1000)) && echo locked || echo "VmLck=$v")"
check "no swap used"                                '0 kB' "$(field VmSwap)"
check "read-only root filesystem"                   'true' "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' weldap-test-server)"
check "no core dumps (ulimit core 0)"               'core=0' "$(docker inspect -f '{{range .HostConfig.Ulimits}}{{.Name}}={{.Hard}} {{end}}' weldap-test-server)"
check "not ptrace-able by its own user"             'denied' "$(docker run --rm --pid container:weldap-test-server --cap-drop ALL -u "$(field Uid | awk '{print $1}')" busybox:latest sh -c 'cat /proc/1/environ >/dev/null 2>&1 && echo readable || echo denied')"
found="$(for b in /bin/sh /usr/bin/bash /usr/bin/ls /usr/bin/rpm /usr/bin/microdnf /usr/bin/openssl /usr/bin/curl /usr/bin/python3; do
    if docker run --rm --entrypoint "$b" weldap-server:latest --version >/dev/null 2>&1; then echo "$b"; fi; done | xargs)"
check "server image: no shell, coreutils, package manager or openssl" 'none' "${found:-none}"

echo "== no password in any output"
docker logs --since "$since" weldap-test-server >"$work/server.log" 2>&1
leaks=0
while read -r who pw; do
    [[ -n "$pw" ]] && grep -F -q -- "$pw" "$work/server.log" && { echo "      leaked: $who"; leaks=$((leaks + 1)); }
done < <(cat .data/passwords; echo "wrong NotThePassword-1")
check "server log: no test password ($(wc -l <"$work/server.log" | tr -d ' ') lines)" '0 leaks' "$leaks leaks"
check "server log: only allow-listed JSON lines" '0 other' "$(grep -c -v '^{"ts":[0-9]*,"event":"[a-z_]*"' "$work/server.log" | sed 's/$/ other/')"

echo "== no password left in server memory"
# A root sidecar with CAP_SYS_PTRACE in the server's PID namespace reads every readable mapping.
for u in alice bob carol; do auth gwtest-other "$u" "$u" >/dev/null; done
{ cut -d' ' -f2 .data/passwords; echo "NotThePassword-1"; } >"$work/secrets"
cp "$REPO/tests/server/memscan.py" "$work/"; chmod 644 "$work/secrets" "$work/memscan.py"
scan="$(docker run --rm --pid container:weldap-test-server --cap-drop ALL --cap-add SYS_PTRACE -u 0 \
    -v "$work:/w:ro" --entrypoint /usr/libexec/platform-python almalinux:9 /w/memscan.py 1 /w/secrets 2>&1 || true)"
echo "      $scan" | tail -1
check "server memory: no test password after logins" ', 0 hits' "$scan"
# Positive control: the scan must see strings that are certainly there, or "0 hits" means nothing.
printf 'WELDAP-auth-v1\ncn=winlogin,ou=services\n' >"$work/control"; chmod 644 "$work/control"
control="$(docker run --rm --pid container:weldap-test-server --cap-drop ALL --cap-add SYS_PTRACE -u 0 \
    -v "$work:/w:ro" --entrypoint /usr/libexec/platform-python almalinux:9 /w/memscan.py 1 /w/control 2>&1 || true)"
check "memory scan control: known strings found" ', 2 hits' "$control"

echo
echo "passed $PASS, failed $FAIL"
((FAIL == 0)) || { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
