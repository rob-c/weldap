#!/usr/bin/env bash
# Paranoia lint: patterns that must never appear in WELDAP's production code. Each rule is a grep that must
# find nothing; a hit prints the rule and the offending lines and fails the gate. Cheap, dumb and strict on
# purpose: it catches the accidental debug print or new dependency before a reviewer has to.
#   tests/lint/paranoia.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
fails=0

# rule [-i] <description> <grep -E pattern> <files...>: no line may match (-i: ignoring case).
# A trailing "| grep -v" filter can be given through EXCEPT (an ERE matched against "file:line:text").
rule() {
    local flags=-nE; [[ "$1" == -i ]] && { flags=-niE; shift; }
    local what="$1" pattern="$2"; shift 2
    local hits
    hits="$(grep "$flags" -- "$pattern" "$@" 2>/dev/null | { [[ -n "${EXCEPT:-}" ]] && grep -v -E -- "$EXCEPT" || cat; } || true)"
    if [[ -n "$hits" ]]; then
        fails=$((fails + 1)); printf 'FAIL  %s\n%s\n' "$what" "$(sed 's/^/      /' <<<"$hits")"
    else
        printf 'ok    %s\n' "$what"
    fi
}

# Rust production sources: everything in server/src except the test module and the probe client.
RS=(); while IFS= read -r f; do RS+=("$f"); done < <(find server/src -name '*.rs' -not -path '*/tests/*' -not -path '*/bin/*' | sort)
RS_NO_OUTPUT=(); for f in "${RS[@]}"; do [[ "$f" == */main.rs || "$f" == */audit.rs ]] || RS_NO_OUTPUT+=("$f"); done
RS_NO_NET=(); RS_SAFE=()
for f in "${RS[@]}"; do
    [[ "$f" == */ldap.rs ]] || RS_NO_NET+=("$f")
    [[ "$f" == */secret.rs || "$f" == */hardening.rs ]] || RS_SAFE+=("$f")
done
CS=(client/Weldap.Core/*.cs client/Weldap.Service/*.cs)
CS_NO_NET=(); for f in "${CS[@]}"; do [[ "$f" == */ServerClient.cs ]] || CS_NO_NET+=("$f"); done
CP=(client/Weldap.CredentialProvider/*.cpp client/Weldap.CredentialProvider/*.h client/Weldap.Shared/*.h)

echo "== server"
rule "server: no printing outside audit.rs and main.rs (startup only)" '(^|[^_a-z])(e?print(ln)?!|dbg!|write!\(std::io::std)' "${RS_NO_OUTPUT[@]}"
rule "server: no logging/tracing crates" '^(log|tracing|env_logger|slog|fern)[[:space:]]*=' server/Cargo.toml
rule "server: rustls without its logging feature" 'rustls.*"logging"' server/Cargo.toml
rule "server: no Debug formatting of request data" '\{:\?\}|\{:#\?\}' "${RS_NO_OUTPUT[@]}"
rule "server: request types are not Debug" 'derive\([^)]*Debug' server/src/server.rs
rule "server: SecretBuf is not Clone/Display/Serialize" '(impl[^{]*(Clone|Display|Serialize)[^{]*for SecretBuf|derive\([^)]*(Clone|Serialize))' server/src/secret.rs
rule "server: no process spawning" 'std::process::Command|libc::(exec|fork|system)' "${RS[@]}"
rule "server: no outbound network except the directory client" 'TcpStream::connect|UdpSocket' "${RS_NO_NET[@]}"
rule "server: no unsafe outside secret.rs and hardening.rs" 'unsafe[[:space:]]*(\{|fn|impl)' "${RS_SAFE[@]}"

echo "== client service (C#)"
rule "service: no console/debug/trace output" '(Console\.(Write|Error|Out)|Debug\.(Write|Print)|Trace\.(Write|TraceInformation))' "${CS[@]}"
rule -i "service: no log template mentions a secret" 'LoggerMessage.*\{(password|verifier|secret|ct|enc|sealed)' "${CS[@]}"
EXCEPT='AuditKind\.PasswordSet, uun\)' rule "service: no audit event built from a password variable" 'new AuditEvent\([^)]*([Pp]assword|[Vv]erifier)[^)]*\)' "${CS[@]}"
rule "service: networking only in ServerClient.cs" 'using System\.Net' "${CS_NO_NET[@]}"
rule "service: no HTTP, DNS or raw sockets" '(HttpClient|WebRequest|WebClient|Dns\.|new Socket\(|UdpClient|TcpListener)' "${CS[@]}"
EXCEPT='Import\("(advapi32|kernel32|netapi32|crypt32)\.dll"' rule "service: P/Invoke only into advapi32, kernel32, netapi32, crypt32" '(DllImport|LibraryImport)\(' "${CS[@]}"
EXCEPT='weldap|Weldap|WELDAP' rule -i "service: no LDAP or directory knowledge on the client" '(ldap|memberof|[^a-z]dn[^a-z]|389)' "${CS[@]}"
rule "service: no process spawning" 'Process\.Start' "${CS[@]}"

echo "== credential provider (C++, runs inside LogonUI)"
rule "provider: no debug output or printing" '(OutputDebugString|printf|wprintf|puts\(|std::cout|ReportEvent)' "${CP[@]}"
rule "provider: no networking headers or libraries" '(winsock|ws2_32|ws2tcpip|winhttp|wininet|wldap32|dnsapi|iphlpapi|urlmon)' "${CP[@]}"
rule "provider: no dynamic code loading or process spawning" '(LoadLibrary|CreateProcess|ShellExecute|WinExec|system\()' "${CP[@]}"
rule -i "provider: no LDAP or directory knowledge" '([^e]ldap|^ldap|memberof|389)' "${CP[@]}"
rule "provider: never memset a secret (SecureZeroMemory only)" 'memset\(' "${CP[@]}"

echo "== scripts"
for f in $(find . -name '*.sh' -not -path './vm/cache/*' -not -path './vm/vms/*' -not -path './out/*' -not -path '*/target/*' | sort) server/weldap-ca; do
    head -40 "$f" | grep -q -E '^set -[a-z]*e[a-z]*u[a-z]* -o pipefail|^set -euo pipefail' \
        || { fails=$((fails + 1)); echo "FAIL  $f: no 'set -euo pipefail'"; }
done
echo "ok    every shell script runs with set -euo pipefail (unless listed above)"

echo
if ((fails > 0)); then echo "paranoia lint: $fails rule(s) failed"; exit 1; fi
echo "paranoia lint: clean"
