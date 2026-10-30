#!/usr/bin/env bash
# Quality gate for the WELDAP server, run in the `dev` image (server/Dockerfile) with the source mounted read-only:
#   1. `unsafe` only in secret.rs and hardening.rs (#![deny(unsafe_code)] at both crate roots, two module allows)
#   2. no coverage-exclusion markers anywhere (we reach 100% by restructuring and real tests, not by hiding
#      code from the measurement)
#   3. rustfmt (rustfmt.toml)
#   4. clippy, all targets, pedantic, warnings are errors
#   5. the tests (hermetic: loopback only), 100% line AND region coverage for everything except main.rs,
#      hardening.rs, src/bin/ and the tests themselves
# The release build and `cargo test --release` run in the image's build stage (docker build server/).
#
# 100% is reached on stable with no nightly and no exclusion markers. Every branch an attacker or peer can
# reach is driven by a hermetic test and keeps its fail-closed Err/deny behaviour. The few branches that
# cannot occur for ANY input -- given prior validation or type invariants -- are written as `.expect(...)`
# with the "cannot happen" reason inline, so the dead arm lives in std and llvm-cov does not count it (e.g.
# HPKE setup after an on-curve-validated enc, a tag slice already guarded to TAG_LEN, the fixed TLS version
# list, an always-valid rustls config, peer certificates guaranteed by mandatory client auth, a reply length
# vs u32, and OOM). Generic I/O helpers take `&mut dyn` so each branch is measured once, not per instantiation.
#   server/check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
docker build --target dev -t weldap-server:dev "$here"
docker volume create weldap-server-cargo >/dev/null
docker volume create weldap-server-target >/dev/null

docker run --rm -v "$here:/src:ro" -v weldap-server-cargo:/root/.cargo/registry -v weldap-server-target:/target \
    weldap-server:dev bash -c '
set -euo pipefail

echo "== unsafe confined to secret.rs and hardening.rs"
for root in src/main.rs src/bin/weldap-probe.rs; do
    grep -q "^#!\[deny(unsafe_code)\]" "$root" || { echo "$root: #![deny(unsafe_code)] missing"; exit 1; }
done
allowed="$(grep -rl "allow(unsafe_code)" src | sort | tr "\n" " ")"
[ "$allowed" = "src/hardening.rs src/secret.rs " ] || { echo "unsafe_code allowed in: $allowed"; exit 1; }

echo "== no coverage-exclusion markers (max 0)"
excl="$(grep -rEc "coverage\(off\)|coverage_nightly|LCOV_EXCL|GRCOV_EXCL" src | grep -v ":0$" || true)"
[ -z "$excl" ] || { echo "coverage exclusions present (cap is 0): $excl"; exit 1; }

echo "== rustfmt"
cargo fmt --check

echo "== clippy"
cargo clippy --locked --all-targets -- -D warnings -D clippy::pedantic

echo "== tests and coverage (100% lines AND regions, excluding main.rs/hardening.rs/bin/tests)"
cargo llvm-cov --locked --fail-under-lines 100 --fail-under-regions 100 \
    --ignore-filename-regex "(^|/)src/(main\.rs|hardening\.rs|bin/|tests/)|/library/(std|core|alloc)/"
'
echo "check.sh: all gates passed"
