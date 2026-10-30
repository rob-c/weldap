#!/usr/bin/env python3
"""Cross-language protocol-constant consistency check.

The wire contracts live, by necessity, in three languages at once: the C++ credential provider seals the
password and frames the pipe request, the C# service parses it, and the Rust server opens the sealed blob.
Nothing links them at build time, so a change made in one copy and forgotten in another would compile cleanly
and only surface as a field-misalignment bug on a real sign-in. This check is the missing link: it extracts
each shared constant from every language that defines it and fails if they disagree, so the protocol can be
evolved in one place and the drift is caught here instead of in LogonUI.

It is deliberately strict about *presence*: if a constant this check knows about can no longer be found (a
rename, a move, a reformat), that is a failure, not a silent skip -- the maintainer updates the code or this
table, on purpose. Run standalone or via `tests/quality.sh protocol`.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

# Files that hold the shared constants.
CPP_PROTO = "client/Weldap.Shared/WeldapProtocol.h"       # pipe v3 layout, shared C++ <-> C#
CPP_SEAL_H = "client/Weldap.CredentialProvider/WeldapSeal.h"   # sealed-password sizes, C++ side
CPP_SEAL_C = "client/Weldap.CredentialProvider/WeldapSeal.cpp"  # the HPKE info string
CS_PROTO = "client/Weldap.Core/Protocol.cs"               # the C# mirror
RS_SEAL = "server/src/seal.rs"                            # sealed-password sizes, Rust side
RS_SERVER = "server/src/server.rs"                        # UUN length, scenario strings

# Each logical constant, and how to read its value out of every language that defines it. Every source listed
# MUST match exactly once; a value group passes only when all its sources agree. The point of listing a source
# that happens to use a bare literal (a "magic number") is to pin that literal to the named constant elsewhere,
# so the two cannot drift apart unnoticed.
#   name -> [(file, regex-with-one-capture-group), ...]
VALUE_GROUPS: dict[str, list[tuple[str, str]]] = {
    "protocol version": [
        (CPP_PROTO, r"#define\s+WELDAP_PROTOCOL_VERSION\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+byte\s+Version\s*=\s*(\d+)"),
    ],
    "max message bytes": [
        (CPP_PROTO, r"#define\s+WELDAP_MAX_MESSAGE_BYTES\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+MaxMessageBytes\s*=\s*(\d+)"),
    ],
    "max reply message chars": [
        (CPP_PROTO, r"#define\s+WELDAP_MAX_REPLY_MESSAGE_CHARS\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+MaxMessageChars\s*=\s*(\d+)"),
    ],
    "max UUN chars": [
        (CPP_PROTO, r"#define\s+WELDAP_MAX_UUN_CHARS\s+(\d+)"),
        # C# request parser: `f[0] is 0 or > 20` is the UUN-length bound (a bare literal, pinned here).
        (CS_PROTO, r"f\[0\]\s+is\s+0\s+or\s+>\s+(\d+)"),
        # Rust UUN validator: `s.len() <= 20`.
        (RS_SERVER, r"s\.len\(\)\s*<=\s*(\d+)"),
    ],
    "max kid chars": [
        (CPP_SEAL_H, r"#define\s+WELDAP_MAX_KID_CHARS\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+MaxKidChars\s*=\s*(\d+)"),
    ],
    "HPKE enc bytes (P-256 point)": [
        (CPP_SEAL_H, r"#define\s+WELDAP_HPKE_ENC_BYTES\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+EncBytes\s*=\s*(\d+)"),
        (RS_SEAL, r"\bconst\s+ENC_LEN:\s*usize\s*=\s*(\d+)"),
    ],
    "HPKE tag bytes": [
        (CPP_SEAL_H, r"#define\s+WELDAP_HPKE_TAG_BYTES\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+TagBytes\s*=\s*(\d+)"),
        (RS_SEAL, r"\bconst\s+TAG_LEN:\s*usize\s*=\s*(\d+)"),
    ],
    "max password UTF-8 bytes": [
        (CPP_SEAL_H, r"#define\s+WELDAP_MAX_PASSWORD_UTF8\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+MaxPasswordUtf8\s*=\s*(\d+)"),
        (RS_SEAL, r"\bconst\s+MAX_PASSWORD_BYTES:\s*usize\s*=\s*(\d+)"),
    ],
    "rid bytes": [
        (CPP_SEAL_H, r"#define\s+WELDAP_RID_BYTES\s+(\d+)"),
        (CS_PROTO, r"\bconst\s+int\s+RidBytes\s*=\s*(\d+)"),
    ],
    "reply result OK": [
        (CPP_PROTO, r"#define\s+WELDAP_RESULT_OK\s+(\d+)"),
        (CS_PROTO, r"\bOk\s*=\s*(\d+)"),
    ],
    "reply result DENY": [
        (CPP_PROTO, r"#define\s+WELDAP_RESULT_DENY\s+(\d+)"),
        (CS_PROTO, r"\bDeny\s*=\s*(\d+)"),
    ],
    "reply result ERROR": [
        (CPP_PROTO, r"#define\s+WELDAP_RESULT_ERROR\s+(\d+)"),
        (CS_PROTO, r"\bError\s*=\s*(\d+)"),
    ],
    "HPKE info string": [
        (CPP_SEAL_C, r'c_szInfo\[\]\s*=\s*"([^"]*)"'),
        (RS_SEAL, r'\bconst\s+INFO:\s*&\[u8\]\s*=\s*b"([^"]*)"'),
    ],
}

# Scenario strings travel inside the sealed AAD: the C++ provider writes one, the Rust server validates it.
# Compared as a set so order and formatting do not matter -- only that both ends agree on the vocabulary.
SCENARIO_SOURCES: list[tuple[str, str]] = [
    (CPP_PROTO, r'#define\s+WELDAP_SCENARIO_\w+\s+"([a-z]+)"'),
    (RS_SERVER, r'r\.scenario\s*==\s*"([a-z]+)"'),
]


def read(rel: str) -> str:
    path = REPO / rel
    if not path.is_file():
        sys.exit(f"error: missing source file {rel}")
    return path.read_text(encoding="utf-8")


def extract_one(rel: str, pattern: str) -> str:
    matches = re.findall(pattern, read(rel))
    if len(matches) != 1:
        raise LookupError(
            f"{rel}: expected exactly one match for /{pattern}/, found {len(matches)}"
            " -- the constant was renamed, moved, or reformatted; update the code or this check")
    return matches[0]


def norm(value: str) -> str:
    """Numbers compare by value (strip any C `u` suffix); strings compare verbatim."""
    v = value.rstrip("uU") if value.rstrip("uU").isdigit() else value
    return str(int(v)) if v.isdigit() else value


def main() -> int:
    failures: list[str] = []
    width = max(len(name) for name in VALUE_GROUPS) + 2

    for name, sources in VALUE_GROUPS.items():
        try:
            values = [(rel, norm(extract_one(rel, pat))) for rel, pat in sources]
        except LookupError as exc:
            failures.append(str(exc))
            print(f"  {name:<{width}} ERROR (see below)")
            continue
        distinct = {v for _, v in values}
        if len(distinct) == 1:
            langs = ", ".join(Path(rel).suffix.lstrip(".") for rel, _ in values)
            print(f"  {name:<{width}} {values[0][1]:<22} [{langs}]")
        else:
            print(f"  {name:<{width}} MISMATCH")
            failures.append(f"{name}: disagreement across languages -> "
                            + "; ".join(f"{rel}={v}" for rel, v in values))

    # Scenario vocabulary: set equality across C++ and Rust.
    scen_sets = {rel: set(re.findall(pat, read(rel))) for rel, pat in SCENARIO_SOURCES}
    all_scen = set.union(*scen_sets.values())
    if len({frozenset(s) for s in scen_sets.values()}) == 1:
        print(f"  {'scenario vocabulary':<{width}} {sorted(all_scen)}")
    else:
        print(f"  {'scenario vocabulary':<{width}} MISMATCH")
        failures.append("scenario strings differ -> "
                        + "; ".join(f"{rel}={sorted(s)}" for rel, s in scen_sets.items()))

    if failures:
        print("\nprotocol consistency: FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("\nprotocol consistency: all shared constants agree across C++, C# and Rust")
    return 0


if __name__ == "__main__":
    sys.exit(main())
