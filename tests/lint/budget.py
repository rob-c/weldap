#!/usr/bin/env python3
"""Code-size budget: production code only (no tests, no blank or comment lines). Less code, fewer places for a
bug to hide: a component that grows past its budget fails the gate, so growth is a decision, not an accident.
    tests/lint/budget.py            check
    tests/lint/budget.py --report   just print the table
"""
import glob, os, re, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# component: (globs, budget in lines). Budgets sit just above today's size; lower them as code is removed.
BUDGETS = {
    "credential provider (C++, in LogonUI)": (["client/Weldap.CredentialProvider/*.cpp", "client/Weldap.CredentialProvider/*.h",
                                              "client/Weldap.Shared/*.h"], 2180),
    "client service (C#)": (["client/Weldap.Service/*.cs"], 920),
    "client core (C#)": (["client/Weldap.Core/*.cs"], 830),  # +70: ServerTransport + AuditFormat moved in from the Service for host-side test coverage
    "server (Rust)": (["server/src/*.rs"], 1160),
}


def strip(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    if path.endswith(".rs"):
        # Everything from a top-level `#[cfg(test)]` on is test code (the convention in this crate).
        m = re.search(r"^#\[cfg\(test\)\]", text, re.M)
        if m:
            text = text[: m.start()]
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("#pragma once"):
            continue
        lines.append(s)
    return len(lines)


def main():
    failed = False
    print(f"{'component':45} {'lines':>6} {'budget':>7}")
    for name, (globs, budget) in BUDGETS.items():
        files = sorted({f for g in globs for f in glob.glob(os.path.join(ROOT, g))})
        n = sum(strip(f) for f in files)
        over = n > budget
        failed |= over
        print(f"{name:45} {n:6} {budget:7}{'  OVER BUDGET' if over else ''}")
    if failed and "--report" not in sys.argv:
        sys.exit(1)


main()
