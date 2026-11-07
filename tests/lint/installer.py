#!/usr/bin/env python3
"""The MSI source, checked on the host in a second instead of in the build VM ten minutes later.

1. installer/*.wxs is well-formed XML (WiX's first error is WIX0104; '--' inside a comment is the usual one).
2. The installer's safety properties, each of which a past bug broke (CHANGELOG.md, [Unreleased]):
   - no Property is Secure: a standard user must never hand SERVERHOST/SERVERKEY to an elevated repair;
   - the install folder's id is not a public property (INSTALLFOLDER): a chosen folder may be user-writable;
   - the state purge runs in the commit phase, and only for a real uninstall of an installed product
     (REMOVE=ALL alone is also set by a session that installs nothing);
   - a REINSTALL for a different build is refused (that session is treated as a removal);
   - the x64 MSI refuses ARM64 Windows (LogonUI loads only a native provider).
"""
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
NS = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
failures = []


def fail(msg: str) -> None:
    failures.append(msg)
    print(f"FAIL  {msg}")


sources = sorted((ROOT / "installer").glob("*.wxs"))
if not sources:
    fail("no installer/*.wxs found")
trees = {}
for path in sources:
    try:
        trees[path.name] = ET.parse(path)
        print(f"ok    {path.relative_to(ROOT)}: well-formed")
    except ET.ParseError as ex:
        fail(f"{path.relative_to(ROOT)}: not well-formed XML: {ex}")

package = trees.get("Package.wxs")
if package is None:
    fail("installer/Package.wxs missing or unreadable")
else:
    root = package.getroot()
    for prop in root.iter(f"{{{NS['w']}}}Property"):
        if prop.get("Secure", "no").lower() == "yes":
            fail(f"Property {prop.get('Id')} is Secure (a standard user could pass it to an elevated repair)")
    for d in root.iter(f"{{{NS['w']}}}Directory"):
        if d.get("Id") == "INSTALLFOLDER" or (d.get("Id", "").isupper() and d.get("Name") == "WELDAP"):
            fail(f"Directory {d.get('Id')}: the install folder's id is a public property (make it mixed case)")

    actions = {a.get("Id"): a for a in root.iter(f"{{{NS['w']}}}CustomAction")}
    purge = actions.get("PurgeWeldapState")
    if purge is None:
        fail("no PurgeWeldapState custom action")
    elif purge.get("Execute") != "commit":
        fail(f"PurgeWeldapState runs Execute={purge.get('Execute')!r}, not 'commit' (a rollback would revive WELDAP without its state)")
    scheduled = [c for c in root.iter(f"{{{NS['w']}}}Custom") if c.get("Action") == "PurgeWeldapState"]
    if len(scheduled) != 1:
        fail(f"PurgeWeldapState scheduled {len(scheduled)} times (want 1)")
    else:
        cond = re.sub(r"\s+", " ", scheduled[0].get("Condition", ""))
        for need in ("Installed", 'REMOVE~="ALL"', "NOT UPGRADINGPRODUCTCODE"):
            if need not in cond:
                fail(f"PurgeWeldapState condition {cond!r} lacks {need!r}")

    launch = [re.sub(r"\s+", " ", c.get("Condition", "")) for c in root.iter(f"{{{NS['w']}}}Launch")]
    if "NOT REINSTALL OR Installed" not in launch:
        fail("no launch condition refusing REINSTALL for a build that is not installed")
    text = (ROOT / "installer" / "Package.wxs").read_text(encoding="utf-8")
    if "QueryNativeMachine" not in text:
        fail("the x64 MSI no longer checks the native machine (it would install on ARM64)")

if failures:
    print(f"{len(failures)} installer check(s) failed")
    sys.exit(1)
print("installer: all checks passed")
