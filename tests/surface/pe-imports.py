#!/usr/bin/env python3
"""Attack-surface check: which DLLs does a PE file import?

    tests/surface/pe-imports.py [--list] [--functions] FILE.dll [FILE.dll ...]

Reads the import table and the delay-load import table of each PE32/PE32+ file (any architecture; a small
reader over the standard library only, no pefile) and prints the imported DLLs. Unless --list is given, each
file is checked as the WELDAP credential provider (WeldapCredentialProvider.dll, loaded into LogonUI): every
imported DLL must be on ALLOWED, and nothing on FORBIDDEN (networking, directory, URL) may appear, even as a
delay-load. Exit status: 0 clean, 1 policy violation, 2 unreadable or not a PE file.
"""
import struct
import sys

# Exactly what the provider imports today (static CRT; CNG, crypt32 base64, LSA, COM, shlwapi, user32), the same
# on x64 and ARM64. (credui.lib and gdi32.lib are on the link line but nothing is pulled from them.) Anything
# new has to be added here on purpose.
ALLOWED = {
    "kernel32.dll",
    "advapi32.dll",
    "ole32.dll",
    "secur32.dll",
    "bcrypt.dll",
    "crypt32.dll",
    "shlwapi.dll",
    "credui.dll",
    "user32.dll",
}
# Never in LogonUI through this DLL: the provider talks only to the local pipe.
FORBIDDEN = {
    "ws2_32.dll", "wsock32.dll", "mswsock.dll", "winhttp.dll", "wininet.dll", "webio.dll", "httpapi.dll",
    "dnsapi.dll", "wldap32.dll", "netapi32.dll", "iphlpapi.dll", "winnsi.dll", "nsi.dll", "dhcpcsvc.dll",
    "urlmon.dll",
}


class PeError(Exception):
    pass


class Pe:
    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeError("no MZ header")
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PeError("no PE signature")
        coff = e_lfanew + 4
        self.machine, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        (magic,) = struct.unpack_from("<H", data, opt)
        if magic == 0x20B:      # PE32+
            self.pe32plus = True
            (self.image_base,) = struct.unpack_from("<Q", data, opt + 24)
            (ndirs,) = struct.unpack_from("<I", data, opt + 108)
            dirs = opt + 112
        elif magic == 0x10B:    # PE32
            self.pe32plus = False
            (self.image_base,) = struct.unpack_from("<I", data, opt + 28)
            (ndirs,) = struct.unpack_from("<I", data, opt + 92)
            dirs = opt + 96
        else:
            raise PeError("unknown optional header magic 0x%x" % magic)
        self.dirs = [struct.unpack_from("<II", data, dirs + 8 * i) for i in range(min(ndirs, 16))]
        self.sections = []
        sec = opt + opt_size
        for i in range(nsections):
            name, vsize, va, rawsize, rawptr = struct.unpack_from("<8sIIII", data, sec + 40 * i)
            self.sections.append((name.rstrip(b"\0").decode("ascii", "replace"), va, max(vsize, rawsize), rawptr, rawsize))

    def offset(self, rva):
        for _, va, size, rawptr, rawsize in self.sections:
            if va <= rva < va + size:
                if rva - va >= rawsize:
                    raise PeError("RVA 0x%x is in uninitialised data" % rva)
                return rawptr + (rva - va)
        raise PeError("RVA 0x%x outside every section" % rva)

    def cstr(self, rva, limit=512):
        off = self.offset(rva)
        end = self.data.find(b"\0", off, off + limit)
        if end < 0:
            raise PeError("unterminated string at RVA 0x%x" % rva)
        return self.data[off:end].decode("ascii", "replace")

    def thunk_names(self, rva):
        names, size = [], 8 if self.pe32plus else 4
        ordinal_flag = 1 << (63 if self.pe32plus else 31)
        off = self.offset(rva)
        for _ in range(65536):
            (v,) = struct.unpack_from("<Q" if self.pe32plus else "<I", self.data, off)
            if v == 0:
                return names
            names.append("#%d" % (v & 0xFFFF) if v & ordinal_flag else self.cstr((v & 0x7FFFFFFF) + 2))
            off += size
        raise PeError("unterminated thunk array")

    def imports(self):
        """[(dll, delay_loaded, [functions])] from the import and delay-import directories."""
        out = []
        if len(self.dirs) > 1 and self.dirs[1][0]:
            off = self.offset(self.dirs[1][0])
            for _ in range(4096):
                oft, _, _, name, ft = struct.unpack_from("<IIIII", self.data, off)
                if not (oft or name or ft):
                    break
                out.append((self.cstr(name), False, self.thunk_names(oft or ft)))
                off += 20
        if len(self.dirs) > 13 and self.dirs[13][0]:
            off = self.offset(self.dirs[13][0])
            for _ in range(4096):
                attrs, name, _, iat, int_, _, _, _ = struct.unpack_from("<8I", self.data, off)
                if not (name or iat or int_):
                    break
                base = 0 if attrs & 1 else self.image_base   # bit 0 clear: old VA-based descriptor
                out.append((self.cstr(name - base), True, self.thunk_names(int_ - base) if int_ else []))
                off += 32
        return out


MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0xA641: "ARM64EC", 0x1C4: "ARMNT"}


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if not args or flags - {"--list", "--functions"}:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    status = 0
    for path in args:
        try:
            with open(path, "rb") as f:
                pe = Pe(f.read())
            imports = pe.imports()
        except (OSError, PeError, struct.error) as e:
            print("%s: cannot read imports: %s" % (path, e), file=sys.stderr)
            status = max(status, 2)
            continue
        print("%s (%s, %d DLLs)" % (path, MACHINES.get(pe.machine, hex(pe.machine)), len(imports)))
        bad = []
        for dll, delay, funcs in sorted(imports, key=lambda t: t[0].lower()):
            lower = dll.lower()
            verdict = ""
            if "--list" not in flags:
                if lower in FORBIDDEN:
                    verdict = "  FORBIDDEN"
                elif lower not in ALLOWED:
                    verdict = "  NOT ALLOWED"
                if verdict:
                    bad.append(dll)
            print("  %-28s %3d function%s%s%s" % (dll, len(funcs), "" if len(funcs) == 1 else "s",
                                                    " (delay-load)" if delay else "", verdict))
            if "--functions" in flags:
                for fn in funcs:
                    print("      " + fn)
        if "--list" not in flags:
            if bad:
                print("  FAIL: imports outside the credential provider allow-list: %s" % ", ".join(bad))
                status = max(status, 1)
            else:
                print("  OK: every import on the allow-list, none forbidden")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
