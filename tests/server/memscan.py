"""Scan a process's memory for secrets: python3 memscan.py <pid> <secrets-file>

secrets-file: one secret per line. Prints how many readable bytes were scanned and every hit as
"HIT <n> <region>" (the secret itself is never printed). Exit 1 if anything was found. Needs root with
CAP_SYS_PTRACE in the target's PID namespace (the server is not dumpable).
"""
import re
import sys

pid, path = sys.argv[1], sys.argv[2]
secrets = [line.rstrip("\n").encode() for line in open(path) if line.strip()]
needles = []
for i, s in enumerate(secrets):
    needles.append((i, s))                                        # UTF-8 (what the server decrypts)
    needles.append((i, s.decode().encode("utf-16-le")))           # UTF-16 for good measure

scanned = 0
hits = 0
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m or not m.group(3).startswith("r"):
            continue
        start, end, name = int(m.group(1), 16), int(m.group(2), 16), m.group(4) or "[anon]"
        if name in ("[vvar]", "[vsyscall]"):
            continue
        try:
            mem.seek(start)
            data = mem.read(end - start)
        except OSError:
            continue
        scanned += len(data)
        for i, needle in needles:
            if needle in data:
                hits += 1
                print(f"HIT secret#{i} in {name}")
print(f"scanned {scanned} bytes, {hits} hits")
sys.exit(1 if hits else 0)
