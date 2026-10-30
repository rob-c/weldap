"""QMP and QEMU guest agent client for vm/vmctl.sh. Unix sockets only; no network.

  qctl.py qmp  <sock> <command> [json-args]       print the command's return value as JSON
  qctl.py keys <sock> <text> [--enter] [--us]     type text on the guest keyboard (en-GB layout;
                                                  --us for firmware screens)
  qctl.py click <sock> <x> <y>                    left-click at screen pixel x,y (usb-tablet)
  qctl.py qga  <sock> ping
  qctl.py qga  <sock> exec <timeout> <exe> [args...]
        prints the exit code, stdout, a "--WELDAP-STDERR--" line, then stderr
  qctl.py qga  <sock> push <local> <guest-path>
  qctl.py qga  <sock> pull <guest-path> <local>

Exit status 2 means the socket or agent did not answer.
"""
import base64
import json
import os
import random
import socket
import sys
import time


class Channel:
    def __init__(self, path, timeout):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(path)
        self.buf = b""

    def send(self, obj):
        self.sock.sendall(json.dumps(obj).encode() + b"\n")

    def recv(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("socket closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        # guest-sync-delimited prefixes its reply with 0xFF; drop it and any stale bytes.
        line = line.rsplit(b"\xff", 1)[-1].strip()
        return json.loads(line) if line else self.recv()

    def call(self, command, args=None):
        msg = {"execute": command}
        if args is not None:
            msg["arguments"] = args
        self.send(msg)
        while True:
            reply = self.recv()
            if "event" in reply:  # QMP async events
                continue
            if "error" in reply:
                raise RuntimeError(f"{command}: {reply['error'].get('desc', reply['error'])}")
            return reply.get("return")


def qmp(path, timeout=10):
    ch = Channel(path, timeout)
    ch.recv()  # greeting
    ch.call("qmp_capabilities")
    return ch


def qga(path, timeout=10):
    ch = Channel(path, timeout)
    # The agent may have half-read requests from an earlier client; resynchronise first.
    token = random.randrange(1, 2**31)
    ch.sock.sendall(b"\xff")
    ch.send({"execute": "guest-sync-delimited", "arguments": {"id": token}})
    while ch.recv().get("return") != token:
        pass
    return ch


KEYS = {" ": "spc", "\n": "ret", "\t": "tab", "-": "minus", "=": "equal", "[": "bracket_left",
        "]": "bracket_right", ";": "semicolon", "'": "apostrophe", ",": "comma", ".": "dot",
        "/": "slash", "\\": "backslash", "`": "grave_accent"}
SHIFTED = {"!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7", "*": "8", "(": "9",
           ")": "0", "_": "-", "+": "=", "{": "[", "}": "]", ":": ";", '"': "'", "<": ",", ">": ".",
           "?": "/", "|": "\\", "~": "`"}
# Guest keyboard is en-GB: a few US-layout shifted keys land elsewhere.
GB_OVERRIDE = {'"': ["shift", "2"], "@": ["shift", "apostrophe"], "#": ["backslash"],
               "~": ["shift", "backslash"], "\\": ["less"], "|": ["shift", "less"]}


def qcodes(ch, us=False):
    if not us and ch in GB_OVERRIDE:
        return GB_OVERRIDE[ch]
    if ch.isalpha():
        return ["shift", ch.lower()] if ch.isupper() else [ch]
    if ch.isdigit():
        return [ch]
    if ch in SHIFTED:
        return ["shift"] + qcodes(SHIFTED[ch], us)
    if ch in KEYS:
        return [KEYS[ch]]
    raise ValueError(f"no key for {ch!r}")


def cmd_keys(sock, text, enter, us):
    ch = qmp(sock)
    # Slow guests (full emulation) drop keys typed too fast: WELDAP_KEY_GAP=0.4 for those.
    gap = float(os.environ.get("WELDAP_KEY_GAP", "0.06"))
    for c in text + ("\n" if enter else ""):
        keys = [{"type": "qcode", "data": k} for k in qcodes(c, us)]
        ch.call("send-key", {"keys": keys, "hold-time": 40 if gap < 0.2 else 120})
        time.sleep(gap)


def screen_size(ch, sock):
    """Width and height of the guest display, from a throwaway PNG screendump."""
    path = sock + ".size.png"
    ch.call("screendump", {"filename": path, "format": "png"})
    with open(path, "rb") as f:
        head = f.read(24)
    os.remove(path)
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def cmd_click(sock, x, y):
    ch = qmp(sock)
    w, h = screen_size(ch, sock)
    # The tablet's absolute axes run 0..0x7fff across the whole display.
    move = [{"type": "abs", "data": {"axis": "x", "value": x * 0x7FFF // max(1, w - 1)}},
            {"type": "abs", "data": {"axis": "y", "value": y * 0x7FFF // max(1, h - 1)}}]
    ch.call("input-send-event", {"events": move})
    time.sleep(0.1)
    for down in (True, False):
        ch.call("input-send-event", {"events": [{"type": "btn", "data": {"down": down, "button": "left"}}]})
        time.sleep(0.08)


def cmd_exec(sock, limit, exe, args):
    ch = qga(sock, 30)
    pid = ch.call("guest-exec", {"path": exe, "arg": args, "capture-output": True})["pid"]
    deadline = time.monotonic() + limit
    while True:
        st = ch.call("guest-exec-status", {"pid": pid})
        if st.get("exited"):
            break
        if time.monotonic() > deadline:
            print(f"124\n\n--WELDAP-STDERR--\ntimed out after {limit} s")
            return
        time.sleep(0.5)
    out = base64.b64decode(st.get("out-data", "")).decode("utf-8", "replace")
    err = base64.b64decode(st.get("err-data", "")).decode("utf-8", "replace")
    code = st.get("exitcode", 1 if st.get("signal") else 0)
    sys.stdout.write(f"{code}\n{out}\n--WELDAP-STDERR--\n{err}")


def cmd_push(sock, local, guest):
    ch = qga(sock, 60)
    h = ch.call("guest-file-open", {"path": guest, "mode": "wb"})
    try:
        with open(local, "rb") as f:
            while chunk := f.read(48 * 1024):
                ch.call("guest-file-write", {"handle": h, "buf-b64": base64.b64encode(chunk).decode()})
    finally:
        ch.call("guest-file-close", {"handle": h})


def cmd_pull(sock, guest, local):
    ch = qga(sock, 60)
    h = ch.call("guest-file-open", {"path": guest, "mode": "rb"})
    try:
        with open(local, "wb") as f:
            while True:
                r = ch.call("guest-file-read", {"handle": h, "count": 48 * 1024})
                f.write(base64.b64decode(r.get("buf-b64", "")))
                if r.get("eof") or not r.get("count"):
                    break
    finally:
        ch.call("guest-file-close", {"handle": h})


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    kind, sock, rest = argv[0], argv[1], argv[2:]
    try:
        if kind == "qmp":
            args = json.loads(rest[1]) if len(rest) > 1 else None
            print(json.dumps(qmp(sock).call(rest[0], args)))
        elif kind == "keys":
            cmd_keys(sock, rest[0], "--enter" in rest[1:], "--us" in rest[1:])
        elif kind == "click":
            cmd_click(sock, int(rest[0]), int(rest[1]))
        elif kind == "qga" and rest[0] == "ping":
            qga(sock, 5).call("guest-ping")
        elif kind == "qga" and rest[0] == "exec":
            cmd_exec(sock, int(rest[1]), rest[2], rest[3:])
        elif kind == "qga" and rest[0] == "push":
            cmd_push(sock, rest[1], rest[2])
        elif kind == "qga" and rest[0] == "pull":
            cmd_pull(sock, rest[1], rest[2])
        else:
            sys.exit(__doc__)
    except (OSError, ConnectionError) as e:  # socket.timeout is an OSError
        print(f"{kind}: {e}", file=sys.stderr)
        sys.exit(2)
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
