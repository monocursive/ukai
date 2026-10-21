"""A scripted terminal for the interactive Claude Code A-row
(docs/specs/jail-interactive-sessions.md §6.3).

The terminal is a local pseudo-terminal whose slave runs `ssh -tt` to the
reference host, the way an operator reaches it. The master side is this
module: every byte in both directions is recorded with a timestamp in an
ndjson transcript, the received bytes are rendered by pyte (an xterm-like
screen), and the few queries a real terminal answers (cursor position,
device attributes, colours, window size, mode reports) are answered here, as
a terminal emulator would, and recorded as `answer` bytes.

Transcript records (one JSON object per line):
  {"t": seconds since the session started (monotonic), "utc": ISO time,
   "dir": "rx" | "tx" | "answer" | "event", "x": the bytes as latin-1
   (reversible: record["x"].encode("latin-1")), ...extra}
`rx` is what the terminal received (from ssh), `tx` what the harness typed,
`answer` what the emulated terminal sent by itself in reply to a query
(`query` names it), `event` a harness note (resize, hangup, snapshot, wait
results). Nothing here reads or handles a credential.
"""
import copy
import datetime
import hashlib
import json
import os
import re
import signal
import threading
import time
from collections import Counter
from pathlib import Path

import ptyprocess
import pyte

HOST = os.environ.get("AROW_HOST", "ubuntu@37.59.114.70")
KEY = os.environ.get("AROW_KEY", str(Path.home() / ".ssh/ouroboros_vps"))
SSH_ARGV = ["ssh", "-tt", "-F", "/dev/null", "-i", KEY, "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=20",
            "-o", "ServerAliveInterval=15", HOST]
TERM = "xterm-256color"


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


class Transcript:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.path, "a", buffering=1)
        self.t0 = time.monotonic()
        self.lock = threading.Lock()

    def rec(self, direction, data=b"", **extra):
        entry = {"t": round(time.monotonic() - self.t0, 6), "utc": utc(), "dir": direction,
                 "x": data.decode("latin-1")}
        entry.update(extra)
        with self.lock:
            self.file.write(json.dumps(entry, ensure_ascii=True) + "\n")

    def close(self):
        self.file.close()


CSI = re.compile(rb"\x1b\[([\x30-\x3f]*)([\x20-\x2f]*)([\x40-\x7e])")
OSC = re.compile(rb"\x1b\]([^\x07\x1b]*)(\x07|\x1b\\)")
DCS = re.compile(rb"\x1bP([^\x1b]*)\x1b\\")
ANY = re.compile(CSI.pattern + b"|" + OSC.pattern + b"|" + DCS.pattern)


class Emulator:
    """pyte plus the query answers and mode bookkeeping of the emulated terminal."""

    # The emulated terminal's fixed facts.
    FG = b"rgb:d0d0/d0d0/d0d0"
    BG = b"rgb:0000/0000/0000"
    CELL = (16, 8)  # pixel height, width of one cell
    DA1 = b"\x1b[?62;22c"   # VT220 with ANSI colour, as many xterm-likes answer
    DA2 = b"\x1b[>1;10;0c"

    def __init__(self, cols, rows):
        self.screen = pyte.Screen(cols, rows)
        self.screen.write_process_input = lambda data: None  # answers are ours
        self.stream = pyte.ByteStream(self.screen)
        self.carry = b""
        self.modes = {}              # DEC private mode -> last state (True set)
        self.mode_changes = Counter()  # "?1049h" -> count
        self.kitty = Counter()       # kitty keyboard protocol sequences seen
        self.queries = Counter()     # query name -> count
        self.unanswered = Counter()
        self.alt = None              # the saved main screen while the alternate one shows

    @property
    def size(self):
        return self.screen.columns, self.screen.lines

    def resize(self, cols, rows):
        self.screen.resize(rows, cols)

    def feed(self, data):
        """Feed received bytes; return [(query, answer_bytes)] in order."""
        answers = []
        buf = self.carry + data
        base = len(self.carry)
        fed = 0
        last_end = 0
        for m in ANY.finditer(buf):
            end = m.end()
            last_end = end
            seq = m.group(0)
            q = self._classify(seq)
            if q is None:
                continue
            name, answer = q
            if name.startswith("alt-screen"):
                stop = max(0, end - base)
                if stop > fed:
                    self.stream.feed(data[fed:stop])
                    fed = stop
                self._alt_screen(name == "alt-screen-enter")
                continue
            self.queries[name] += 1
            if answer is None:
                self.unanswered[name] += 1
                continue
            stop = max(0, end - base)
            if stop > fed:
                self.stream.feed(data[fed:stop])
                fed = stop
            answers.append((name, answer() if callable(answer) else answer))
        if fed < len(data):
            self.stream.feed(data[fed:])
        tail = buf[last_end:]
        i = tail.find(b"\x1b")
        self.carry = tail[i:] if i >= 0 and len(tail) - i < 4096 else b""
        return answers

    def _alt_screen(self, enter):
        """xterm's 1049: save the main screen and cursor and show a cleared
        alternate one; leaving shows the saved main screen again. pyte has a
        single buffer, so the emulator keeps the main one aside."""
        scr = self.screen
        if enter and self.alt is None:
            self.alt = (copy.deepcopy(scr.buffer), copy.copy(scr.cursor))
            scr.erase_in_display(2)
        elif not enter and self.alt is not None:
            buffer, cursor = self.alt
            self.alt = None
            scr.buffer = buffer
            scr.cursor = cursor
            scr.cursor.x = min(scr.cursor.x, scr.columns - 1)
            scr.cursor.y = min(scr.cursor.y, scr.lines - 1)
            scr.dirty.update(range(scr.lines))

    def _cpr(self):
        c = self.screen.cursor
        return b"\x1b[%d;%dR" % (c.y + 1, c.x + 1)

    def _classify(self, seq):
        """None when the sequence is no query and changes no tracked mode."""
        if seq.startswith(b"\x1b["):
            m = CSI.fullmatch(seq)
            params, inter, final = m.group(1), m.group(2), m.group(3)
            if final in (b"h", b"l") and params.startswith(b"?") and not inter:
                alt = None
                for p in params[1:].split(b";"):
                    if p.isdigit():
                        self.modes[int(p)] = final == b"h"
                        self.mode_changes["?" + p.decode() + final.decode()] += 1
                        if int(p) in (47, 1047, 1049):
                            alt = final == b"h"
                if alt is not None:
                    return ("alt-screen-enter" if alt else "alt-screen-leave", None)
                return None
            if final == b"u" and not inter and params[:1] in (b">", b"<", b"=", b"?"):
                self.kitty[(params + final).decode(errors="replace")] += 1
                if params == b"?":
                    return ("kitty-keyboard-query", None)  # an xterm does not answer it
                return None
            if final == b"n" and not inter:
                if params == b"6":
                    return ("CPR", self._cpr)
                if params == b"5":
                    return ("DSR-status", b"\x1b[0n")
                if params == b"?6":
                    return ("DECXCPR", lambda: self._cpr()[:-1].replace(b"[", b"[?") + b";1R")
                return ("DSR-" + params.decode(errors="replace"), None)
            if final == b"c" and not inter:
                if params in (b"", b"0"):
                    return ("DA1", self.DA1)
                if params in (b">", b">0"):
                    return ("DA2", self.DA2)
                if params.startswith(b"="):
                    return ("DA3", None)
                return None
            if final == b"p" and inter == b"$":
                mode = params.lstrip(b"?")
                prefix = b"?" if params.startswith(b"?") else b""
                if mode.isdigit():
                    known = {1, 7, 25, 47, 1000, 1002, 1003, 1004, 1006, 1047, 1049, 2004}
                    if prefix and int(mode) in known:
                        state = 1 if self.modes.get(int(mode)) else 2
                    else:
                        state = 0
                    return ("DECRQM" + params.decode(), b"\x1b[" + prefix + mode + b";%d$y" % state)
                return ("DECRQM?" + params.decode(errors="replace"), None)
            if final == b"q" and params in (b">", b">0") and not inter:
                return ("XTVERSION", None)
            if final == b"t" and not inter:
                cols, rows = self.size
                h, w = self.CELL
                if params == b"18":
                    return ("XTWINOPS-18", b"\x1b[8;%d;%dt" % (rows, cols))
                if params == b"14":
                    return ("XTWINOPS-14", b"\x1b[4;%d;%dt" % (rows * h, cols * w))
                if params == b"16":
                    return ("XTWINOPS-16", b"\x1b[6;%d;%dt" % (h, w))
                return None
            return None
        if seq.startswith(b"\x1b]"):
            m = OSC.fullmatch(seq)
            body, term = m.group(1), m.group(2)
            if body == b"10;?":
                return ("OSC10", b"\x1b]10;" + self.FG + term)
            if body == b"11;?":
                return ("OSC11", b"\x1b]11;" + self.BG + term)
            if body.endswith(b";?"):
                return ("OSC" + body.split(b";")[0].decode(errors="replace"), None)
            return None
        if seq.startswith(b"\x1bP"):
            body = DCS.fullmatch(seq).group(1)
            if body.startswith(b"$q") or body.startswith(b"+q"):
                return ("DCS" + body[:2].decode(errors="replace"), None)
        return None

    def text(self):
        return "\n".join(line.rstrip() for line in self.screen.display)


class Session:
    """One terminal connected to the host by `ssh -tt`."""

    def __init__(self, out_dir, cols=120, rows=40, name="t1"):
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "screens").mkdir(exist_ok=True)
        self.name = name
        self.transcript = Transcript(self.out / f"transcript-{name}.ndjson")
        self.rx_file = open(self.out / f"stream-{name}.rx.bin", "ab")
        self.tx_file = open(self.out / f"stream-{name}.tx.bin", "ab")
        self.emu = Emulator(cols, rows)
        self.lock = threading.Condition()
        self.raw = bytearray()
        self.version = 0
        self.last_rx = time.monotonic()
        self.eof = False
        self.snapshots = 0
        env = {"HOME": str(Path.home()), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "USER": os.environ.get("USER", ""), "LOGNAME": os.environ.get("USER", ""),
               "TERM": TERM, "LANG": "C.UTF-8"}
        if os.environ.get("SSH_AUTH_SOCK"):
            env["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
        self.transcript.rec("event", event="spawn", argv=SSH_ARGV, cols=cols, rows=rows,
                            term=TERM)
        self.proc = ptyprocess.PtyProcess.spawn(SSH_ARGV, env=env, dimensions=(rows, cols))
        self.fd = self.proc.fd
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    # -- bytes ------------------------------------------------------------
    def _read(self):
        while True:
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                self.transcript.rec("rx", data)
                self.rx_file.write(data)
                answers = self.emu.feed(data)
                self.raw.extend(data)
                self.version += 1
                self.last_rx = time.monotonic()
                for name, answer in answers:
                    self._write(answer, "answer", query=name)
                self.lock.notify_all()
        with self.lock:
            self.eof = True
            self.transcript.rec("event", event="eof")
            self.lock.notify_all()

    def _write(self, data, direction="tx", **extra):
        self.transcript.rec(direction, data, **extra)
        self.tx_file.write(data)
        try:
            os.write(self.fd, data)
        except OSError as e:
            self.transcript.rec("event", event="write_failed", error=str(e))

    def send(self, data, note=None):
        if isinstance(data, str):
            data = data.encode()
        with self.lock:
            self._write(data, "tx", **({"note": note} if note else {}))

    def type(self, text, delay=0.02, enter=False, enter_pause=0.4):
        """Type like a person: one character at a time, then Enter after a pause."""
        for ch in text:
            self.send(ch)
            time.sleep(delay)
        if enter:
            time.sleep(enter_pause)
            self.send(b"\r", note="enter")

    def key(self, name):
        cursor_app = self.emu.modes.get(1, False)
        keys = {"enter": b"\r", "esc": b"\x1b", "ctrl-c": b"\x03", "ctrl-z": b"\x1a",
                "ctrl-d": b"\x04", "tab": b"\t", "backspace": b"\x7f",
                "up": b"\x1bOA" if cursor_app else b"\x1b[A",
                "down": b"\x1bOB" if cursor_app else b"\x1b[B",
                "right": b"\x1bOC" if cursor_app else b"\x1b[C",
                "left": b"\x1bOD" if cursor_app else b"\x1b[D"}
        self.send(keys[name], note=name)

    def resize(self, cols, rows):
        with self.lock:
            self.emu.resize(cols, rows)
            self.transcript.rec("event", event="resize", cols=cols, rows=rows)
            self.proc.setwinsize(rows, cols)

    def hangup(self):
        """Close the terminal as a window close does: SIGHUP to ssh (what the
        kernel sends the session leader when the master closes); ssh exits,
        the connection drops, and sshd hangs up the far end's pty. The master
        is closed once the reader has seen the slave go away."""
        self.transcript.rec("event", event="hangup", pid=self.proc.pid)
        try:
            os.kill(self.proc.pid, signal.SIGHUP)
        except OSError as e:
            self.transcript.rec("event", event="hangup_error", error=repr(e))
        self.reader.join(timeout=10)
        try:
            self.proc.close(force=True)
        except Exception as e:  # noqa: BLE001 - recorded
            self.transcript.rec("event", event="close_error", error=repr(e))

    def close(self):
        if self.proc.isalive():
            self.hangup()
        self.transcript.rec("event", event="closed", queries=dict(self.emu.queries),
                            unanswered=dict(self.emu.unanswered),
                            mode_changes=dict(self.emu.mode_changes), kitty=dict(self.emu.kitty))
        self.transcript.close()
        self.rx_file.close()
        self.tx_file.close()

    # -- screen -----------------------------------------------------------
    def text(self):
        with self.lock:
            return self.emu.text()

    def raw_since(self, mark):
        with self.lock:
            return bytes(self.raw[mark:])

    def mark(self):
        with self.lock:
            return len(self.raw)

    def snapshot(self, label):
        with self.lock:
            self.snapshots += 1
            text = self.emu.text()
            cols, rows = self.emu.size
            name = f"{self.name}-{self.snapshots:03d}-{re.sub(r'[^A-Za-z0-9_.-]+', '_', label)}.txt"
            (self.out / "screens" / name).write_text(text + "\n")
            self.transcript.rec("event", event="snapshot", label=label, file=name, cols=cols,
                                rows=rows,
                                sha256=hashlib.sha256(text.encode()).hexdigest())
        return text

    def note(self, event, **extra):
        self.transcript.rec("event", event=event, **extra)

    def wait(self, pred, timeout, desc, settle=0.0):
        """Wait until pred(screen_text, raw_bytes) holds (and, with settle,
        has held with no new output for `settle` seconds). Records the result."""
        start = time.monotonic()
        deadline = start + timeout
        with self.lock:
            while True:
                text = self.emu.text()
                ok = pred(text, self.raw)
                now = time.monotonic()
                if ok and (not settle or now - self.last_rx >= settle):
                    self.transcript.rec("event", event="wait", desc=desc, ok=True,
                                        waited=round(now - start, 3))
                    return True
                if now >= deadline or (self.eof and not ok):
                    self.transcript.rec("event", event="wait", desc=desc, ok=False,
                                        waited=round(now - start, 3), eof=self.eof)
                    return False
                self.lock.wait(min(0.1, deadline - now))

    def wait_raw(self, pattern, timeout, desc, start=0):
        """Wait for a regex over the received bytes from offset `start`; return the match."""
        rx = re.compile(pattern)
        found = {}

        def pred(_text, raw):
            m = rx.search(bytes(raw[start:]))
            if m:
                found["m"] = m
            return m is not None
        self.wait(pred, timeout, desc)
        return found.get("m")

    def quiet(self, seconds, timeout=60):
        """Wait until nothing was received for `seconds`."""
        return self.wait(lambda t, r: True, timeout, f"quiet {seconds}s", settle=seconds)
