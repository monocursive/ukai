"""Exploration helper: keep one harness terminal open and take commands from
a FIFO, so the screens of Claude Code can be learned step by step.

usage: uv run --with pexpect --with pyte python3 serve.py DIR
Commands (one JSON object per line written to DIR/ctl):
  {"op": "type", "text": "...", "enter": true}   {"op": "key", "name": "enter"}
  {"op": "send", "text": "..."}                   {"op": "resize", "cols": 100, "rows": 30}
  {"op": "snap", "label": "x"}                    {"op": "hangup"}   {"op": "quit"}
DIR/screen.txt always holds the current screen; DIR/status.json the modes and queries.
"""
import json
import os
import sys
import threading
import time
from pathlib import Path

from ttyharness import Session

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
ctl = out / "ctl"
if not ctl.exists():
    os.mkfifo(ctl)
s = Session(out, name=sys.argv[2] if len(sys.argv) > 2 else "x")
done = threading.Event()


def dumper():
    seen = None
    while not done.is_set():
        text = s.text()
        if text != seen:
            (out / "screen.txt").write_text(text + "\n")
            seen = text
        (out / "status.json").write_text(json.dumps({
            "size": s.emu.size, "eof": s.eof, "modes": s.emu.modes,
            "queries": s.emu.queries, "unanswered": s.emu.unanswered,
            "mode_changes": s.emu.mode_changes, "kitty": s.emu.kitty,
            "cursor": [s.emu.screen.cursor.x, s.emu.screen.cursor.y]}, default=dict, indent=1))
        time.sleep(0.3)


threading.Thread(target=dumper, daemon=True).start()
while not done.is_set():
    with open(ctl) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
            except ValueError:
                continue
            op = c["op"]
            if op == "type":
                s.type(c["text"], enter=c.get("enter", False))
            elif op == "key":
                s.key(c["name"])
            elif op == "send":
                s.send(c["text"].encode("latin-1"))
            elif op == "resize":
                s.resize(c["cols"], c["rows"])
            elif op == "snap":
                s.snapshot(c.get("label", "snap"))
            elif op == "hangup":
                s.hangup()
            elif op == "quit":
                done.set()
s.close()
