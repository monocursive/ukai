"""Client for serve.py: ctl.py DIR type TEXT [enter] | key NAME | resize C R | snap L | hangup | quit | show [SECS]"""
import json, sys, time
from pathlib import Path
d = Path(sys.argv[1]); op = sys.argv[2]; a = sys.argv[3:]
cmd = None
if op == "type":
    cmd = {"op": "type", "text": a[0], "enter": len(a) > 1 and a[1] == "enter"}
elif op == "key":
    cmd = {"op": "key", "name": a[0]}
elif op == "send":
    cmd = {"op": "send", "text": a[0].encode().decode("unicode_escape")}
elif op == "resize":
    cmd = {"op": "resize", "cols": int(a[0]), "rows": int(a[1])}
elif op in ("snap", "hangup", "quit"):
    cmd = {"op": op, "label": a[0] if a else op}
if cmd:
    with open(d / "ctl", "w") as f:
        f.write(json.dumps(cmd) + "\n")
wait = float(a[-1]) if op == "show" and a else (2.0 if cmd else 0)
time.sleep(wait)
text = (d / "screen.txt").read_text().rstrip("\n").split("\n")
while text and not text[-1].strip():
    text.pop()
print("\n".join(f"{i:02d}|{l}" for i, l in enumerate(text)))
