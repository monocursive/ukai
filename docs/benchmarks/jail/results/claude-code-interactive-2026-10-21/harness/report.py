"""Summarise one arow_int.py output directory: per attempt, §6.3's checks and
the evidence path; per run, the harness observations that are not in a
receipt (K62, pre-exec lines, live summary = tail, session ids, screens);
the terminal facts the emulator recorded (alternate screen, modes, queries).

usage: python3 report.py OUT_DIR > OUT_DIR/report.md
"""
import json
import sys
from collections import Counter
from pathlib import Path

out = Path(sys.argv[1])
print(f"# Interactive Claude Code A-row: {out.name}\n")
chain = json.loads((out / "chain.json").read_text()) if (out / "chain.json").exists() else {}
print("## Attempts\n")
print("| run/attempt | pass | failed checks | outcome | state | generation | K62 pending | live = tail | evidence |")
print("|---|---|---|---|---|---|---|---|---|")
term = Counter()
for run_dir in sorted(p for p in out.iterdir() if p.is_dir() and (p / "run.json").exists()):
    rec = json.loads((run_dir / "run.json").read_text())
    obs = rec.get("observations", {})
    for a in rec.get("attempts", []):
        label = a.get("label")
        check = run_dir / label / "check.json"
        facts = json.loads(check.read_text())["facts"] if check.exists() else {}
        k62 = a.get("k62_pending", "n/a")
        vs = facts.get("vendor_state") or {}
        print(f"| {run_dir.name}/{label} | {'PASS' if a.get('pass') else 'FAIL'} | {', '.join(a.get('failed') or [])} "
              f"| {a.get('outcome')} {a.get('code')} | {facts.get('state_cleanup')} {vs.get('kind', '')} "
              f"| {a.get('generation')} | {k62} | {a.get('live_equals_tail', 'n/a')} "
              f"| `{run_dir.name}/{label}/check.json` |")
    for t in run_dir.glob("transcript-*.ndjson"):
        for line in t.read_text().splitlines():
            e = json.loads(line)
            if e.get("event") == "closed":
                for k, v in (e.get("mode_changes") or {}).items():
                    term["mode " + k] += v
                for k, v in (e.get("queries") or {}).items():
                    term["query " + k] += v
                for k, v in (e.get("unanswered") or {}).items():
                    term["unanswered " + k] += v
                for k, v in (e.get("kitty") or {}).items():
                    term["kitty " + k] += v
print("\n## Chain\n")
print("```\n" + json.dumps(chain, indent=1) + "\n```\n")
print("## Observations per run\n")
for run_dir in sorted(p for p in out.iterdir() if p.is_dir() and (p / "run.json").exists()):
    rec = json.loads((run_dir / "run.json").read_text())
    print(f"### {run_dir.name} ({rec.get('spec')})\n")
    for k, v in rec.get("observations", {}).items():
        if k.endswith("results") and isinstance(v, dict):
            v = {kk: vv for kk, vv in v.items() if kk not in ("live_summary",)}
        print(f"- `{k}`: {json.dumps(v, ensure_ascii=False, default=str)[:600]}")
    for s in rec.get("steps", []):
        print(f"- step: {json.dumps(s, ensure_ascii=False)[:300]}")
    print()
print("## Terminal facts (all sessions)\n")
for k, v in sorted(term.items()):
    print(f"- {k}: {v}")
if (out / "k70-sweep.txt").exists():
    print("\n## K70 sweep\n\n```\n" + (out / "k70-sweep.txt").read_text() + "```")
