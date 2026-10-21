"""Stage the compact confirmation of one arow_int.py output directory.

usage: python3 package_confirm.py OUT STAGE
Keeps, per attempt: check.json, the receipt (attempt/jail.json), the summary
`tail --summary` printed (tail-summary.txt), the summary the terminal showed
(live-summary.txt, absent after the hangup), the pre-exec lines the terminal
showed (pre-exec.txt) and summary_check.py's output; per run: run.json; at the
top: report.md, results.ndjson, chain.json, facts.json, k70-sweep.txt,
harness.sha256, driver.log and host-evidence/. Leaves out the transcripts, the
raw streams, the journals, the policy snapshots and the state listings: the
token search ran over all of them on the host (k70-sweep.txt and each
attempt's token-search.json, which is kept).
"""
import json
import shutil
import sys
from pathlib import Path

out, stage = Path(sys.argv[1]), Path(sys.argv[2])
stage.mkdir(parents=True, exist_ok=False)
for name in ("report.md", "results.ndjson", "chain.json", "facts.json", "k70-sweep.txt", "harness.sha256",
             "driver.log"):
    if (out / name).exists():
        shutil.copy2(out / name, stage / name)
if (out / "host-evidence").is_dir():
    shutil.copytree(out / "host-evidence", stage / "host-evidence")
for run in sorted(p for p in out.iterdir() if p.is_dir() and (p / "run.json").exists()):
    rec = json.loads((run / "run.json").read_text())
    obs = rec.get("observations", {})
    dst = stage / "runs" / run.name
    dst.mkdir(parents=True)
    shutil.copy2(run / "run.json", dst / "run.json")
    for line in rec.get("attempts", []):
        label = line["label"]
        src = run / label
        ldst = dst / label
        (ldst / "attempt").mkdir(parents=True)
        shutil.copy2(src / "attempt" / "jail.json", ldst / "attempt" / "jail.json")
        for name in ("check.json", "tail-summary.txt", "summary-check.txt", "token-search.json"):
            if (src / name).exists():
                shutil.copy2(src / name, ldst / name)
        res = obs.get(f"{label}:results") or obs.get(label.split("-")[0] + ":results") or obs.get("results")
        if line.get("pre_exec") is not None:
            (ldst / "pre-exec.txt").write_text("\n".join(line["pre_exec"]) + "\n")
        if isinstance(res, dict) and res.get("live_summary"):
            (ldst / "live-summary.txt").write_text("\n".join(res["live_summary"]) + "\n")
print(sum(1 for p in stage.rglob("*") if p.is_file()), "files staged")
