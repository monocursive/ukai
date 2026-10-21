"""Stage one arow_int.py output directory as the record's results directory.

usage: python3 package.py OUT STAGE
Copies (never the token: everything here came from the host after its token
search, or was rendered from transcripts searched there):
  STAGE/<top-level>      chain.json facts.json results.ndjson report.md k70-sweep.txt
                         driver.log harness.sha256 and host-evidence/
  STAGE/runs/<run>/      run.json, final screens, screens/, transcript-*.ndjson
  STAGE/runs/<run>/<attempt label>/  attempt/{jail,policy}.json, attempt/trace.ndjson,
                         check.json, tail-summary.*, summary-check.txt, state-*.txt|json,
                         token-search.json
Left out: the raw stream-*.bin copies (the ndjson transcripts hold the same
bytes, reversibly) and each attempt's transcripts/ (a copy of its run's
transcripts, kept on the host only for the token search).
Compression (gzip -9 -n of transcripts and journals) is a separate step, after
the staged tree has been searched on the host.
"""
import shutil
import sys
from pathlib import Path

out, stage = Path(sys.argv[1]), Path(sys.argv[2])
stage.mkdir(parents=True, exist_ok=False)
for name in ("chain.json", "facts.json", "results.ndjson", "report.md", "k70-sweep.txt", "driver.log",
             "harness.sha256"):
    if (out / name).exists():
        shutil.copy2(out / name, stage / name)
if (out / "host-evidence").is_dir():
    shutil.copytree(out / "host-evidence", stage / "host-evidence")
for run in sorted(p for p in out.iterdir() if p.is_dir() and (p / "run.json").exists()):
    dst = stage / "runs" / run.name
    dst.mkdir(parents=True)
    for f in run.iterdir():
        if f.is_file() and (f.name == "run.json" or f.name.startswith(("final-screen-", "transcript-"))
                            or f.name == "editor-ps.txt"):
            shutil.copy2(f, dst / f.name)
    if (run / "screens").is_dir():
        shutil.copytree(run / "screens", dst / "screens")
    for label in sorted(p for p in run.iterdir() if p.is_dir() and (p / "check.json").exists()):
        ldst = dst / label.name
        shutil.copytree(label, ldst, ignore=shutil.ignore_patterns("transcripts"))
print(sum(1 for p in stage.rglob("*") if p.is_file()), "files staged")
