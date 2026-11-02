#!/usr/bin/env python3
"""Reconcile the receipt's whole-stop phase marks against the harness oracle.

For each k92 trial: stop_to_snapshot_ms (operator stop -> independent
process-oracle confirmation) against the receipt's stop.phases deltas
(requested -> freeze_done -> first_kill -> result -> guardian_record ->
settled), all on the continuous clock. The 2026-11-01 spike measured 20 ms
of machine drain against a 5 s oracle confirmation with no way to see where
the interval went; this table is that reconciliation.
"""
import json
from pathlib import Path
import sys

from macos_j16_spike_guest import guard, save

guard()
root = Path(sys.argv[1]).resolve()
results = json.loads((root / "results/k92.json").read_text())
rows = []
for trial in results["trials"]:
    name = trial["name"]
    receipt = root / "trials" / name / "receipt.json"
    if not receipt.exists():
        rows.append({"name": name, "receipt": False,
                     "stop_to_snapshot_ms": trial.get("stop_to_snapshot_ms")})
        continue
    record = json.loads(receipt.read_text())
    stop = (record.get("lifetime", {}).get("native", {}).get("details", {}).get("stop") or {})
    phases = stop.get("phases") or {}
    marks = {k: v for k, v in phases.items() if isinstance(v, int)}
    requested = marks.get("requested")
    deltas = {}
    if requested is not None:
        for phase, value in marks.items():
            if value is not None and value >= requested:
                deltas[phase + "_ms"] = round((value - requested) / 1e6, 1)
    rows.append({
        "name": name,
        "stop_to_snapshot_ms": trial.get("stop_to_snapshot_ms"),
        "elapsed_ns": stop.get("elapsed_ns"),
        "phases": phases,
        "deltas_from_requested": deltas,
        "drained": (record.get("lifetime", {}).get("native", {}).get("details", {})
                    .get("custodians", {}).get("supervisor", {}).get("result")),
    })
    missing = [p for p in ("requested", "result", "settled") if phases.get(p) is None]
    if missing:
        rows[-1]["missing_marks"] = missing

summary = {
    "rows": rows,
    "oracle_p50_ms": sorted(r["stop_to_snapshot_ms"] for r in rows
                            if r.get("stop_to_snapshot_ms") is not None),
}
save(root / "results/k92-phases.json", summary)
print(json.dumps({"trials": len(rows), "with_phases": sum(1 for r in rows if r.get("phases"))}))
