#!/usr/bin/env python3
"""Condense retained guest records; never promote a release gate."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def trial_summary(t):
    r = t.get("receipt") or {}
    lifetime = r.get("lifetime") or {}
    details = (lifetime.get("native") or {}).get("details") or {}
    before = t.get("before_emergency_cleanup", {})
    identities = before.get("identities", [])
    after = t.get("after_emergency_cleanup", {})
    out = {key: t.get(key) for key in (
        "name", "outcome", "exit", "elapsed_ms", "ready_ms", "stop_to_snapshot_ms",
        "harness_error", "readiness_failure", "blocked_reason", "false_tree_empty",
        "honest_unknown", "custodian_loss_reported", "observation_checks", "expected_mutations",
        "ordinary_build_observation_loss_free", "ordinary_build_custody_loss_free")}
    out.update(phase=r.get("phase"), tree_empty=lifetime.get("tree_empty"),
               integrity=lifetime.get("integrity"), receipt_outcome=r.get("outcome"),
               errors=r.get("errors", []), profile_digest=details.get("profile_digest"),
               receipt_stop=details.get("stop"),
               custody={k: {field: v.get(field) for field in ("stream", "result", "events")}
                        for k, v in details.get("custodians", {}).items()},
               known_identities=len(identities), oracle_empty_before_cleanup=before.get("empty"),
               live_known_members_before_cleanup=sum(x["snapshot"]["alive"] for x in identities),
               oracle_empty_after_cleanup=after.get("empty"),
               custodians_alive_before_cleanup=[pid for pid, s in t.get("custodians_before_emergency_cleanup", {}).items() if s.get("alive")],
               signals=[{k: a.get(k) for k in ("pid", "signal", "sent", "signal_result")}
                        for a in t.get("actions", [])],
               coverage={k: {f: v.get(f) for f in ("status", "observed_count", "lost_count")}
                         for k, v in r.get("coverage", {}).items() if isinstance(v, dict)})
    if "inside" in t:
        out.update(inside_execution_marker=t["inside"].get("execution_marker"),
                   outside_execution_marker=t["outside"].get("execution_marker"),
                   positive_control_reached_target=t.get("positive_control_reached_target"))
    if "build" in t:
        out["build"] = {k: t["build"].get(k) for k in (
            "project", "version_define", "parallel_jobs", "source_lines", "source_bytes",
            "source_sha256", "source_files", "source_revision", "outputs", "built_version")}
        out["build_stderr_tail"] = t.get("stderr", "")[-2000:]
    out["fork_errors"] = dict(Counter(str(row["fork_errno"]) for row in t.get("fixture_records", [])
                                      if "fork_errno" in row))
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args()
    output = {"scope": "SIP-disabled isolated development VM; not release qualification",
              "release_gates_promoted": [], "scenarios": {}}
    for path in sorted((a.root / "results").glob("*.json")):
        data = path.read_bytes()
        result = json.loads(data)
        trials = result if isinstance(result, list) else result.get("trials", [])
        if not trials:
            continue
        summary = {"source": str(path.relative_to(a.root)), "sha256": hashlib.sha256(data).hexdigest(),
                   "outcome": result.get("outcome") if isinstance(result, dict) else None,
                   "counts": dict(Counter(t["outcome"] for t in trials)),
                   "trials": [trial_summary(t) for t in trials]}
        timings = [t["stop_to_snapshot_ms"] for t in trials if "stop_to_snapshot_ms" in t]
        if timings:
            summary["timing_tail"] = {"max_stop_to_oracle_start_ms": max(timings),
                                      "confirmed_after_5000ms": [t["name"] for t in trials
                                                                 if t.get("stop_to_snapshot_ms", 0) > 5000],
                                      "scope": "End-to-end confirmation time; not the receipt's internal drain timer"}
        if isinstance(result, dict):
            summary.update({k: result.get(k) for k in ("timings", "guest_nproc_before", "guest_nproc_after", "runner_sha256")})
        output["scenarios"][path.stem] = summary
    text = json.dumps(output, indent=2) + "\n"
    if a.output:
        a.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
