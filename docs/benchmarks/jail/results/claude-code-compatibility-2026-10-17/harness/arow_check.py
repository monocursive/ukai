#!/usr/bin/env python3
"""Check one arow_run.py run against jail-launch-and-summary.md §6.3.

usage: arow_check.py RUN_DIR JAIL SUMMARY_CHECK [--workspace DIR]
                     [--expect FILE=CONTENT]... [--credential ID]

Archives the attempt's receipt, policy and journal into RUN_DIR/attempt/,
prints `ukai-jail tail --summary` (text and --json) into RUN_DIR, compares
the text with the summary the live run printed on its terminal, runs the
repository's independent recomputation (docs/specs/jail-v1/summary_check.py)
on the archived copy, and evaluates the receipt and journal conditions.
Writes RUN_DIR/check.json and prints one line. Reads no credential value.
"""
import argparse
import collections
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]
PREFIX = "ukai-jail: "


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("jail")
    parser.add_argument("summary_check")
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--expect", action="append", default=[])
    parser.add_argument("--credential", default="claude-oauth",
                        help="the one credential id expected, or `none` for a run without one")
    parser.add_argument("--hosts", default="api.anthropic.com:443",
                        help="comma-separated allow_host grants the launch profile declares")
    parser.add_argument("--install-root")
    args = parser.parse_args()
    run = args.run
    result = json.loads((run / "exit.json").read_text())
    terminal = (run / "terminal.txt").read_bytes().decode(errors="replace").replace("\r\n", "\n")
    lines = terminal.split("\n")
    receipts = [l for l in lines if re.search(r"ukai-jail: receipt (/\S+/jail\.json)$", l)]
    out = {"run": run.name, "exit": result["exit"], "elapsed_s": result["elapsed_s"],
           "timed_out": result["timed_out"], "checks": {}, "facts": {}}
    checks, facts = out["checks"], out["facts"]
    if not receipts:
        out["receipt"] = None
        (run / "check.json").write_text(json.dumps(out, indent=1) + "\n")
        print(json.dumps({"run": run.name, "exit": result["exit"], "receipt": None}))
        return
    receipt_path = Path(re.search(r"(/\S+/jail\.json)$", receipts[-1]).group(1))
    attempt = receipt_path.parent
    out["attempt_id"] = attempt.name
    archive = run / "attempt"
    archive.mkdir(exist_ok=True)
    for name in ("jail.json", "policy.json", "trace.ndjson"):
        if (attempt / name).exists():
            shutil.copy2(attempt / name, archive / name)

    # The live summary: the run's last block of `ukai-jail: ` lines, ending
    # with the receipt line. A `tail --summary` of the archived attempt must
    # print it byte for byte (K52).
    index = max(i for i, l in enumerate(lines) if l == receipts[-1])
    tail_text = subprocess.run([args.jail, "tail", "--summary", "--attempt", attempt.name],
                               capture_output=True)
    (run / "tail-summary.txt").write_bytes(tail_text.stdout)
    tail_json = subprocess.run([args.jail, "tail", "--summary", "--json", "--attempt", attempt.name],
                               capture_output=True)
    (run / "tail-summary.json").write_bytes(tail_json.stdout)
    printed = tail_text.stdout.decode().rstrip("\n").split("\n")
    live = lines[index - len(printed) + 1:index + 1]
    # The agent's own last stderr bytes may share the first summary line
    # (no trailing newline from the agent): compare from the line's prefix.
    if live and not live[0].startswith(PREFIX) and PREFIX in live[0]:
        live[0] = live[0][live[0].index(PREFIX):]
    checks["tail_summary_exit_0"] = tail_text.returncode == 0 and tail_json.returncode == 0
    checks["tail_summary_equals_live"] = live == printed
    summary = json.loads(tail_json.stdout) if tail_json.returncode == 0 else {}
    texts = [PREFIX + entry["text"] for entry in summary.get("lines", [])]
    checks["json_text_equals_live"] = texts == printed[:-1]
    recompute = subprocess.run([sys.executable, "-I", args.summary_check, str(archive),
                                str(run / "tail-summary.json")], capture_output=True, text=True)
    (run / "summary-check.txt").write_text(recompute.stdout + recompute.stderr)
    checks["independent_recompute"] = recompute.returncode == 0

    receipt = json.loads((archive / "jail.json").read_text())
    facts["receipt_digest_in_summary"] = summary.get("receipt_digest")
    facts["phase"] = receipt["phase"]
    facts["outcome"] = receipt["outcome"]
    facts["errors"] = receipt["errors"]
    facts["coverage"] = {k: [v.get("status"), len(v.get("gaps") or []), v.get("observed_count")]
                         for k, v in receipt["coverage"].items()}
    facts["tree_empty"] = receipt["lifetime"].get("tree_empty")
    facts["state_cleanup"] = receipt["state_cleanup"]
    facts["credentials"] = receipt["credentials"]
    facts["grants"] = receipt["policy"]["grants"]
    facts["child_protection"] = receipt["child_protection"]
    checks["settled"] = receipt["phase"] == "settled"
    checks["exited_0"] = receipt["outcome"].get("kind") == "exited" and receipt["outcome"].get("code") == 0
    checks["no_errors"] = receipt["errors"] == []
    checks["six_classes_active_no_gaps"] = (sorted(receipt["coverage"]) == sorted(CLASSES) and all(
        v.get("status") == "active" and not v.get("gaps") for v in receipt["coverage"].values()))
    checks["tree_empty"] = receipt["lifetime"].get("tree_empty") is True
    checks["state_cleanup_complete"] = receipt["state_cleanup"] == "complete"
    facts["observer_gaps"] = [[g.get("reason"), g.get("classes"), g.get("lost_count")]
                              for g in receipt["observer"].get("gaps") or []]
    creds = receipt["credentials"]
    cred_line = [e for e in summary.get("lines", []) if e["line"] == "credentials"]
    cred_facts = cred_line[0]["facts"]["credentials"] if cred_line else []
    facts["summary_credential"] = cred_facts
    if args.credential == "none":
        checks["no_credential"] = creds == [] and cred_facts == []
    else:
        checks["one_credential_never_staged"] = (len(creds) == 1 and creds[0]["id"] == args.credential
                                                 and creds[0].get("never_staged") is True)
        checks["summary_shows_use_count"] = (len(cred_facts) == 1 and cred_facts[0]["id"] == args.credential
                                             and isinstance(cred_facts[0].get("uses"), int)
                                             and cred_facts[0].get("uses_bound") == "exact")
    derived = [g for g in receipt["policy"]["grants"] if g.get("by") == "program_resolution"]
    others = [g for g in receipt["policy"]["grants"] if g.get("by") != "program_resolution"]
    checks["derived_install_root_only"] = (
        len(derived) == 1 and derived[0]["kind"] == "read_only"
        and (args.install_root is None or derived[0]["value"] == args.install_root))
    checks["no_unexpected_grant"] = sorted(others, key=str) == sorted(
        ({"kind": "allow_host", "value": host, "by": "operator"} for host in args.hosts.split(",")), key=str)

    events = [json.loads(l) for l in (archive / "trace.ndjson").read_text().splitlines() if l.strip()]
    proxy = collections.Counter()
    refusals = collections.Counter()
    uses = 0
    for e in events:
        f = e.get("fields") or {}
        if e.get("source") == "proxy" and e.get("operation") == "net.connect" and e.get("stage") == "result":
            proxy[(f.get("destination"), e.get("decision"), f.get("reason"),
                   (e.get("outcome") or {}).get("ok"))] += 1
            if args.credential in (f.get("credentials") or []):
                uses += 1
            if str(f.get("reason", "")).startswith("credential_"):
                refusals[f.get("reason")] += 1
    facts["proxy_results"] = [list(k) + [v] for k, v in sorted(proxy.items(), key=str)]
    facts["results_carrying_credential"] = uses
    facts["credential_refusals"] = dict(refusals)
    facts["credential_notes"] = [[(e.get("fields") or {}).get("credential_id"),
                                  (e.get("fields") or {}).get("transition")]
                                 for e in events if e.get("operation") == "note"
                                 and (e.get("fields") or {}).get("kind") == "credential"]
    facts["fs_deny"] = [[(e.get("fields") or {}).get("attempted_operation"),
                         (e.get("fields") or {}).get("syscall"),
                         (e.get("fields") or {}).get("path")]
                        for e in events if e.get("operation") == "fs.deny"]
    facts["exec_paths"] = sorted(collections.Counter(
        json.dumps((e.get("fields") or {}).get("path"), sort_keys=True)
        for e in events if e.get("operation") == "proc.exec").items())
    facts["frames"] = len(events)
    checks["credential_process_denied_absent"] = "credential_process_denied" not in refusals
    if args.credential != "none":
        checks["uses_match_summary"] = bool(cred_facts) and cred_facts[0].get("uses") == uses

    for expectation in args.expect:
        name, _, content = expectation.partition("=")
        path = args.workspace / name
        actual = path.read_text() if path.is_file() else None
        facts["file:" + name] = actual
        checks["file:" + name] = actual is not None and actual.strip() == content
    out["pass"] = all(checks.values())
    (run / "check.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({"run": run.name, "pass": out["pass"],
                      "failed": [k for k, v in checks.items() if not v],
                      "elapsed_s": result["elapsed_s"], "proxy": facts["proxy_results"],
                      "fs_deny": len(facts["fs_deny"])}))


if __name__ == "__main__":
    main()
