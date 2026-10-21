#!/usr/bin/env python3
"""Collect and check one attempt of the interactive Claude Code A-row
(docs/specs/jail-interactive-sessions.md §6.3) on the reference host.

usage: arow_int_collect.py RUN_DIR ATTEMPT_ID --workspace WS [options]

Archives the attempt's receipt, policy and journal into RUN_DIR/attempt/,
writes `ukai-jail tail --summary` (text and --json), `state list` (text and
--json), `state show claude --workspace WS` and a listing of the state's
vendor directory (names, types, sizes: the operator's host only), runs the
repository's independent recomputation (summary_check.py) on the archived
copy, evaluates §6.3's pass conditions, and writes RUN_DIR/check.json. With
--token-file it then runs the token search (grep -rlF -f, file names only)
over RUN_DIR, the attempt directory, the workspace and the state, and
records it in RUN_DIR/token-search.json. Never reads a credential value
itself: only grep reads the token file.

Options:
  --kind persistent|attempt_fallback   what vendor_state must be (default persistent)
  --prev-attempt ATT --prev-generation N   the chain: the attempt and generation the
                                       state must start from (omit for a new state)
  --new-state                          the state must be new (generation 1, new_state)
  --holder ATT                         for attempt_fallback: the attempt that held it
  --attached yes|no                    whether applied.terminal must be present
  --expect-exit 0|any                  (default 0)
  --extra-host HOST:PORT               an allow_host grant the operator added (repeatable)
  --expect FILE=CONTENT                a workspace file the task must leave (repeatable)
  --absent-in-state NAME               a file name that must not be in the state after release
"""
import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]
HERE = Path(__file__).resolve().parent


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, **kw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("attempt")
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--jail", default=str(Path.home() / "arow-int-pilot/bin/ukai-jail"))
    ap.add_argument("--summary-check", default=str(HERE / "summary_check.py"))
    ap.add_argument("--kind", default="persistent", choices=["persistent", "attempt_fallback"])
    ap.add_argument("--prev-attempt")
    ap.add_argument("--prev-generation", type=int)
    ap.add_argument("--new-state", action="store_true")
    ap.add_argument("--holder")
    ap.add_argument("--attached", choices=["yes", "no"], default="yes")
    ap.add_argument("--expect-exit", default="0")
    ap.add_argument("--extra-host", action="append", default=[])
    ap.add_argument("--hosts", default="api.anthropic.com:443")
    ap.add_argument("--install-root", default=str(Path.home() / ".local/share/claude/versions"))
    ap.add_argument("--credential", default="claude-oauth")
    ap.add_argument("--expect", action="append", default=[])
    ap.add_argument("--absent-in-state", action="append", default=[])
    ap.add_argument("--token-file")
    ap.add_argument("--hangup", action="store_true",
                    help="run 4: the terminal was hung up, so restore cannot succeed; require only "
                         "a non-null restored record with after_tree_death true")
    ap.add_argument("--search", action="append", default=[], help="extra paths for the token search")
    a = ap.parse_args()

    run_dir = a.run
    run_dir.mkdir(parents=True, exist_ok=True)
    data = Path(os.environ.get("UKAI_DATA_DIR") or Path.home() / ".local/share/ukai")
    attempt = data / "attempts" / a.attempt
    archive = run_dir / "attempt"
    archive.mkdir(exist_ok=True)
    for name in ("jail.json", "policy.json", "trace.ndjson"):
        if (attempt / name).exists():
            shutil.copy2(attempt / name, archive / name)
    out = {"attempt_id": a.attempt, "checks": {}, "facts": {}}
    checks, facts = out["checks"], out["facts"]

    # The summary, as `tail` prints it from the attempt, and its recomputation.
    t = run([a.jail, "tail", "--summary", "--attempt", a.attempt])
    (run_dir / "tail-summary.txt").write_bytes(t.stdout + t.stderr)
    tj = run([a.jail, "tail", "--summary", "--json", "--attempt", a.attempt])
    (run_dir / "tail-summary.json").write_bytes(tj.stdout)
    checks["tail_summary_exit_0"] = t.returncode == 0 and tj.returncode == 0
    summary = json.loads(tj.stdout) if tj.returncode == 0 else {}
    printed = t.stdout.decode().rstrip("\n").split("\n")
    texts = ["ukai-jail: " + e["text"] for e in summary.get("lines", [])]
    checks["json_text_equals_tail"] = texts == printed[:-1]
    rc = run([sys.executable, "-I", a.summary_check, str(archive), str(run_dir / "tail-summary.json")],
             text=True)
    (run_dir / "summary-check.txt").write_text(rc.stdout + rc.stderr)
    checks["independent_recompute"] = rc.returncode == 0

    # The state verbs and the state's files.
    sl = run([a.jail, "state", "list"])
    (run_dir / "state-list.txt").write_bytes(sl.stdout + sl.stderr)
    slj = run([a.jail, "state", "list", "--json"])
    (run_dir / "state-list.json").write_bytes(slj.stdout)
    ss = run([a.jail, "state", "show", "claude", "--workspace", str(a.workspace)])
    (run_dir / "state-show.txt").write_bytes(ss.stdout + ss.stderr)
    states = json.loads(slj.stdout) if slj.returncode == 0 else []
    mine = [s for s in states if s.get("workspace") == str(a.workspace) and s.get("launch") == "claude"]
    state_dir = None
    if mine:
        facts["state_list_entry"] = mine[0]
        state_dir = data / "state" / "claude" / mine[0]["key"]
        files = []
        vendor = state_dir / "vendor"
        for root, dirs, names in os.walk(vendor, followlinks=False):
            for n in sorted(dirs + names):
                p = Path(root) / n
                st = p.lstat()
                kind = "d" if p.is_dir() and not p.is_symlink() else "l" if p.is_symlink() else "f"
                files.append([kind, oct(st.st_mode & 0o7777), st.st_size, str(p.relative_to(vendor))])
        files.sort(key=lambda f: f[3])
        (run_dir / "state-files.txt").write_text(
            "".join(f"{k} {m} {s:>9} {n}\n" for k, m, s, n in files))
        facts["state_files"] = len([f for f in files if f[0] == "f"])
        facts["state_bytes"] = sum(f[2] for f in files if f[0] == "f")
        facts["state_top_level"] = sorted({f[3].split("/")[0] for f in files})
        for name in a.absent_in_state:
            checks["state_has_no:" + name] = not any(Path(f[3]).name == name for f in files)

    receipt = json.loads((archive / "jail.json").read_text())
    policy = json.loads((archive / "policy.json").read_text()) if (archive / "policy.json").exists() else {}
    snapshot = policy.get("snapshot") or {}
    facts["phase"] = receipt["phase"]
    facts["outcome"] = receipt["outcome"]
    facts["errors"] = receipt["errors"]
    facts["coverage"] = {k: [v.get("status"), len(v.get("gaps") or []), v.get("observed_count")]
                         for k, v in receipt["coverage"].items()}
    facts["observer_gaps"] = collections.Counter(
        (g.get("reason"), tuple(g.get("classes") or [])) for g in receipt["observer"].get("gaps") or [])
    facts["observer_gaps"] = [[r, list(c), n] for (r, c), n in facts["observer_gaps"].items()]
    facts["tree_empty"] = receipt["lifetime"].get("tree_empty")
    facts["state_cleanup"] = receipt["state_cleanup"]
    facts["vendor_state"] = receipt.get("vendor_state")
    facts["credentials"] = receipt["credentials"]
    facts["grants"] = receipt["policy"]["grants"]
    facts["terminal"] = receipt["applied"].get("terminal")
    facts["policy_terminal"] = snapshot.get("terminal")
    facts["policy_vendor_state"] = (snapshot.get("roots") or {}).get("vendor_state")
    facts["environment_names"] = receipt["applied"].get("environment_names")
    facts["requested"] = receipt.get("requested")

    checks["settled"] = receipt["phase"] == "settled"
    if a.expect_exit == "any":
        facts["exit_condition"] = "any (recorded)"
    else:
        checks["exited_" + a.expect_exit] = (receipt["outcome"].get("kind") == "exited"
                                             and receipt["outcome"].get("code") == int(a.expect_exit))
        checks["no_errors"] = receipt["errors"] == []
    checks["six_classes_active_no_gaps"] = (sorted(receipt["coverage"]) == sorted(CLASSES) and all(
        v.get("status") == "active" and not v.get("gaps") for v in receipt["coverage"].values()))
    checks["tree_empty"] = receipt["lifetime"].get("tree_empty") is True
    creds = receipt["credentials"]
    checks["one_credential_never_staged"] = (len(creds) == 1 and creds[0]["id"] == a.credential
                                             and creds[0].get("never_staged") is True)
    derived = [g for g in receipt["policy"]["grants"] if g.get("by") == "program_resolution"]
    others = [g for g in receipt["policy"]["grants"] if g.get("by") != "program_resolution"]
    checks["derived_install_root_only"] = (len(derived) == 1 and derived[0]["kind"] == "read_only"
                                           and derived[0]["value"] == a.install_root)
    expected_hosts = a.hosts.split(",") + a.extra_host
    facts["other_grants"] = others
    checks["no_unexpected_grant"] = (sorted(g.get("value") for g in others if g.get("kind") == "allow_host")
                                     == sorted(expected_hosts)
                                     and all(g.get("kind") == "allow_host" for g in others))

    # State (§4.7).
    vs = receipt.get("vendor_state") or {}
    if a.kind == "persistent":
        checks["state_cleanup_released"] = receipt["state_cleanup"] == "released"
        checks["vendor_state_persistent"] = vs.get("kind") == "persistent"
        checks["secret_scan_clean"] = vs.get("secret_scan") == "clean"
        start = vs.get("generation_start")
        checks["generation_end_is_start_plus_1"] = (isinstance(start, int)
                                                    and vs.get("generation_end") == start + 1)
        if a.new_state:
            checks["new_state"] = (start == 0 and vs.get("inherited_from") is None
                                   and vs.get("matches_release") is None
                                   and vs.get("matches_release_reason") == "new_state")
        else:
            checks["matches_release_true"] = vs.get("matches_release") is True
            if a.prev_generation is not None:
                checks["chains_generation"] = start == a.prev_generation
            if a.prev_attempt:
                checks["chains_attempt"] = vs.get("inherited_from") == a.prev_attempt
    else:
        checks["state_cleanup_complete"] = receipt["state_cleanup"] == "complete"
        checks["vendor_state_attempt_fallback"] = vs.get("kind") == "attempt_fallback"
        if a.holder:
            checks["held_by_holder"] = vs.get("held_by") == a.holder and vs.get("reason") == "held"
        state_line = [e for e in summary.get("lines", []) if e.get("line") == "state"]
        facts["summary_state_line"] = state_line[0]["text"] if state_line else None
        checks["summary_says_NOT_kept"] = bool(state_line) and "NOT kept" in state_line[0]["text"]

    # Terminal (§3.7).
    term = receipt["applied"].get("terminal")
    facts["lifetime_integrity"] = receipt["lifetime"].get("integrity")
    checks["tree_death_verified"] = (receipt["lifetime"].get("integrity") == "verified"
                                     and receipt["lifetime"].get("tree_empty") is True)
    if a.attached == "yes" and a.hangup:
        restored = (term or {}).get("restored") or {}
        facts["restored_after_hangup"] = restored
        checks["terminal_hangup_exception"] = (term is not None and restored.get("after_tree_death") is True
                                               and sorted(restored) == sorted(["foreground", "termios",
                                                                               "input_flushed", "reset_written",
                                                                               "after_tree_death"]))
        checks["policy_terminal_attached"] = snapshot.get("terminal") == "attached"
    elif a.attached == "yes":
        restored = (term or {}).get("restored") or {}
        checks["terminal_attached_restored_all_five"] = (
            term is not None and term.get("device") == "pty" and term.get("session") == "caller"
            and term.get("process_group") == "own"
            and sorted(restored) == sorted(["foreground", "termios", "input_flushed", "reset_written",
                                            "after_tree_death"])
            and all(v is True for v in restored.values()))
        checks["policy_terminal_attached"] = snapshot.get("terminal") == "attached"
    else:
        checks["no_applied_terminal"] = term is None
        checks["policy_terminal_omitted"] = "terminal" not in snapshot

    # The journal.
    events = [json.loads(l) for l in (archive / "trace.ndjson").read_text().splitlines() if l.strip()]
    proxy = collections.Counter()
    refusals = collections.Counter()
    uses = 0
    for e in events:
        f = e.get("fields") or {}
        if e.get("source") == "proxy" and e.get("operation") == "net.connect" and e.get("stage") == "result":
            proxy[(f.get("destination"), e.get("decision"), f.get("reason"),
                   (e.get("outcome") or {}).get("ok"), f.get("end"))] += 1
            if a.credential in (f.get("credentials") or []):
                uses += 1
            if str(f.get("reason", "")).startswith("credential_"):
                refusals[f.get("reason")] += 1
    facts["proxy_results"] = [list(k) + [v] for k, v in sorted(proxy.items(), key=str)]
    facts["results_carrying_credential"] = uses
    facts["credential_refusals"] = dict(refusals)
    notes = [e for e in events if e.get("operation") == "note"]
    facts["lifecycle_notes"] = [[round(int(e.get("monotonic_ns") or 0) / 1e9, 3), (e.get("fields") or {}).get("kind"),
                                 (e.get("fields") or {}).get("transition"),
                                 (e.get("fields") or {}).get("reason") or (e.get("fields") or {}).get("cause")]
                                for e in notes]
    facts["terminal_notes"] = collections.Counter(
        (e.get("fields") or {}).get("transition") for e in notes
        if str((e.get("fields") or {}).get("transition", "")).startswith("terminal_"))
    facts["fs_deny"] = [[(e.get("fields") or {}).get("attempted_operation"),
                         (e.get("fields") or {}).get("syscall"),
                         (e.get("fields") or {}).get("path")]
                        for e in events if e.get("operation") == "fs.deny"]
    facts["exec_count"] = sum(1 for e in events if e.get("operation") == "proc.exec")
    facts["exec_paths"] = sorted(collections.Counter(
        json.dumps((e.get("fields") or {}).get("path"), sort_keys=True)
        for e in events if e.get("operation") == "proc.exec").items())
    facts["frames"] = len(events)
    checks["credential_process_denied_absent"] = "credential_process_denied" not in refusals
    cred_line = [e for e in summary.get("lines", []) if e.get("line") == "credentials"]
    cred_facts = cred_line[0]["facts"]["credentials"] if cred_line else []
    facts["summary_credential"] = cred_facts
    checks["summary_uses_match_journal"] = bool(cred_facts) and cred_facts[0].get("uses") == uses

    for expectation in a.expect:
        name, _, content = expectation.partition("=")
        path = a.workspace / name
        actual = path.read_text() if path.is_file() else None
        facts["file:" + name] = actual
        checks["file:" + name] = actual is not None and actual.strip() == content

    # The token search (K70): file names only.
    if a.token_file:
        paths = [str(run_dir), str(attempt), str(a.workspace)] + a.search
        if state_dir is not None:
            paths.append(str(state_dir))
        g = run(["grep", "-rlF", "-f", a.token_file, "--"] + paths, text=True)
        search = {"paths": paths, "exit": g.returncode, "hits": g.stdout.split("\n")[:-1] if g.stdout else [],
                  "stderr": g.stderr[-2000:]}
        (run_dir / "token-search.json").write_text(json.dumps(search, indent=1) + "\n")
        checks["token_absent"] = g.returncode == 1
        facts["token_search_exit"] = g.returncode

    out["pass"] = all(checks.values())
    (run_dir / "check.json").write_text(json.dumps(out, indent=1, default=list) + "\n")
    print(json.dumps({"attempt": a.attempt, "pass": out["pass"],
                      "failed": [k for k, v in checks.items() if not v],
                      "outcome": receipt["outcome"].get("kind"), "code": receipt["outcome"].get("code"),
                      "state_cleanup": receipt["state_cleanup"],
                      "generation": [vs.get("generation_start"), vs.get("generation_end")],
                      "proxy": facts["proxy_results"]}, default=list))


if __name__ == "__main__":
    main()
