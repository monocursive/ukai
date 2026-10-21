#!/usr/bin/env python3
"""Checks and row records for the action self-test (.github/workflows/
action-selftest.yml; docs/specs/jail-ci-action.md §6.1, K76-K85).

Every check appends one JSON line to $SELFTEST/rows.jsonl: the row, the job
and image, what was checked, pass or fail, and whether it ran for real on
the runner or was simulated. `rows` merges every job's lines into the
per-row list in the job summary and fails on any failure or missing row.
No credential is involved: the fixture value is derived from the run id
(`token`), masked by each job before use, and never printed here.

usage: selftest.py COMMAND (see the functions below); context comes from
environment variables the workflow sets.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]
ARTIFACT_FILES = {"jail.json", "policy.json", "trace.ndjson", "summary.json", "summary.txt", "doctor.json",
                  "setup.txt"}
HOST_LINE = ("host setup (this runner only): bubblewrap 0.11.1 built from its release tarball (sha256:c1b7455a…) "
             "at /usr/local/bin/bwrap · AppArmor profile ukai-jail-action-bwrap allows user namespaces for that "
             "binary only · kernel.apparmor_restrict_unprivileged_userns stays 1")
ROWS = ["K76", "K77", "K78", "K79", "K80", "K81", "K82", "K83", "K84", "K85"]
IMAGES = ["ubuntu-24.04", "ubuntu-24.04-arm"]


def env(name, default=None):
    value = os.environ.get(name, default)
    if value is None:
        sys.exit(f"selftest: {name} is not set")
    return value


RUNNER_TEMP = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
SELFTEST = Path(os.environ.get("SELFTEST") or RUNNER_TEMP / "selftest")
UKAI = RUNNER_TEMP / "ukai"
FAILED = []


def record(row, check, ok, detail="", how="real"):
    status = "pass" if ok else "fail"
    if ok is None:
        status = "recorded"
    line = {"row": row, "job": os.environ.get("SELFTEST_JOB", "?"), "image": os.environ.get("SELFTEST_IMAGE", "?"),
            "check": check, "status": status, "how": how, "detail": str(detail)[:300]}
    SELFTEST.mkdir(parents=True, exist_ok=True)
    with open(SELFTEST / "rows.jsonl", "a", encoding="utf-8") as rows:
        rows.write(json.dumps(line) + "\n")
    print(f"{row} {status:8} {how:9} {check}{': ' + str(detail)[:600] if detail else ''}")
    if status == "fail":
        FAILED.append(check)


def finish():
    if FAILED:
        sys.exit(f"selftest: {len(FAILED)} check(s) failed: {'; '.join(FAILED)}")


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def token_for(key):
    seed = f"ukai-selftest:{env('GITHUB_RUN_ID')}:{env('GITHUB_RUN_ATTEMPT', '1')}:{key}"
    return "ukai-selftest-" + hashlib.sha256(seed.encode()).hexdigest()


def files_holding(root, value):
    """Every file below root that holds value, as names."""
    needle = value.encode()
    hits = []
    for path in sorted(Path(root).rglob("*")):
        if path.is_file() and needle in path.read_bytes():
            hits.append(str(path.relative_to(root)))
    return hits


def jail(*args, **kwargs):
    return subprocess.run([str(UKAI / "bin" / "ukai-jail"), *args], capture_output=True, text=True,
                          env={**os.environ, "UKAI_CONFIG_DIR": str(UKAI / "config"),
                               "UKAI_DATA_DIR": str(UKAI / "data")}, **kwargs)


def summary_lines(summary):
    return {line["line"]: line.get("facts", {}) for line in summary["lines"]}


def report_summary_md(heading, attempt_id):
    """The summary.md the action's report step appended to the job summary
    for this attempt (its receipt line names the attempt)."""
    for path in sorted(UKAI.glob("report.*/summary.md")):
        text = path.read_text()
        if text.startswith(heading) and f"/attempts/{attempt_id}/" in text:
            return path, text
    return None, ""


def fenced(text):
    match = re.search(r"^(`{3,})text\n(.*?)^\1$", text, re.S | re.M)
    return match.group(2) if match else None


# --- commands -----------------------------------------------------------------------
def cmd_token(key):
    print(token_for(key))


def cmd_begin():
    """K84: the image this job ran on, and the sysctl before any action."""
    facts = {"ImageOS": os.environ.get("ImageOS"), "ImageVersion": os.environ.get("ImageVersion"),
             "RUNNER_ARCH": os.environ.get("RUNNER_ARCH"), "uname": os.uname().release}
    try:
        facts["os_release"] = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                                   if "=" in line).get("PRETTY_NAME", "").strip('"')
    except OSError:
        facts["os_release"] = None
    try:
        facts["sysctl"] = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
    except OSError:
        facts["sysctl"] = "absent"
    SELFTEST.mkdir(parents=True, exist_ok=True)
    (SELFTEST / "image.json").write_text(json.dumps(facts))
    record("K84", "image recorded", bool(facts["ImageVersion"]),
           f"{facts['ImageOS']} {facts['ImageVersion']}, {facts['os_release']}, {facts['RUNNER_ARCH']}, "
           f"kernel {facts['uname']}, sysctl {facts['sysctl']}")


def cmd_end():
    """K77: the sysctl reads the same at the end of the job as at its start."""
    before = load(SELFTEST / "image.json")["sysctl"]
    try:
        after = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip()
    except OSError:
        after = "absent"
    record("K77", "sysctl the same before and after the job", before == after, f"{before} → {after}")
    finish()


def cmd_status():
    """Fail when any check this job recorded on this image failed (for steps
    that record several checks with `set +e`)."""
    rows = SELFTEST / "rows.jsonl"
    lines = [json.loads(line) for line in rows.read_text().splitlines()] if rows.is_file() else []
    failed = [line["check"] for line in lines if line["status"] == "fail"]
    if failed:
        sys.exit(f"selftest: failed so far: {'; '.join(failed)}")


def cmd_row(row, check, status, detail="", how="real"):
    record(row, check, {"pass": True, "fail": False, "recorded": None}[status], detail, how)
    finish()


def check_artifact(row_prefix, art, token, heading):
    art = Path(art)
    names = {p.name for p in art.iterdir()} if art.is_dir() else set()
    record("K79", f"{row_prefix}: artifact holds receipt, policy, journal, summary, doctor, setup.txt",
           ARTIFACT_FILES <= names, sorted(names))
    record("K79", f"{row_prefix}: artifact holds nothing from the config directory",
           not any("credential" in n for n in names), sorted(names))
    checked = subprocess.run([sys.executable, "-I", str(ROOT / "docs/specs/jail-v1/summary_check.py"), str(art),
                              str(art / "summary.json")], capture_output=True, text=True)
    record("K79", f"{row_prefix}: summary_check.py recomputes the summary from the artifact alone",
           checked.returncode == 0, (checked.stdout + checked.stderr).strip()[-200:])
    hits = files_holding(art, token)
    record("K78", f"{row_prefix}: the credential value is in no artifact file", not hits, hits)
    receipt = load(art / "jail.json")
    path, page = report_summary_md(heading, receipt["attempt_id"])
    block = fenced(page)
    tail = jail("tail", "--summary", "--attempt", receipt["attempt_id"])
    record("K79", f"{row_prefix}: the job summary's jail lines equal `tail --summary`",
           block is not None and block == tail.stdout == (art / "summary.txt").read_text(),
           f"{path}; {len((block or '').splitlines())} lines")
    on_page = [p.name for p in (RUNNER_TEMP / "_runner_file_commands").glob("step_summary_*")
               if block and block in p.read_text(errors="replace")]
    record("K79", f"{row_prefix}: the runner's step-summary file holds those lines", None,
           on_page or "no step_summary file left to read (checked through the report's summary.md)")
    return receipt, page


def cmd_verify_profile():
    token = env("SELFTEST_TOKEN")
    art = Path(env("ART"))
    record("K81", "profile mode: a passing command succeeds with exit-code 0 and settled true",
           env("OUTCOME") == "success" and env("EXIT_CODE") == "0" and env("SETTLED") == "true",
           f"outcome {env('OUTCOME')}, exit-code {env('EXIT_CODE')}, settled {env('SETTLED')}")
    record("K79", "outputs: attempt-id, summary-json and receipt are set",
           env("ATTEMPT_ID").startswith("att_") and Path(env("SUMMARY_JSON")).is_file()
           and Path(env("RECEIPT")).is_file(), env("ATTEMPT_ID"))
    receipt, page = check_artifact("profile", art, token, "### ukai-jail (profile agent)")
    record("K83", "profile mode runs `run` under the named profile", receipt["policy"]["name"] == "agent",
           receipt["policy"]["name"])

    # K77: what setup.txt and the host-setup line say against what was done
    setup = (art / "setup.txt").read_text()
    bwrap = subprocess.run(["sha256sum", "/usr/local/bin/bwrap"], capture_output=True, text=True).stdout.split()
    record("K77", "setup.txt: the tarball verified against the pinned digest",
           "sha256:c1b7455a1283b1295879a46d5f001dfd088c0bb0f238abb5e128b3583a246f71 (pinned)" in setup)
    record("K77", "setup.txt: the installed bwrap's digest is the file's",
           bool(bwrap) and f"bubblewrap 0.11.1 sha256:{bwrap[0]}" in setup, bwrap[:1])
    profiles = subprocess.run(["sudo", "cat", "/sys/kernel/security/apparmor/profiles"], capture_output=True,
                              text=True).stdout
    record("K77", "the profile is loaded, as setup.txt says",
           "loaded ukai-jail-action-bwrap" in setup and "ukai-jail-action-bwrap (" in profiles,
           [line for line in profiles.splitlines() if "ukai" in line])
    record("K77", "the profile was loaded because the sysctl read 1; both readings recorded",
           "kernel.apparmor_restrict_unprivileged_userns=1 before setup" in setup
           and "kernel.apparmor_restrict_unprivileged_userns=1 at report" in setup)
    record("K77", "the job summary's host-setup line matches what was done", HOST_LINE in page,
           next((line for line in page.splitlines() if line.startswith("host setup")), "missing"))

    # K80: inside, as the probe recorded it, and the journal
    workspace = Path(env("GITHUB_WORKSPACE"))
    inside = load(workspace / ".ukai-selftest/inside.json")
    leaked = [n for n in inside["env_names"] if n.startswith(("GITHUB_", "ACTIONS_", "RUNNER_"))]
    record("K80", "inside: no GITHUB_*, ACTIONS_* or RUNNER_* variable", not leaked, leaked)
    record("K80", "inside: no credential variable, and the value nowhere in what the probe saw",
           "SELFTEST_TOKEN" not in inside["env_names"]
           and token not in (workspace / ".ukai-selftest/inside.json").read_text())
    present = {k: v["path"] for k, v in inside["paths"].items() if v["exists"]}
    record("K80", "inside: $RUNNER_TEMP, the file-command files and the action's directories are absent",
           not present, present or sorted(inside["paths"]))
    record("K80", "inside: a connection to /var/run/docker.sock fails", inside["docker_socket"] != "connected",
           inside["docker_socket"])
    summary = summary_lines(load(art / "summary.json"))
    denied = [d["destination"] for d in summary.get("network", {}).get("denied", [])]
    allowed = [d["destination"] for d in summary.get("network", {}).get("allowed", [])]
    record("K80", "inside: the allowed host is reached through the proxy",
           inside["allowed_host"].get("http") not in ("", "000", None) and "api.github.com:443" in allowed,
           f"{inside['allowed_host']}; allowed {allowed}")
    record("K80", "inside: a host off the allowlist is denied and journaled",
           inside["off_allowlist"].get("http") != "200" and "example.com:443" in denied,
           f"{inside['off_allowlist']}; denied {denied}")
    record("K80", "inside: the runner's metadata address is denied through the proxy and journaled",
           inside["metadata_via_proxy"].get("http") != "200" and any(d.startswith("169.254.169.254") for d in denied),
           f"{inside['metadata_via_proxy']}")
    record("K80", "inside: the metadata address is unreachable without the proxy",
           inside["metadata_direct"].get("rc") not in (0, None), inside["metadata_direct"])
    native = receipt.get("lifetime", {}).get("native", {}).get("details", {}).get("agent", {})
    record("K80", "inside, under agent: can a nested user namespace be created", None,
           f"unshare -Ur exit {inside['nested_user_namespace'].get('rc')}; receipt: "
           f"{native.get('nested_user_namespace')} ({native.get('nested_user_namespace_evidence')})")
    record("K80", "the run's evidence: six classes active, no gaps",
           all(summary.get("evidence", {}).get("classes", {}).get(c) == "active" for c in CLASSES)
           and not summary.get("evidence", {}).get("gaps"), summary.get("evidence", {}).get("classes"))

    # K85: the script text arrived whole; no shell outside evaluated it
    expected = (SELFTEST / "expected-run.txt").read_text()
    got = (workspace / ".ukai-selftest/run-text.txt").read_text()
    record("K85", "profile mode: `run` reaches bash -c as its exact text (newlines, quotes, $(), ``, ${{ }})",
           got == expected, f"{len(got)} bytes")
    finish()


def cmd_verify_launch():
    token = env("SELFTEST_TOKEN")
    workspace = Path(env("LAUNCH_WS"))
    record("K81", "launch mode: a passing command succeeds with exit-code 0 and settled true",
           env("OUTCOME") == "success" and env("EXIT_CODE") == "0" and env("SETTLED") == "true",
           f"outcome {env('OUTCOME')}, exit-code {env('EXIT_CODE')}, settled {env('SETTLED')}")
    receipt, _ = check_artifact("launch", Path(env("ART")), token, "### ukai-jail (launch claude)")
    argv = (workspace / "argv.bin").read_bytes().split(b"\0")[:-1]
    expected = [a.encode() for a in load(SELFTEST / "expected-argv.json")]
    record("K85", "launch mode: every `args` line reaches the program as one literal argv element",
           argv == expected, f"{len(argv)} of {len(expected)} elements")
    environment = (workspace / "env.txt").read_text()
    names = [line.split("=", 1)[0] for line in environment.splitlines() if "=" in line]
    record("K78", "launch: the agent holds a placeholder, not the value, and not the variable",
           "ANTHROPIC_API_KEY" in names and "SELFTEST_TOKEN" not in names and token not in environment)
    credentials = receipt.get("credentials", [])
    record("K78", "launch: the receipt lists the credential as vault, never staged",
           [(c.get("id"), c.get("mode"), c.get("never_staged")) for c in credentials] == [("anthropic", "vault", True)],
           credentials)
    finish()


def cmd_verify_watch():
    watch = load(SELFTEST / "env-watch.json")
    runs = sum(tally["readable"] for verb, tally in watch["by_verb"].items() if verb.startswith("run "))
    record("K78", "the named variable is absent from ukai-jail's own environment (sampled)",
           not watch["name_found"] and not watch["value_found"] and runs > 0,
           f"name in {watch['name_found']}, value in {watch['value_found']}; {runs} readable snapshots of "
           f"`run` before release; {watch['processes']} processes, by verb {watch['by_verb']}")
    finish()


def cmd_verify_alias():
    launch = load(Path(env("ART")) / "jail.json")
    attempts = [p for p in (UKAI / "data/attempts").iterdir() if p.name != launch["attempt_id"]]
    alias = max((load(p / "jail.json") for p in attempts if (p / "jail.json").is_file()),
                key=lambda r: r.get("created_at", ""))
    same = (launch["policy"]["digest"], launch["argv_digest"]) == (alias["policy"]["digest"], alias["argv_digest"])
    record("K83", "launch mode equals `ukai-jail claude ARG...` (policy and argv digests, K33's method)", same,
           f"policy {launch['policy']['digest'][:19]}… vs {alias['policy']['digest'][:19]}…, "
           f"argv {launch['argv_digest'][:19]}… vs {alias['argv_digest'][:19]}…")
    finish()


def cmd_markers():
    named = load(SELFTEST / "markers.json") if (SELFTEST / "markers.json").is_file() else []
    left = [m for m in named if os.path.lexists(m)]
    left += [str(p) for p in Path(env("HOME")).glob("ukai-k85-*")]
    record("K85", "no input was evaluated by the action's own steps (no marker file exists)", not left, left)
    finish()


def cmd_verify_comment():
    """K82 on this event: posted once and updated in place on a same-repository
    pull request; nothing on any other event, a fork's or without the flag."""
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    flagged = [p for p in UKAI.glob("report.*") if (p / "comment.md").is_file()]
    posted = [p.name for p in flagged if (p / "comment-request.json").exists()]
    payload = load(env("GITHUB_EVENT_PATH")) if event == "pull_request" else {}
    pull = payload.get("pull_request") or {}
    head = ((pull.get("head") or {}).get("repo") or {}).get("full_name")
    if event != "pull_request" or head != env("GITHUB_REPOSITORY"):
        why = f"a {event} event" if event != "pull_request" else f"a pull request from {head}"
        record("K82", f"pr-comment: true on {why} posts nothing, and the step succeeds",
               len(flagged) == 1 and not posted and env("OUTCOME") == "success",
               f"{len(flagged)} run(s) with the flag, {len(posted)} posted")
        finish()
        return
    listed = subprocess.run(["gh", "api", "--paginate", "--slurp",
                             f"repos/{env('GITHUB_REPOSITORY')}/issues/{pull['number']}/comments"],
                            capture_output=True, text=True, check=True)
    comments = [c for page in json.loads(listed.stdout) for c in page
                if (c.get("user") or {}).get("login") == "github-actions[bot]"]
    marker = f"ukai-jail-action:{env('GITHUB_WORKFLOW')}:{env('GITHUB_JOB')}:"
    mine = [c for c in comments if marker + env("PROFILE_ARTIFACT") in (c.get("body") or "")]
    unflagged = [c for c in comments if marker + env("LAUNCH_ARTIFACT") in (c.get("body") or "")]
    record("K82", "same-repository pull request: exactly one comment, holding this run's link",
           len(mine) == 1 and f"/actions/runs/{env('GITHUB_RUN_ID')})" in mine[0]["body"],
           [(c["id"], c["created_at"], c["updated_at"]) for c in mine])
    record("K82", "updated in place on a later run (created before this run, edited by it)", None,
           [c["created_at"] != c["updated_at"] for c in mine])
    record("K82", "no comment from the run without the flag", not unflagged, len(unflagged))
    finish()


def cmd_verify_exit():
    cases = [("FAIL", "a failing command fails the step with its status", "3", "exited", True),
             ("REFUSED", "a refusal fails the step with 125 and its error", "125", "refused", False),
             ("GAPS", "fail-on gaps fails a step whose command exited 0", "0", "exited", True)]
    for prefix, check, code, outcome, settled in cases:
        art = Path(env(f"{prefix}_ART"))
        summary = summary_lines(load(art / "summary.json")) if (art / "summary.json").is_file() else {}
        status = summary.get("status", {})
        ok = (env(f"{prefix}_OUTCOME") == "failure" and env(f"{prefix}_EXIT_CODE") == code
              and (status.get("phase") == "settled") == settled
              and (status.get("outcome") == outcome or (not settled and not summary)))
        detail = (f"outcome {env(f'{prefix}_OUTCOME')}, exit-code {env(f'{prefix}_EXIT_CODE')}, "
                  f"settled {env(f'{prefix}_SETTLED')}, phase {status.get('phase')}, errors {status.get('errors')}")
        if prefix == "GAPS":
            ok = ok and summary.get("evidence", {}).get("classes", {}).get("proxy.net") == "unsupported"
        record("K81", check, ok, detail)
        # a refusal before any attempt leaves no receipt: setup.txt and doctor.json then
        needed = ARTIFACT_FILES if settled else {"setup.txt", "doctor.json"}
        names = {p.name for p in art.iterdir()} if art.is_dir() else set()
        record("K81", f"{check}: the report steps ran (job summary and artifact)", needed <= names, sorted(names))
    finish()


def cmd_verify_exposure():
    path, page = None, ""
    for candidate in sorted(UKAI.glob("report.*")):
        if (candidate / "setup.txt").is_file() and not (candidate / "artifact").exists():
            path = candidate
    summaries = [p.read_text(errors="replace") for p in (RUNNER_TEMP / "_runner_file_commands").glob("step_summary_*")]
    page = next((s for s in summaries if "exposure check FAILED" in s), "")
    token = env("SELFTEST_TOKEN")
    record("K78", "positive control: a run whose journal holds the value fails the step",
           env("OUTCOME") == "failure", env("OUTCOME"))
    record("K78", "positive control: the report names the files, never the value, and removes its copies",
           path is not None and token not in page, f"report dir {path}, step summary found: {bool(page)}")
    names = json.loads(env("ARTIFACTS"))
    record("K78", "positive control: nothing was uploaded", env("ARTIFACT_NAME") not in names, names)
    finish()


def cmd_rows():
    """Merge every job's rows, render them, check the job logs for the values."""
    lines = []
    for path in sorted(Path(env("ROWS_DIR")).rglob("rows.jsonl")):
        lines += [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for job, need in json.loads(env("NEEDS")).items():
        lines.append({"row": "K84", "job": "rows", "image": "-", "check": f"job {job} finished green",
                      "status": "pass" if need.get("result") == "success" else "fail", "how": "real",
                      "detail": need.get("result")})
    keys = sorted({(line["job"], line["image"]) for line in lines})
    # K78 over the job logs as GitHub stores them: no value unmasked anywhere
    logs = Path(env("LOGS_DIR"))
    tokens = {f"{job}-{image}": token_for(f"{job}-{image}") for job, image in keys}
    for log in sorted(logs.glob("*.log")):
        text = log.read_bytes()
        hits = [key for key, value in tokens.items() if value.encode() in text]
        lines.append({"row": "K78", "job": "rows", "image": "-", "check": f"job log {log.stem}: no fixture value unmasked",
                      "status": "fail" if hits else "pass", "how": "real", "detail": hits})
    if not list(logs.glob("*.log")):
        lines.append({"row": "K78", "job": "rows", "image": "-", "check": "job logs fetched", "status": "fail",
                      "how": "real", "detail": "no log"})
    by_row = {row: [line for line in lines if line["row"] == row] for row in ROWS}
    verdicts = {}
    for row in ROWS:
        checks = by_row[row]
        failed = [c for c in checks if c["status"] == "fail"]
        real_images = {c["image"] for c in checks if c["status"] == "pass" and c["how"] == "real"}
        simulated = any(c["how"] == "simulated" for c in checks)
        if row == "K84":
            continue
        if failed or not checks:
            verdicts[row] = "FAIL"
        elif not set(IMAGES) <= real_images:
            verdicts[row] = "MISSING on " + ", ".join(i for i in IMAGES if i not in real_images)
        else:
            verdicts[row] = "pass, partly simulated" if simulated else "pass"
    # K84: every other row passed on both images, and each image was recorded
    others = all(verdicts[row].startswith("pass") for row in ROWS if row != "K84")
    images = {c["image"] for c in by_row["K84"] if c["check"] == "image recorded" and c["status"] == "pass"}
    green = all(c["status"] != "fail" for c in by_row["K84"])
    verdicts["K84"] = "pass" if others and green and set(IMAGES) <= images else "FAIL"
    out = ["## Action self-test, rows K76-K85", "",
           "Each check ran for real on the runner unless marked *simulated* (a stand-in or a set environment "
           "where the real condition cannot be produced in a hosted job).", ""]
    for row in ROWS:
        out.append(f"### {row}: {verdicts[row]}")
        out.append("")
        for c in by_row[row]:
            how = f" *{c['how']}*" if c["how"] != "real" else ""
            detail = f" — {c['detail']}" if c["detail"] not in ("", "[]") else ""
            out.append(f"- {c['status']}{how} · {c['job']} · {c['image']} · {c['check']}{detail}")
        out.append("")
    text = "\n".join(out) + "\n"
    with open(env("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as summary:
        summary.write(text)
    (Path(env("ROWS_DIR")) / "rows.md").write_text(text)
    print(text)
    bad = [row for row, verdict in verdicts.items() if not verdict.startswith("pass")]
    if bad:
        sys.exit(f"selftest: rows not passing: {', '.join(bad)}")


# --- the A-row record (§6.2; .github/workflows/action-arow.yml) ------------------
def cmd_verify_arow(kind):
    """One Claude Code run of the A-row: the 2026-10-17 headless row's pass
    conditions, the job summary, and the stored value nowhere it should not be."""
    value = env("ANTHROPIC_API_KEY")
    art, workspace = Path(env("ART")), Path(env("WS"))
    record("A-row", f"{kind}: the step succeeded, exit-code 0, settled",
           env("OUTCOME") == "success" and env("EXIT_CODE") == "0" and env("SETTLED") == "true",
           f"outcome {env('OUTCOME')}, exit-code {env('EXIT_CODE')}, settled {env('SETTLED')}")
    receipt = load(art / "jail.json")
    lifetime, outcome = receipt.get("lifetime", {}), receipt.get("outcome", {})
    record("A-row", f"{kind}: receipt settled, exited 0, no error, tree empty",
           receipt.get("phase") == "settled" and outcome.get("kind") == "exited" and outcome.get("code") == 0
           and not receipt.get("errors") and lifetime.get("tree_empty") is True,
           f"{receipt.get('phase')}, {outcome}, errors {receipt.get('errors')}, tree_empty {lifetime.get('tree_empty')}")
    summary = summary_lines(load(art / "summary.json"))
    evidence = summary.get("evidence", {})
    record("A-row", f"{kind}: six classes active, no gaps",
           all(evidence.get("classes", {}).get(c) == "active" for c in CLASSES) and not evidence.get("gaps"),
           evidence.get("classes"))
    credentials = receipt.get("credentials", [])
    uses = [(c.get("id"), c.get("uses"), c.get("uses_bound")) for c in summary.get("credentials", {}).get("credentials", [])]
    record("A-row", f"{kind}: one credential, anthropic, vault, never staged, used",
           [(c.get("id"), c.get("mode"), c.get("never_staged")) for c in credentials] == [("anthropic", "vault", True)]
           and bool(uses) and (uses[0][1] or 0) > 0, f"receipt {credentials}; summary uses {uses}")
    check_artifact(kind, art, value, "### ukai-jail (launch claude)")
    hits = files_holding(workspace, value) + [f"data/{h}" for h in files_holding(UKAI / "data", value)]
    record("A-row", f"{kind}: the key is in no workspace file and nothing under the data directory", not hits, hits)
    if kind == "a01":
        greeting = (workspace / "greeting.txt").read_text() if (workspace / "greeting.txt").is_file() else None
        record("A-row", "a01: greeting.txt holds hello", (greeting or "").strip() == "hello", repr(greeting))
    finish()


def cmd_verify_arow_task():
    workspace = Path(env("WS"))
    digest = hashlib.sha256((workspace / "test_slug.py").read_bytes()).hexdigest()
    record("A-row", "task: python3 -m unittest passes, run inside the jail after the agent",
           env("OUTCOME") == "success" and env("EXIT_CODE") == "0", f"outcome {env('OUTCOME')}")
    record("A-row", "task: test_slug.py unchanged", digest == env("TEST_SHA256"), digest[:16])
    diff = subprocess.run(["git", "-C", str(workspace), "diff", "--stat"], capture_output=True, text=True).stdout
    record("A-row", "task: what the agent changed", None, diff.strip().replace("\n", "; "))
    finish()


def cmd_arow_report():
    """K78 over the A-row's job logs and artifacts (the fixed value, and any
    Anthropic key shape), then the record's list in the job summary."""
    value = env("ANTHROPIC_API_KEY").encode()
    shape = re.compile(rb"sk-ant-[A-Za-z0-9_-]{20,}")
    lines = []
    for path in sorted(Path(env("ROWS_DIR")).rglob("rows.jsonl")):
        lines += [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for job, need in json.loads(env("NEEDS")).items():
        lines.append({"row": "A-row", "job": "logs", "image": "-", "check": f"job {job} finished green",
                      "status": "pass" if need.get("result") == "success" else "fail", "how": "real",
                      "detail": need.get("result")})
    logs = sorted(Path(env("LOGS_DIR")).glob("*.log"))
    for log in logs:
        text = log.read_bytes()
        lines.append({"row": "A-row", "job": "logs", "image": "-", "how": "real",
                      "check": f"job log {log.stem}: the key nowhere, unmasked or key-shaped",
                      "status": "fail" if value in text or shape.search(text) else "pass", "detail": ""})
    if not logs:
        lines.append({"row": "A-row", "job": "logs", "image": "-", "check": "job logs fetched", "status": "fail",
                      "how": "real", "detail": "no log"})
    artifacts = Path(env("ARTIFACTS_DIR"))
    hits = [str(p.relative_to(artifacts)) for p in sorted(artifacts.rglob("*"))
            if p.is_file() and (value in p.read_bytes() or shape.search(p.read_bytes()))]
    lines.append({"row": "A-row", "job": "logs", "image": "-", "how": "real", "status": "fail" if hits else "pass",
                  "check": "every artifact of the run: the key nowhere, unmasked or key-shaped", "detail": hits})
    images = {line["image"] for line in lines if line["status"] == "pass"}
    failed = [line for line in lines if line["status"] == "fail"]
    verdict = "pass" if not failed and set(IMAGES) <= images else "FAIL"
    out = [f"## A-row (docs/specs/jail-ci-action.md §6.2): {verdict}", ""]
    out += [f"- {c['status']} · {c['job']} · {c['image']} · {c['check']}"
            + (f" — {c['detail']}" if c["detail"] not in ("", "[]") else "") for c in lines]
    text = "\n".join(out) + "\n"
    with open(env("GITHUB_STEP_SUMMARY"), "a", encoding="utf-8") as page:
        page.write(text)
    print(text)
    if verdict != "pass":
        sys.exit("selftest: the A-row did not pass")


COMMANDS = {"status": cmd_status, "token": cmd_token, "verify-arow": cmd_verify_arow, "verify-arow-task": cmd_verify_arow_task,
            "arow-report": cmd_arow_report, "begin": cmd_begin, "end": cmd_end, "row": cmd_row,
            "verify-comment": cmd_verify_comment,
            "verify-profile": cmd_verify_profile, "verify-launch": cmd_verify_launch,
            "verify-watch": cmd_verify_watch, "verify-alias": cmd_verify_alias, "markers": cmd_markers,
            "verify-exit": cmd_verify_exit, "verify-exposure": cmd_verify_exposure, "rows": cmd_rows}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(__doc__)
    COMMANDS[sys.argv[1]](*sys.argv[2:])
