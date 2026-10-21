#!/usr/bin/env python3
"""JSON reading for the action's step scripts (docs/specs/jail-ci-action.md).

Run as `python3 -I facts.py COMMAND ARG...`; standard library only. It reads
records ukai-jail and GitHub wrote and prints plain `key=value` lines or
messages; it never prints a credential (none reaches it).

  doctor FILE               exit 0 when `ready` is true; else print why
  summary FILE FAIL_ON      print settled=, phase= and one `fail=` line per
                            `fail-on` condition that holds (§3.6)
  event FILE                print pr=NUMBER and same_repository=true|false
                            for a pull_request event payload
  find-comment FILE MARKER  print the id of the first comment by
                            github-actions[bot] whose body holds MARKER
  comment-body MARKDOWN     print {"body": ...} for the GitHub API
"""

import json
import sys

CLASSES = ["exec", "fs.write", "fs.deny", "net", "proxy.net", "limits"]


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def doctor(path):
    try:
        report = load(path)
    except (OSError, ValueError):
        print("doctor wrote no report (its error is in the log above)")
        return 1
    if report.get("ready") is True:
        return 0
    capabilities = {c.get("name"): c for c in report.get("capabilities", [])}
    for name in report.get("requirements", []):
        capability = capabilities.get(name, {})
        if capability.get("status") != "available":
            print(f"requirement {name}: {capability.get('status', 'not probed')}"
                  f" ({capability.get('reason_code')})")
    backend = capabilities.get("bwrap_present", {})
    if backend and backend.get("status") != "available":
        print(f"bwrap_present: {backend.get('status')} ({backend.get('reason_code')})")
    launch = report.get("launch") or {}
    for credential in launch.get("credentials", []):
        if credential.get("status") != "available":
            print(f"launch {launch.get('name')} credential {credential.get('id')}:"
                  f" {credential.get('status')} ({credential.get('reason_code')})")
    workspace = report.get("workspace")
    if workspace:
        print(f"workspace: {workspace.get('status')} ({workspace.get('reason_code')})")
    return 1


def summary(path, fail_on):
    """§3.6: what `fail-on` adds to the command's own status."""
    wanted = {word for word in fail_on.replace(",", " ").split() if word}
    try:
        lines = {line["line"]: line.get("facts", {}) for line in load(path)["lines"]}
    except (OSError, ValueError, KeyError, TypeError):
        lines = None
    if lines is None:
        print("settled=false")
        print("phase=none")
        for condition in sorted(wanted):
            print(f"fail={condition}: no summary of an attempt could be read")
        return 0
    status = lines.get("status", {})
    phase = status.get("phase")
    print(f"settled={'true' if phase == 'settled' else 'false'}")
    print(f"phase={phase}")
    if "unsettled" in wanted and phase != "settled":
        print(f"fail=unsettled: the receipt's phase is {phase}, not settled")
    survivors = status.get("survivors")
    if "survivors" in wanted and survivors != "none_verified":
        print(f"fail=survivors: survivors are {survivors}, not verified none")
    if "gaps" in wanted:
        evidence = lines.get("evidence", {})
        classes = evidence.get("classes", {})
        short = [f"{name} {classes.get(name, 'missing')}"
                 for name in CLASSES if classes.get(name) != "active"]
        if evidence.get("gaps"):
            short.append(f"{len(evidence['gaps'])} gap(s)")
        if evidence.get("disagree"):
            short.append("journal and receipt disagree on " + ", ".join(evidence["disagree"]))
        if short:
            print("fail=gaps: " + "; ".join(short))
    return 0


def event(path):
    payload = load(path)
    pull = payload.get("pull_request") or {}
    number = pull.get("number")
    head = ((pull.get("head") or {}).get("repo") or {}).get("full_name")
    base = (payload.get("repository") or {}).get("full_name")
    print(f"pr={number if isinstance(number, int) else ''}")
    print(f"same_repository={'true' if head and head == base else 'false'}")
    return 0


def find_comment(path, marker):
    pages = load(path)
    # `gh api --paginate --slurp` gives a list of pages; a single page is a list.
    comments = [c for page in pages for c in page] if pages and isinstance(pages[0], list) else pages
    for comment in comments:
        user = comment.get("user") or {}
        if user.get("login") == "github-actions[bot]" and marker in (comment.get("body") or ""):
            print(comment["id"])
            return 0
    return 0


def comment_body(path):
    with open(path, encoding="utf-8") as handle:
        print(json.dumps({"body": handle.read()}))
    return 0


def main(argv):
    commands = {"doctor": (doctor, 1), "summary": (summary, 2), "event": (event, 1),
                "find-comment": (find_comment, 2), "comment-body": (comment_body, 1)}
    if len(argv) < 2 or argv[1] not in commands or len(argv) - 2 != commands[argv[1]][1]:
        print(__doc__, file=sys.stderr)
        return 2
    function, _ = commands[argv[1]]
    return function(*argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
