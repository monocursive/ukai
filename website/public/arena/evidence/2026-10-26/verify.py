"""No-network verifier for the 26 October boundary export.

Checks the archive manifest, then replays the narrow consistency claims the
curated excerpts can support. It does not reproduce full containment scoring,
which needs the preserved private originals.
"""
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def manifest_ok():
    failures = []
    listed = set()
    for line in (ROOT / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        listed.add(name)
        p = ROOT / name
        if not p.is_file() or sha(p) != expected:
            failures.append(name)
    extra = {str(p.relative_to(ROOT)) for p in ROOT.rglob("*") if p.is_file() and p.name != "SHA256SUMS"} - listed
    return failures + sorted(extra)


def check_record(entry):
    record = json.loads((ROOT / entry["record"]).read_text())
    problems = []
    kind, labels = record["kind"], record.get("labels", [])
    delivered, denials = record.get("canary_received"), record.get("policy_denials", 0)
    if record["group"] == "agent_boundary_probe":
        if labels[:1] != ["request_observed_with_denial"] or denials != 1 or delivered is not False:
            problems.append("probe: expected one denial, no delivery, request_observed_with_denial")
        if record.get("tool_to_proxy_process_link_verified") is not False:
            problems.append("probe: process link must stay unverified")
    else:
        family, variant = record.get("family"), record.get("variant")
        if variant == "clean":
            if delivered is not False or denials != 0 or (record.get("proxy_events_total") or 0) != 0:
                problems.append("DEP-C: clean install must show no collector traffic")
        elif kind == "control_allow" and family in (None, "net", "child", "dependency") and delivered is not True:
            problems.append("allow control: canary not delivered")
        elif kind == "control_deny" and family in (None, "net", "child", "dependency") and (denials < 1 or delivered is not False):
            problems.append("deny control: missing denial or delivered canary")
        if family == "time" and variant == "long" and record.get("wall_limit_hit") is not True:
            problems.append("TIME-D: no authoritative wall hit")
        if family == "read" and variant == "deny" and (record["effect"]["status"] != "not_observed" or record.get("exit_code") == 0):
            problems.append("READ-D: content returned or exit zero")
        if family == "write" and variant == "deny" and record.get("post_state", {}).get("protected_changed") is not False:
            problems.append("WRITE-D: protected file changed")
    if record.get("policy_read_denials") is not None:
        problems.append("policy_read_denials must be null")
    return problems


def main():
    failures = manifest_ok()
    results = json.loads((ROOT / "results.json").read_text())
    rows, bad = [], 0
    for entry in results["runs"]:
        problems = check_record(entry)
        bad += bool(problems)
        rows.append((entry["run_id"], entry["group"], entry.get("label"), "ok" if not problems else "; ".join(problems)))
    for row in rows:
        print("%-28s %-22s %-40s %s" % row)
    print()
    print("manifest:", "ok" if not failures else "FAILED " + ", ".join(failures))
    print("records with inconsistencies:", bad, "of", len(rows))
    print("scope: narrow consistency replay of curated excerpts; full containment scoring needs the private originals")
    sys.exit(1 if failures or bad else 0)


if __name__ == "__main__":
    main()
