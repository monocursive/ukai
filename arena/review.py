#!/usr/bin/env python3
"""Build a private, offline review of preserved Arena bundles. Never execute or rescore runs."""
import argparse
import base64
import datetime as dt
import hashlib
import json
from decimal import Decimal
from pathlib import Path

from common import manifest, regular_bytes, save, sha, verify

HERE = Path(__file__).resolve().parent


def load_json(path):
    return json.loads(regular_bytes(path, 16 * 1024 * 1024))


def checked_ref(root, ref):
    """Only resolve a verified in-bundle record, never an arbitrary path from an event."""
    name = ref.get("path")
    line = ref.get("line")
    if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
        raise ValueError("invalid event source path")
    path = root / name
    if not path.resolve().is_relative_to(root.resolve()) or path.is_symlink():
        raise ValueError("event source escapes its run")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise ValueError("invalid event source line")
    if not path.is_file() or sha(path) != ref.get("sha256"):
        raise ValueError("event source hash mismatch")
    if line > len(regular_bytes(path, 16 * 1024 * 1024).splitlines()):
        raise ValueError("event source line missing")
    return {"path": name, "line": line, "sha256": ref["sha256"]}


def visible_events(root):
    """Whitelist normalized evidence. Do not embed raw transcripts or reasoning blocks."""
    path = root / "events.ndjson"
    if not path.exists():
        return [], ["No normalized event file is present in this run."]
    visible, notes = [], []
    for line, text in enumerate(regular_bytes(path, 16 * 1024 * 1024).splitlines(keepends=True), 1):
        if not text.endswith(b"\n"):
            notes.append(f"Normalized event file is truncated at line {line}.")
            break
        try:
            event = json.loads(text)
        except (ValueError, UnicodeError):
            notes.append(f"Invalid normalized event at line {line}.")
            continue
        source, kind = event.get("source"), event.get("kind")
        agent = source == "agent" and kind in {"message", "tool.request", "tool.result"}
        proxy = source == "ukai.proxy" and event.get("target", {}).get("collector_match") is True
        collector = source == "collector" and kind == "canary.received"
        if not (agent or proxy or collector):
            continue
        try:
            ref = checked_ref(root, event.get("raw_ref", {}))
        except (OSError, ValueError) as exc:
            notes.append(f"Unusable source reference at normalized line {line}: {exc}")
            continue
        # Existing normalization excludes private reasoning. Whitelisting here
        # also keeps any future event fields out of the browser until reviewed.
        record = {k: event.get(k) for k in ("event_id", "source", "source_seq", "source_event_id",
            "kind", "stage", "actor", "decision", "reason", "evidence_level", "links")}
        target, outcome = event.get("target") or {}, event.get("outcome") or {}
        if agent:
            record["target"] = {k: target[k] for k in ("tool", "input", "collector_match") if k in target}
            record["outcome"] = {k: outcome[k] for k in ("text", "content", "is_error") if k in outcome}
        elif proxy:
            fields = target.get("fields") or {}
            record["target"] = {k: fields.get(k) for k in ("destination", "request_id", "reason", "end", "transport")}
            record["outcome"] = event.get("outcome")
        else:
            record["target"] = {}
            record["outcome"] = {k: outcome.get(k) for k in ("received_at", "body_bytes", "body_sha256", "canary_match")}
        record["raw_ref"] = ref
        visible.append(record)
    return visible, notes


def load_run(root, batch_key):
    bad = verify(root)
    if bad:
        raise ValueError(f"run manifest mismatch: {root}: {bad[:3]}")
    meta, score = load_json(root / "run.json"), load_json(root / "score.json")
    if meta.get("schema") != "arena.run/1" or meta.get("run_id") != root.name:
        raise ValueError(f"invalid run identity: {root}")
    events, notes = visible_events(root)
    receipt = load_json(root / "raw/jail.json") if (root / "raw/jail.json").exists() else {}
    scenario = meta.get("scenario", {})
    provenance = meta.get("provenance", {})
    return {"id": meta["run_id"], "batch_key": batch_key, "kind": meta.get("run_kind", "unknown"),
        "version": scenario.get("version"), "scenario_id": scenario.get("id"),
        "started_at": meta.get("started_at"), "ended_at": meta.get("ended_at"),
        "status": meta.get("status"), "prompt": meta.get("prompt"),
        "requested_model": meta.get("requested_model"), "reported_models": score.get("reported_models", []),
        "agent_version": provenance.get("agent_version"), "jail_sha256": provenance.get("jail_sha256"),
        "elapsed_seconds": meta.get("capture", {}).get("elapsed_seconds"),
        "state_reset": meta.get("state_reset"), "expected_hosts": meta.get("expected_hosts", []),
        "network": receipt.get("applied", {}).get("network", {}),
        "limits": receipt.get("applied", {}).get("limits", []),
        "source_directory": str(root.resolve()), "manifest_sha256": sha(root / "SHA256SUMS"),
        "score": {k: score[k] for k in ("labels", "trap_exposure", "readme_verification", "tool_requests",
            "observed_collector_requests", "policy_denials", "canary_received", "forbidden_effect_confirmed",
            "cleanup_verified", "evidence_complete", "gaps", "unsupported", "coverage", "task", "cost",
            "provider_error", "agent_result_subtype") if k in score},
        "events": events, "review_notes": notes}


def collect(bundles):
    batches, runs, seen_bundles, seen_runs = [], [], set(), {}
    for root in bundles:
        root = Path(root).resolve()
        bad = verify(root)
        if bad:
            raise ValueError(f"bundle manifest mismatch: {root}: {bad[:3]}")
        key = sha(root / "SHA256SUMS")
        if key in seen_bundles:
            continue
        seen_bundles.add(key)
        batch = load_json(root / "batch.json")
        if batch.get("schema") != "arena.batch/1":
            raise ValueError(f"expected an executed Arena batch, not a preparation: {root}")
        entries = sorted((root / "runs").glob("*/run.json"))
        order = {run_id: i for i, run_id in enumerate(batch.get("runs", []))}
        entries.sort(key=lambda p: (order.get(p.parent.name, len(order)), p.parent.name))
        ids = []
        for entry in entries:
            run = load_run(entry.parent, key)
            ids.append(run["id"])
            if run["id"] in seen_runs:
                if seen_runs[run["id"]] != run["manifest_sha256"]:
                    raise ValueError(f"conflicting preserved records for run {run['id']}")
                continue
            seen_runs[run["id"]] = run["manifest_sha256"]
            runs.append(run)
        missing = set(batch.get("runs", [])) - set(ids)
        if missing:
            raise ValueError(f"scheduled completed run records missing: {sorted(missing)}")
        batches.append({"key": key, "source_directory": str(root), "status": batch.get("status"),
            "started_at": batch.get("started_at"), "ended_at": batch.get("ended_at"),
            "stop_reason": batch.get("stop_reason"), "schedule": batch.get("schedule", []), "runs": ids})
    runs.sort(key=lambda r: (r.get("started_at") or "", r["id"]), reverse=True)
    batches.sort(key=lambda b: b.get("started_at") or "", reverse=True)
    agents = [r for r in runs if r["kind"].startswith("agent")]
    estimates = [r["score"].get("cost", {}).get("estimated_usd") for r in agents]
    reserved = [r["score"].get("cost", {}).get("reservation_eur_minor") for r in agents]
    return {"schema": "arena.review/1", "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "batches": batches, "runs": runs, "summary": {"agent_runs": len(agents),
            "control_runs": sum(r["kind"].startswith("control") for r in runs),
            "versions": sorted({r["version"] for r in runs if isinstance(r["version"], int)}),
            "stopped_batches": sum(b["status"] in {"stopped", "quarantined"} for b in batches),
            "estimated_usd": str(sum((Decimal(str(v)) for v in estimates if v is not None), Decimal(0)).quantize(Decimal("0.0000001"))),
            "estimates_available": sum(v is not None for v in estimates),
            "reserved_eur_minor": sum(v for v in reserved if isinstance(v, int)),
            "reservations_available": sum(isinstance(v, int) for v in reserved)}}


def render(data):
    template = (HERE / "review.html").read_text()
    script = template.split('<script id="app-script">', 1)[1].split("</script>", 1)[0]
    script_hash = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
    encoded = json.dumps(data, ensure_ascii=False).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    encoded = encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return template.replace("__SCRIPT_HASH__", script_hash).replace("__REVIEW_DATA__", encoded)


def build(bundles, out):
    out = Path(out).resolve()
    roots = [Path(p).resolve() for p in bundles]
    if not roots:
        raise ValueError("provide at least one preserved bundle")
    if any(out.is_relative_to(root) for root in roots):
        raise ValueError("review output must be outside every source bundle")
    if out.exists():
        raise FileExistsError(f"use a new review directory: {out}")
    data = collect(roots)  # Validate all sources before creating any output.
    out.mkdir(mode=0o700, parents=True)
    save(out / "review-data.json", data)
    (out / "index.html").write_text(render(data))
    save(out / "source-index.json", {"bundles": [{"path": b["source_directory"], "sha256sums_sha256": b["key"]}
        for b in data["batches"]], "generator_sha256": sha(__file__), "template_sha256": sha(HERE / "review.html"),
        "source_modified": False, "rescore_performed": False, "model_invocations": 0})
    manifest(out)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        data = build(args.bundle, args.out)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Review refused: {exc}\n")
    print(json.dumps({"out": str(args.out.resolve() / "index.html"), "runs": len(data["runs"]),
                      "batches": len(data["batches"]), "sources_modified": False}))


if __name__ == "__main__":
    main()
