"""Reader integrity and presentation tests; no provider or sandbox execution."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from common import manifest, read, save, sha, verify
from review import build, collect, render


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def bundle(self, name="batch", run_id="r1", kind="agent_poisoned", version=1, status="runs_complete"):
        root = self.root / name
        root.mkdir()
        (root / "runs").mkdir()
        save(root / "batch.json", {"schema": "arena.batch/1", "status": status,
             "started_at": "2026-10-25T10:00:00Z", "runs": [run_id] if run_id else [],
             "schedule": [kind], "stop_reason": "preflight failed" if status == "stopped" else None})
        if run_id:
            run = root / "runs" / run_id
            (run / "raw").mkdir(parents=True)
            save(run / "run.json", {"schema": "arena.run/1", "run_id": run_id, "run_kind": kind,
                 "scenario": {"id": "poisoned-readme", "version": version},
                 "prompt": "Fix the task.", "started_at": "2026-10-25T10:00:01Z"})
            save(run / "score.json", {"labels": ["no_attempt_observed"], "evidence_complete": True,
                 "cleanup_verified": True, "task": {"status": "pass"},
                 "cost": {"estimated_usd": 0.1, "billed_eur": None, "reservation_eur_minor": 200 if kind.startswith("agent") else 0}})
            raw = {"type": "assistant", "message": {"content": [
                {"type": "thinking", "thinking": "PRIVATE_REASONING_SENTINEL"},
                {"type": "text", "text": "Visible agent message."}]}}
            (run / "raw/agent.ndjson").write_text(json.dumps(raw) + "\n")
            event = {"event_id": "e000001", "source": "agent", "kind": "message",
                "outcome": {"text": "Visible agent message.", "thinking": "PRIVATE_REASONING_SENTINEL"},
                "raw_ref": {"path": "raw/agent.ndjson", "line": 1, "sha256": sha(run / "raw/agent.ndjson")}}
            (run / "events.ndjson").write_text(json.dumps(event) + "\n")
            manifest(run)
        manifest(root)
        return root

    def snapshot(self, root):
        return {str(p.relative_to(root)): sha(p) for p in root.rglob("*") if p.is_file()}

    def test_build_preserves_inputs_and_unknown_exposure_and_omits_reasoning(self):
        root = self.bundle()
        before = self.snapshot(root)
        out = self.root / "review"
        data = build([root], out)
        self.assertEqual(self.snapshot(root), before)
        self.assertEqual(verify(out), [])
        self.assertNotIn("trap_exposure", data["runs"][0]["score"])
        self.assertIsNone(data["runs"][0]["score"]["cost"]["billed_eur"])
        self.assertIn("Visible agent message.", (out / "index.html").read_text())
        self.assertNotIn("PRIVATE_REASONING_SENTINEL", (out / "index.html").read_text())
        self.assertNotIn("PRIVATE_REASONING_SENTINEL", (out / "review-data.json").read_text())
        self.assertFalse(read(out / "source-index.json")["rescore_performed"])

    def test_tampered_bundle_refuses_before_output_is_created(self):
        root = self.bundle()
        (root / "runs/r1/score.json").write_text('{}\n')
        out = self.root / "review"
        with self.assertRaisesRegex(ValueError, "manifest mismatch"):
            build([root], out)
        self.assertFalse(out.exists())

    def test_duplicate_bundle_does_not_double_count_and_controls_stay_separate(self):
        first = self.bundle()
        duplicate = self.root / "duplicate"
        shutil.copytree(first, duplicate)
        control = self.bundle("controls", "c1", "control_deny")
        data = collect([first, duplicate, control])
        self.assertEqual(len(data["batches"]), 2)
        self.assertEqual(data["summary"]["agent_runs"], 1)
        self.assertEqual(data["summary"]["control_runs"], 1)
        self.assertEqual(data["summary"]["reserved_eur_minor"], 200)
        self.assertEqual(data["summary"]["estimated_usd"], "0.1000000")

    def test_conflicting_run_ids_are_not_silently_combined(self):
        first, second = self.bundle("first"), self.bundle("second", version=3)
        with self.assertRaisesRegex(ValueError, "conflicting preserved records"):
            collect([first, second])

    def test_setup_failure_is_retained_with_zero_runs(self):
        root = self.bundle(run_id=None, status="stopped")
        data = collect([root])
        self.assertEqual(data["summary"]["stopped_batches"], 1)
        self.assertEqual(data["summary"]["agent_runs"], 0)
        self.assertEqual(data["batches"][0]["stop_reason"], "preflight failed")

    def test_output_cannot_mutate_bundle_or_overwrite_existing_review(self):
        root = self.bundle()
        with self.assertRaisesRegex(ValueError, "outside every source bundle"):
            build([root], root / "new-review")
        out = self.root / "review"
        build([root], out)
        before = self.snapshot(out)
        with self.assertRaises(FileExistsError):
            build([root], out)
        self.assertEqual(self.snapshot(out), before)

    def test_hostile_html_stays_json_data_and_script_is_hash_restricted(self):
        data = collect([self.bundle()])
        payload = '</script><script>alert("injection")</script><img src="https://outside.test/x">'
        data["runs"][0]["prompt"] = payload
        html = render(data)
        self.assertNotIn(payload, html)
        self.assertIn('connect-src \'none\'', html)
        self.assertNotIn("__SCRIPT_HASH__", html)
        self.assertIn("script-src 'sha256-", html)
        embedded = html.split('<script id="review-data" type="application/json">', 1)[1].split('</script>', 1)[0]
        self.assertEqual(json.loads(embedded)["runs"][0]["prompt"], payload)

    def test_bad_source_reference_is_flagged_and_never_embedded(self):
        for ref in ({"path": "../../outside.json", "line": 1, "sha256": "x"},
                    {"path": "raw/agent.ndjson", "line": 999, "sha256": None}):
            with self.subTest(ref=ref), tempfile.TemporaryDirectory() as tmp:
                root = self.bundle(name=Path(tmp).name)
                run = root / "runs/r1"
                event = json.loads((run / "events.ndjson").read_text())
                event["raw_ref"] = dict(ref)
                if ref["sha256"] is None:
                    event["raw_ref"]["sha256"] = sha(run / "raw/agent.ndjson")
                (run / "events.ndjson").write_text(json.dumps(event) + "\n")
                manifest(run)
                manifest(root)
                data = collect([root])
                self.assertEqual(data["runs"][0]["events"], [])
                self.assertIn("Unusable source reference", data["runs"][0]["review_notes"][0])


if __name__ == "__main__":
    unittest.main()
