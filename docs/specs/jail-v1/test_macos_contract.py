# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""DOCS contract regressions; no live ES, guest or release claims.

Run: uv run --offline docs/specs/jail-v1/test_macos_contract.py
For the red side, add --base 2da5c8d13 (phase 1) or c151e4e20 (phase 2). Reads that commit with git show;
never switches or writes a checkout. Schema/semantic checks exercise records;
prose checks pin the scope disclosures that prevent historical evidence or
component tests from being presented as implementation acceptance.
"""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import types
import unittest

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = "docs/specs/jail-v1/"
BASE = None
if "--base" in sys.argv:
    index = sys.argv.index("--base")
    BASE = sys.argv[index + 1]
    del sys.argv[index:index + 2]


def read(path):
    if BASE:
        return subprocess.check_output(
            ["git", "show", f"{BASE}:{path}"], cwd=ROOT, text=True
        )
    return (ROOT / path).read_text()


def record(path):
    return json.loads(read(CONTRACT + path))


def validator_module():
    name = "phase1_validator"
    if BASE:
        module = types.ModuleType(name)
        module.__file__ = str(ROOT / CONTRACT / "validate_contract.py")
        exec(compile(read(CONTRACT + "validate_contract.py"), module.__file__, "exec"), module.__dict__)
        return module
    spec = importlib.util.spec_from_file_location(name, ROOT / CONTRACT / "validate_contract.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MacosContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = validator_module()
        schemas = {
            p.name.removesuffix(".schema.json"): record(p.name)
            for p in (ROOT / CONTRACT).glob("*.schema.json")
        }
        cls.validators = cls.module.build_validators(schemas)

    def test_d1_status_discloses_incomplete_work_and_unrun_spike(self):
        for path in ["docs/specs/jail-macos.md", "docs/roadmap.md", "docs/guide.md",
                     "docs/RELEASING.md", "docs/benchmarks/jail/README.md"]:
            with self.subTest(path=path):
                text = " ".join(read(path).split())
                self.assertIn("work in progress", text)
                self.assertIn("measurement spike", text)
                self.assertRegex(text, r"(?s)J18.*?lacks.*?network.*?`agent`.*?workspace.*?credentials")
                self.assertNotRegex(text, r"(?i)(?:are|is now|both|2026-10-22,) code-complete|The code is complete")
        self.assertIn("refusal-only", read("docs/specs/jail-macos.md"))

    def test_d2_prototype_trials_are_distinguished_from_implementation(self):
        text = read("docs/roadmap.md")
        self.assertIn("40 of 40 single-custodian kill trials", text)
        self.assertIn("40 of 200 total trials", text)
        self.assertIn("750 ms heartbeat", text)
        self.assertIn("`(allow default)`", text)
        self.assertIn("not this code", text)
        self.assertIn("not run against those custodians", text)

    def test_d3_lane_claims_disclose_actual_scope(self):
        text = read("docs/benchmarks/jail/README.md")
        rows = dict(re.findall(r"^\| `([^`]+)` \| (.*?) \|$", text, re.M))
        scopes = {
            "macos_custody_core": "No start/release or receipt integration proof",
            "macos_guardian": "No live custodian-loss or stall trial",
            "macos_defense_matrix": "operator sleeper and a sibling member",
            "macos_bridge": "No vendor-agent run or credential-binding receipt assertion",
            "macos_terminal_relay": "No complete jailed descriptor-isolation",
            "macos_gc": "fabricated attempt roots",
            "macos_boundary": "development opt-in",
            "macos_observe": "No observed live attempt",
            "vm_tier": "No VM boots",
        }
        for lane, disclosure in scopes.items():
            with self.subTest(lane=lane):
                self.assertIn(disclosure, rows[lane])

    def ready_mac(self):
        value = record("examples/doctor-macos.json")
        value["ready"] = True
        for row in value["capabilities"]:
            row.update(status="available", reason_code="ok", mechanism="synthetic-native-capability",
                       measured_at="2026-10-22T12:00:00Z", evidence_ref="fixture:not-live-evidence")
        return value

    def test_d4_ready_mac_validates_without_bubblewrap(self):
        value = self.ready_mac()
        self.assertNotIn("bwrap", value["binaries"])
        self.assertEqual([], [e.message for e in self.validators["jail-doctor"].iter_errors(value)])
        # Keep the pre-existing refusal record valid too.
        self.validators["jail-doctor"].validate(record("examples/doctor-macos.json"))

    def test_d4_unavailable_requirement_still_prevents_ready(self):
        value = self.ready_mac()
        value["capabilities"][0].update(status="unavailable", reason_code="es_not_entitled")
        self.assertTrue(list(self.validators["jail-doctor"].iter_errors(value)))

    def test_d4_linux_ready_containment_still_requires_bubblewrap(self):
        # Start with a Linux example, retain all its host/build invariants,
        # then isolate the backend requirement.
        examples = sorted((ROOT / CONTRACT / "examples").glob("doctor-*.json"))
        value = next(record(p.relative_to(ROOT / CONTRACT).as_posix()) for p in examples
                     if record(p.relative_to(ROOT / CONTRACT).as_posix())["platform"]["os"] == "linux")
        value["ready"] = True
        value["requirements"] = ["filesystem_containment"]
        value["capabilities"] = []
        self.assertIn("bwrap", value["binaries"])
        self.validators["jail-doctor"].validate(value)
        for missing in [False, True]:
            bad = copy.deepcopy(value)
            if missing:
                del bad["binaries"]["bwrap"]
            else:
                bad["binaries"]["bwrap"] = None
            self.assertTrue(list(self.validators["jail-doctor"].iter_errors(bad)))

    def test_d5_illustration_has_no_unsupported_audit_claim(self):
        value = record("examples/receipt-macos-native.json")
        for name in ["fs.deny", "net"]:
            self.assertEqual(value["coverage"][name], dict(status="unsupported", sources=[], observed_count=None, gaps=[]))
        self.assertEqual(value["policy"]["evidence"], "best-effort")
        self.validators["jail-receipt"].validate(value)
        text = read(CONTRACT + "frozen-schemas.toml")
        self.assertRegex(text, r"receipt-macos-native.json \(hand-written\n#\s+illustrative fixture, not product output")

    def test_d6_cli_narrowing_and_digest_contract_agree(self):
        spec = read("docs/specs/jail-v1.md")
        commands = spec.split("### 6.1 Commands", 1)[1].split("### 6.2", 1)[0]
        for item in ["[--vm]", "[--lifetime kernel-bound]", "ukai-jail vm stop"]:
            self.assertIn(item, commands)
        narrowing = spec.split("### 6.3 Policy shape and narrowing", 1)[1].split("### 6.4", 1)[0]
        self.assertIn('Add `lifetime_boundary = "kernel-bound"`', narrowing)
        canonical = read(CONTRACT + "canonicalization.md")
        self.assertIn("| lifetime_boundary |", canonical)
        value = record("fixtures/policy-snapshot.json")
        original = self.module.policy_hash(value)
        value["lifetime_boundary"] = "kernel-bound"
        self.validators["policy-snapshot"].validate(value)
        self.assertNotEqual(original, self.module.policy_hash(value))
        del value["lifetime_boundary"]
        self.assertEqual(original, self.module.policy_hash(value))

    def test_d7_live_claims_cannot_pass_on_component_tests_alone(self):
        acceptance = tomllib.loads(read(CONTRACT + "acceptance-map.toml"))
        rows = dict(re.findall(r"^\| (K\d+) \| (.*?) \|$", read("docs/specs/jail-macos.md"), re.M))
        gates = {g["id"]: g for g in acceptance["gate"]}
        for gate in [f"K{i}" for i in range(87, 114)]:
            with self.subTest(gate=gate):
                self.assertIn(gate, gates)
                self.assertEqual(gates[gate]["row"], rows[gate])
        for gate in ["L02", "M01"] + [f"K{i}" for i in range(87, 114)]:
            with self.subTest(gate=gate):
                pending = [c for c in acceptance["clause"] if c["gate"] == gate and c.get("lane") == "macos" and c["tag"] == "untested"]
                self.assertTrue(pending, "live native claim needs an explicit failing clause")
                self.assertTrue(all(not c.get("tests") and not c.get("checks") for c in pending))
        for c in acceptance["clause"]:
            if c["gate"] not in {f"K{i}" for i in range(87, 114)}:
                continue
            for test in c.get("tests", []):
                source, name = test.split("::", 1)
                self.assertRegex(read("crates/" + source), r"(?m)^fn " + re.escape(name) + r"\(")

    def test_d8_other_writable_is_never_accepted(self):
        for path in ["docs/specs/jail-launch-and-summary.md", "docs/specs/jail-macos.md"]:
            text = read(path)
            self.assertIn("directory-service membership cannot", text)
            self.assertIn("neither group-writable nor other-writable", " ".join(text.split()))
            self.assertIn("refuse", text)
            self.assertNotIn("nested groups are refused", text)
            self.assertNotIn("with nested groups refused", text)
        self.assertIn("exception was withdrawn", read("docs/specs/jail-macos.md"))

    def test_d9_binding_is_optional_and_only_macos_vault_attempt(self):
        for os_name in ["linux", "macos"]:
            for mode in ["vault", "copy_rw", "bind_ro"]:
                for binding in ["absent", "attempt", "program", None, "other"]:
                    with self.subTest(os=os_name, mode=mode, binding=binding):
                        value = record("examples/receipt-macos-native.json")
                        value["platform"]["os"] = os_name
                        value["credentials"] = [copy.deepcopy(record("examples/receipt-agent-proxy-only.json")["credentials"][0])]
                        item = value["credentials"][0]
                        item["mode"] = mode
                        item.pop("binding", None)
                        if binding != "absent":
                            item["binding"] = binding
                        rules = [v[0] for v in self.module.semantic_receipt(value)]
                        valid = binding == "absent" or (os_name == "macos" and mode == "vault" and binding == "attempt")
                        self.assertEqual("credential_binding" not in rules, valid)
        value = record("examples/receipt-macos-native.json")
        value["credentials"] = []
        self.validators["jail-receipt"].validate(value)

    def test_l1_counterexample_is_bounded_by_the_design_choice(self):
        text = read("docs/benchmarks/jail/apple-lifetime-question.md")
        self.assertIn("limit of this design without a root", text)
        self.assertNotIn("stands as a property of the platform", text)

    def test_l2_unrecorded_counts_and_homebrew_are_labelled(self):
        text = read("docs/specs/jail-macos.md")
        self.assertRegex(text, r"(?s)900-of-900.*?observed, not recorded")
        self.assertIn("`admin` (observed, not recorded)", text)
        self.assertIn("`admin`-writable (observed, not recorded)", read("docs/specs/jail-launch-and-summary.md"))

    def test_l3_counts_include_the_guard_client(self):
        text = read("docs/specs/jail-macos.md")
        self.assertNotRegex(text, r"[Tt]wo ES clients")
        self.assertIn("three ES clients (S, G, G′; four with J17)", text)
        self.assertIn("Three ES clients (S, G and G′; four with J17)", text)
        self.assertIn("A fourth ES client", text)

    def test_l4_boundary_name_does_not_assert_verified_end(self):
        text = read("docs/guide.md")
        self.assertIn("`native_tree` receipt can instead report `tree_unknown`", text)
        self.assertIn("`tree_empty: true`", text)

    def test_l6_single_guardian_loss_is_not_the_residual(self):
        text = read("docs/specs/jail-macos.md")
        self.assertRegex(text, r"(?s)One lost guardian.*?not the named residual.*?loss of both\n  custodians")

    def test_l7_deleted_vm_requires_a_reclone(self):
        text = read("docs/specs/jail-macos.md").split("### 4.12 Packaging", 1)[1].split("## 5.", 1)[0]
        self.assertIn("deleted on 2026-10-22", text)
        self.assertIn("must be re-cloned", text)
        self.assertNotIn("continues in the SIP-disabled VM", text)

    def test_phase2_product_shape_illustration(self):
        value = record("examples/receipt-macos-native.json")
        self.assertEqual(value["jail"]["backend"], "ukai-jail-macos")
        self.assertEqual(value["policy"]["observe"], "off")
        self.assertNotIn("closed_set_observation", value["policy"]["requirements"])
        self.assertEqual(value["credentials"], [])
        self.assertIsNone(value["applied"]["syscalls"])
        self.assertEqual(value["applied"]["filesystem"]["protected_coverage"], "existing_and_root")
        details = value["lifetime"]["native"]["details"]
        self.assertEqual(details["native_execution"], "dev")
        self.assertRegex(details["profile_digest"], r"^[a-f0-9]{64}$")
        self.assertEqual(set(details["profile_parameters"]), {
            "read_write", "read_only", "deny_read", "protected_segments", "setuid_exec_denied",
            "setuid_scan_holes", "setuid_backstop", "mach_services", "unix_socket_paths",
            "terminal_slave", "bridge_http_port", "bridge_socks_port"})
        for facts in details["custodians"].values():
            self.assertTrue(facts["events"] is None or type(facts["events"]) is int)
            if facts["events"] is None:
                self.assertEqual(facts["stream"], "unknown")
        self.assertIsNone(value["observer"]["backend"])
        self.assertFalse(value["observer"]["attached"])
        for name in ["exec", "fs.write", "fs.deny", "net"]:
            self.assertEqual(value["coverage"][name], dict(status="unsupported", sources=[], observed_count=None, gaps=[]))
        self.validators["jail-receipt"].validate(value)
        self.assertEqual(self.module.semantic_receipt(value), [])

    def test_phase2_native_shape_widening_keeps_linux_and_proxy_requirements(self):
        native = record("examples/receipt-macos-native.json")
        native["applied"]["syscalls"] = None
        native["applied"]["network"]["mechanism"] = None
        self.validators["jail-receipt"].validate(native)
        for field in ["syscalls", "network"]:
            linux = record("examples/receipt-settled-unknown.json")
            if field == "syscalls":
                linux["applied"][field] = None
            else:
                linux["applied"][field]["mechanism"] = None
            self.assertTrue(list(self.validators["jail-receipt"].iter_errors(linux)))
        native["applied"]["network"]["mode"] = "proxy"
        self.assertTrue(list(self.validators["jail-receipt"].iter_errors(native)))

    def test_phase2_status_matches_deliberate_refusals(self):
        for path in ["docs/specs/jail-macos.md", "docs/roadmap.md", "docs/guide.md",
                     "docs/RELEASING.md", "docs/benchmarks/jail/README.md"]:
            with self.subTest(path=path):
                text = " ".join(read(path).split())
                for fact in ["UKAI_JAIL_MACOS_NATIVE=dev", "native_execution=dev", "J17_OBSERVE=false",
                             "ObserveRun", "unwired", "fs.write", "degraded", "before connecting"]:
                    self.assertIn(fact, text)
                self.assertRegex(text, r"credential.*vault.*vendor.*unsupported")
        spec = read("docs/specs/jail-macos.md")
        self.assertIn('`sequence_start: "unverified"`', spec)
        self.assertIn("requires the root to have entered the table", " ".join(spec.split()))
        self.assertIn("before the first delivered message", spec)

    def test_phase2_release_scope_is_explicit_and_complete(self):
        acceptance = tomllib.loads(read(CONTRACT + "acceptance-map.toml"))
        clauses = {c["id"]: c for c in acceptance["clause"]}
        native = {c["id"] for c in clauses.values() if c["tag"] == "untested" and
                  (c["gate"] in {f"K{i}" for i in range(87, 114)} or c["id"] in {"L02.12", "M01.4"})}
        release = json.loads(read("crates/ukai-jail/dist/release.json"))["jail"]["unsupported_clauses"]
        self.assertEqual(set(release), native | {"K22.2", "K23.1", "K24.1", "K26.1", "K29.1"})
        self.assertEqual(len(release), len(set(release)))
        self.assertTrue(all(re.fullmatch(r"[A-Z][0-9]+\.[0-9]+", c) for c in release))
        self.assertEqual(clauses["K105.2"]["tests"], ["ukai-jail/tests/macos_observe.rs::k105_events_map_to_schema_valid_audit_results_with_honest_coverage"])
        self.assertIn("degraded", clauses["K105.2"]["clause"])

    def test_phase2_reblessed_artifacts_match_digests(self):
        frozen = tomllib.loads(read(CONTRACT + "frozen-schemas.toml"))
        artifacts = {item["file"]: item for item in frozen["frozen_artifact"]}
        self.assertTrue({"fixtures/semantic-cases.json", "examples/receipt-macos-native.json"} <= artifacts.keys())
        for item in artifacts.values():
            if item["file"] not in {"fixtures/semantic-cases.json", "examples/receipt-macos-native.json"}:
                continue
            self.assertEqual(item["sha256"], hashlib.sha256(read(CONTRACT + item["file"]).encode()).hexdigest())

    def test_freeze_requires_a_new_reference_run(self):
        text = read("docs/RELEASING.md")
        self.assertIn("fresh reference conformance rerun on the VPS", text)
        self.assertIn("freeze --doctor <successful-run>/doctor.json", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
