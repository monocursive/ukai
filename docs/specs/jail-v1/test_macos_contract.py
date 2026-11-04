# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema==4.26.0", "rfc3339-validator==0.1.4", "rfc8785==0.1.4"]
# ///
"""DOCS contract regressions; no live ES, guest or release claims.

Run: uv run --offline docs/specs/jail-v1/test_macos_contract.py
For the red side, add --base 2da5c8d13 (phase 1) or c151e4e20 (phase 2), or 395294c42 (round 3). Reads that commit with git show;
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


def rust_test_definition(reference):
    """Resolve integration and nested library ids as xtask's map checker does.

    Library ids name the test binary (src/lib.rs), not the module file.
    Prefer the longest module prefix that exists; inline `tests` stays in
    that file. Use read(), so --base validates that revision's sources too.
    """
    source, name = reference.split("::", 1)
    parts = name.split("::")
    modules, function = parts[:-1], parts[-1]
    if source.endswith("/src/lib.rs"):
        base = source.removesuffix("lib.rs")
        for count in range(len(modules), 0, -1):
            prefix = base + "/".join(modules[:count])
            for candidate in [prefix + ".rs", prefix + "/mod.rs"]:
                try:
                    return read("crates/" + candidate), function
                except (FileNotFoundError, subprocess.CalledProcessError):
                    pass
    return read("crates/" + source), function


def exists(path):
    """Whether `path` (a file or directory) is in the tree being validated."""
    if BASE:
        return subprocess.run(["git", "cat-file", "-e", f"{BASE}:{path.rstrip('/')}"],
                              cwd=ROOT, capture_output=True).returncode == 0
    return (ROOT / path).exists()


def seatbelt_template_digest():
    """`sandbox::template_digest()`: SHA-256 of the raw `TEMPLATE` literal.

    The K90 pins in tests/macos_sandbox_profile.rs and
    tests/macos_defense_matrix.rs assert the Rust side equals the same value.
    """
    source = read("crates/ukai-jail/src/platform/macos/sandbox.rs")
    match = re.search(r'pub const TEMPLATE: &str = r#"(.*?)"#;', source, re.S)
    return hashlib.sha256(match.group(1).encode()).hexdigest()


CITED_PATH = re.compile(r"(?:docs|crates)/[A-Za-z0-9_./-]+")
NATIVE_GATES = ["L02", "M01"] + [f"K{i}" for i in range(87, 114)]


def cited_paths(note):
    return [path.rstrip(".,;:") for path in CITED_PATH.findall(note or "")]


def live_promotion_problems(acceptance, exists):
    """Why the map breaks the D7 rule; [] when it holds.

    An untested native clause lists no evidence. A native gate left with no
    untested clause was promoted, and component tests alone cannot promote
    it: it needs a live clause that names a test or check a gate evaluates
    and cites an evidence record under docs/benchmarks/ that exists. Every
    path any note cites must exist (a substring is not a record).
    """
    problems = []
    for gate in NATIVE_GATES:
        clauses = [c for c in acceptance["clause"] if c["gate"] == gate and c.get("lane") == "macos"]
        pending = [c for c in clauses if c["tag"] == "untested"]
        measured = [c for c in clauses if c["tag"] in ("live-cli", "live-lib")]
        problems += [f"{c['id']} is untested but lists evidence" for c in pending
                     if c.get("tests") or c.get("checks")]
        if pending:
            continue
        if not measured:
            problems.append(f"{gate} has no untested clause and no live clause: "
                            "component tests alone cannot promote a gate")
        for c in measured:
            if not c.get("tests") and not c.get("checks"):
                problems.append(f"{c['id']} is {c['tag']} but names no test or check a gate evaluates")
            if not any(p.startswith("docs/benchmarks/") for p in cited_paths(c.get("note"))):
                problems.append(f"{c['id']} cites no docs/benchmarks/ evidence record")
    for c in acceptance["clause"]:
        problems += [f"{c['id']} cites {p}, which does not exist"
                     for p in cited_paths(c.get("note")) if not exists(p)]
    return problems


# A J18 row claimed as passing, in any spelling: a K108-K113 range (hyphen,
# en or em dash, "to", "through") or a list of those ids, then pass/passes/passed.
VM_ROW = r"K1(?:0[89]|1[0-3])(?:\.1)?"
PASSING_VM_ROWS = re.compile(
    rf"\b{VM_ROW}\s*(?:[-–—]|to|through)\s*{VM_ROW}\s+(?:all\s+|now\s+)?pass(?:es|ed)?\b"
    rf"|\b{VM_ROW}(?:,?\s+(?:and\s+)?{VM_ROW})+,?\s+(?:all\s+|now\s+)?pass(?:es|ed)?\b"
    rf"|\b{VM_ROW}\s+(?:now\s+)?pass(?:es|ed)?\b")


def passing_vm_row_claims(text):
    return [match.group(0) for match in PASSING_VM_ROWS.finditer(text)]


def candidate_tag_problems(readme, tag_prefix, candidate):
    """The preview.2 README names the candidate's tag correctly outside its errata.

    Erratum 1 quotes the wrong tag on purpose; everywhere else the candidate
    may be tagged only with `tag_prefix`, and the publication steps must name
    that tag.
    """
    start = readme.index("**Errata (2026-11-03, fix wave 1103).**")
    end = readme.index("This build (", start)
    outside = readme[:start] + readme[end:]
    problems = [f"`{match.group(1)}{candidate}` outside the erratum"
                for match in re.finditer(r"([A-Za-z0-9_.-]*-v)" + re.escape(candidate), outside)
                if match.group(1) != tag_prefix]
    if f"`{tag_prefix}{candidate}`" not in outside:
        problems.append(f"the publication steps do not name `{tag_prefix}{candidate}`")
    return problems


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

    def test_d1_status_discloses_incomplete_work_and_measured_spike(self):
        for path in ["docs/specs/jail-macos.md", "docs/roadmap.md", "docs/guide.md",
                     "docs/RELEASING.md", "docs/benchmarks/jail/README.md"]:
            with self.subTest(path=path):
                text = " ".join(read(path).split())
                self.assertIn("work in progress", text)
                self.assertIn("measurement spike", text)
                self.assertIn("macos-custody-spike-2026-11-01/README.md", text)
                self.assertIn("kickstart", text)
                # J18 status per fix wave 1103 (D1, D2, D11): the rows are
                # untested, unmeasured requirements and uncarried policy
                # refuse by name before any connection or boot, and no
                # macOS client ships.
                self.assertRegex(text, r"K108–K113 (?:are|remain|stay) `?untested`?")
                for fact in ["`vm:not-measured:<requirement>`", "`vm:not-carried:<field>`",
                             "before any connection or boot", "built from source"]:
                    self.assertIn(fact, text)
                for stale in ["lacks network", "no qualified VM backend exists yet",
                              "refuses before connecting"]:
                    self.assertNotIn(stale, text)
                self.assertEqual([], passing_vm_row_claims(text))
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
                self.assertIn(disclosure.lower(), rows[lane].lower())

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
        self.assertEqual([], live_promotion_problems(acceptance, exists))
        # K108-K113 were promoted on 2026-11-03 with notes that named no
        # test and records that did not meet their clauses; they are
        # untested again (fix wave 1103, D11).
        for gate in [f"K{i}" for i in range(108, 114)]:
            with self.subTest(gate=gate):
                self.assertEqual(next(c for c in acceptance["clause"] if c["id"] == gate + ".1")["tag"], "untested")
        for c in acceptance["clause"]:
            if c["gate"] not in {f"K{i}" for i in range(87, 114)}:
                continue
            for test in c.get("tests", []):
                with self.subTest(reference=test):
                    source, name = rust_test_definition(test)
                    self.assertRegex(source, r"(?m)^\s*#\[test\]\s*(?:#\[[^\n]+\]\s*)*fn " + re.escape(name) + r"\(")

    def test_d7_guard_refuses_a_promotion_without_evaluated_tests_or_an_existing_record(self):
        # Every native gate has an untested clause today, so the guard's
        # promotion branch runs only on these synthetic maps.
        acceptance = tomllib.loads(read(CONTRACT + "acceptance-map.toml"))
        test = "ukai-jail/tests/vm_tier.rs::the_transport_record_carries_the_recorded_facts"
        record = "docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md"
        self.assertTrue(exists(record))

        def promote(tag="live-cli", **fields):
            value = copy.deepcopy(acceptance)
            next(c for c in value["clause"] if c["id"] == "K111.1").update(tag=tag, **fields)
            return live_promotion_problems(value, exists)

        # A promotion that holds: a live clause a gate evaluates, citing a real record.
        self.assertEqual([], promote(tests=[test], note=f"Live row; evidence {record}."))
        for name, problems in {
            "a cited record that does not exist":
                promote(tests=[test], note="Live row; evidence docs/benchmarks/jail/results/no-such-run/README.md."),
            "no test or check a gate evaluates": promote(note=f"Live row; evidence {record}."),
            "no evidence record": promote(tests=[test], note="Live row, measured on the dev Mac."),
            "component tests alone": promote(tag="portable", tests=[test], note=f"Evidence {record}."),
        }.items():
            with self.subTest(defect=name):
                self.assertTrue(problems)
        # An untested clause's cited path must exist too.
        value = copy.deepcopy(acceptance)
        next(c for c in value["clause"] if c["id"] == "K108.1")["note"] = "See docs/benchmarks/jail/results/gone/."
        self.assertEqual(live_promotion_problems(value, exists),
                         ["K108.1 cites docs/benchmarks/jail/results/gone/, which does not exist"])
        # An untested clause lists no evidence: a test or a check on it is
        # the one problem, whichever it names.
        for field in ["tests", "checks"]:
            with self.subTest(untested_lists=field):
                value = copy.deepcopy(acceptance)
                clause = next(c for c in value["clause"] if c["id"] == "K111.1")
                self.assertEqual(clause["tag"], "untested")
                clause[field] = [test]
                self.assertEqual(live_promotion_problems(value, exists),
                                 ["K111.1 is untested but lists evidence"])

    def test_d11_vm_docs_imply_no_shipped_client_and_no_passing_row(self):
        def flat(path):
            return " ".join(read(path).split())
        # No macOS ukai-jail client ships (the DMG carries ukai-vm and
        # ukai-vm-install): every doc that shows `ukai-jail run --vm` says so.
        for path in ["crates/ukai-jail/vm/PREVIEW.txt", "crates/ukai-jail/vm/README.md",
                     "docs/guide.md", "docs/specs/jail-macos.md"]:
            with self.subTest(path=path):
                text = flat(path).replace("`", "")
                self.assertIn("ukai-jail run --vm", text)
                self.assertIn("built from source", text)
                self.assertRegex(text, r"(?i)no macOS ukai-jail client ships")
        # No current VM page claims a J18 row passes, in any spelling.
        for path in ["crates/ukai-jail/vm/PREVIEW.txt", "crates/ukai-jail/vm/README.md",
                     CONTRACT + "agent-compatibility.md", "crates/ukai-jail/dist/release.json"]:
            with self.subTest(path=path, check="no passing row"):
                self.assertEqual([], passing_vm_row_claims(flat(path)))
        vm_row = next(line for line in read(CONTRACT + "agent-compatibility.md").splitlines()
                      if line.startswith("| Claude Code | 2.1.311"))
        self.assertNotIn("Supported", vm_row)
        self.assertIn("K113 `untested`", vm_row)
        platform = vm_row.split(" | ")[3]
        self.assertNotIn("installed ukai-vm 0.1.0-preview.1", platform)
        for fact in ["development package labeled 0.1.0-preview.1, not the public preview (erratum 5)",
                     "built from the repository"]:
            self.assertIn(fact, platform)
        # The cited receipt digest matched no file; the guest receipt is
        # 53837b58. The wrong one may appear only in its erratum.
        for path in [CONTRACT + "agent-compatibility.md",
                     "docs/benchmarks/jail/results/macos-vm-claude-2026-11-03/README.md"]:
            with self.subTest(path=path):
                text = flat(path)
                self.assertIn("sha256:53837b58", text)
                for match in re.finditer("10c3c58f", text):
                    self.assertIn("matches no file", text[max(0, match.start() - 200):match.end() + 200])
        self.assertNotIn("or at minimum the install check",
                         flat("docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md"))
        vm = json.loads(read("crates/ukai-jail/dist/release.json"))["vm"]
        self.assertNotEqual(vm["version"], vm["candidate_version"])
        self.assertEqual([], candidate_tag_problems(
            read("docs/benchmarks/jail/results/macos-vm-preview2-2026-11-03/README.md"),
            vm["tag_prefix"], vm["candidate_version"]))
        self.assertTrue(read("crates/ukai-jail/vm/PREVIEW.txt").startswith(
            f"Ukai VM {vm['candidate_version']} "))

    def test_d13_rule6_receipts_carry_the_guardians_report(self):
        """D13: both limits lowered when clamped; the guardian reports on B."""
        native = " ".join(read("docs/specs/jail-macos.md").split("## 4.", 1)[1].split("## 5.", 1)[0].split())
        for fact in ["min(soft, hard)", "`allowance` frame on B immediately before `ready`",
                     "A handshake without exactly one `allowance` before `ready` refuses",
                     "`allowance ` + limit (u64) + headroom (u64) + clamped (one byte, 0 or 1)",
                     "`process_limit`", "`process_headroom`", "`process_headroom_clamped`",
                     "`process_allowance`", "`stop.phases`", "the supervisor plans nothing",
                     "min(hard, `kern.maxprocperuid`)",
                     "preparation refuses if either has moved below the decided limit",
                     "a limit that rose after the decision is not refused"]:
            self.assertIn(fact, native)
        for stale in ["The clamped path sets nothing", "the process headroom (rule 6) and pending",
                      "any member could raise its soft limit up to the hard limit",
                      "reports `ready` on B. If", "if the limits moved during preparation"]:
            self.assertNotIn(stale, native)
        compat = " ".join(read("docs/benchmarks/jail/results/macos-compat-2026-11-02/README.md").split())
        for fact in ["## Errata (2026-11-03, fix wave 1103)", "the supervisor's figure",
                     "The clamped row ran with the hard limit unlowered", "`60f7eb7b6`",
                     "the hard limit of 2000 is from that later state, not the clamped row"]:
            self.assertIn(fact, compat)
        self.assertTrue(exists("docs/benchmarks/jail/results/macos-nproc-raise-2026-11-03/output.txt"))
        # Rule 6's evidence: what tests drive, what only reading verifies.
        for fact in ["`guardian::announcement`", "`MacosPrepared::assemble`",
                     "are verified by reading only", "The corrected rule has not run under ES"]:
            self.assertIn(fact, native)

    def test_failed_bootstrap_strip_is_a_refusal_not_an_exec_error(self):
        """288c00933: nothing executed, so the attempt is refused, never exec_error."""
        native = " ".join(read("docs/specs/jail-macos.md").split("## 4.", 1)[1].split("## 5.", 1)[0].split())
        for fact in ["`bootstrap_strip:KERN_…`", "exits 126 without the exec",
                     "outcome `refused`, error `backend_unavailable`, remediation `inspect_state`, exit 125",
                     "never as `exec_error`", "`a_failed_containment_step_is_a_refusal_not_an_exec_error`",
                     "no strip failure has been observed live",
                     # The residual is named, not claimed fixed.
                     "`ProgramChanged` and `TerminalUnavailable`, are still recorded as `exec_error`",
                     "A failed bootstrap strip (§4.7, class 2) also arrives on E",
                     # §4 step 7 says the same as §4.7 class 2.
                     "it is outcome `refused` with `backend_unavailable`, never `exec_error`"]:
            self.assertIn(fact, native)
        # A pin only proves a sentence is present; no other sentence of §4 may
        # give a strip (or anything else) the exec_error outcome.
        self.assertNotIn("outcome `exec_error`", native)
        # jail-v1 §13.2 names the residual instead of claiming every pre-exec
        # refusal is refused.
        core = " ".join(read("docs/specs/jail-v1.md").split())
        for fact in ["Known deviation, not yet reclassified: two launcher refusals after the "
                     "release record `exec_error` although the launcher did not exec",
                     "A failed macOS bootstrap strip is `refused` (jail-macos §4.7 class 2)."]:
            self.assertIn(fact, core)

    def test_vm_fix_wave_docs_describe_the_carry_rule_stop_and_share(self):
        """D1-D8: the VM docs describe the fix wave's code and its test limits."""
        def flat(path):
            return " ".join(read(path).split())
        vm_tier = flat("docs/specs/jail-macos.md").split("## 6.", 1)[1].split("## 7.", 1)[0]
        readme = flat("crates/ukai-jail/vm/README.md")
        for path, text in [("jail-macos.md section 6", vm_tier), ("vm/README.md", readme)]:
            with self.subTest(path=path):
                for fact in ["`vm:owner-loss-not-provided`", "`GUEST_MEASUREMENTS`",
                             "`vm:not-measured:<requirement>`", "`vm:not-carried:<field>`",
                             "`environment.bindings`", "`guest_carried`", "`guest_receipt_sha256`",
                             "`<data>/vm/serve.stderr`", "`attempt_tree_unverified`",
                             "`attempt_files_not_cleared`", "`live_share_mount_failed`",
                             "`launch_profile_unstageable`", "`launch_without_toml`",
                             "`nosuid,nodev`", "`init.scope`", "`test_guest_main.py`",
                             "`guest_harness.py`", "`test_custodian.py`",
                             "covered by unit and model tests only",
                             "kill paths have not run on a booted guest",
                             "`populated_before_kill`" if path == "vm/README.md" else "verified its own tree",
                             # Round 4: the learned stop, the serve binding,
                             # standard input, exit, policy digest, summary.
                             "`infrastructure_unknown`", "`strays_killed`", "`members`",
                             "`(sd-pam)`", "pinned by pid and start time", "`6c1f11852`",
                             "`<data>/vm/serve-failed.stderr`", "another serve replaced it; rerun",
                             "and the guest jail's standard input is /dev/null: nothing written "
                             "to it would reach the target; run with `</dev/null`, or without --vm",
                             "128 + s", "`outcome.cause`", "`/mnt/workspace`", "staged_secrets",
                             "pinned in `image.json`, and it is not", "is summarized as itself",
                             "`vm-transport.json` is absent"]:
                    self.assertIn(fact, text)
                self.assertNotIn("kernel_bound_requires_vm", text)
                self.assertNotIn("measured floor", text)
                # The stop no longer spares a fixed set of units.
                for stale in ["INFRASTRUCTURE_UNITS",
                              "`session.slice/dbus.service` or `app.slice/dbus.service`",
                              "comes from what `prepare.py` installs",
                              "digest-checked against `vm-transport.json`"]:
                    self.assertNotIn(stale, text)
        for fact in ["None is silently dropped", "`KEPT_BOOT_DIRS`", "`UKAI_VM_PACKAGE_VERSION`",
                     "`<crate version>-dev`", "wake gap"]:
            self.assertIn(fact, readme)
        # Each guest-side paragraph carries its own hedge (F2): the share's,
        # the serve check's and the attempt stop's.
        paragraphs = [" ".join(p.split()) for p in read("crates/ukai-jail/vm/README.md").split("\n\n")]
        for marker, hedge in [("powers off with `live_share_mount_failed`. The guest's", "unit and model tests only"),
                              ("`<data>/vm/serve-failed.stderr`", "not against a real serve"),
                              ("**The attempt stop (decision D6).**", "kill paths have not run on a booted guest"),
                              ("`populated_before_kill`", "no booted guest has sent the report yet"),
                              ("gives 128 + s", "none has run against a booted guest"),
                              ("is summarized as itself", "not yet on a new run")]:
            with self.subTest(paragraph=marker):
                paragraph = next(p for p in paragraphs if marker in p)
                self.assertIn(hedge, paragraph)
        # The errata name what each record got wrong and point at the fix.
        results = "docs/benchmarks/jail/results/"
        for path, facts in [
            ("macos-vm-installed-2026-11-03/README.md",
             ["K112's `--vm` refusal named native macOS", "`kernel_bound_requires_vm`",
              "`vm:owner-loss-not-provided`", "Since `7b1f6d875` (decision D5)"]),
            ("macos-vm-claude-2026-11-03/README.md",
             ["The TLS-only grant did not cross as TLS-only",
              '`["api.anthropic.com:443", "api.anthropic.com:443"]`', "there is no `tls_only` field",
              "This record does not test a plaintext request", "`407b18b05`"]),
            ("macos-vm-share-2026-11-02/README.md",
             ["## Errata (2026-11-03, fix wave 1103)", "The preflight's normalization probe could not fail",
              "case-sensitive APFS volume folds normalization only", "the disclosure below stands"]),
            ("macos-vm-warm-2026-11-02/README.md",
             ["moved the kill to a cgroup the jail leaves", "Case B stayed inside the custodian's lease",
              "`bfcf1f9d4`", "`7af4af5c1`", "it has not run on a booted guest",
              "Revised in `6c1f11852`", "kills by pidfd every other live process"]),
        ]:
            with self.subTest(path=path):
                text = flat(results + path)
                for fact in facts:
                    self.assertIn(fact, text)
        # The raw K113 guest receipt still shows the defect the erratum names.
        guest = json.loads(read(results + "macos-vm-claude-2026-11-03/k113-attempt/evidence/jail.json"))
        network = guest["applied"]["network"]
        self.assertNotIn("tls_only", network)
        self.assertEqual(["api.anthropic.com:443"] * 2, network["allowed_hosts"])
        k112 = json.loads(read(results + "macos-vm-installed-2026-11-03/k112.json"))
        self.assertIn("native macOS does not provide", k112["vm_installed"]["stderr"])

    def test_vm_harness_and_packaging_docs_describe_code_not_measurements(self):
        """D9-D11 (harnesses, packaging): what the scripts do, and that none ran live."""
        readme = " ".join(read("crates/ukai-jail/vm/README.md").split())
        for fact in ["`harness.py mark`", "`UKAI_VM_BINARY`", "`--budget-ms`", "`--ukai-jail <client>`",
                     "Every output directory must be new", "No probe uses `/dev/tcp`",
                     "recorded as `REFUSED`, never `PASS`", "`fault_matrix.py`** has nine cases",
                     "`measurements[<requirement>]`",
                     "an upper bound on the overhead the clause limits, not the guest jail's own release time",
                     "under `not_measured`", "none of it has run against a booted guest",
                     "`cargo build --release --locked`", "`source_revision`",
                     "No package has been built with the current script yet", "`notarization.2.json`",
                     "`payload-extra`", "It has not been run against a package yet",
                     # Round 4 (S3): the denial needs a route, receipts are
                     # bound, installed modes, the scrubbed pinned build.
                     "`ENETUNREACH`", "`1.1.1.1:443`", "the proxy answered 200",
                     "never a PASS", "no `--guest-nat` flag",
                     "The live phase therefore needs outbound access to `1.1.1.1:443`",
                     "argv digest (in the binding and in the receipt), profile, serve boot and guest boot",
                     "`row-k111-<nonce>`", "`installed-modes-normalized`",
                     "directories 0755, files 0755", "`/dev/null` as standard input",
                     "assume-unchanged or skip-worktree", "`rustc -vV`", "`cargo -V`",
                     "K112 is `REFUSED` when a lane was refused for its standard input",
                     "its live acceptance is pending",
                     "refuses unless both report that file's exact release",
                     "never an absolute host path",
                     "No rebuild from such an archive under the pinned toolchain has been verified"]:
            self.assertIn(fact, readme)
        self.assertNotIn("the script refuses to run twice", readme)
        self.assertNotIn("`CARGO_TARGET_DIR` is dropped", readme)
        self.assertNotIn("`crates/`, enough to rebuild", readme)
        preview = " ".join(read("crates/ukai-jail/vm/PREVIEW.txt").split())
        for fact in ["source_revision in payload/image/image.json",
                     "cargo build --release --locked -p ukai-jail --bin ukai-vm",
                     "holds only the VM tooling (crates/ukai-jail/vm)",
                     "a rebuild with that pinned toolchain has not been verified",
                     "the earlier published preview and this version's first candidate"]:
            self.assertIn(fact, preview)
        self.assertNotIn("The VM tooling's source (crates/ukai-jail/vm) is included", preview)
        # test_coordinates: PREVIEW names only the candidate version.
        self.assertNotIn("0.1.0-preview.1", preview)

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
        self.assertRegex(text, r"(?i)\ba fourth ES client\b")

    def test_l4_boundary_name_does_not_assert_verified_end(self):
        text = read("docs/guide.md")
        self.assertIn("`native_tree` receipt can instead report `tree_unknown`", text)
        self.assertIn("`tree_empty: true`", text)

    def test_l6_single_guardian_loss_is_not_the_residual(self):
        text = read("docs/specs/jail-macos.md")
        self.assertRegex(text, r"(?s)One lost guardian.*?not the named residual.*?loss of both\n  custodians")

    def test_l7_fresh_vm_is_not_release_qualification(self):
        text = read("docs/specs/jail-macos.md").split("### 4.12 Packaging", 1)[1].split("## 5.", 1)[0]
        self.assertIn("deleted on 2026-10-22", text)
        self.assertIn("fresh pinned", text)
        self.assertIn("ukai-custody-spike-20261101", text)
        self.assertIn("development measurements only", text)
        self.assertIn("normally protected Mac", text)
        self.assertNotIn("continues in the SIP-disabled VM", text)

    def test_phase2_product_shape_illustration(self):
        value = record("examples/receipt-macos-native.json")
        self.assertEqual(value["jail"]["backend"], "ukai-jail-macos")
        self.assertEqual(value["policy"]["observe"], "off")
        self.assertNotIn("closed_set_observation", value["policy"]["requirements"])
        self.assertEqual(value["credentials"], [])
        self.assertIsNone(value["applied"]["syscalls"])
        self.assertEqual(value["applied"]["network"]["mechanism"], "seatbelt-deny-network")
        self.assertEqual(value["applied"]["filesystem"]["protected_coverage"], "existing_and_root")
        details = value["lifetime"]["native"]["details"]
        self.assertEqual(details["native_execution"], "dev")
        self.assertRegex(details["profile_digest"], r"^[a-f0-9]{64}$")
        self.assertEqual(set(details["profile_parameters"]), {
            "read_write", "read_only", "deny_read", "protected_segments", "setuid_exec_denied",
            "setuid_scan_holes", "setuid_backstop", "mach_services", "unix_socket_paths",
            "terminal_slave", "bridge_http_port", "bridge_socks_port", "path_anchors"})
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

    def test_native_wall_hit_states_and_guardian_followup_are_documented(self):
        for path in ["docs/specs/jail-macos.md", "docs/specs/jail-v2.md"]:
            with self.subTest(path=path):
                text = " ".join(read(path).split())
                for fact in ["`hit=false`", "settlement finishes before the deadline",
                             "`hit=true`", "confirmed expiry", "`hit=null`",
                             "deadline elapsed without an observed trigger",
                             "`degraded`", "`wall_hit_unobserved`",
                             "guardian record has no stop trigger", "known follow-up"]:
                    self.assertIn(fact, text)

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
                for fact in ["UKAI_JAIL_MACOS_NATIVE=dev", "native_execution=dev", "J17_OBSERVE=true",
                             "macos-closed-v1", "fs.write", "active", "refuses at probing",
                             "before any connection or boot"]:
                    self.assertIn(fact, text)
                self.assertNotIn("J17_OBSERVE=false", text)
                self.assertNotIn("unwired", text)
                self.assertRegex(text, r"credential.*vault.*vendor.*unsupported")
        self.assertRegex(read("crates/ukai-jail/src/profiles.rs"), r"pub const J17_OBSERVE: bool = true;")
        spec = read("docs/specs/jail-macos.md")
        self.assertIn('`sequence_start: "unverified"`', spec)
        self.assertIn("requires the root to have entered the table", " ".join(spec.split()))
        self.assertIn("before the first delivered message", spec)

    def test_phase2_release_scope_is_explicit_and_complete(self):
        acceptance = tomllib.loads(read(CONTRACT + "acceptance-map.toml"))
        clauses = {c["id"]: c for c in acceptance["clause"]}
        native = {c["id"] for c in clauses.values() if c["tag"] == "untested" and
                  (c["gate"] in {f"K{i}" for i in range(87, 114)} or c["id"] in {"L02.12", "M01.4"})}
        coordinates = json.loads(read("crates/ukai-jail/dist/release.json"))
        release = coordinates["jail"]["unsupported_clauses"]
        self.assertEqual(set(release), native | {"K22.2", "K23.1", "K24.1", "K26.1", "K29.1"})
        self.assertEqual(len(release), len(set(release)))
        self.assertTrue(all(re.fullmatch(r"[A-Z][0-9]+\.[0-9]+", c) for c in release))
        # The VM scope names exactly the untested J18 clauses, each also
        # excluded from the Linux release; nothing else reads this list.
        vm = coordinates["vm"]["unsupported_clauses"]
        j18 = {c["id"] for c in clauses.values() if c["tag"] == "untested"
               and c["gate"] in {f"K{i}" for i in range(108, 114)}}
        self.assertEqual(j18, {f"K{i}.1" for i in range(108, 114)})
        self.assertEqual(vm, sorted(j18, key=lambda c: int(c[1:].split(".")[0])))
        self.assertTrue(set(vm) <= set(release))
        expected = {
            "ukai-jail/tests/macos_observe.rs::k105_events_map_to_schema_valid_audit_results_with_honest_coverage",
            "ukai-jail/tests/macos_observe.rs::j17_published_closed_set_equals_the_subscription_rows",
            "ukai-jail/src/lib.rs::platform::macos::boundary::tests::j17_synthetic_native_producer_receipts_and_strict_refusal",
            "ukai-jail/src/lib.rs::platform::macos::boundary::tests::j17_requested_attachment_failure_refuses_in_both_modes",
        }
        self.assertTrue(expected <= set(clauses["K105.2"]["tests"]))
        self.assertEqual(clauses["K105.2"]["tag"], "simulated")
        self.assertIn("loss degrades", clauses["K105.2"]["clause"])
        self.assertIn("no live ES", clauses["K105.2"]["note"])

    def test_j17_refusal_and_proxy_rows_preserve_live_gates(self):
        acceptance = tomllib.loads(read(CONTRACT + "acceptance-map.toml"))
        gates = {g["id"]: g["row"] for g in acceptance["gate"]}
        clauses = {c["id"]: c for c in acceptance["clause"]}
        for gate in ["K98", "K99"]:
            self.assertEqual(clauses[gate + ".1"]["tag"], "untested")
            self.assertEqual(clauses[gate + ".1"]["clause"], gates[gate])
        for fact in ["no entitlement", "client limit", "muted", "--profile none", "pids", "mem", "cpu",
                     "requested observation cannot attach", "both evidence modes"]:
            self.assertIn(fact, gates["K98"])
        for fact in ["Claude Code", "OpenCode", "supported proxy protocol", "HTTP CONNECT", "SOCKS5",
                     "allowed-host", "missing or invalid secret", "ungranted loopback", "binding: attempt"]:
            self.assertIn(fact, gates["K99"])

    def test_phase2_reblessed_artifacts_match_digests(self):
        frozen = tomllib.loads(read(CONTRACT + "frozen-schemas.toml"))
        artifacts = {item["file"]: item for item in frozen["frozen_artifact"]}
        self.assertTrue({"fixtures/semantic-cases.json", "examples/receipt-macos-native.json"} <= artifacts.keys())
        for item in artifacts.values():
            if item["file"] not in {"fixtures/semantic-cases.json", "examples/receipt-macos-native.json"}:
                continue
            self.assertEqual(item["sha256"], hashlib.sha256(read(CONTRACT + item["file"]).encode()).hexdigest())

    def test_r3_k112_component_clause_uses_its_linux_test_lane(self):
        acceptance = tomllib.loads(read(CONTRACT + "acceptance-map.toml"))
        clause = next(c for c in acceptance["clause"] if c["id"] == "K112.2")
        self.assertEqual(clause.get("lane", "linux"), "linux")
        self.assertRegex(read("crates/ukai-jail/tests/vm_tier.rs"),
                         r'#\[cfg\(target_os = "linux"\)\]\s+fn the_kernel_bound_key_is_a_narrowing_none_refuses')
        self.assertIn("unavailable in this build", " ".join(read("docs/specs/jail-macos.md").split()))

    def test_r3_illustration_uses_the_producer_structure_and_requirement_order(self):
        value = record("examples/receipt-macos-native.json")
        self.assertNotIn("target_process", value["lifetime"]["native"]["details"])
        self.assertEqual(value["observer"]["sources"]["wrapper"], "supported")
        # The one real value in the illustration (frozen-schemas.toml,
        # 2026-10-23: "the template digest matches the integrated Seatbelt
        # template"): computed from the template's source, never pinned as a
        # literal, so a template change cannot leave the example stale.
        self.assertEqual(value["lifetime"]["native"]["details"]["profile_digest"],
                         seatbelt_template_digest())
        for pin in ["crates/ukai-jail/tests/macos_sandbox_profile.rs",
                    "crates/ukai-jail/tests/macos_defense_matrix.rs"]:
            self.assertRegex(" ".join(read(pin).split()),
                             'const PINNED_TEMPLATE_DIGEST: &str = "' + seatbelt_template_digest() + '";')
        self.assertEqual(value["policy"]["requirements"], [
            "tree_termination", "filesystem_containment", "syscall_filter", "network_none",
            "protected_coverage:existing_and_root", "limit:wall"])
        self.assertEqual(value["lifetime"]["native"]["details"]["profile_parameters"]["path_anchors"], [])
        self.assertEqual(value["process"]["identity"]["kind"], "macos_audit_token")

    def test_r3_gc_documents_proof_refusal_and_recovery(self):
        for path in ["docs/specs/jail-macos.md", "docs/specs/jail-v1.md"]:
            with self.subTest(path=path):
                text = " ".join(read(path).split())
                for fact in ["`gc_finished`", "`exec_observed=false`", "resolving/probing",
                             "`guardian.json`", "genuinely absent", "exit 1", "reboot",
                             "only when signalling succeeds"]:
                    self.assertIn(fact, text)
        self.assertNotIn("a no-op after a later exec), records this", " ".join(read("docs/specs/jail-v1.md").split()))

    def test_r3_proxy_attribution_and_uncertain_count_are_disclosed(self):
        text = " ".join(read("docs/specs/jail-macos.md").split())
        for fact in ["as soon as the secret verifies", "proxy_unattributable",
                     "accepted connections refused before attribution", "relay capacity",
                     "upstream Unix-socket connect failure", "`lost_count`", "null observed count",
                     "not a count of proven workload events", "proxy_stopped"]:
            self.assertIn(fact, text)
        self.assertIn("proxy_unattributable", read("docs/specs/jail-v1.md"))

    def test_r3_policy_and_refusal_remediations_are_current(self):
        text = " ".join(read("docs/specs/jail-v1.md").split())
        for fact in ["top-level `lifetime_boundary`", "operator and project `[jail]`",
                     "same canonical bytes and digest", "exit 125", "host_setup",
                     "unavailable in this build", "unsupported"]:
            self.assertIn(fact, text)
        self.assertNotIn("that requirement with `--vm` remediation", text)
        self.assertNotIn("requirement, naming `--vm`", " ".join(read("docs/guide.md").split()))
        native = " ".join(read("docs/specs/jail-macos.md").split())
        self.assertIn("`es_not_entitled`", native)
        self.assertIn("`es_too_many_clients`", native)

    def test_r3_custody_headroom_and_sync_evidence_are_honest(self):
        text = " ".join(read("docs/specs/jail-macos.md").split())
        for fact in ["`PROCESS_HEADROOM=1024`", "neither inherited limit is raised",
                     "kernel read-back", "refuses", "A synchronization timeout is not a gap"]:
            self.assertIn(fact, text)

    def test_r3_observation_start_overlap_paths_and_summary_are_disclosed(self):
        text = " ".join(read("docs/specs/jail-macos.md").split("## 5.", 1)[1].split("## 6.", 1)[0].split())
        for fact in ["0 or 1", 'sequence_start: "unverified"', "unknown exact loss",
                     "not added together", "F_GETPATH", "created", "metadata changes",
                     "workspace-root", "entry counts"]:
            self.assertIn(fact, text)
        summary = read("docs/specs/jail-launch-and-summary.md")
        self.assertIn("workspace root content modified", summary)
        self.assertIn("workspace root metadata changed", summary)

    def test_r3_native_paths_and_staging_scope_are_explicit(self):
        text = " ".join(read("docs/specs/jail-macos.md").split())
        for fact in ["`profile_parameters.path_anchors`", "every ancestor", "rename, unlink and link",
                     "more than one hard link", "nested repositories created later",
                     "before acquisition", "each later confirmed target exec"]:
            self.assertIn(fact, text)

    def test_r3_doctor_rebless_notes_describe_current_readiness(self):
        notes = " ".join(read(CONTRACT + "frozen-schemas.toml").split())
        self.assertNotIn("pins every refusal-era rule", notes)
        self.assertNotIn("backend record, `ready` false", notes)
        self.assertIn("ready true", notes)

    def test_freeze_requires_a_new_reference_run(self):
        text = read("docs/RELEASING.md")
        self.assertIn("fresh reference conformance rerun on the VPS", text)
        self.assertIn("freeze --doctor <successful-run>/doctor.json", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
