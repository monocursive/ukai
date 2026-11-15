"""Negative controls over a retained real guest measurement, without booting."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import execution_boundary_measurement as measurement

ROOT = Path(__file__).resolve().parents[3]
RECORD = ROOT / 'docs/benchmarks/jail/results/macos-vm-probes-2026-11-04/capabilities.json'


class ExecutionBoundaryMeasurementTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads(RECORD.read_text())

    def test_retained_real_resource_and_tree_controls_satisfy_the_derived_claim(self):
        facts, passed = measurement.judge(self.record)
        self.assertTrue(passed, [key for key, value in facts.items() if not value])

    def test_missing_boot_identity_and_mixed_boots_cannot_be_combined(self):
        for mutate in (
            lambda r: r['status'].pop('boot_id'),
            lambda r: r['results']['pids']['binding'].update(guest_boot_id='another-guest'),
            lambda r: r['results']['pids'].update(boot_id='another-service'),
            lambda r: r['status'].update(disk_sha256=''),
            lambda r: r['binary'].update(sha256='not-a-digest'),
        ):
            with self.subTest(mutate=mutate):
                record = copy.deepcopy(self.record)
                mutate(record)
                self.assertFalse(measurement.judge(record)[1])

    def test_each_attempt_requires_its_own_bound_receipt_and_clean_boundary(self):
        for name in measurement.ATTEMPTS:
            mutations = (
                lambda r: r.update(receipt_digest_ok=False),
                lambda r: r['binding'].update(attempt_id='another-attempt'),
                lambda r: r['receipt'].update(phase='running'),
                lambda r: r['receipt'].update(containment='not_enforced'),
                lambda r: r['receipt'].update(child_protection='not_enforced'),
                lambda r: r['receipt'].update(state_cleanup='pending'),
                lambda r: r['receipt'].update(cleanup_error='cleanup failed'),
                lambda r: r['receipt'].update(errors=[{'code': 'evidence_lost'}]),
                lambda r: r['receipt']['policy'].update(requirements=[]),
                lambda r: r['receipt']['lifetime'].update(tree_empty=False),
                lambda r: r['receipt']['lifetime'].update(integrity='unknown'),
                lambda r: r['receipt']['lifetime'].update(verification_scope='unknown'),
                lambda r: r['receipt']['lifetime']['native']['details']['execution_cgroup'].update(
                    path='/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/../other'),
                lambda r: r['guest_stop'].update(boundaries=[]),
                lambda r: r['guest_stop'].update(live_before_kill=[[99, 'workload']]),
                lambda r: r['guest_stop'].update(strays_killed=[[99, 'workload']]),
                lambda r: r.update(started_at='yesterday'),
            )
            for mutate in mutations:
                with self.subTest(attempt=name, mutate=mutate):
                    record = copy.deepcopy(self.record)
                    mutate(record['results'][name])
                    self.assertFalse(measurement.judge(record)[1])

    def test_pass_labels_cannot_replace_raw_resource_and_descendant_controls(self):
        for name in ('pids', 'mem', 'tree_termination', 'tree_wall'):
            with self.subTest(attempt=name):
                record = copy.deepcopy(self.record)
                record['results'][name]['stdout'] = ''
                self.assertFalse(measurement.judge(record)[1])
        record = copy.deepcopy(self.record)
        record['tree_watch']['tree_wall']['settled_to']['normal'] += 1
        self.assertFalse(measurement.judge(record)[1])

    def test_reusing_one_execution_cgroup_does_not_pass_for_distinct_attempts(self):
        record = copy.deepcopy(self.record)
        paths = [record['results'][name]['receipt']['lifetime']['native']['details']['execution_cgroup']
                 for name in measurement.ATTEMPTS]
        paths[1]['path'] = paths[0]['path']
        self.assertFalse(measurement.judge(record)[1])

    def test_shared_conditions_and_malformed_evidence_refuse(self):
        for record in ({}, {'schema': 'ukai.vm.capabilities/2', 'results': []}):
            self.assertFalse(measurement.judge(record)[1])
        for field in ('service_exit', 'summary'):
            record = copy.deepcopy(self.record)
            record[field] = 1 if field == 'service_exit' else {'git_config_untouched': False}
            self.assertFalse(measurement.judge(record)[1])

    def test_output_binds_original_bytes_without_promoting_client_capabilities(self):
        runtime = ROOT / 'crates/ukai-jail/src/platform/macos/vm.rs'
        before = runtime.read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / 'measurement'
            self.assertEqual(measurement.main(['--record', str(RECORD), '--out', str(out)]), 0)
            report = json.loads((out / 'execution-boundary.json').read_text())
            self.assertEqual(report['source_record_sha256'], hashlib.sha256(RECORD.read_bytes()).hexdigest())
            self.assertEqual(len(report['measurements']['execution_boundary']['attempt_ids']), 4)
            self.assertIn('no client capability promotion', report['scope'])
            with self.assertRaises(measurement.harness.HarnessError):
                measurement.main(['--record', str(RECORD), '--out', str(out)])
        self.assertEqual(runtime.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
