"""Detector control's own negative controls; actual proc test runs on Linux."""
import contextlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock

import guest_exposure_control as control


class ControlTests(unittest.TestCase):
    def sampler(self):
        return types.SimpleNamespace(
            hits=[{'pid': 51, 'starttime': 100, 'channel': name, 'representation': 'raw', 'identity_stable': True}
                  for name in ('environment', 'argv')],
            program_counts={name: {'readable': 1} for name in ('environment', 'argv')},
            identities={(51, 100): {'supervisor'}}, source_digest='a'*64)

    def test_both_raw_channels_need_exact_stable_owned_identity(self):
        with mock.patch.object(control.guest_exposure, 'source_sha256', return_value='a'*64):
            self.assertTrue(all(control.detection_facts(self.sampler(), (51, 100)).values()))
            for field, value in [('pid', 52), ('starttime', 101), ('representation', 'base64'), ('identity_stable', False)]:
                sampler = self.sampler()
                sampler.hits[0][field] = value
                self.assertFalse(control.detection_facts(sampler, (51, 100))['environment_canary_detected'])

    def test_other_process_and_source_changes_cannot_pass(self):
        sampler = self.sampler()
        sampler.identities[(99, 200)] = {'workload_uid'}
        with mock.patch.object(control.guest_exposure, 'source_sha256', return_value='b'*64):
            facts = control.detection_facts(sampler, (51, 100))
        self.assertFalse(facts['only_owned_child_observed'])
        self.assertFalse(facts['sampler_source_unchanged'])

    def test_existing_output_refuses_before_spawning_any_control(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'control.json'
            out.write_bytes(b'prior evidence')
            with mock.patch.object(control, 'run_control') as run:
                with self.assertRaises(FileExistsError):
                    control.main(['--out', str(out)])
                run.assert_not_called()
            self.assertEqual(out.read_bytes(), b'prior evidence')

    def test_cli_writes_private_exact_report_and_marker_without_canary(self):
        report = {'schema': control.SCHEMA, 'passed': True, 'facts': {'fixture': True}}
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / 'control.json'
            stdout = io.StringIO()
            with mock.patch.object(control, 'run_control', return_value=report), contextlib.redirect_stdout(stdout):
                self.assertEqual(control.main(['--out', str(out)]), 0)
            self.assertEqual(json.loads(out.read_bytes()), report)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
            self.assertEqual(stdout.getvalue(), 'UKAI_EXPOSURE_CONTROL ' + out.read_text())
            self.assertNotIn(control.CANARY.decode(), stdout.getvalue())

    def test_failure_is_retained_and_never_claimed_as_pass(self):
        with mock.patch.object(control.sys, 'platform', 'darwin'):
            report = control.run_control()
        self.assertFalse(report['passed'])
        self.assertFalse(report['jail_execution_claimed'])
        self.assertEqual(report['errors'], ['RuntimeError'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'real process positive control needs Linux')
    def test_actual_owned_child_environment_and_argv_are_detected_and_reaped(self):
        report = control.run_control()
        self.assertTrue(report['passed'], report)
        self.assertTrue(report['facts']['owned_child_reaped'])
        self.assertNotIn(control.CANARY, json.dumps(report).encode())


if __name__ == '__main__':
    unittest.main()
