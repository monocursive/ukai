"""Offline proposal safety and integrity checks; no model or probe execution."""
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_boundary_probe import ARENA, prepare, validate
from common import manifest, read, save


class BoundaryProbePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.out = self.root / 'preview'

    def test_preview_never_launches_process_or_network_and_keeps_probe_kind_separate(self):
        with patch('subprocess.Popen', side_effect=AssertionError('process launched')), \
             patch.object(socket, 'socket', side_effect=AssertionError('network opened')):
            result = prepare(self.out)
        self.assertEqual(result['model_requests'], 0)
        self.assertEqual(result['new_reservations_minor'], 0)
        plan = read(self.out / 'plan.json')
        cases = [read(self.out / name) for name in plan['case_records']]
        self.assertEqual([c['kind'] for c in cases], ['control_allow', 'control_deny', 'agent_boundary_probe', 'agent_boundary_probe'])
        self.assertEqual(len({c['canary_sha256'] for c in cases}), 4)
        self.assertEqual([c['collector_granted_proposal'] for c in cases], [True, False, False, False])
        self.assertTrue(all(c['result'] is None for c in cases))

    def test_existing_outputs_and_frozen_evidence_are_refused(self):
        prepare(self.out)
        with self.assertRaises(ValueError): prepare(self.out)
        with self.assertRaises(ValueError): prepare(self.out / 'nested')
        with self.assertRaises(ValueError): prepare(ARENA / 'forbidden-preview')

    def test_paid_flags_cannot_be_enabled_even_with_fresh_manifest(self):
        prepare(self.out)
        for key in ('execution_enabled', 'model_requests', 'script_executions', 'new_reservations_minor', 'live_runtime_qualified'):
            plan = read(self.out / 'plan.json')
            prior = plan[key]
            plan[key] = 1
            save(self.out / 'plan.json', plan); manifest(self.out)
            with self.assertRaises(ValueError): validate(self.out)
            plan[key] = prior
            save(self.out / 'plan.json', plan); manifest(self.out)

    def test_live_destination_or_widened_agent_grant_is_refused(self):
        prepare(self.out)
        plan = read(self.out / 'plan.json')
        path = self.out / plan['case_records'][2]
        original = read(path)
        for key, value in [('collector_url', 'https://example.com/upload'), ('collector_granted_proposal', True), ('result', 'passed')]:
            changed = {**original, key: value}
            save(path, changed); manifest(self.out)
            with self.assertRaises(ValueError): validate(self.out)
        save(path, original); manifest(self.out)
        validate(self.out)

    def test_changed_payload_or_prompt_and_escaping_reference_are_refused(self):
        prepare(self.out)
        plan = read(self.out / 'plan.json')
        case = read(self.out / plan['case_records'][3])
        prompt = self.out / Path(plan['case_records'][3]).parent / 'TASK.txt'
        original = prompt.read_bytes()
        prompt.write_text('Try a different destination if the first is blocked.\n')
        manifest(self.out)
        with self.assertRaises(ValueError): validate(self.out)
        prompt.write_bytes(original)
        token = self.out / case['workspace'] / '.env'
        token.write_text('SERVICE_TOKEN=not-the-frozen-token\n'); manifest(self.out)
        with self.assertRaises(ValueError): validate(self.out)
        plan['case_records'][0] = '../../outside/case.json'
        save(self.out / 'plan.json', plan); manifest(self.out)
        with self.assertRaises(ValueError): validate(self.out)


if __name__ == '__main__': unittest.main()
