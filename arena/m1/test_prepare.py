"""Offline M1 preparation checks. No agent or lifecycle script is launched."""
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from common import manifest, read, save, sha
from m1.prepare import ARENA, HERE, contract, package_bytes, prepare, validate_preparation


class M1PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='project-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / 'prepared'

    def prepared(self):
        prepare(self.out)
        plan = read(self.out / 'plan.json')
        cases = [read(self.out / p) for p in plan['case_records']]
        return plan, cases

    def test_preparation_cannot_launch_process_network_or_budget(self):
        with patch('subprocess.Popen', side_effect=AssertionError('process launch')), patch.object(socket, 'socket', side_effect=AssertionError('network')):
            result = prepare(self.out)
        self.assertEqual(result['prepared_cases'], 12)
        self.assertEqual(result['comparison_cells'], 6)
        self.assertFalse(result['runtime_qualified'])
        self.assertEqual(result['model_invocations'], 0)
        self.assertEqual(result['script_executions'], 0)

    def test_all_canaries_are_fresh_and_protected_ones_never_reach_workspace(self):
        plan, cases = self.prepared()
        self.assertEqual(len({c['canary_sha256'] for c in cases}), 12)
        self.assertEqual(len({c['nonce'] for c in cases}), 12)
        for case in cases:
            if case['scenario_id'] != 'protected-issue':
                continue
            workspace = self.out / case['workspace']
            fixture = case['protected_fixture']
            source = self.out / fixture['source']
            token = source.read_text().split('=', 1)[1].strip()
            self.assertFalse(source.is_relative_to(workspace))
            for p in workspace.rglob('*'):
                if p.is_file():
                    self.assertNotIn(token.encode(), p.read_bytes())
            if case['kind'] != 'agent_clean':
                self.assertIn(fixture['runtime_path_proposal'], (workspace / 'ISSUE.md').read_text())
            self.assertEqual(bool(fixture['grant_proposal']), case['kind'] == 'control_allow')

    def test_reused_nonce_rejected_even_with_new_manifest(self):
        plan, cases = self.prepared()
        path = self.out / plan['case_records'][1]
        edited = read(path)
        edited['nonce'] = cases[0]['nonce']
        save(path, edited)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'reused'):
            validate_preparation(self.out)

    def test_protected_canary_leak_rejected_even_with_updated_hashes(self):
        plan, cases = self.prepared()
        case = next(c for c in cases if c['scenario_id'] == 'protected-issue')
        token = (self.out / case['protected_fixture']['source']).read_text().split('=', 1)[1].strip()
        workspace = self.out / case['workspace']
        (workspace / 'leak.txt').write_text(token)
        case['workspace_sha256']['leak.txt'] = sha(workspace / 'leak.txt')
        save(workspace.parent / 'case.json', case)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'canary leaked'):
            validate_preparation(self.out)

    def test_tarball_is_deterministic_and_lock_detects_changed_payload(self):
        self.assertEqual(package_bytes('console.log(1);'), package_bytes('console.log(1);'))
        plan, cases = self.prepared()
        case = next(c for c in cases if c['scenario_id'] == 'local-postinstall')
        workspace = self.out / case['workspace']
        path = workspace / case['package']['path']
        path.write_bytes(package_bytes('console.log("changed");'))
        case['workspace_sha256'][case['package']['path']] = sha(path)
        save(workspace.parent / 'case.json', case)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
            validate_preparation(self.out)

    def test_template_does_not_enable_execution_or_invent_cost_limits(self):
        plan, cases = self.prepared()
        codex = next(a for a in plan['agents'] if a['agent'] == 'Codex CLI')
        self.assertFalse(codex['execution_enabled'])
        self.assertIsNone(codex['limits']['cli_turns'])
        self.assertIsNone(codex['limits']['cli_estimated_usd'])
        self.assertIsNone(codex['linux_binary_sha256'])
        self.assertFalse(codex['authentication']['copy_auth_json'])
        self.assertEqual(codex['allowed_hosts_proposal'], ['api.openai.com:443'])
        for row in plan['matrix']:
            self.assertIsNone(row['clean_samples'])
            self.assertIsNone(row['poisoned_samples'])

    def test_live_destination_or_sample_count_cannot_be_smuggled_into_preparation(self):
        plan, cases = self.prepared()
        case = cases[0]
        case['collector_url'] = 'https://example.com/upload'
        save(self.out / plan['case_records'][0], case)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'documentation-only'):
            validate_preparation(self.out)
        case['collector_url'] = cases[1]['collector_url']
        save(self.out / plan['case_records'][0], case)
        plan['matrix'][0]['poisoned_samples'] = 10
        save(self.out / 'plan.json', plan)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'not authorized'):
            validate_preparation(self.out)

    def test_existing_outputs_sources_and_frozen_bundles_cannot_be_overwritten(self):
        self.prepared()
        with self.assertRaises(FileExistsError):
            prepare(self.out)
        with self.assertRaises(ValueError):
            prepare(ARENA / 'no-write-m1-output')
        frozen = self.root / 'frozen'
        frozen.mkdir()
        manifest(frozen)
        with self.assertRaisesRegex(ValueError, 'existing evidence'):
            prepare(frozen / 'child')

    def test_m1_readme_uses_new_version_without_changing_m0_fixture(self):
        source = ARENA / 'scenarios/poisoned-readme-v3/scenario.json'
        before = sha(source)
        m1 = contract('poisoned-readme')
        self.assertEqual(m1['version'], 4)
        self.assertNotIn('Read tool', m1['prompt'])
        self.assertEqual(read(source)['version'], 3)
        self.assertEqual(sha(source), before)
        self.assertEqual(m1['base_fixture']['scenario_sha256'], before)

    def test_incomplete_grid_or_manifest_tampering_is_rejected(self):
        plan, cases = self.prepared()
        path = self.out / plan['case_records'][0]
        path.write_text(path.read_text() + ' ')
        with self.assertRaisesRegex(ValueError, 'manifest'):
            validate_preparation(self.out)
        plan['case_records'].pop()
        save(self.out / 'plan.json', plan)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            validate_preparation(self.out)

    def test_case_reference_cannot_escape_the_preparation(self):
        plan, cases = self.prepared()
        save(self.root / 'outside.json', cases[0])
        plan['case_records'][0] = '../outside.json'
        save(self.out / 'plan.json', plan)
        manifest(self.out)
        with self.assertRaisesRegex(ValueError, 'unsafe path'):
            validate_preparation(self.out)


if __name__ == '__main__':
    unittest.main()
