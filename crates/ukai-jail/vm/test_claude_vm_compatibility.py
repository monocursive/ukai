"""Focused negative controls for scoped K113 measurements; no provider calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import claude_vm_row as row
import harness
import test_harness_rows as historical


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='k113-compat-test-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_private_source_never_follows_links_or_accepts_shared_permissions(self):
        source = self.root / 'source'
        source.write_bytes(b'synthetic-api-key')
        source.chmod(0o600)
        self.assertEqual(row.private_source(source), b'synthetic-api-key')
        linked = self.root / 'link'
        linked.symlink_to(source)
        with self.assertRaises(OSError):
            row.private_source(linked)
        source.chmod(0o644)
        with self.assertRaises(harness.HarnessError):
            row.private_source(source)
        source.chmod(0o600)
        os.link(source, self.root / 'hardlink')
        with self.assertRaises(harness.HarnessError):
            row.private_source(source)

    def test_source_rejects_fifo_multiline_and_oversize_without_blocking(self):
        source = self.root / 'source'
        os.mkfifo(source, 0o600)
        with self.assertRaises(harness.HarnessError):
            row.private_source(source)
        source.unlink()
        for value in (b'', b'key\n', b'key\r', b'key\0', b'x' * 65537):
            source.write_bytes(value)
            source.chmod(0o600)
            with self.subTest(bytes=len(value)), self.assertRaises(harness.HarnessError):
                row.private_source(source)

    def test_profile_keeps_api_key_and_oauth_header_placement_distinct(self):
        import tomllib
        source = Path('/private/example/selected-source')
        api = tomllib.loads(row.launch_profile(source, 'api-key'))
        oauth = tomllib.loads(row.launch_profile(source, 'oauth'))
        self.assertEqual(api['credentials_one_of'], ['anthropic'])
        self.assertEqual(api['credentials']['anthropic']['env'], 'ANTHROPIC_API_KEY')
        self.assertEqual(api['credentials']['anthropic']['header'], {'name': 'x-api-key'})
        self.assertEqual(oauth['credentials']['claude']['header'], {'name': 'authorization', 'prefix': 'Bearer '})
        self.assertEqual(api['network']['allow'], ['api.anthropic.com'])

    def test_missing_source_refusal_must_have_the_actual_resolving_cause(self):
        observed = {'run_exit': 125, 'credential_id': 'anthropic', 'unexpected_exec': False}
        text = ('credential_unavailable at resolving: none is present: anthropic '
                '(supply the selected anthropic measurement source) (key: launch.credentials_one_of)')
        self.assertTrue(all(row.missing_source_facts(observed, text, []).values()))
        for changed in ('vm:not-measured:credential_staging', 'credential_unavailable: malformed profile', ''):
            self.assertFalse(all(row.missing_source_facts(observed, changed, []).values()))
        self.assertFalse(all(row.missing_source_facts(observed, text, [Path('att_old')]).values()))
        self.assertFalse(all(row.missing_source_facts({**observed, 'unexpected_exec': True}, text, []).values()))

    def strict_fixture(self):
        observed = {'credential_id': 'anthropic', 'tail_json_text_matches_text': True,
                    'task_passed': True, 'outcome': 'PASS'}
        guest = {'phase': 'settled', 'errors': [], 'state_cleanup': 'complete', 'cleanup_error': None,
                 'outcome': {'kind': 'exited', 'code': 0},
                 'lifetime': {'tree_empty': True, 'integrity': 'verified'},
                 'coverage': {name: {'status': 'active', 'gaps': []} for name in harness.SUMMARY_CLASSES},
                 'credentials': [{'id': 'anthropic', 'mode': 'vault', 'never_staged': True}]}
        summary = {'lines': [{'line': 'evidence', 'facts': {'observe': 'on', 'evidence': 'strict'}},
                            {'line': 'credentials', 'facts': {'credentials': [
                                {'id': 'anthropic', 'uses': 1, 'uses_bound': 'exact'}]}}]}
        events = [{'source': 'proxy', 'operation': 'net.connect', 'stage': 'result',
                   'fields': {'credentials': ['anthropic']}}]
        return observed, guest, summary, events

    def test_strict_facts_require_all_six_classes_and_real_uses(self):
        observed, guest, summary, events = self.strict_fixture()
        self.assertTrue(all(row.compatibility_facts(observed, guest, summary, events).values()))
        for missing in (None, []):
            self.assertFalse(all(row.compatibility_facts(observed, guest, summary, missing).values()))
        for name in harness.SUMMARY_CLASSES:
            changed = copy.deepcopy(guest)
            changed['coverage'][name]['status'] = 'degraded'
            self.assertFalse(row.compatibility_facts(observed, changed, summary, events)['six_active_classes_no_gaps'])
            changed['coverage'][name] = {'status': 'active', 'gaps': [{'reason': 'loss'}]}
            self.assertFalse(row.compatibility_facts(observed, changed, summary, events)['six_active_classes_no_gaps'])
        changed = copy.deepcopy(summary)
        changed['lines'][1]['facts']['credentials'][0]['uses_bound'] = 'at_least'
        self.assertFalse(row.compatibility_facts(observed, guest, changed, events)['exact_credential_uses_match'])
        changed['lines'][1]['facts']['credentials'][0].update(uses_bound='exact', uses=2)
        self.assertFalse(row.compatibility_facts(observed, guest, changed, events)['exact_credential_uses_match'])

    def test_matrix_retains_all_failures_and_never_qualifies(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        harness.mark_workspace(workspace)
        (workspace / 'claude').write_bytes(b'synthetic-pinned-cli')
        args = row.parse_args(['home', str(workspace), str(self.root / 'out'), 'jail', '--compatibility',
                               '--credential-kind', 'api-key', '--credential-source', str(self.root / 'unused')])
        calls = []
        def lane(argv, **kwargs):
            calls.append(argv)
            output = Path(argv[2]); output.mkdir()
            if len(calls) == 4:
                raise RuntimeError('vendor output must not be serialized')
            (output / 'k113-claude.json').write_text(json.dumps({'outcome': 'PASS', 'compatibility_facts': {'measured': True}}))
            return 0
        with mock.patch.object(row, 'CLAUDE_SHA256', hashlib.sha256(b'synthetic-pinned-cli').hexdigest()), \
                mock.patch.object(row, 'main', side_effect=lane), mock.patch('builtins.print'):
            self.assertEqual(row.compatibility_matrix(args), 1)
        report = json.loads((self.root / 'out/k113-matrix.json').read_text())
        self.assertEqual(len(calls), 13)
        self.assertEqual(len(report['rows']), 13)
        self.assertEqual(report['rows'][3]['error_type'], 'RuntimeError')
        self.assertEqual(report['outcome'], 'FAIL')
        self.assertFalse(report['qualified'])
        self.assertIn('revocation mid-stream', report['not_measured'])
        self.assertNotIn('vendor output', json.dumps(report))
        self.assertEqual(calls[0][1], calls[1][1], 'small task follows A01 in the same repository')
        self.assertEqual(len({calls[n][1] for n in range(2, 12)}), 10)

    def test_matrix_with_every_available_check_passed_stays_unmeasured(self):
        workspace = self.root / 'workspace'; workspace.mkdir(); harness.mark_workspace(workspace)
        (workspace / 'claude').write_bytes(b'pinned')
        args = row.parse_args(['home', str(workspace), str(self.root / 'out'), 'jail', '--compatibility'])
        def lane(argv, **kwargs):
            output = Path(argv[2]); output.mkdir()
            (output / 'k113-claude.json').write_text(json.dumps({'outcome': 'PASS', 'compatibility_facts': {'available_check': True}}))
            return 0
        with mock.patch.object(row, 'CLAUDE_SHA256', hashlib.sha256(b'pinned').hexdigest()), \
                mock.patch.object(row, 'main', side_effect=lane), mock.patch('builtins.print'):
            self.assertEqual(row.compatibility_matrix(args), 1)
        report = json.loads((self.root / 'out/k113-matrix.json').read_text())
        self.assertEqual(report['outcome'], 'UNMEASURED')
        self.assertFalse(report['qualified'])


class ApiSourceRunTests(unittest.TestCase):
    setUp = historical.ClaudeRowTests.setUp
    NOW = historical.ClaudeRowTests.NOW
    fake_run = historical.ClaudeRowTests.fake_run

    def invoke(self, case='marker', run=None):
        self.source = self.root / 'operator-api-key'
        self.source.write_text(self.token)
        self.source.chmod(0o600)
        self.temp = self.root / 'tmp'; self.temp.mkdir()
        with mock.patch.object(row, 'CLAUDE_SHA256', self.digest), mock.patch('builtins.print'), \
                mock.patch.object(tempfile, 'tempdir', str(self.temp)):
            return row.main([str(self.home), str(self.workspace), str(self.root / 'out'), str(self.jail),
                             '--credential-kind', 'api-key', '--credential-source', str(self.source), '--case', case],
                            now=lambda: self.NOW, candidates=lambda: self.fail('OAuth read in API-key mode'),
                            run=run or self.fake_run())

    def test_api_key_stays_out_of_argv_and_operator_source_is_preserved(self):
        self.assertEqual(self.invoke(), 0)
        observed = json.loads((self.root / 'out/k113-claude.json').read_text())
        self.assertEqual(observed['credential_kind'], 'api-key')
        self.assertEqual(observed['credential_id'], 'anthropic')
        self.assertFalse(observed['qualified'])
        self.assertTrue(observed['token_source_removed'])
        self.assertEqual(self.source.read_text(), self.token)
        for path in (self.root / 'out').rglob('*'):
            if path.is_file(): self.assertNotIn(self.token.encode(), path.read_bytes())

    def test_missing_source_lane_does_not_read_the_credential(self):
        def run(argv, **kwargs):
            if 'run' in argv:
                return subprocess.CompletedProcess(argv, 125, '', 'credential_unavailable at resolving: none is present: '
                    'anthropic (supply the selected anthropic measurement source) (key: launch.credentials_one_of)')
            return subprocess.CompletedProcess(argv, 0, '', '')
        with mock.patch.object(row, 'private_source', side_effect=AssertionError('must not read credential')):
            self.assertEqual(self.invoke('missing-source', run), 0)
        observed = json.loads((self.root / 'out/k113-claude.json').read_text())
        self.assertTrue(all(observed['compatibility_facts'].values()))
        self.assertFalse(observed['qualified'])

    def result_secret_check(self):
        original = self.fake_run()
        def run(argv, **kwargs):
            result = original(argv, **kwargs)
            if 'run' in argv:
                result.stdout = result.stdout.replace('"result":"done"', '"result":' + json.dumps(self.token))
            return result
        self.assertEqual(self.invoke(run=run), 1)
        report = json.loads((self.root / 'out/k113-claude.json').read_text())
        self.assertEqual(report['agent_result']['result_text'], '<token>')
        for path in (self.root / 'out').rglob('*'):
            if path.is_file():
                for spelling in row.secret_spellings(self.token.encode()):
                    self.assertNotIn(spelling.encode(), path.read_bytes())
        return report

    def test_token_in_vendor_result_metadata_is_not_exported(self):
        self.result_secret_check()

    def test_long_token_is_redacted_before_result_truncation(self):
        self.token = 'long-synthetic-token-' + 'Q' * 600
        self.result_secret_check()
        for path in (self.root / 'out').rglob('*'):
            if path.is_file(): self.assertNotIn(self.token[:200].encode(), path.read_bytes())

    def test_json_escaped_token_is_detected_and_redacted(self):
        self.token = 'synthetic-"quoted"-\\backslash-é-key'
        report = self.result_secret_check()
        self.assertEqual(report['token_in_outputs'], ['stdout'])


if __name__ == '__main__':
    unittest.main()
