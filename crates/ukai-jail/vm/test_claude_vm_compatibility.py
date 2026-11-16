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
                 'containment': 'enforced', 'child_protection': 'enforced', 'exec_observed': True,
                 'outcome': {'kind': 'exited', 'code': 0},
                 'lifetime': {'tree_empty': True, 'integrity': 'verified'},
                 'coverage': {name: {'status': 'active', 'gaps': []} for name in harness.SUMMARY_CLASSES},
                 'credentials': [{'id': 'anthropic', 'mode': 'vault', 'never_staged': True}]}
        summary = {'lines': [{'line': 'evidence', 'facts': {'observe': 'on', 'evidence': 'strict'}},
                            {'line': 'credentials', 'facts': {'credentials': [
                                {'id': 'anthropic', 'uses': 1, 'uses_bound': 'exact'}]}}]}
        events = [{'source': 'proxy', 'operation': 'net.connect', 'stage': 'result',
                   'fields': {'credentials': ['anthropic']}},
                  {'source': 'wrapper', 'operation': 'note', 'fields': {
                      'kind': 'credential', 'credential_id': 'anthropic', 'uses_recorded': True}}]
        guest['coverage']['proxy.net']['observed_count'] = 1
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
        guest['coverage']['proxy.net']['observed_count'] = 999
        self.assertFalse(row.compatibility_facts(observed, guest, summary, events)['guest_proxy_count_matches_receipt'])
        self.assertFalse(row.compatibility_facts(observed, guest, summary, events[:1])['credential_use_recording_confirmed'])

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


class GuestJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.attempt = Path(temporary.name) / 'attempt'
        self.root = self.attempt / 'evidence/guest-journal'
        self.root.mkdir(parents=True)
        self.guest = {'attempt_id': 'att_00000000-0000-4000-8000-000000000001', 'phase': 'settled'}
        self.events = [{'attempt_id': self.guest['attempt_id'], 'source': 'proxy', 'source_seq': 1,
                        'operation': 'net.connect', 'decision': 'allow', 'stage': 'result',
                        'fields': {'credentials': ['anthropic']}}]
        self.note()
        self.write()

    def note(self):
        self.events.append({'attempt_id': self.guest['attempt_id'], 'source': 'wrapper', 'source_seq': 1,
                            'operation': 'jail.receipt', 'fields': {'phase': 'settled',
                            'receipt_digest': 'sha256:' + hashlib.sha256(row.canonical_receipt(self.guest).encode()).hexdigest()}})

    def write(self, payload=None):
        for child in self.root.iterdir():
            if child.is_file() or child.is_symlink(): child.unlink()
        raw = json.dumps(self.guest).encode()
        (self.attempt / 'evidence/jail.json').write_bytes(raw)
        self.payload = payload if payload is not None else b''.join(json.dumps(e).encode() + b'\n' for e in self.events)
        parts = [self.payload[index:index + row.JOURNAL_PART] for index in range(0, len(self.payload), row.JOURNAL_PART)]
        for index, part in enumerate(parts): (self.root / f'{index:04}.part').write_bytes(part)
        self.manifest = {'schema': 'ukai.vm.guest-journal/1', 'guest_attempt_id': self.guest['attempt_id'],
                         'guest_receipt_sha256': hashlib.sha256(raw).hexdigest(), 'state': 'exported',
                         'bytes': len(self.payload), 'parts': len(parts), 'sha256': hashlib.sha256(self.payload).hexdigest()}
        self.manifest_write()

    def manifest_write(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.manifest))

    def invalid(self):
        guest, events, info = row.verified_guest_journal(self.attempt)
        self.assertIsNone(events)
        self.assertFalse(info['verified'])
        self.assertIsInstance(guest, dict)

    def test_complete_journal_is_independently_bound_to_exact_guest_receipt(self):
        guest, events, info = row.verified_guest_journal(self.attempt)
        self.assertEqual(guest, self.guest)
        self.assertEqual(events, self.events)
        self.assertTrue(info['verified'])
        self.assertEqual(info['sha256'], hashlib.sha256(self.payload).hexdigest())
        (self.attempt / 'trace.ndjson').write_bytes(b'not guest evidence')
        self.assertEqual(row.verified_guest_journal(self.attempt)[1], self.events)

    def test_multi_part_journal_keeps_exact_events(self):
        self.events = [dict(self.events[0], source_seq=index, padding='x' * 4000) for index in range(1, 145)]
        self.note(); self.write()
        self.assertGreater(self.manifest['parts'], 1)
        self.assertEqual(row.verified_guest_journal(self.attempt)[1], self.events)

    def test_manifest_size_identity_hash_part_set_and_unexpected_keys_refuse(self):
        for key, value in [('schema', 'other'), ('guest_attempt_id', 'other'), ('guest_receipt_sha256', '0' * 64),
                           ('bytes', True), ('bytes', row.JOURNAL_MAX + 1), ('bytes', 0),
                           ('parts', True), ('parts', 33), ('sha256', '0' * 64), ('unexpected', 1)]:
            with self.subTest(key=key, value=value):
                self.write(); self.manifest[key] = value; self.manifest_write(); self.invalid()
        for mutation in ('missing', 'extra', 'changed', 'receipt'):
            with self.subTest(mutation=mutation):
                self.write()
                if mutation == 'missing': (self.root / '0000.part').unlink()
                elif mutation == 'extra': (self.root / '0001.part').write_bytes(b'extra')
                elif mutation == 'changed': (self.root / '0000.part').write_bytes(b'changed')
                else: (self.attempt / 'evidence/jail.json').write_text(json.dumps(self.guest) + ' ')
                self.invalid()

    def test_torn_foreign_duplicate_hole_and_wrong_receipt_notes_refuse(self):
        original = copy.deepcopy(self.events)
        for mutation in ('torn', 'foreign', 'duplicate', 'hole', 'no-note', 'wrong-note', 'not-settled', 'bad-ids', 'constant', 'duplicate-json'):
            with self.subTest(mutation=mutation):
                self.events = copy.deepcopy(original)
                payload = None
                if mutation == 'torn': payload = self.payload.rstrip(b'\n')
                elif mutation == 'foreign': self.events[0]['attempt_id'] = 'another'
                elif mutation == 'duplicate': self.events.insert(1, copy.deepcopy(self.events[0]))
                elif mutation == 'hole': self.events[0]['source_seq'] = 2
                elif mutation == 'no-note': self.events.pop()
                elif mutation == 'wrong-note': self.events[-1]['fields']['receipt_digest'] = 'sha256:' + '0' * 64
                elif mutation == 'not-settled': self.events[-1]['fields']['phase'] = 'running'
                elif mutation == 'bad-ids': self.events[0]['fields']['credentials'] = 'anthropic'
                elif mutation == 'constant': payload = b'{"x":NaN}\n'
                elif mutation == 'duplicate-json': payload = b'{"source":"proxy","source":"wrapper"}\n'
                self.write(payload); self.invalid()

    def test_absent_unreadable_and_over_cap_states_provide_no_events(self):
        for state, size in [('absent', None), ('unreadable', None), ('not_scanned', row.JOURNAL_MAX + 1)]:
            self.write(); (self.root / '0000.part').unlink()
            self.manifest.update(state=state, bytes=size, parts=0, sha256=None); self.manifest_write()
            self.invalid()
            self.assertEqual(row.verified_guest_journal(self.attempt)[2]['state'], state)
        shutil.rmtree(self.root)
        self.invalid()
        self.assertEqual(row.verified_guest_journal(self.attempt)[2]['state'], 'absent')

    def test_links_fifo_and_directory_replacement_are_refused(self):
        part = self.root / '0000.part'
        original = self.attempt / 'original'
        original.write_bytes(part.read_bytes())
        for kind in ('symlink', 'hardlink', 'fifo'):
            self.write(); part.unlink()
            if kind == 'symlink': part.symlink_to(original)
            elif kind == 'hardlink': os.link(original, part)
            else: os.mkfifo(part)
            self.invalid(); part.unlink()
        self.write()
        self.root.rename(self.attempt / 'outside')
        self.root.symlink_to(self.attempt / 'outside', target_is_directory=True)
        self.invalid()

    def test_canonicalization_uses_utf16_order_and_rejects_float_domain(self):
        self.assertEqual(row.canonical_receipt({'\ue000': 2, '\U00010000': 1}), '{"\U00010000":1,"\ue000":2}')
        for value in (1.25, 2 ** 64, -(2 ** 63) - 1):
            with self.assertRaises(ValueError): row.canonical_receipt(value)


if __name__ == '__main__':
    unittest.main()
