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


class NativeModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'installed'; (self.home / 'bin').mkdir(parents=True)
        self.image = self.home / 'image'; self.image.mkdir()
        self.jail = self.home / 'bin/ukai-jail'
        self.jail.write_bytes(b'fake-client'); self.jail.chmod(0o755)
        (self.home / 'bin/ukai-vm').write_bytes(b'fake-service')
        profile = Path(row.__file__).resolve().parents[1] / 'profiles/launch/claude.toml'
        self.catalog = json.loads((Path(row.__file__).parent / 'fixtures/guest-program-catalog.json').read_bytes())
        entry = self.catalog['entries'][0]
        root = f'/opt/ukai/programs/claude/{row.CLAUDE_VERSION}'
        entry.update(id='claude-' + row.CLAUDE_VERSION, alias='claude', version=row.CLAUDE_VERSION,
                     executable=root + '/claude', install_root=root, argv_prefix=[root + '/claude'],
                     executable_sha256=row.CLAUDE_SHA256,
                     guest_jail_sha256=row.NATIVE_GUEST_JAIL_SHA256,
                     profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest())
        entry['tree'][1]['path'] = 'claude'
        self.catalog_bytes = json.dumps(self.catalog).encode()
        (self.image / 'guest-program-catalog.json').write_bytes(self.catalog_bytes)
        self.metadata = {'guest_program_catalog_sha256': hashlib.sha256(self.catalog_bytes).hexdigest(),
                         'ukai_vm_sha256': hashlib.sha256(b'fake-service').hexdigest(),
                         'ukai_jail_sha256': hashlib.sha256(b'fake-client').hexdigest()}
        self.metadata['source_sha256'] = {'guest_exposure.py': hashlib.sha256(Path(row.__file__).with_name('guest_exposure.py').read_bytes()).hexdigest()}
        self.metadata['source_sha256']['guest_exposure_control.py'] = hashlib.sha256(Path(row.__file__).with_name('guest_exposure_control.py').read_bytes()).hexdigest()
        read_counts = {'readable': 1, 'unreadable': 0, 'oversize': 0, 'vanished': 0, 'unstable': 0, 'capped': 0}
        control = {'schema': 'ukai.vm.sampled-exposure-control/1', 'passed': True,
            'scope': 'owned-public-canary-process-detector-control', 'actual_values_retained': False,
            'jail_execution_claimed': False, 'errors': [],
            'facts': {key: True for key in ('environment_canary_detected', 'argv_canary_detected',
                'verified_program_environment_read', 'verified_program_argv_read', 'only_owned_child_observed',
                'sampler_source_unchanged', 'owned_child_reaped')},
            'sampler_sha256': self.metadata['source_sha256']['guest_exposure.py'],
            'control_source_sha256': self.metadata['source_sha256']['guest_exposure_control.py'],
            'guest_boot_id': 'bootstrap-fixture', 'guest_kernel': '7.0.0-fixture',
            'process': {'pid': 11, 'starttime': 100, 'executable_dev': 1, 'executable_ino': 101},
            'sampling': {'ticks': 1, 'verified_program_reads': {channel: dict(read_counts) for channel in ('environment', 'argv')},
                         'scan_errors': {}}}
        self.metadata['guest_exposure_control'] = control
        self.metadata['guest_exposure_control_sha256'] = hashlib.sha256((json.dumps(control, sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()
        self.metadata.update(jail_archive_sha256='1' * 64, jail_candidate={
            'kind': 'signed-local-candidate', 'signature_verified': True, 'verifier': 'publish_release.check',
            'trusted_key_sha256': hashlib.sha256((profile.parents[2] / 'dist/release.pub').read_bytes()).hexdigest(),
            'target': 'aarch64-unknown-linux-gnu', 'binary_sha256': row.NATIVE_GUEST_JAIL_SHA256,
            'source_revision': row.NATIVE_GUEST_REVISION, 'build_inputs': row.NATIVE_GUEST_INPUTS,
            'archive_sha256': '1' * 64, 'version': {'component': 'ukai-jail', 'version': '0.1.0', 'frozen': True,
                'build': {'revision': row.NATIVE_GUEST_REVISION, 'inputs': row.NATIVE_GUEST_INPUTS, 'dirty': False,
                          'debug_assertions': False, 'opt_level': '3', 'target': 'aarch64-unknown-linux-gnu',
                          'rustc': 'rustc 1.98.1 (fixture)'}}})
        (self.image / 'image.json').write_text(json.dumps(self.metadata))
        self.workspace = self.root / 'workspace'; self.workspace.mkdir(); harness.mark_workspace(self.workspace)
        self.out = self.root / 'out'

    def args(self, *extra):
        return [str(self.home), str(self.workspace), str(self.out), str(self.jail), *extra]

    def test_mode_is_explicit_and_never_discovers_operator_credentials(self):
        self.assertEqual(row.parse_args(self.args()).execution_mode, 'workspace-literal')
        with mock.patch('sys.stderr'), self.assertRaises(SystemExit):
            row.parse_args(self.args('--execution-mode', 'guest-native'))
        args = row.parse_args(self.args('--execution-mode', 'guest-native', '--case', 'missing-source'))
        self.assertIsNone(args.credential_source)
        with mock.patch('sys.stderr'), self.assertRaises(SystemExit):
            row.parse_args(self.args('--execution-mode', 'guest-native', '--case', 'missing-source', '--compatibility'))

    def test_installed_catalog_must_match_profile_vendor_and_installed_binaries(self):
        context = row.native_context(self.home, self.jail)
        self.assertEqual(context['entry']['alias'], 'claude')
        self.assertEqual(context['profile']['credentials_one_of'], ['claude-oauth', 'anthropic'])
        (self.home / 'bin/ukai-vm').write_bytes(b'different')
        with self.assertRaises(harness.HarnessError): row.native_context(self.home, self.jail)
        (self.home / 'bin/ukai-vm').write_bytes(b'fake-service')
        self.catalog['entries'][0]['profile_sha256'] = '0' * 64
        data = json.dumps(self.catalog).encode()
        (self.image / 'guest-program-catalog.json').write_bytes(data)
        self.metadata['guest_program_catalog_sha256'] = hashlib.sha256(data).hexdigest()
        (self.image / 'image.json').write_text(json.dumps(self.metadata))
        with self.assertRaises(harness.HarnessError): row.native_context(self.home, self.jail)

    def test_native_command_is_direct_with_explicit_attempt_state(self):
        command, suffix = row.native_argv(self.jail, self.workspace, 'small-task')
        self.assertEqual(command[command.index('--') + 1:], suffix)
        self.assertEqual(command[command.index('--state') + 1], 'attempt')
        self.assertEqual(command[command.index('--launch') + 1], 'claude')
        self.assertIn('--from-path', command)
        self.assertNotIn('/bin/sh', command)
        self.assertNotIn('./claude', command)
        self.assertNotIn('&&', ' '.join(command))

    def test_catalog_cannot_choose_a_different_self_consistent_guest_artifact(self):
        original = copy.deepcopy(self.metadata)
        changes = [('binary_sha256', 'a' * 64), ('source_revision', 'b' * 40),
                   ('build_inputs', 'sha256:' + 'c' * 64), ('signature_verified', 1),
                   ('archive_sha256', '2' * 64), ('trusted_key_sha256', '3' * 64)]
        for key, value in changes:
            self.metadata = copy.deepcopy(original); self.metadata['jail_candidate'][key] = value
            (self.image / 'image.json').write_text(json.dumps(self.metadata))
            with self.subTest(key=key), self.assertRaises(harness.HarnessError):
                row.native_context(self.home, self.jail)
        self.metadata = copy.deepcopy(original)
        self.catalog['entries'][0]['guest_jail_sha256'] = self.metadata['jail_candidate']['binary_sha256'] = 'a' * 64
        data = json.dumps(self.catalog).encode()
        (self.image / 'guest-program-catalog.json').write_bytes(data)
        self.metadata['guest_program_catalog_sha256'] = hashlib.sha256(data).hexdigest()
        (self.image / 'image.json').write_text(json.dumps(self.metadata))
        with self.assertRaises(harness.HarnessError): row.native_context(self.home, self.jail)

    def test_image_control_requires_all_facts_positive_reads_and_source_pins(self):
        original = copy.deepcopy(self.metadata)
        mutations = [lambda c: c['facts'].update(environment_canary_detected=False),
                     lambda c: c['facts'].update(owned_child_reaped=1),
                     lambda c: c['sampling']['verified_program_reads']['argv'].update(readable=0),
                     lambda c: c.update(sampler_sha256='0' * 64), lambda c: c.update(control_source_sha256='0' * 64),
                     lambda c: c.update(jail_execution_claimed=True)]
        for mutate in mutations:
            metadata = copy.deepcopy(original); mutate(metadata['guest_exposure_control'])
            metadata['guest_exposure_control_sha256'] = hashlib.sha256((json.dumps(metadata['guest_exposure_control'], sort_keys=True, separators=(',', ':')) + '\n').encode()).hexdigest()
            with self.subTest(mutate=mutate), self.assertRaises(harness.HarnessError): row.native_exposure_control(metadata)

    def missing_text(self):
        profile = row.native_context(self.home, self.jail)['profile']
        return ('credential_unavailable at resolving: none is present: launch.credentials_one_of '
                + ' '.join(name + ' ' + profile['credentials'][name]['hint'] for name in profile['credentials_one_of']))

    def test_missing_source_requires_both_unchanged_hints_and_actual_cause(self):
        profile = row.native_context(self.home, self.jail)['profile']
        text = self.missing_text()
        self.assertTrue(all(row.native_missing_source_facts({'run_exit': 125}, text, [], profile).values()))
        for changed in (text.replace(profile['credentials']['anthropic']['hint'], ''),
                        text.replace('credential_unavailable', ''), text + ' vm:not-measured:credential_staging'):
            self.assertFalse(all(row.native_missing_source_facts({'run_exit': 125}, changed, [], profile).values()))
        self.assertFalse(all(row.native_missing_source_facts({'run_exit': True}, text, [], profile).values()))
        self.assertFalse(all(row.native_missing_source_facts({'run_exit': 125}, text, [Path('att_early')], profile).values()))

    def test_missing_native_source_executes_no_workspace_binary_or_override(self):
        calls = []
        def fake(command, **options):
            calls.append(command)
            config = Path(options['env']['UKAI_CONFIG_DIR'])
            data = Path(options['env']['UKAI_DATA_DIR'])
            self.addCleanup(shutil.rmtree, data, True)
            self.assertFalse((config / 'launch').exists())
            self.assertEqual(list((config / 'credentials').iterdir()), [])
            self.assertEqual(options['stdin'], subprocess.DEVNULL)
            return subprocess.CompletedProcess(command, 125, '', self.missing_text())
        with mock.patch.object(row, 'credential_candidates', side_effect=AssertionError('must not read credentials')):
            code = row.main(self.args('--execution-mode', 'guest-native', '--case', 'missing-source'), run=fake)
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        report = json.loads((self.out / 'k113-native.json').read_bytes())
        self.assertEqual(report['outcome'], 'PASS')
        self.assertEqual(report['compatibility_outcome'], 'UNMEASURED')
        self.assertFalse(report['qualified'])

    def test_selected_source_is_private_no_override_and_removed_on_refusal(self):
        source = self.root / 'operator-source'; source.write_bytes(b'synthetic-native-secret'); source.chmod(0o600)
        configs = []
        def fake(command, **options):
            config = Path(options['env']['UKAI_CONFIG_DIR']); configs.append(config)
            self.addCleanup(shutil.rmtree, Path(options['env']['UKAI_DATA_DIR']), True)
            self.assertFalse((config / 'launch').exists())
            selected = config / 'credentials/anthropic'
            self.assertEqual(list((config / 'credentials').iterdir()), [selected])
            self.assertEqual(selected.stat().st_mode & 0o777, 0o600)
            self.assertEqual(selected.read_bytes(), source.read_bytes())
            self.assertNotIn(source.read_text(), ' '.join(command))
            return subprocess.CompletedProcess(command, 125, '', 'vm:not-measured:guest-native')
        code = row.main(self.args('--execution-mode', 'guest-native', '--credential-kind', 'api-key',
                                 '--credential-source', str(source)), run=fake)
        self.assertEqual(code, 1)
        self.assertEqual(source.read_bytes(), b'synthetic-native-secret')
        self.assertTrue(all(not config.exists() for config in configs))
        self.assertNotIn(source.read_bytes(), (self.out / 'k113-native.json').read_bytes())

    def test_native_grants_and_binding_are_exact(self):
        context = row.native_context(self.home, self.jail)
        observed, guest, summary, events = CompatibilityTests.strict_fixture(self)
        _, suffix = row.native_argv(self.jail, self.workspace, 'a01')
        guest.update(outcome={'kind': 'exited', 'code': 0, 'signal': None, 'cause': None, 'error': None})
        guest.update(jail={'component': 'ukai-jail', 'version': '0.1.0', 'backend': 'bubblewrap'},
                     platform={'os': 'linux', 'arch': 'aarch64', 'kernel': 'Linux 7.0.0-fixture'})
        entry = context['entry']; resolved = harness.argv_digest(entry['argv_prefix'] + suffix)
        guest['argv_digest'] = resolved
        guest['policy'] = {'digest': 'sha256:' + 'b' * 64, 'grants': [
            {'kind': 'read_only', 'value': entry['install_root'], 'by': 'program_resolution'},
            {'kind': 'allow_host', 'value': 'api.anthropic.com:443', 'by': 'operator'},
            {'kind': 'allow_host', 'value': 'platform.claude.com:443', 'by': 'operator'}]}
        observed.update(independent_summary={'outcome': 'PASS', 'scope': 'bound_guest', 'sampling': {
                            'state': 'complete', 'verified_program_observed': True, 'no_hits': True, 'scan_errors': {},
                            'sampler_sha256': self.metadata['source_sha256']['guest_exposure.py'], 'last_ns': 100,
                            'lifecycle': {'stop_reason': 'supervisor_exit', 'supervisor_exit_observed_ns': 110, 'stopped_ns': 120}}}, run_exit=0,
                        tail_exit=0, tail_json_exit=0, source_removed_before_stop=True, stop_exit=0,
                        service_shutdown={'complete': True}, leaks=[], files_scanned=5, output_leaks=[],
                        installed_identity_unchanged=True, agent_result={'subtype': 'success', 'is_error': False})
        native = {'catalog_sha256': context['catalog_sha256'], 'entry_id': entry['id'],
                  'profile_sha256': entry['profile_sha256'], 'executable_sha256': entry['executable_sha256'],
                  'selected_credential_id': 'anthropic', 'state': 'attempt',
                  'request_argv_digest': harness.argv_digest(['claude', *suffix]), 'resolved_argv_digest': resolved,
                  'policy_digest': guest['policy']['digest']}
        host = copy.deepcopy(guest)
        host.update(credentials=[{'id': 'anthropic', 'mode': 'vault', 'never_staged': True,
                                 'digest': None, 'digest_unavailable_reason': 'never_staged'}], state_cleanup='not_needed')
        def facts(g=guest, b=native, h=host): return row.native_facts(observed, g, events, summary, context, suffix, {'native_program': b}, h)
        self.assertTrue(all(facts().values()), facts())
        for key in native:
            changed = dict(native); changed[key] = 'wrong'
            self.assertFalse(all(facts(b=changed).values()), key)
        for mutation in ('wrong-root', 'operator-grant', 'extra-grant', 'missing-grant'):
            changed = copy.deepcopy(guest)
            if mutation == 'wrong-root': changed['policy']['grants'][0]['value'] = '/tmp/workspace'
            elif mutation == 'operator-grant': changed['policy']['grants'][0]['by'] = 'operator'
            elif mutation == 'extra-grant': changed['policy']['grants'].append({'kind': 'read_only', 'value': '/', 'by': 'operator'})
            else: changed['policy']['grants'].pop()
            self.assertFalse(all(facts(g=changed).values()), mutation)
        for value in (True, 0.0, '0'):
            changed = copy.deepcopy(guest); changed['outcome']['code'] = value
            self.assertFalse(all(facts(g=changed).values()))
        for key, value in [('version', '0.2.0'), ('component', 'other'), ('backend', 'none')]:
            changed = copy.deepcopy(guest); changed['jail'][key] = value
            self.assertFalse(all(facts(g=changed).values()), key)
        for key, value in [('phase', 'prepared'), ('errors', ['tree_unknown']), ('exec_observed', False),
                           ('credentials', [{'id': 'pending-source'}]), ('vendor_state', {'pending': True})]:
            changed = copy.deepcopy(host); changed[key] = value
            self.assertFalse(all(facts(h=changed).values()), key)
        changed = copy.deepcopy(host); changed['credentials'][0]['never_staged'] = 1
        self.assertFalse(all(facts(h=changed).values()))
        sample = observed['independent_summary']['sampling']
        for key, value in [('state', 'incomplete'), ('state', 'unavailable'), ('state', 'invalid'), ('no_hits', False),
                           ('verified_program_observed', False), ('scan_errors', {'unreadable': 1}), ('sampler_sha256', '0' * 64)]:
            prior = sample[key]; sample[key] = value
            self.assertFalse(all(facts().values()), (key, value))
            sample[key] = prior

    def test_native_matrix_never_requires_workspace_cli_and_retains_all_failures(self):
        source = self.root / 'not-read'
        args = row.parse_args(self.args('--execution-mode', 'guest-native', '--compatibility',
                                       '--credential-source', str(source)))
        calls = []
        def lane(argv, **kwargs):
            calls.append(argv)
            self.assertIn('guest-native', argv)
            self.assertFalse((Path(argv[1]) / 'claude').exists())
            if len(calls) == 3: raise RuntimeError('unsafe detail')
            output = Path(argv[2]); output.mkdir()
            (output / 'k113-native.json').write_text(json.dumps({'outcome': 'PASS', 'facts': {'available': True}}))
            return 0
        with mock.patch.object(row, 'main', side_effect=lane): self.assertEqual(row.native_matrix(args), 1)
        report = json.loads((self.out / 'k113-native-matrix.json').read_bytes())
        self.assertEqual(len(calls), 13)
        self.assertEqual(calls[0][1], calls[1][1])
        self.assertEqual(report['rows'][2]['error_type'], 'RuntimeError')
        self.assertEqual(report['outcome'], 'FAIL')
        self.assertFalse(report['qualified'])
        self.assertNotIn('unsafe detail', json.dumps(report))

    def test_native_retained_roundtrip_and_bad_summary_with_real_independent_checker(self):
        import base64
        import credential_revocation_measurement as lifecycle
        from test_vm_summary_check import Fixture, HOST_ID, install_exposure
        source = self.root / 'source'; source.write_bytes(b'synthetic-native-token'); source.chmod(0o600)
        context = row.native_context(self.home, self.jail)
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt):
                self.out = self.root / ('out-bad' if corrupt else 'out-good')
                fixtures = {}
                def fake(command, **options):
                    data = Path(options['env']['UKAI_DATA_DIR'])
                    self.addCleanup(shutil.rmtree, data, True)
                    config = Path(options['env']['UKAI_CONFIG_DIR'])
                    if 'run' in command:
                        suffix = command[command.index('--') + 1:]
                        fixture = Fixture(data / 'attempts' / HOST_ID); fixtures['current'] = fixture
                        entry = context['entry']; policy_digest = fixture.guest['policy']['digest']
                        resolved = harness.argv_digest(entry['argv_prefix'] + suffix)
                        native = {'catalog_sha256': context['catalog_sha256'], 'entry_id': entry['id'],
                                  'profile_sha256': entry['profile_sha256'], 'executable_sha256': entry['executable_sha256'],
                                  'selected_credential_id': 'anthropic', 'state': 'attempt',
                                  'request_argv_digest': harness.argv_digest(['claude', *suffix]),
                                  'resolved_argv_digest': resolved, 'policy_digest': policy_digest}
                        fixture.binding.update(native_program=native, argv_digest=resolved)
                        fixture.guest['argv_digest'] = fixture.host['argv_digest'] = resolved
                        fixture.guest['credentials'][0]['id'] = 'anthropic'
                        fixture.guest['jail'] = {'component': 'ukai-jail', 'version': '0.1.0', 'backend': 'bubblewrap'}
                        fixture.host['credentials'] = [{'id': 'anthropic', 'mode': 'vault', 'never_staged': True,
                                                        'digest': None, 'digest_unavailable_reason': 'never_staged'}]
                        fixture.events[0]['fields']['credential_id'] = 'anthropic'
                        fixture.events[2]['fields']['credentials'] = ['anthropic']
                        fixture.guest['policy']['grants'] = [
                            {'kind': 'read_only', 'value': entry['install_root'], 'by': 'program_resolution'},
                            {'kind': 'allow_host', 'value': 'api.anthropic.com:443', 'by': 'operator'},
                            {'kind': 'allow_host', 'value': 'platform.claude.com:443', 'by': 'operator'}]
                        intent = {key: value for key, value in native.items() if key not in ('executable_sha256', 'policy_digest')}
                        intent.update(schema='ukai.vm.guest-native-launch/1', launch_name='claude',
                                      expected_policy_digest=policy_digest,
                                      argv_suffix=[base64.b64encode(word.encode()).decode() for word in suffix])
                        fixture.transport['native_program'] = intent
                        fixture.transport['image']['guest_program_catalog_sha256'] = context['catalog_sha256']
                        (fixture.root / 'guest-native-catalog.json').write_bytes(self.catalog_bytes)
                        fixture.write()
                        install_exposure(fixture)
                        (self.workspace / 'k113-marker.txt').write_text('contained\n')
                        (data / 'vm').mkdir(); (data / 'vm/serve.lock').touch()
                        return subprocess.CompletedProcess(command, 0, '{"type":"result","subtype":"success","is_error":false,"result":"done"}\n', '')
                    if 'tail' in command:
                        summary, text = fixtures['current'].expected()
                        credential = next(line for line in summary['lines'] if line['line'] == 'credentials')
                        credential['text'] = credential['text'].replace('credential test:', 'credential anthropic:')
                        credential['facts']['credentials'][0]['id'] = 'anthropic'
                        text = text.replace('credential test:', 'credential anthropic:')
                        if corrupt: summary['lines'][1]['facts']['opened_for_writing'] = 999
                        return subprocess.CompletedProcess(command, 0, json.dumps(summary) if '--json' in command else text, '')
                    self.assertEqual(command[-1], 'stop')
                    self.assertFalse((config / 'credentials/anthropic').exists())
                    return subprocess.CompletedProcess(command, 0, '', '')
                with mock.patch.object(lifecycle, 'running_service_lock', side_effect=lambda data: (data / 'vm/serve.lock').open('rb')), \
                     mock.patch.object(lifecycle, 'stopped_service_lock', return_value={'complete': True}):
                    code = row.main(self.args('--execution-mode', 'guest-native', '--credential-kind', 'api-key',
                                             '--credential-source', str(source)), run=fake)
                report = json.loads((self.out / 'k113-native.json').read_bytes())
                self.assertEqual(code, 1 if corrupt else 0, report)
                self.assertEqual(report['outcome'], 'FAIL' if corrupt else 'PASS')
                self.assertFalse(report['qualified'])
                if not corrupt:
                    self.assertEqual(report['retained_summary']['scope'], 'bound_guest')
                    inputs = (self.out / 'native-inputs.json').read_bytes()
                    self.assertEqual(hashlib.sha256(inputs).hexdigest(), report['inputs_sha256'])
                    self.assertNotIn(source.read_bytes(), inputs)
                    self.assertTrue(all(report['facts'].values()), report['facts'])


if __name__ == '__main__':
    unittest.main()
