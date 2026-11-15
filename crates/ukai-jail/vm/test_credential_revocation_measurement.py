"""Independent peer/order and negative evidence controls; no VM/provider calls."""
import copy
import base64
import hashlib
import http.server
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

import credential_revocation_measurement as measurement
import harness


class PeerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / 'source'
        self.source.write_bytes(b'synthetic-private-value')
        self.witness = measurement.StreamWitness(self.source.read_bytes())
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), measurement.StreamingPeer)
        self.server.daemon_threads = True
        self.server.witness = self.witness
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.witness.stop.set()
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)

    def connect(self, header):
        stream = socket.create_connection(self.server.server_address, timeout=2)
        self.addCleanup(stream.close)
        stream.sendall(f'GET /stream HTTP/1.1\r\nHost: local\r\nx-test-token: {header}\r\n\r\n'.encode())
        return stream

    def test_source_deletion_requires_independent_substituted_header_and_stream(self):
        with self.assertRaises(harness.HarnessError): self.witness.delete_source(self.source)
        stream = self.connect('synthetic-private-value')
        self.assertTrue(self.witness.accepted.wait(2))
        self.assertTrue(self.source.exists())
        self.witness.delete_source(self.source)
        self.assertFalse(self.source.exists())
        stream.shutdown(socket.SHUT_RDWR); stream.close()
        self.assertTrue(self.witness.finished.wait(2))
        peer = self.witness.snapshot()
        self.assertLess(peer['accepted_at'], peer['deleted_at'])
        self.assertLessEqual(peer['deleted_at'], peer['disconnected_at'])
        self.assertNotIn('synthetic-private-value', json.dumps(peer))
        self.assertEqual(peer['requests'][0]['credential_matches'], True)

    def test_wrong_header_never_triggers_source_deletion(self):
        stream = self.connect('vault:placeholder:test')
        self.assertIn(b'403', stream.recv(4096))
        self.assertFalse(self.witness.accepted.is_set())
        with self.assertRaises(harness.HarnessError): self.witness.delete_source(self.source)
        self.assertTrue(self.source.exists())

    def test_script_contains_no_source_or_real_value_and_tries_after_stream(self):
        script = measurement.guest_script('192.0.2.1', 1234)
        self.assertNotIn('synthetic-private-value', script)
        self.assertNotIn(str(self.source), script)
        self.assertIn("request('/after')", script)
        self.assertIn("response.read()", script)
        self.assertIn('timeout=30', script)
        compile(script, '<guest>', 'exec')


class JudgeTests(unittest.TestCase):
    def fixture(self):
        guest_id = 'att_00000000-0000-4000-8000-000000000001'
        placeholder = f'vault:{guest_id}:test'
        observed = {'peer': {'accepted_at': 1.0, 'deleted_at': 1.1, 'disconnected_at': 1.2, 'expired': False,
                             'requests': [{'path': '/stream', 'credential_matches': True, 'at': .9}]},
                    'guest_journal': {'verified': True}, 'after_refused': True,
                    'placeholder': {'value': placeholder, 'length': len(placeholder),
                                    'sha256': hashlib.sha256(placeholder.encode()).hexdigest()},
                    'receipt_bound': True, 'host_receipt_contradictions': [], 'host_clean': True,
                    'run_exit': 0, 'tail_exit': 0, 'tail_json_exit': 0, 'tail_agrees': True,
                    'client_thread_settled': True, 'source_removed_before_stop': True,
                    'leaks': [], 'files_scanned': 5, 'output_leak': False, 'same_boot': True,
                    'disk_scan': 'clean', 'sync_exit': 0, 'stop_exit': 0}
        guest = {'attempt_id': guest_id, 'phase': 'settled', 'errors': [],
                 'policy': {'name': 'agent'},
                 'containment': 'enforced', 'child_protection': 'enforced', 'exec_observed': True,
                 'process': {'identity': {'value': {'boot_id': 'guest-boot'}}},
                 'outcome': {'kind': 'exited', 'code': 0}, 'state_cleanup': 'complete', 'cleanup_error': None,
                 'lifetime': {'tree_empty': True, 'integrity': 'verified'},
                 'credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True}],
                 'coverage': {name: {'status': 'active', 'gaps': []} for name in harness.SUMMARY_CLASSES}}
        guest['coverage']['proxy.net']['observed_count'] = 2
        events = [{'source': 'proxy', 'source_seq': 1, 'operation': 'net.connect', 'decision': 'allow',
                   'fields': {'reason': 'relayed', 'end': 'credential_revoked', 'credentials': ['test']}},
                  {'source': 'proxy', 'source_seq': 2, 'operation': 'net.connect', 'decision': 'deny',
                   'fields': {'reason': 'credential_revoked'}},
                  {'source': 'wrapper', 'operation': 'note', 'fields': {'kind': 'credential',
                   'credential_id': 'test', 'transition': 'revoked', 'uses_recorded': True}}]
        summary = {'lines': [{'line': 'credentials', 'facts': {'credentials': [
            {'id': 'test', 'uses': 1, 'uses_bound': 'exact'}]}},
            {'line': 'evidence', 'facts': {'observe': 'on', 'evidence': 'strict'}}]}
        return observed, guest, events, summary

    def test_complete_control_passes_without_qualifying_vendor_or_tls(self):
        self.assertTrue(all(measurement.judge(*self.fixture()).values()))

    def test_missing_or_reordered_independent_witness_never_passes(self):
        for patch in ({'accepted_at': None}, {'deleted_at': None}, {'disconnected_at': None},
                      {'deleted_at': .5}, {'disconnected_at': 1.05}, {'disconnected_at': 7.0},
                      {'expired': True}, {'requests': []},
                      {'requests': [{'path': '/after', 'credential_matches': True}]},
                      {'requests': [{'path': '/stream', 'credential_matches': False}]},
                      {'requests': [{'path': '/stream', 'credential_matches': True}] * 2}):
            with self.subTest(patch=patch):
                fixture = self.fixture(); fixture[0]['peer'].update(patch)
                self.assertFalse(all(measurement.judge(*fixture).values()))

    def test_proxy_revocation_end_and_subsequent_denial_are_both_required(self):
        for mutation in ('normal-end', 'wrong-denial', 'second-use', 'unconfirmed', 'missing-later', 'missing-note', 'wrong-order'):
            with self.subTest(mutation=mutation):
                fixture = self.fixture(); events = fixture[2]
                if mutation == 'normal-end': events[0]['fields']['end'] = 'upstream_closed'
                elif mutation == 'wrong-denial': events[1]['fields']['reason'] = 'host_not_allowed'
                elif mutation == 'second-use': events[1]['fields']['credentials'] = ['test']
                elif mutation == 'unconfirmed': events[1]['fields']['credentials_unconfirmed'] = ['test']
                elif mutation == 'missing-later': events.pop(1)
                elif mutation == 'missing-note': events.pop()
                else: events[1]['source_seq'] = 0
                self.assertFalse(all(measurement.judge(*fixture).values()))

    def test_unavailable_journal_false_tail_or_receipt_counts_never_pass(self):
        observed, guest, _, summary = self.fixture()
        self.assertFalse(all(measurement.judge(observed, guest, None, summary).values()))
        for target, change in [('tail', 0), ('tail', 2), ('receipt', 0), ('receipt', 3), ('bound', 'at_least')]:
            fixture = self.fixture()
            if target == 'tail': fixture[3]['lines'][0]['facts']['credentials'][0]['uses'] = change
            elif target == 'receipt': fixture[1]['coverage']['proxy.net']['observed_count'] = change
            else: fixture[3]['lines'][0]['facts']['credentials'][0]['uses_bound'] = change
            self.assertFalse(all(measurement.judge(*fixture).values()))

    def test_leak_cleanup_binding_and_settlement_failures_remain_failures(self):
        changes = {'leaks': ['private-file'], 'files_scanned': 0, 'output_leak': True,
                   'source_removed_before_stop': False, 'receipt_bound': False,
                   'host_receipt_contradictions': ['different'], 'host_clean': False,
                   'same_boot': False, 'disk_scan': 'not-scanned', 'sync_exit': 1,
                   'stop_exit': 1, 'run_exit': 1, 'tail_exit': 1, 'tail_json_exit': 1,
                   'tail_agrees': False, 'after_refused': False, 'client_thread_settled': False}
        for key, value in changes.items():
            with self.subTest(key=key):
                fixture = self.fixture(); fixture[0][key] = value
                self.assertFalse(all(measurement.judge(*fixture).values()))
        for key, value in [('phase', 'running'), ('errors', ['lost']), ('state_cleanup', 'pending'),
                           ('cleanup_error', 'failure'), ('containment', 'not_enforced'),
                           ('child_protection', 'unprotected'), ('exec_observed', False)]:
            fixture = self.fixture(); fixture[1][key] = value
            self.assertFalse(all(measurement.judge(*fixture).values()))


class RawTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def channel(self, witness, mutation=None):
        class FakeChannel:
            def __init__(self):
                self.stream = self
                self.requests = []
                self.buffer = b''
                self.closed = False
                self.emit(event='ready', schema='ukai.jail.vm-attempt/1', boot_id='service-boot')
            def emit(self, **frame): self.buffer += json.dumps(frame).encode() + b'\n'
            def settimeout(self, timeout): pass
            def recv(self, size):
                if not self.buffer: raise TimeoutError()
                block, self.buffer = self.buffer[:size], self.buffer[size:]
                return block
            def close(self): self.closed = True
            def send(self, **frame):
                self.requests.append(frame)
                if frame['op'] == 'prepare':
                    self.emit(event='prepared', kernel='test-kernel', staged_secrets=[['test', '/run/ukai-vm/credentials/test']])
                elif frame['op'] == 'run':
                    # Witness fires before the local caller has read Released.
                    witness.accepted_at = time.monotonic(); witness.accepted.set()
                    self.emit(event='released', supervisor_pid=123)
                elif frame['op'] == 'revoke_secrets':
                    if mutation != 'missing-ack':
                        self.emit(event='secrets_revoked', ids=['wrong'] if mutation == 'wrong-ack' else ['test'])
                        if mutation == 'duplicate-ack': self.emit(event='secrets_revoked', ids=['test'])
                    data = json.dumps({'attempt_id': 'guest-test', 'phase': 'settled'}).encode()
                    if mutation == 'traversal':
                        self.emit(event='file', group='evidence', path='../escape', data=base64.b64encode(b'bad').decode())
                    self.emit(event='bound_receipt', data=base64.b64encode(data).decode(),
                              sha256='bad' if mutation == 'receipt-hash' else hashlib.sha256(data).hexdigest(), binding={})
                    self.emit(event='done', exit_code=0, stop={})
        return FakeChannel()

    def probe(self, mutation=None):
        artifact = self.root / ('artifact-' + str(mutation)); artifact.mkdir()
        witness = measurement.StreamWitness(b'synthetic')
        channel = self.channel(witness, mutation)
        service = mock.Mock(connect=mock.Mock(return_value=channel))
        result = measurement.raw_attempt(service, artifact, ['/bin/true'], 'exact toml', b'synthetic', witness, '192.0.2.1:80')
        return result, channel, witness

    def test_raw_mode_stages_exact_declaration_and_secret_and_revoke_after_release_read(self):
        result, channel, witness = self.probe()
        self.assertIsNone(result['error'])
        self.assertTrue(result['revocation_ack'])
        self.assertLess(witness.accepted_at, witness.revocation_sent_at)
        self.assertEqual([frame['op'] for frame in channel.requests], ['prepare', 'run', 'revoke_secrets'])
        self.assertEqual(channel.requests[0]['launch'], {'name': 'revocation-measurement', 'toml': 'exact toml'})
        self.assertEqual(channel.requests[0]['secrets'], [{'id': 'test', 'data': base64.b64encode(b'synthetic').decode()}])
        self.assertEqual(channel.requests[-1], {'op': 'revoke_secrets', 'ids': ['test']})
        self.assertNotIn('synthetic', json.dumps(result))
        self.assertNotIn(base64.b64encode(b'synthetic').decode(), json.dumps(result))
        self.assertTrue(channel.closed)

    def test_missing_wrong_duplicate_ack_and_unbound_files_never_complete(self):
        for mutation in ('missing-ack', 'wrong-ack', 'duplicate-ack', 'receipt-hash', 'traversal'):
            with self.subTest(mutation=mutation):
                result, channel, _ = self.probe(mutation)
                self.assertIsNotNone(result['error'])
                self.assertTrue(channel.closed)
        self.assertFalse((self.root / 'escape').exists())

    def test_raw_export_refuses_links_duplicates_paths_and_oversized_files(self):
        root = self.root / 'files'; root.mkdir()
        seen = set()
        measurement.store_raw_file(root, 'evidence', 'part', b'valid', seen)
        for group, name, raw in [('evidence', 'part', b'again'), ('unknown', 'x', b'x'),
                                  ('evidence', '../escape', b'x'), ('evidence', '/escape', b'x'),
                                  ('evidence', 'a//b', b'x'), ('evidence', 'huge', b'x' * (512 * 1024 + 1))]:
            with self.assertRaises(harness.HarnessError):
                measurement.store_raw_file(root, group, name, raw, seen)
        (root / 'evidence/link').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(harness.HarnessError):
            measurement.store_raw_file(root, 'evidence', 'link/escaped', b'bad', seen)
        self.assertFalse((self.root / 'escaped').exists())

    def test_frame_partial_timeout_preserves_bytes_and_size_bound_refuses(self):
        stream = mock.Mock()
        stream.recv.side_effect = [b'{"event":', TimeoutError(), b'"ready"}\n']
        reader = measurement.BoundedFrames(mock.Mock(stream=stream))
        with self.assertRaises(TimeoutError): reader.receive(.1)
        self.assertEqual(reader.receive(.1), {'event': 'ready'})
        stream.recv.side_effect = [b'x' * (2 * 1024 * 1024 + 1)]
        with self.assertRaises(harness.HarnessError):
            measurement.BoundedFrames(mock.Mock(stream=stream)).receive(.1)

    def test_raw_flag_dispatch_is_explicit(self):
        with mock.patch.object(measurement, 'raw_main', return_value=19) as raw:
            self.assertEqual(measurement.main(['home', 'workspace', 'out', 'jail', '--raw-transport']), 19)
            self.assertTrue(raw.call_args.args[0].raw_transport)

    def raw_fixture(self):
        observed, guest, events, summary = JudgeTests().fixture()
        observed['peer'].update(deleted_at=None, revocation_sent_at=1.1)
        observed['image_binding'] = True
        guest['argv_digest'] = 'sha256:command'
        record = {'receipt_digest_ok': True, 'attempt_id': 'host-attempt', 'argv_digest': 'sha256:command',
                  'profile': 'agent', 'boot_id': 'service-boot', 'receipt': guest, 'exit_code': 0, 'error': None,
                  'revocation_ack': True, 'revocation_ack_at': 1.15, 'events': ['released', 'secrets_revoked', 'done'],
                  'binding': {'attempt_id': 'host-attempt', 'argv_digest': 'sha256:command', 'profile': 'agent',
                              'boot_id': 'service-boot', 'guest_boot_id': 'guest-boot', 'guest_attempt_id': guest['attempt_id']},
                  'guest_stop': {'boundaries': ['ukai-attempts.slice/attempt-123'], 'populated_before_kill': [],
                                 'live_before_kill': [], 'strays_killed': []}}
        return observed, guest, events, summary, record

    def test_raw_judge_binds_boot_ack_deadline_and_component_scope(self):
        facts = measurement.raw_judge(*self.raw_fixture())
        self.assertTrue(all(facts.values()), facts)
        self.assertNotIn('host_binding_and_settlement', facts)
        self.assertNotIn('source_removed_before_stop', facts)
        for mutation in ('guest-boot', 'guest-id', 'late-ack', 'early-ack', 'missing-ack', 'wrong-image', 'no-stop', 'survivor'):
            with self.subTest(mutation=mutation):
                fixture = self.raw_fixture(); observed, _, _, _, record = fixture
                if mutation == 'guest-boot': record['binding']['guest_boot_id'] = 'different'
                elif mutation == 'guest-id': record['binding']['guest_attempt_id'] = 'different'
                elif mutation == 'late-ack': record['revocation_ack_at'] = 3.2
                elif mutation == 'early-ack': record['revocation_ack_at'] = 1.0
                elif mutation == 'missing-ack': record['revocation_ack'] = False
                elif mutation == 'wrong-image': observed['image_binding'] = False
                elif mutation == 'no-stop': record['guest_stop'] = {}
                else: record['guest_stop']['live_before_kill'] = [[1, 'some-cgroup']]
                self.assertFalse(all(measurement.raw_judge(*fixture).values()))


class RefusalTests(unittest.TestCase):
    def test_installed_capability_refusal_is_preserved_and_source_removed(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        workspace = root / 'workspace'; workspace.mkdir(); harness.mark_workspace(workspace)
        home = root / 'installed'; (home / 'bin').mkdir(parents=True)
        jail = home / 'bin/ukai-jail'; jail.write_text('#!/bin/sh\n'); jail.chmod(0o755)
        scratch = root / 'scratch'; scratch.mkdir()
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if 'run' in argv:
                return subprocess.CompletedProcess(argv, 125, '', 'vm:not-measured:credential_staging')
            self.assertFalse(list(scratch.glob('ukai-revoke-source-*/token')))
            return subprocess.CompletedProcess(argv, 0, '', '')
        with mock.patch.object(measurement.subprocess, 'run', side_effect=run), \
                mock.patch.object(measurement, 'raw_main', side_effect=AssertionError('hidden raw fallback')), \
                mock.patch.object(measurement.vault_measurement, 'mac_address', return_value='127.0.0.1'), \
                mock.patch.object(tempfile, 'tempdir', str(scratch)), mock.patch('builtins.print'):
            self.assertEqual(measurement.main([str(home), str(workspace), str(root / 'out'), str(jail)]), 1)
        report = json.loads((root / 'out/credential-revocation.json').read_text())
        self.assertEqual(report['outcome'], 'REFUSED')
        self.assertFalse(report['qualified'])
        self.assertIsNone(report['observed']['peer']['deleted_at'])
        self.assertTrue(report['observed']['source_removed_before_stop'])
        self.assertFalse(any('revoke_secrets' in argument for call in calls for argument in call))


if __name__ == '__main__':
    unittest.main()
