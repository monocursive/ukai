"""Synthetic controls and replay mutations; no VM, provider or operator source."""
import base64
import copy
import contextlib
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import tomllib
import unittest
from unittest import mock

import guest
import harness
import program_binding_measurement as measurement
import vm_summary_check as summary_check
from test_vm_summary_check import Fixture, GUEST_ID, encoded, canonical_hash, frame


def stop():
    return {'boundaries': ['ukai-attempts.slice/attempt-1'], 'populated_before_kill': [],
            'live_before_kill': [], 'strays_killed': []}


def write_artifact(root, receipt, events, binding):
    directory = root / 'evidence/guest-journal'; directory.mkdir(parents=True, exist_ok=True)
    raw = encoded(receipt); digest = hashlib.sha256(raw).hexdigest()
    final = {'source': 'wrapper', 'source_seq': 2, 'operation': 'jail.receipt', 'attempt_id': receipt['attempt_id'],
             'fields': {'phase': 'settled', 'receipt_digest': canonical_hash(receipt)}}
    trace = b''.join(encoded(event) for event in [*events, final])
    (root / 'evidence/jail.json').write_bytes(raw)
    (root / 'evidence/vm-binding.json').write_bytes(encoded(binding))
    (directory / '0000.part').write_bytes(trace)
    manifest = {'schema': 'ukai.vm.guest-journal/1', 'guest_attempt_id': receipt['attempt_id'],
                'guest_receipt_sha256': digest, 'state': 'exported', 'bytes': len(trace), 'parts': 1,
                'sha256': hashlib.sha256(trace).hexdigest()}
    (directory / 'manifest.json').write_bytes(encoded(manifest))
    return raw, trace, manifest


class ComponentFixture:
    """Hand-stated execution evidence; renderer fixture only supplies receipt shape."""
    def __init__(self, root):
        base = Fixture(root / 'base')
        self.root = root; self.address = '192.0.2.1'; self.port = 1234
        self.argv = ['/usr/bin/python3', '-I', '-c', measurement.guest_script(self.address, self.port)]
        self.guest = copy.deepcopy(base.guest)
        self.guest['argv_digest'] = harness.argv_digest(self.argv)
        self.guest['coverage'] = {name: {'status': 'active', 'gaps': [], 'observed_count':
            2 if name == 'proxy.net' else 1 if name == 'exec' else 0} for name in harness.SUMMARY_CLASSES}
        self.events = [frame('wrapper', 1, 'note', {'kind': 'credential', 'credential_id': 'test',
            'transition': 'loaded', 'uses_recorded': True}),
            frame('audit', 1, 'proc.exec', {'path': {'kind': 'workspace_relative', 'value': measurement.COPY},
                                          'path_complete': True, 'pid': 71, 'pid_start_ticks': 1000}),
            frame('proxy', 1, 'net.connect', {'destination': '192.0.2.1:1234', 'reason': 'relayed', 'credentials': ['test']},
                  stage='result', decision='allow', outcome={'ok': True}),
            frame('proxy', 2, 'net.connect', {'destination': '192.0.2.1:1234', 'reason': 'credential_process_denied'},
                  stage='result', decision='deny', outcome={'ok': False})]
        binding = dict(base.binding, argv_digest=self.guest['argv_digest'])
        raw, trace, manifest = write_artifact(root / 'guest-artifact', self.guest, self.events, binding)
        placeholder = f'vault:{GUEST_ID}:test'.encode()
        self.driver = {'placeholder': {'sha256': hashlib.sha256(placeholder).hexdigest(), 'bytes': len(placeholder), 'shape': True},
            'original': {'device': 1, 'inode': 10, 'size': 100}, 'copy': {'device': 1, 'inode': 11, 'size': 100},
            'original_sha256': 'a' * 64, 'copy_sha256': 'a' * 64,
            'own': {'status': 200, 'body_ok': True}, 'other': {'status': 403, 'reason': 'credential_process_denied'},
            'other_exit': 0, 'other_stderr_empty': True, 'copy_absent': True}
        image = {**base.transport['image'], 'ukai_vm_sha256': '1' * 64, 'ukai_jail_sha256': '2' * 64}
        self.record = dict(attempt_id=binding['attempt_id'], boot_id=binding['boot_id'], profile='agent',
            argv_digest=self.guest['argv_digest'], receipt=self.guest, binding=binding, receipt_digest_ok=True,
            receipt_sha256=manifest['guest_receipt_sha256'], error=None, exit_code=0, guest_stop=stop(),
            ready=dict(image, schema='ukai.jail.vm-attempt/1', boot_id=binding['boot_id']),
            prepared={'staged_secrets': [['test', '/run/ukai-vm/credentials/test']]},
            stdout='PROGRAM_BINDING ' + json.dumps(self.driver) + '\n')
        self.peer = {'requests': [{'path': '/own', 'credential_matches': True}], 'overflow': False}
        # This test targets retained-input binding; summary math has separate
        # independent golden fixtures in test_vm_summary_check.
        self.summary = summary_check.compute_summary(self.guest, self.events, 'complete', len(trace))
        self.journal = {'verified': True}
        offline = root / 'guest-attempt'; offline.mkdir()
        (offline / 'jail.json').write_bytes(raw); (offline / 'trace.ndjson').write_bytes(trace)
        tail = ''.join('ukai-jail: ' + line['text'] + '\n' for line in self.summary['lines'])
        tail += 'ukai-jail: receipt ' + str(offline / 'jail.json') + '\n'
        identity = {'image': image, 'image_manifest_json': json.dumps(image),
            'image_manifest_sha256': hashlib.sha256(json.dumps(image).encode()).hexdigest(),
            'service': {'sha256': '1' * 64}, 'client': {'sha256': '2' * 64}}
        sync_guest = copy.deepcopy(self.guest)
        sync_guest['attempt_id'] = 'att_00000000-0000-4000-8000-000000000003'
        sync_guest['argv_digest'] = harness.argv_digest(['/bin/sync'])
        sync_guest['policy']['name'] = 'tool'; sync_guest['credentials'] = []
        sync_binding = dict(binding, attempt_id='program-binding-sync', guest_attempt_id=sync_guest['attempt_id'],
                            profile='tool', argv_digest=sync_guest['argv_digest'])
        sync_events = [{'source': 'wrapper', 'source_seq': 1, 'operation': 'note', 'attempt_id': sync_guest['attempt_id'],
                        'fields': {'kind': 'lifecycle', 'transition': 'exec_confirmed'}}]
        _, _, sync_manifest = write_artifact(root / 'sync-artifact', sync_guest, sync_events, sync_binding)
        self.sync_events = sync_events
        sync = dict(self.record, attempt_id='program-binding-sync', profile='tool', binding=sync_binding, receipt=sync_guest,
                    argv_digest=sync_guest['argv_digest'], receipt_sha256=sync_manifest['guest_receipt_sha256'])
        self.inputs = dict(schema=measurement.INPUTS, record=self.record, identity_before=identity, identity_after=copy.deepcopy(identity),
            argv=self.argv, launch_toml=measurement.declaration(self.address, self.port),
            upstream={'address': self.address, 'port': self.port}, peer=self.peer,
            service_status={'boot_id': binding['boot_id']}, offline_attempt=str(offline),
            tail={'text': tail, 'json': json.dumps(self.summary), 'exit': 0, 'json_exit': 0}, sync=sync,
            service_exit=0, shutdown={'complete': True, 'held_before_stop': True, 'sockets_absent': True, 'boot_entries_remaining': []},
            scans=[{'encoding': name, 'file_hits': [], 'files_scanned': 8, 'disk_hits': 0, 'disk_bytes': 1000}
                   for name in ('raw', 'base64', 'base64url', 'hex', 'url', 'json')])
        self.write()

    def write(self):
        data = encoded(self.inputs); (self.root / 'inputs.json').write_bytes(data)
        (self.root / 'measurement.json').write_bytes(encoded({'schema': measurement.SCHEMA, 'qualified': False,
                                                            'inputs_sha256': hashlib.sha256(data).hexdigest()}))

    def judge(self):
        return measurement.judge(self.record, self.guest, self.events, self.journal, self.summary, self.peer)


class ControlTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.fixture = ComponentFixture(self.root)

    def test_real_literal_command_keeps_absolute_program_and_program_bound_profile(self):
        launch = tomllib.loads(measurement.declaration('192.0.2.1', 1234))
        self.assertEqual(launch['credentials']['test']['binaries'], ['@program'])
        self.assertEqual(launch['credentials']['test']['env'], 'AGENT_TOKEN')
        argv = [b'/usr/bin/python3', b'-I', b'-c', measurement.guest_script('192.0.2.1', 1234).encode()]
        command = guest.run_command('agent', argv, 50, workspace=self.root, evidence=self.root, launch=measurement.NAME)
        self.assertNotIn(b'--from-path', command)
        self.assertEqual(command[command.index(b'--') + 1:], argv)
        self.assertEqual(command[command.index(b'--launch') + 1], measurement.NAME.encode())
        compile(argv[-1], '<program-binding-driver>', 'exec')
        self.assertNotIn(b'synthetic-private-value', argv[-1])

    def test_actual_proxy_control_and_complete_persisted_replay_pass_without_qualification(self):
        self.assertTrue(all(self.fixture.judge().values()), self.fixture.judge())
        result = measurement.replay(self.root)
        self.assertEqual(result['outcome'], 'PASS', result)
        self.assertFalse(result['qualified'])
        self.assertEqual(result['independent_summary']['scope'], 'host_only')

    def test_wrong_denial_substitution_counts_and_controller_refusal_never_pass(self):
        for change in ('controller', 'host_denial', 'second_use', 'unconfirmed', 'missing_denial', 'order', 'missing_exec'):
            with self.subTest(change=change):
                f = copy.deepcopy(self.fixture)
                if change == 'controller': f.record['error'] = 'native_prepare_refused'
                if change == 'host_denial': f.events[-1]['fields']['reason'] = 'host_not_allowed'
                if change == 'second_use': f.events[-1]['fields']['credentials'] = ['test']
                if change == 'unconfirmed': f.events[-1]['fields']['credentials_unconfirmed'] = ['test']
                if change == 'missing_denial': f.events.pop()
                if change == 'order': f.events[-1]['source_seq'] = 0
                if change == 'missing_exec': f.events.pop(1)
                self.assertFalse(all(f.judge().values()))

    def test_wrong_copy_identity_placeholder_peer_or_settlement_never_pass(self):
        for change in ('same_inode', 'changed_bytes', 'wrong_placeholder', 'no_upstream', 'wrong_header',
                       'second_upstream', 'lost', 'error', 'cleanup', 'native_binding', 'false_exit'):
            with self.subTest(change=change):
                f = copy.deepcopy(self.fixture)
                if change == 'same_inode': f.driver['copy'] = f.driver['original']
                if change == 'changed_bytes': f.driver['copy_sha256'] = 'b' * 64
                if change == 'wrong_placeholder': f.driver['placeholder']['sha256'] = '0' * 64
                if change == 'no_upstream': f.peer['requests'] = []
                if change == 'wrong_header': f.peer['requests'][0]['credential_matches'] = False
                if change == 'second_upstream': f.peer['requests'].append({'path': '/other', 'credential_matches': True})
                if change == 'lost': f.guest['lifetime']['integrity'] = 'lost'
                if change == 'error': f.guest['outcome']['error'] = {'code': 'evidence_lost'}
                if change == 'cleanup': f.record['guest_stop']['boundaries'] = []
                if change == 'native_binding': f.record['binding']['native_program'] = {}
                if change == 'false_exit': f.record['exit_code'] = False
                f.record['stdout'] = 'PROGRAM_BINDING ' + json.dumps(f.driver) + '\n'
                self.assertFalse(all(f.judge().values()))

    def test_rehashed_inputs_still_require_exact_argv_summary_identity_scans_and_cleanup(self):
        original = copy.deepcopy(self.fixture.inputs)
        mutations = [lambda v: v['argv'].append('other'),
                     lambda v: v.update(launch_toml=v['launch_toml'].replace('binaries = ["@program"]', 'binaries = []')),
                     lambda v: v['record'].update(receipt_sha256='0' * 64),
                     lambda v: v['identity_after']['service'].update(sha256='3' * 64),
                     lambda v: v['tail'].update(text=v['tail']['text'].replace('used on 1', 'used on 9')),
                     lambda v: v['sync']['binding'].update(guest_boot_id='other'),
                     lambda v: v['shutdown'].update(complete=False),
                     lambda v: v['scans'].pop(), lambda v: v['scans'][0].update(encoding='base64'),
                     lambda v: v['scans'][0].update(file_hits=['scan-error:read']),
                     lambda v: v['scans'][0].update(disk_hits=1)]
        for change in mutations:
            with self.subTest(change=change):
                self.fixture.inputs = copy.deepcopy(original); change(self.fixture.inputs); self.fixture.write()
                self.assertEqual(measurement.replay(self.root)['outcome'], 'FAIL')

    def test_changed_or_linked_guest_part_and_sync_receipt_refuse(self):
        for relative in ('guest-artifact/evidence/guest-journal/0000.part', 'sync-artifact/evidence/jail.json'):
            path = self.root / relative; raw = path.read_bytes(); path.write_bytes(raw + b' ')
            self.assertEqual(measurement.replay(self.root)['outcome'], 'FAIL')
            path.write_bytes(raw)
        path = self.root / 'guest-artifact/evidence/guest-journal/0000.part'
        outside = self.root / 'outside'; outside.write_bytes(path.read_bytes()); path.unlink(); path.symlink_to(outside)
        self.assertEqual(measurement.replay(self.root)['outcome'], 'FAIL')

    def test_rehashed_sync_receipt_still_requires_actual_execution_and_clean_settlement(self):
        original = copy.deepcopy(self.fixture.inputs)
        changes = [lambda g: g['outcome'].update(kind='unknown', code=None),
                   lambda g: g.update(exec_observed=False), lambda g: g.update(phase='prepared'),
                   lambda g: g['lifetime'].update(integrity='lost'), lambda g: g['lifetime'].update(tree_empty=None),
                   lambda g: g.update(state_cleanup='pending'), lambda g: g.update(cleanup_error={'code': 'cleanup'}),
                   lambda g: g.update(containment='refused'), lambda g: g.update(errors=[{'code': 'evidence_lost'}])]
        for change in changes:
            with self.subTest(change=change):
                self.fixture.inputs = copy.deepcopy(original)
                sync = self.fixture.inputs['sync']; change(sync['receipt'])
                _, _, manifest = write_artifact(self.root / 'sync-artifact', sync['receipt'], self.fixture.sync_events, sync['binding'])
                sync['receipt_sha256'] = manifest['guest_receipt_sha256']
                self.fixture.write()
                self.assertFalse(measurement.clean_sync(sync, self.fixture.inputs['record']))
                result = measurement.replay(self.root)
                self.assertEqual(result['outcome'], 'FAIL', result)
                self.assertIs(result['facts'].get('same_boot_sync'), False)
        self.fixture.inputs = copy.deepcopy(original)
        self.fixture.inputs['sync']['guest_stop']['boundaries'] = []
        self.assertFalse(measurement.clean_sync(self.fixture.inputs['sync'], self.fixture.inputs['record']))

    def test_retention_scans_exact_bytes_and_refuses_links(self):
        source = self.root / 'private'; source.mkdir(); (source / 'value').write_bytes(b'synthetic-private-value')
        with self.assertRaises(ValueError): measurement.retain_tree(source, self.root / 'retained', [b'synthetic-private-value'])
        self.assertFalse((self.root / 'retained').exists())
        (source / 'value').unlink(); (source / 'value').symlink_to(self.root / 'inputs.json')
        with self.assertRaises((ValueError, OSError)): measurement.retain_tree(source, self.root / 'retained', [])
        self.assertFalse((self.root / 'retained').exists())

    def run_driver(self, child_error=False):
        # Execute the exact generated driver's I/O and cleanup using a private
        # source file; only kernel-exe lookup, HTTP and child execution are
        # modeled. This never executes a copied host binary or contacts a peer.
        source = self.root / 'fixture-native-bytes'; source.write_bytes(b'fixture-executable-bytes')
        response = mock.MagicMock(); response.__enter__.return_value.status = 200
        response.__enter__.return_value.read.return_value = b'accepted'
        original_open = os.open
        def opened(path, *args, **kwargs):
            return original_open(source if path == '/proc/self/exe' else path, *args, **kwargs)
        def child(argv, **kwargs):
            path = Path(argv[0])
            self.assertEqual(path.read_bytes(), source.read_bytes())
            self.assertNotEqual(path.stat().st_ino, source.stat().st_ino)
            self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
            if child_error: raise subprocess.TimeoutExpired('synthetic-private-value', 15)
            return subprocess.CompletedProcess(argv, 0, json.dumps({'status': 403, 'reason': 'credential_process_denied'}), '')
        output = io.StringIO(); previous = Path.cwd()
        try:
            os.chdir(self.root)
            with mock.patch('os.open', side_effect=opened), mock.patch('urllib.request.urlopen', return_value=response), \
                    mock.patch('subprocess.run', side_effect=child), mock.patch.dict(os.environ, {'AGENT_TOKEN': f'vault:{GUEST_ID}:test'}), \
                    contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as exited:
                exec(compile(measurement.guest_script('192.0.2.1', 1234), '<driver>', 'exec'), {})
        finally:
            os.chdir(previous)
        return exited.exception.code, measurement.driver_result(output.getvalue())

    def test_generated_driver_copies_exact_bytes_removes_copy_and_keeps_placeholder_value_out(self):
        code, result = self.run_driver()
        self.assertEqual(code, 0)
        self.assertEqual(result['original_sha256'], result['copy_sha256'])
        self.assertNotEqual(result['original']['inode'], result['copy']['inode'])
        self.assertTrue(result['copy_absent'])
        self.assertNotIn(f'vault:{GUEST_ID}:test', json.dumps(result))

    def test_generated_driver_removes_copy_after_child_failure_without_exception_value(self):
        code, result = self.run_driver(child_error=True)
        self.assertEqual(code, 1)
        self.assertEqual(result['error_type'], 'TimeoutExpired')
        self.assertTrue(result['copy_absent'])
        self.assertNotIn('synthetic-private-value', json.dumps(result))


class PeerTests(unittest.TestCase):
    def test_partial_request_line_is_bounded_before_handler_dispatch(self):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), measurement.Peer)
        server.daemon_threads = True; server.witness = measurement.Witness(b'fixture')
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with mock.patch.object(measurement.Peer, 'READ_TIMEOUT', .1), socket.create_connection(server.server_address, timeout=2) as stream:
                stream.sendall(b'GET /own')
                self.assertEqual(stream.recv(1024), b'')
            self.assertEqual(server.witness.snapshot()['requests'], [])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_peer_requires_header_and_never_reflects_or_retains_it(self):
        witness = measurement.Witness(b'synthetic-private-value')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), measurement.Peer)
        server.daemon_threads = True; server.witness = witness
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            for path, header, status in [('/own', 'placeholder', b'403'), ('/own', witness.secret, b'200'),
                                         ('/other', witness.secret, b'403')]:
                with socket.create_connection(server.server_address, timeout=2) as stream:
                    stream.sendall(f'GET {path} HTTP/1.1\r\nHost: fixture\r\nx-test-token: {header}\r\n\r\n'.encode())
                    received = b''
                    while data := stream.recv(4096): received += data
                self.assertIn(status, received)
                self.assertNotIn(witness.secret.encode(), received)
            self.assertNotIn(witness.secret, json.dumps(witness.snapshot()))
        finally:
            server.shutdown(); server.server_close(); thread.join(2)


class ProtocolTests(unittest.TestCase):
    def test_wrong_staging_and_duplicate_release_are_retained_failures_without_secret(self):
        for failure in ('staging', 'release'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                channel = mock.Mock(); service = mock.Mock(); service.connect.return_value = channel
                frames = [{'event': 'ready', 'schema': 'ukai.jail.vm-attempt/1', 'boot_id': 'boot'},
                          {'event': 'prepared', 'staged_secrets': [['test', '/run/ukai-vm/credentials/test']]},
                          {'event': 'released'}, {'event': 'released'}]
                if failure == 'staging': frames[1]['staged_secrets'] = []
                with mock.patch.object(measurement.lifecycle, 'BoundedFrames') as parser:
                    parser.return_value.receive.side_effect = frames
                    record = measurement.attempt(service, Path(temporary), ['/usr/bin/python3'],
                        launch=measurement.declaration('192.0.2.1', 1234), secret=b'synthetic-private-value', allow_host='192.0.2.1:1234')
                self.assertIsNotNone(record['error'])
                self.assertIsNone(record['exit_code'])
                self.assertNotIn('synthetic-private-value', json.dumps(record))
                channel.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
