"""harness.py: the pieces every VM-tier harness judges with.

No VM boots and no packet leaves this host: the egress probe's real source
runs against loopback targets only, and the attempt and control sockets are
in-process fakes (FakeAttemptServer) speaking the §6 protocol.

    python3 -s -E -m unittest test_harness
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import harness

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[2] / 'docs' / 'benchmarks' / 'jail' / 'results'


def probe_line(tag, control='connected', accepted=True, egress='ENETUNREACH', dns=None):
    record = {'nonce': tag, 'control': control, 'control_accepted': accepted, 'egress': egress,
              'target': ['1.1.1.1', 443]}
    if dns is not None:
        record['dns'] = dns
    return 'UKAI_NET_PROBE ' + json.dumps(record)


class ProbeVerdictTests(unittest.TestCase):
    """Each way a probe can fail to prove a denial is never a denial."""

    def test_a_denial_needs_the_positive_control(self):
        self.assertEqual(harness.probe_verdict(probe_line('t1'), 't1')['verdict'], 'egress_denied')
        self.assertTrue(harness.probe_verdict(probe_line('t1'), 't1')['denied'])

    def test_mutations_are_never_a_denial(self):
        cases = {
            'no probe line (python3 missing, /dev/tcp style shell)': ('net_refused\n', 'no_probe'),
            'control failed to connect': (probe_line('t', control='ECONNREFUSED'), 'inconclusive'),
            'control connected but never accepted': (probe_line('t', accepted=False), 'inconclusive'),
            'listener could not bind': (probe_line('t', control='listener-EPERM', accepted=False), 'inconclusive'),
            'egress connected': (probe_line('t', egress='connected'), 'egress_allowed'),
            'another run\'s probe': (probe_line('other'), 'no_probe'),
            'two probes with the tag': (probe_line('t') + '\n' + probe_line('t'), 'ambiguous'),
            'malformed json': ('UKAI_NET_PROBE {not json', 'no_probe'),
        }
        for name, (stdout, verdict) in cases.items():
            with self.subTest(name):
                result = harness.probe_verdict(stdout, 't')
                self.assertEqual(result['verdict'], verdict)
                self.assertFalse(result['denied'])

    def test_shell_text_cannot_forge_a_denial(self):
        # The old harness's `(echo > /dev/tcp/...) && echo NET_ALLOWED || echo net_refused`
        # printed net_refused for every outcome under dash; no such text counts here.
        self.assertFalse(harness.probe_verdict('net_refused\nnet_denied\n', 'x')['denied'])


class ProbeSourceTests(unittest.TestCase):
    """The probe's real source, against loopback targets only (no external network)."""

    def run_probe(self, port):
        tag = harness.nonce()
        argv = harness.probe_argv(tag, target=('127.0.0.1', port), timeout=2.0)
        argv[0] = sys.executable  # the guest's /usr/bin/python3; any python3 runs the source
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return harness.probe_verdict(done.stdout, tag)

    def test_detects_a_connection_and_a_refusal(self):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        open_port = listener.getsockname()[1]
        try:
            self.assertEqual(self.run_probe(open_port)['verdict'], 'egress_allowed')
        finally:
            listener.close()
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        verdict = self.run_probe(closed_port)
        self.assertEqual(verdict['verdict'], 'egress_denied')
        self.assertEqual(verdict['egress'], 'ECONNREFUSED')

    def test_the_shell_form_quotes_the_source(self):
        tag = harness.nonce()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(4)
        try:
            command = harness.probe_shell(tag, target=('127.0.0.1', listener.getsockname()[1]), timeout=2.0)
            command = command.replace(harness.PYTHON, sys.executable, 1)
            # The verdict ignores the shell's status: `false ||` and `&& false` change nothing.
            done = subprocess.run(['/bin/sh', '-c', f'false || {command} && false; echo after'],
                                  capture_output=True, text=True, timeout=30)
        finally:
            listener.close()
        self.assertEqual(harness.probe_verdict(done.stdout, tag)['verdict'], 'egress_allowed')
        self.assertNotIn('/dev/tcp', command)


class VmClientRuleTests(unittest.TestCase):
    """S1's carry rule, as every harness `ukai-jail run --vm` must meet it."""

    def test_the_environment_admits_lang_only(self):
        base = {'TERM': 'dumb', 'TZ': 'UTC', 'LC_CTYPE': 'UTF-8', 'LC_ALL': 'C', 'LANG': 'fr_FR.UTF-8',
                'UKAI_VM_GUEST_NAT': '1', 'PATH': '/bin', 'HOME': '/h'}
        environment = harness.vm_client_environment(base, UKAI_DATA_DIR=Path('/d'))
        self.assertEqual(environment, {'LANG': 'C.UTF-8', 'PATH': '/bin', 'HOME': '/h', 'UKAI_DATA_DIR': '/d'})
        self.assertEqual(base['TERM'], 'dumb', 'the caller\'s mapping is not modified')

    def test_the_wall_is_whole_seconds_up_to_300(self):
        self.assertEqual(harness.vm_wall(300), ['--limit', 'wall=300s'])
        for bad in (0, 301, 2.5, '20', None):
            with self.subTest(bad=bad), self.assertRaises(harness.HarnessError):
                harness.vm_wall(bad)

    def test_refusal_codes_are_found_and_named(self):
        text = ('ukai-jail: refused at probing [unsupported]: vm:not-measured:limit:wall, '
                'vm:not-measured:network_none; vm:not-carried:environment.TERM\n')
        self.assertEqual(harness.vm_refusals(text), ['vm:not-carried:environment.TERM',
                                                     'vm:not-measured:limit:wall', 'vm:not-measured:network_none'])
        self.assertEqual(harness.vm_refusals('settled · exited 0'), [])


class WorkspaceGuardTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='harness-guard-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.workspace = self.root / 'ws'
        self.workspace.mkdir()

    def test_mark_then_guard_then_clean(self):
        harness.mark_workspace(self.workspace)
        (self.workspace / 'stale.txt').write_text('old')
        (self.workspace / 'keep-me').write_text('binary')
        (self.workspace / 'dir').mkdir()
        (self.workspace / 'dir' / 'f').write_text('x')
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'precious').write_text('never removed')
        (self.workspace / 'link').symlink_to(outside)
        removed = harness.clean_workspace(self.workspace, keep=('keep-me',))
        self.assertEqual(sorted(removed), ['dir', 'link', 'stale.txt'])
        self.assertEqual(sorted(p.name for p in self.workspace.iterdir()),
                         sorted([harness.WORKSPACE_MARKER, 'keep-me']))
        self.assertEqual((outside / 'precious').read_text(), 'never removed')

    def test_unmarked_and_wrongly_marked_directories_refuse(self):
        with self.assertRaisesRegex(harness.HarnessError, 'no .ukai-vm-harness-workspace'):
            harness.clean_workspace(self.workspace)
        marker = self.workspace / harness.WORKSPACE_MARKER
        marker.write_text('something else\n')
        with self.assertRaisesRegex(harness.HarnessError, 'does not carry'):
            harness.guarded_workspace(self.workspace)
        marker.unlink()
        real = self.root / 'real-marker'
        real.write_text(harness.WORKSPACE_MARKER_TEXT)
        marker.symlink_to(real)
        with self.assertRaisesRegex(harness.HarnessError, 'regular single-link'):
            harness.guarded_workspace(self.workspace)
        marker.unlink()
        os.link(real, marker)
        with self.assertRaisesRegex(harness.HarnessError, 'regular single-link'):
            harness.guarded_workspace(self.workspace)

    def test_mark_needs_an_empty_directory(self):
        (self.workspace / 'something').write_text('x')
        with self.assertRaisesRegex(harness.HarnessError, 'not empty'):
            harness.mark_workspace(self.workspace)

    def test_protected_places_refuse_even_when_marked(self):
        for path in ('relative/dir', '/', str(Path.home()), str(harness.REPOSITORY),
                     str(harness.REPOSITORY / 'crates'), str(Path.home().parent)):
            with self.subTest(path=path):
                with self.assertRaises(harness.HarnessError):
                    harness.guarded_workspace(path)
        link = self.root / 'ws-link'
        link.symlink_to(self.workspace)
        harness.mark_workspace(self.workspace)
        with self.assertRaisesRegex(harness.HarnessError, 'symlink'):
            harness.guarded_workspace(link)


class OutputTests(unittest.TestCase):
    def test_an_output_directory_and_record_are_never_reused(self):
        root = Path(tempfile.mkdtemp(prefix='harness-out-'))
        self.addCleanup(shutil.rmtree, root, True)
        out = harness.fresh_out_dir(root / 'run')
        harness.write_json(out / 'record.json', {'a': 1})
        with self.assertRaisesRegex(harness.HarnessError, 'previous run'):
            harness.fresh_out_dir(root / 'run')
        with self.assertRaises(FileExistsError):
            harness.write_json(out / 'record.json', {'a': 2})
        self.assertEqual(json.loads((out / 'record.json').read_text()), {'a': 1})

    def test_no_binary_default(self):
        environment = {key: value for key, value in os.environ.items() if key != 'UKAI_VM_BINARY'}
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(harness.HarnessError, 'no default'):
                harness.required_binary('UKAI_VM_BINARY')
        self.assertEqual(harness.required_binary('X', sys.executable), Path(sys.executable).resolve())


class FakeAttemptServer:
    """The §6 attempt socket, scripted: one `script(index, request, send)` per connection."""

    def __init__(self, script, boot_id='vm-fake'):
        self.root = Path(tempfile.mkdtemp(prefix='fake-serve-'))
        self.path = self.root / 'attempt.sock'
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        self.listener.listen(8)
        self.script = script
        self.boot_id = boot_id
        self.closed = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        index = 0
        while True:
            try:
                stream, _ = self.listener.accept()
            except OSError:
                return
            channel = harness.Channel(stream)

            def send(**value):
                channel.send(**value)
            try:
                send(event='ready', boot_id=self.boot_id)
                request = channel.frame()
                self.script(index, request, send, channel)
            except (OSError, harness.StreamEnded):
                pass
            finally:
                self.closed.append(index)
                channel.close()
            index += 1

    def connect(self):
        return harness.connect_unix(self.path, timeout=10)

    def close(self):
        self.listener.close()
        shutil.rmtree(self.root, ignore_errors=True)


def receipt_frame(receipt, binding=None, corrupt=False):
    raw = json.dumps(receipt).encode()
    digest = hashlib.sha256(raw).hexdigest()
    return {'event': 'bound_receipt', 'sha256': ('0' * 64) if corrupt else digest,
            'data': base64.b64encode(raw).decode(),
            'binding': binding or {'guest_boot_id': 'guest-boot-1', 'argv_digest': 'sha256:x'}}


def completing(stdout=b'hello\n', exit_code=0, corrupt=False):
    def script(index, request, send, channel):
        send(event='prepared', kernel='k', staged_secrets=[])
        assert channel.frame()['op'] == 'run'
        send(event='released', supervisor_pid=7)
        send(event='stdout', data=base64.b64encode(stdout).decode())
        send(**receipt_frame({'outcome': {'code': exit_code}}, corrupt=corrupt))
        send(event='done', exit_code=exit_code)
    return script


class ChannelTests(unittest.TestCase):
    def test_two_streams_never_share_a_buffer(self):
        # fault_matrix.frame(s, buf=[b'']) shared one default buffer between
        # sockets: a frame left over from one stream was read as another's.
        a_local, a_peer = socket.socketpair()
        b_local, b_peer = socket.socketpair()
        a_peer.sendall(b'{"from": "a", "n": 1}\n{"from": "a", "n": 2}\n')
        b_peer.sendall(b'{"from": "b", "n": 1}\n')
        a, b = harness.Channel(a_local), harness.Channel(b_local)
        self.assertEqual(a.frame(), {'from': 'a', 'n': 1})
        self.assertEqual(b.frame(), {'from': 'b', 'n': 1})
        self.assertEqual(a.frame(), {'from': 'a', 'n': 2})
        for sock in (a_local, a_peer, b_local, b_peer):
            sock.close()

    def test_end_of_stream_is_named(self):
        local, peer = socket.socketpair()
        peer.sendall(b'{"partial":')
        peer.close()
        with self.assertRaises(harness.StreamEnded):
            harness.Channel(local).frame()
        local.close()


class RunAttemptTests(unittest.TestCase):
    def test_a_completed_attempt_is_recorded_with_its_receipt(self):
        server = FakeAttemptServer(completing())
        self.addCleanup(server.close)
        record = harness.run_attempt(server.connect, 'a1', ['/bin/sh', '-c', 'echo hello'])
        self.assertEqual(record['exit_code'], 0)
        self.assertEqual(record['stdout'], 'hello\n')
        self.assertTrue(record['receipt_digest_ok'])
        self.assertEqual(harness.guest_boot(record), 'guest-boot-1')
        self.assertEqual(record['boot_id'], 'vm-fake')
        for key in ('connect_to_released', 'run_to_released', 'prepare_to_released', 'released_to_done'):
            self.assertIsNotNone(record['timings_ms'][key], key)

    def test_a_receipt_digest_mismatch_is_seen(self):
        server = FakeAttemptServer(completing(corrupt=True))
        self.addCleanup(server.close)
        self.assertFalse(harness.run_attempt(server.connect, 'a1', ['true'])['receipt_digest_ok'])

    def test_a_dropped_attempt_is_a_record_with_an_error(self):
        def drop(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
        server = FakeAttemptServer(drop)
        self.addCleanup(server.close)
        record = harness.run_attempt(server.connect, 'a1', ['true'])
        self.assertIsNone(record['exit_code'])
        self.assertIn('StreamEnded', record['error'])

    def test_the_argv_crosses_base64_encoded(self):
        seen = {}

        def capture(index, request, send, channel):
            seen.update(request)
        server = FakeAttemptServer(capture)
        self.addCleanup(server.close)
        harness.run_attempt(server.connect, 'a1', ['/bin/sh', '-c', 'x y'], secrets=[('id/one', b'v')])
        self.assertEqual([base64.b64decode(word) for word in seen['argv']], [b'/bin/sh', b'-c', b'x y'])
        self.assertEqual(seen['secrets'], [{'id': 'id/one', 'data': base64.b64encode(b'v').decode()}])


class HeartbeatTests(unittest.TestCase):
    """The K110 workload: a leader with descendants, beating into the workspace."""

    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix='harness-beats-'))
        self.addCleanup(shutil.rmtree, self.workspace, True)
        shim = self.workspace / '.bin'
        shim.mkdir()
        # The guest's GNU date prints nanoseconds; macOS date does not.
        (shim / 'date').write_text(f'#!/bin/sh\nexec {sys.executable} -c "import time; print(time.time_ns())"\n')
        (shim / 'date').chmod(0o755)
        self.environment = dict(os.environ, PATH=f'{shim}:/usr/bin:/bin')

    def start(self, marker, beats):
        return subprocess.Popen(['/bin/sh', '-c', harness.heartbeat_script(marker, beats=beats)],
                                cwd=self.workspace, env=self.environment, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True, text=True)

    def test_a_bounded_workload_beats_from_every_process_then_finishes(self):
        process = self.start('m1', beats=8)
        watch = harness.BeatWatch(self.workspace, 'm1')
        self.assertTrue(watch.wait_beating(10))
        out, _ = process.communicate(timeout=20)
        self.assertEqual(process.returncode, 0)
        self.assertIn('hb-m1-done', out)
        quiet, last = watch.wait_quiet(0.5, 5)
        self.assertTrue(quiet)

    def test_killing_the_group_stops_every_descendant(self):
        process = self.start('m2', beats=None)
        watch = harness.BeatWatch(self.workspace, 'm2')
        self.assertTrue(watch.wait_beating(10))
        # Killing only the leader leaves the children beating: the watch sees it.
        os.kill(process.pid, signal.SIGKILL)
        quiet, _ = watch.wait_quiet(1.0, 2.5)
        self.assertFalse(quiet, 'the descendants kept beating after the leader died')
        killed_at = time.monotonic()
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        quiet, last = watch.wait_quiet(1.0, 10)
        process.stdout.close()
        self.assertTrue(quiet)
        self.assertLess(last - killed_at, 1.0)


class ClientProcessTests(unittest.TestCase):
    def test_a_killed_client_ends_the_attempt_by_eof(self):
        released = threading.Event()
        ended = threading.Event()

        def hold(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            released.set()
            try:
                channel.frame()
            except harness.StreamEnded:
                ended.set()
        server = FakeAttemptServer(hold)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c1', ['sleep', '60'], 60)
        self.assertIsNotNone(client.wait_event('released', 10))
        self.assertIsNotNone(client.capture_identity())
        harness.signal_checked(client.process.pid, client.identity, signal.SIGKILL)
        self.assertTrue(ended.wait(5), 'the server never saw the lease end')
        self.assertEqual(client.finish(), -signal.SIGKILL)
        self.assertFalse(client.ended_by_itself())

    def test_a_ctrl_z_suspends_without_ending_and_resume_completes(self):
        go = threading.Event()

        def slow(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            go.wait(10)
            send(event='done', exit_code=0)
        server = FakeAttemptServer(slow)
        self.addCleanup(server.close)
        client = harness.ClientProcess(server.path, 'c2', ['true'], 60)
        self.assertIsNotNone(client.wait_event('released', 10))
        os.killpg(os.getpgid(client.process.pid), signal.SIGTSTP)
        time.sleep(0.3)
        state = subprocess.run(['ps', '-p', str(client.process.pid), '-o', 'stat='],
                               capture_output=True, text=True).stdout.strip()
        self.assertTrue(state.startswith('T'), state)
        go.set()
        os.killpg(os.getpgid(client.process.pid), signal.SIGCONT)
        self.assertEqual((client.wait_event('done', 10) or {}).get('exit_code'), 0)
        self.assertEqual(client.finish(), 0)

    def test_a_kill_of_a_recycled_pid_refuses(self):
        with self.assertRaisesRegex(harness.HarnessError, 'not signalled'):
            harness.signal_checked(os.getpid(), 'Mon Jan  1 00:00:00 1990 not-this', signal.SIGTERM)


class ReceiptRecordTests(unittest.TestCase):
    """Checked against the committed 2026-11-03 evidence the review judged."""

    def test_the_argv_digest_is_the_receipts_own_construction(self):
        binding = json.loads((EVIDENCE / 'macos-vm-installed-2026-11-03/k111-attempt/evidence/vm-binding.json').read_text())
        self.assertEqual(harness.argv_digest(['/bin/sh', '-c', 'printf "row-k111\\n" > k111.txt; echo row-k111-done']),
                         binding['argv_digest'])
        self.assertNotEqual(harness.argv_digest(['/bin/sh', '-c', 'something else']), binding['argv_digest'])

    def test_the_k113_host_receipt_contradicts_its_guest_receipt(self):
        attempt = EVIDENCE / 'macos-vm-claude-2026-11-03/k113-attempt'
        host = json.loads((attempt / 'jail.json').read_text())
        guest = json.loads((attempt / 'evidence/jail.json').read_text())
        fields = {entry['field'] for entry in harness.receipt_contradictions(host, guest)}
        self.assertEqual(fields, {'network.mode', 'observer.attached'})
        mirrored = json.loads(json.dumps(host))
        mirrored['applied']['network'] = guest['applied']['network']
        mirrored['observer'] = {'carried_by': 'guest', 'receipt': 'evidence/jail.json'}
        self.assertEqual(harness.receipt_contradictions(mirrored, guest), [])

    def test_the_k113_run_summary_states_no_guest_fact(self):
        attempt = EVIDENCE / 'macos-vm-claude-2026-11-03/k113-attempt'
        guest = json.loads((attempt / 'evidence/jail.json').read_text())
        transport = json.loads((attempt / 'vm-transport.json').read_text())
        text = json.loads((EVIDENCE / 'macos-vm-claude-2026-11-03/k113-claude.json').read_text())['stdout_tail']
        facts = harness.summary_facts(text, guest, transport)
        self.assertTrue(facts['transport_line_from_record'])
        self.assertFalse(facts['network_line_is_the_guests'])        # "network: not applied"
        self.assertFalse(facts['observer_classes_are_the_guests'])   # "0/6 classes active"
        self.assertFalse(facts['observer_attachment_is_the_guests'])  # "observer not attached"
        fixed = (text.replace('network: not applied', 'network: allowed api.anthropic.com (4)')
                 .replace('observer not attached · 0/6 classes active', '6/6 classes active, no gaps'))
        self.assertTrue(all(harness.summary_facts(fixed, guest, transport).values()))
        self.assertFalse(harness.summary_facts('', guest, transport)['transport_line_present'])
        forged = text.replace(transport['boot_id'], 'vm-forged')
        self.assertFalse(harness.summary_facts(forged, guest, transport)['transport_line_from_record'])


if __name__ == '__main__':
    unittest.main()
