"""Exercise ukai-vm with stand-in custodian and VZ processes; never boots a VM.

Run after cargo build --offline, from this directory:
    python3 -s -E -m unittest test_warm_service
UKAI_VM_TEST_BINARY selects a saved baseline binary for regression replay.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

BINARY = Path(os.environ.get('UKAI_VM_TEST_BINARY', Path(__file__).resolve().parents[3] / 'target/debug/ukai-vm'))

CUSTODIAN = r'''
import os, select, signal, subprocess, sys, time
lease, ack = map(int, sys.argv[1:3])
child = subprocess.Popen(sys.argv[3:])
try:
    deadline = time.monotonic() + 3
    while child.poll() is None:
        if time.monotonic() > deadline:
            break
        if select.select([lease], [], [], .02)[0]:
            data = os.read(lease, 64)
            if not data or any(b != 46 for b in data):
                break
            deadline = time.monotonic() + 3
            if os.environ.get('ACK_MODE') != 'silent':
                os.write(ack, b'!' if os.environ.get('ACK_MODE') == 'invalid' else b'.')
finally:
    if child.poll() is None:
        child.kill()
    child.wait()
'''

HELPER = r'''
import base64, hashlib, json, os, struct, sys

# The custodian's child argv: DISK SEED NVRAM CONSOLE run [SHARE_DIR].
console, share = sys.argv[4], (sys.argv[6] if len(sys.argv) > 6 else None)

def record(value):
    if os.environ.get('RECORD'):
        with open(os.environ['RECORD'], 'a') as out:
            out.write(json.dumps(value) + '\n')

record(dict(helper_argv=sys.argv[1:], nat=os.environ.get('UKAI_VM_GUEST_NAT')))
if os.environ.get('POWEROFF_REASON'):
    # A guest that ended itself: the controller's audit on the console.
    with open(console, 'a') as out:
        out.write('UKAI_VM ' + json.dumps(dict(event='poweroff', reason=os.environ['POWEROFF_REASON'])) + '\r\n')
    sys.exit(0)

def emit(value):
    print(json.dumps(value), flush=True)

def guest(value, split=False):
    raw = (json.dumps(value) + '\n').encode()
    for offset in range(0, len(raw), 65536 if split else len(raw)):
        emit(dict(event='data', data=base64.b64encode(raw[offset:offset+65536] if split else raw).decode()))

if os.environ.get('BLOCK_READY') == '1':
    sys.stdin.read()
    sys.exit(0)
guest(dict(event='ready', kernel='stand-in-kernel'))
sessions = 0
for line in sys.stdin:
    message = json.loads(line)
    if message['op'] == 'stop':
        emit(dict(event='stopped'))
        break
    for raw in base64.b64decode(message['data']).splitlines():
        request = json.loads(raw)
        record(request)
        op = request['op']
        if op == 'session':
            sessions += 1
            if sessions > 1:
                guest(dict(event='error', message='duplicate session'))
                sys.exit(125)
            # The guest states whether it mounted the share (D7); LIVE_SHARE
            # makes it lie, or (omit) say nothing like an old controller.
            live = os.environ.get('LIVE_SHARE', '1' if share else '0')
            reply = dict(event='session', kernel='stand-in-kernel')
            if live != 'omit':
                reply['live_share'] = live == '1'
            if os.environ.get('BAD_SESSION') == '1':
                del reply['kernel']
            guest(reply)
            if os.environ.get('EXIT_AFTER_SESSION') == '1': sys.exit(1)
        elif op == 'reset':
            guest(dict(event='reset'))
        elif op == 'cancel2':
            guest(dict(event='cancelled'))
        elif op == 'put':
            guest(dict(event='put', path=request['path']))
        elif op == 'secret':
            if os.environ.get('REFUSE_SECRET') == '1':
                guest(dict(event='error', message='secret_refused:FileExistsError'))
            else:
                guest(dict(event='secret', id=request['id'], path='/run/ukai-vm/credentials/' + request['id']))
        elif op == 'launch_toml':
            guest(dict(event='launch_toml'))
        elif op == 'run2':
            guest(dict(event='running', supervisor_pid=os.getpid()))
            if os.environ.get('HOLD_RUN') == '1':
                continue
            guest(dict(event='stdout', data=base64.b64encode(b'guest stdout\n').decode()))
            guest(dict(event='file', group='workspace', path='large.bin', executable=False,
                       data=base64.b64encode(b'x' * 100000).decode()), split=True)
            argv = [base64.b64decode(a) for a in request['argv']]
            preimage = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(argv))
            preimage += b''.join(struct.pack('>Q', len(a)) + a for a in argv)
            digest = 'sha256:' + hashlib.sha256(preimage).hexdigest()
            receipt = dict(schema='ukai.jail.receipt/1', attempt_id='guest-attempt', argv_digest=digest,
                           platform=dict(os='linux'), policy=dict(name=request['profile']),
                           containment='enforced', child_protection='enforced', exec_observed=True,
                           state_cleanup='complete', errors=[],
                           lifetime=dict(boundary='pid_namespace', tree_empty=True, integrity='verified'),
                           process=dict(identity=dict(value=dict(boot_id='guest-boot'))),
                           applied=dict(network=dict(mode='none'), limits=[dict(key=k, applied=True) for k in ['wall','mem','pids','swap']]))
            guest(dict(event='file', group='evidence', path='jail.json', executable=False,
                       data=base64.b64encode(json.dumps(receipt).encode()).decode()))
            binding = dict(attempt_id=request.get('attempt_id'), boot_id=request.get('boot_id'),
                           guest_attempt_id='guest-attempt', guest_boot_id='guest-boot',
                           profile=request['profile'], argv_digest=digest)
            done = dict(event='done', exit_code=0, binding=binding)
            if os.environ.get('NO_STOP') != '1':
                done['stop'] = dict(boundaries=['ukai-attempts.slice/attempt-1'], populated_before_kill=[],
                                    live_before_kill=[[77, None]], strays_killed=[[77, '/user.slice/s']])
            guest(done)
'''


@unittest.skipUnless(sys.platform == 'darwin', 'warm service is macOS-only')
class WarmServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ukai-vm-test-')
        self.root = Path(self.temp.name)
        self.install = self.root / 'install'
        image = self.install / 'image'
        image.mkdir(parents=True)
        (image / 'base.raw').write_bytes(b'stand-in disk, not bootable')
        (image / 'seed.iso').write_bytes(b'stand-in seed')
        for name, source in [('custodian', CUSTODIAN), ('vz', HELPER)]:
            (image / name).write_text('#!' + sys.executable + '\n' + source)
            (image / name).chmod(0o700)
        manifest = dict(status='prepared')
        for name, key in [('base.raw', 'disk'), ('seed.iso', 'seed'), ('custodian', 'custodian'), ('vz', 'helper')]:
            manifest[key + '_sha256'] = hashlib.sha256((image / name).read_bytes()).hexdigest()
        (image / 'image.json').write_text(json.dumps(manifest))
        self.env = dict(os.environ, UKAI_VM_HOME=str(self.install), UKAI_DATA_DIR=str(self.root / 'data'))
        self.children = []
        self.streams = []

    def tearDown(self):
        for stream in self.streams:
            stream.close()
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            if child.stderr:
                child.stderr.close()
        self.temp.cleanup()

    def launch(self, idle=600, args=(), **env):
        child = subprocess.Popen([str(BINARY), 'serve', '--idle-seconds', str(idle), *args],
                                 env=dict(self.env, **env), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.children.append(child)
        return child

    def recorded(self):
        path = self.root / 'record.ndjson'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def wait_recorded(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = [frame for frame in self.recorded() if predicate(frame)]
            if found:
                return found
            time.sleep(.02)
        self.fail('the stand-in guest never received the expected frame')

    def assert_exit(self, child, expected):
        _, stderr = child.communicate(timeout=6)
        self.assertEqual(child.returncode, expected, stderr.decode())
        return stderr.decode()

    def socket(self, name):
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(3)
        deadline = time.monotonic() + 5
        while True:
            try:
                stream.connect(str(self.root / 'data/vm' / (name + '.sock')))
                self.streams.append(stream)
                return stream
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    stream.close()
                    self.fail('service did not bind ' + name)
                time.sleep(.02)

    def frame(self, stream):
        buffers = getattr(self, '_buffers', {})
        self._buffers = buffers
        raw = buffers.get(stream, b'')
        while b'\n' not in raw:
            chunk = stream.recv(16384)
            if not chunk:
                self.fail('stream ended before a complete frame')
            raw += chunk
        line, buffers[stream] = raw.split(b'\n', 1)
        return json.loads(line)

    def send(self, stream, **value):
        stream.sendall((json.dumps(value) + '\n').encode())

    def control(self, op):
        stream = self.socket('control')
        self.send(stream, op=op)
        reply = self.frame(stream)
        stream.close()
        return reply

    def attempt(self, **prepare):
        stream = self.socket('attempt')
        ready = self.frame(stream)
        frame = dict(op='prepare', attempt_id='host-attempt', profile='tool',
                     wall_seconds=30, argv=[base64.b64encode(b'/bin/true').decode()], secrets=[])
        frame.update(prepare)
        self.send(stream, **frame)
        self.assertEqual(self.frame(stream)['event'], 'prepared')
        self.send(stream, op='run')
        self.assertEqual(self.frame(stream)['event'], 'released')
        return stream, ready

    def test_a_done_without_a_stop_is_relayed_without_one(self):
        child = self.launch(NO_STOP='1')
        stream, _ = self.attempt()
        while (frame := self.frame(stream))['event'] != 'done':
            pass
        self.assertNotIn('stop', frame)
        self.control('stop')
        child.wait(timeout=6)

    def test_status_is_ready_only_once_the_guest_session_is_open(self):
        # `warm` holds from the boot's start; `ready` waits for the session
        # handshake, which a guest that never says `ready` never reaches.
        child = self.launch(BLOCK_READY='1')
        status = self.control('status')
        self.assertTrue(status['warm'])
        self.assertIs(status['ready'], False)
        self.assertIsNone(status['kernel'])
        self.control('stop')
        child.wait(timeout=6)
        child = self.launch()
        deadline = time.monotonic() + 3
        while not (status := self.control('status'))['ready']:
            self.assertIsNone(status['kernel'], 'a kernel was known before the serve said ready')
            if time.monotonic() >= deadline:
                self.fail('the serve never said ready')
            time.sleep(.01)
        self.assertEqual(status['kernel'], 'stand-in-kernel')
        self.assertTrue(status['warm'])
        self.control('stop')
        child.wait(timeout=6)

    def test_lease_refresh_survives_three_seconds_and_stop_exits(self):
        child = self.launch()
        first = self.control('status')
        self.assertTrue(first['warm'])
        time.sleep(3.3)
        self.assertTrue(self.control('status')['warm'])
        self.assertIsNone(child.poll())
        self.assertEqual(self.control('stop')['event'], 'stopping')
        child.wait(timeout=6)

    def test_two_attempts_release_export_split_frame_and_finish_without_eof(self):
        child = self.launch()
        for _ in range(2):
            stream, ready = self.attempt()
            found = {}
            while True:
                frame = self.frame(stream)
                found[frame['event']] = frame
                if frame['event'] == 'done':
                    break
            self.assertEqual(len(base64.b64decode(found['file']['data'])), 100000)
            self.assertEqual(base64.b64decode(found['stdout']['data']), b'guest stdout\n')
            binding = found['bound_receipt']['binding']
            self.assertEqual(binding['attempt_id'], 'host-attempt')
            self.assertEqual(binding['boot_id'], ready['boot_id'])
            # D6: the serve relays the guest's stop as the guest reported it
            # (the client, not the relay, judges it).
            self.assertEqual(found['done']['stop'],
                             dict(boundaries=['ukai-attempts.slice/attempt-1'], populated_before_kill=[],
                                  live_before_kill=[[77, None]], strays_killed=[[77, '/user.slice/s']]))
            # Keep prior clients open: the service must not wait for their EOF.
        self.control('stop')
        child.wait(timeout=6)

    def test_disconnect_cancels_only_that_attempt(self):
        child = self.launch(HOLD_RUN='1')
        first, _ = self.attempt()
        first.close()
        second, _ = self.attempt()
        second.close()
        self.assertIsNone(child.poll())
        self.control('stop')
        child.wait(timeout=6)

    def test_failed_prepare_does_not_end_service(self):
        child = self.launch()
        stream = self.socket('attempt')
        self.frame(stream)
        stream.close()
        self.attempt()
        self.assertIsNone(child.poll())
        self.control('stop')
        child.wait(timeout=6)

    def test_idle_timeout_and_sigterm_exit_with_idle_control_clients(self):
        for idle in (1, 0):
            with self.subTest(idle=idle):
                child = self.launch(idle=idle)
                self.socket('control')  # silent client cannot hold teardown
                if idle == 0:
                    child.send_signal(signal.SIGTERM)
                self.assert_exit(child, 0)

    def test_sigterm_is_an_orderly_stop_before_and_during_an_attempt(self):
        for phase in ('starting', 'idle', 'preparing', 'running'):
            with self.subTest(phase=phase):
                child = self.launch(idle=0, HOLD_RUN='1',
                                    BLOCK_READY='1' if phase == 'starting' else '0')
                if phase == 'starting':
                    self.assertTrue(self.control('status')['warm'])
                elif phase == 'idle':
                    deadline = time.monotonic() + 3
                    while self.control('status')['kernel'] is None:
                        if time.monotonic() >= deadline:
                            self.fail('service did not finish its session handshake')
                        time.sleep(.01)
                elif phase == 'preparing':
                    stream = self.socket('attempt')
                    self.assertEqual(self.frame(stream)['event'], 'ready')
                else:
                    self.attempt()
                child.send_signal(signal.SIGTERM)
                stderr = self.assert_exit(child, 0)
                self.assertNotIn('VM custody or transport failed', stderr)
                for name in ('control.sock', 'attempt.sock'):
                    self.assertFalse((self.root / 'data/vm' / name).exists())

    def test_ack_invalid_or_absent_terminates_within_bound(self):
        for mode in ('invalid', 'silent'):
            with self.subTest(mode=mode):
                child = self.launch(ACK_MODE=mode)
                self.assert_exit(child, 125)

    def test_bad_session_is_not_an_orderly_stop(self):
        child = self.launch(BAD_SESSION='1')
        self.assertIn('session omitted kernel', self.assert_exit(child, 125))

    def test_helper_death_and_stop_during_silent_attempt_are_bounded(self):
        child = self.launch(EXIT_AFTER_SESSION='1')
        self.assert_exit(child, 125)
        child = self.launch()
        stream = self.socket('attempt')
        self.frame(stream)  # never send prepare
        self.control('stop')
        self.assert_exit(child, 0)

    def test_second_serve_cannot_unlink_first_sockets(self):
        first = self.launch()
        boot = self.control('status')['boot_id']
        second = self.launch()
        self.assertEqual(second.wait(timeout=3), 125)
        self.assertEqual(self.control('status')['boot_id'], boot)
        self.control('stop')
        first.wait(timeout=6)

    def test_vault_values_including_duplicate_ids_refuse_before_prepared(self):
        child = self.launch()
        stream = self.socket('attempt')
        self.frame(stream)
        self.send(stream, op='prepare', attempt_id='host', profile='tool', wall_seconds=30,
                  argv=[base64.b64encode(b'/bin/true').decode()],
                  secrets=[dict(id='same', data=base64.b64encode(value).decode()) for value in (b'one', b'two')])
        self.assertEqual(stream.recv(1000), b'')
        self.assertTrue(self.control('status')['warm'])
        self.control('stop')
        child.wait(timeout=6)

    def test_status_returns_exact_control_reply_and_absence_prints_once(self):
        import threading
        runtime = self.root / 'data/vm'
        runtime.mkdir(parents=True)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(runtime / 'control.sock'))
        listener.listen()
        reply = dict(event='status', schema='ukai.jail.vm-control/1', boot_id='actual-boot',
                     warm=False, ready=False, attempt_live=False, kernel=None, disk_sha256='d'*64,
                     helper_sha256='h'*64, custodian_sha256='c'*64, seed_sha256='s'*64,
                     vsock_port=1024, idle_seconds=600, guest_nat=False)
        def answer():
            with listener:
                stream, _ = listener.accept()
                with stream:
                    stream.recv(1000)
                    stream.sendall((json.dumps(reply) + '\n').encode())
        thread = threading.Thread(target=answer)
        thread.start()
        status = subprocess.run([str(BINARY), 'status'], env=self.env, capture_output=True, timeout=6)
        thread.join(timeout=1)
        self.assertEqual(json.loads(status.stdout), reply)
        stopped = subprocess.run([str(BINARY), 'stop'], env=self.env, capture_output=True, timeout=6)
        self.assertEqual(stopped.stdout.decode().strip(), 'ukai-vm: no VM is running')

    def test_guest_nat_is_the_flags_alone(self):
        record = str(self.root / 'record.ndjson')
        for args, expected in [((), None), (('--guest-nat',), '1')]:
            with self.subTest(args=args):
                (self.root / 'record.ndjson').unlink(missing_ok=True)
                # An inherited variable must never attach the adapter behind
                # a status that says false.
                child = self.launch(args=args, UKAI_VM_GUEST_NAT='1', RECORD=record)
                start = self.wait_recorded(lambda frame: 'helper_argv' in frame)[0]
                self.assertEqual(start['nat'], expected)
                self.assertIs(self.control('status')['guest_nat'], expected == '1')
                self.control('stop')
                child.wait(timeout=6)

    def test_the_agent_policy_launch_and_secrets_reach_the_guest(self):
        child = self.launch(RECORD=str(self.root / 'record.ndjson'))
        launch = dict(name='claude', toml='[credentials.api]\nsource = "/run/ukai-vm/credentials/api/token"\n')
        secrets = [dict(id='api/token', data=base64.b64encode(b'value').decode())]
        # TLS-only grants arrive without their port (S1's snapshot shape).
        stream, _ = self.attempt(profile='agent', allow_hosts=['api.anthropic.com', 'example.org:8443'],
                                 launch=launch, secrets=secrets)
        while self.frame(stream)['event'] != 'done':
            pass
        ops = [frame for frame in self.recorded() if 'op' in frame]
        names = [frame['op'] for frame in ops]
        self.assertLess(names.index('reset'), names.index('launch_toml'))
        self.assertLess(names.index('launch_toml'), names.index('secret'))
        self.assertLess(names.index('secret'), names.index('run2'))
        self.assertEqual(ops[names.index('launch_toml')]['toml'], launch['toml'])
        self.assertEqual(ops[names.index('secret')]['id'], 'api/token')
        run2 = ops[names.index('run2')]
        self.assertEqual((run2['profile'], run2['allow_hosts'], run2['launch']),
                         ('agent', ['api.anthropic.com', 'example.org:8443'], 'claude'))
        self.control('stop')
        child.wait(timeout=6)

    def test_nested_credential_ids_refuse_before_any_guest_traffic(self):
        child = self.launch(RECORD=str(self.root / 'record.ndjson'))
        stream = self.socket('attempt')
        self.frame(stream)
        self.send(stream, op='prepare', attempt_id='host', profile='tool', wall_seconds=30,
                  argv=[base64.b64encode(b'/bin/true').decode()],
                  secrets=[dict(id=name, data=base64.b64encode(b'v').decode()) for name in ('a', 'a/b')])
        self.assertEqual(stream.recv(1000), b'')
        self.wait_recorded(lambda frame: frame.get('op') == 'cancel2')
        self.assertEqual([frame['op'] for frame in self.recorded() if 'op' in frame and frame['op'] != 'session'],
                         ['cancel2'], 'a nested id reached the guest')
        self.assertTrue(self.control('status')['warm'])
        self.control('stop')
        child.wait(timeout=6)

    def test_a_secret_the_guest_refuses_cancels_only_that_attempt(self):
        child = self.launch(REFUSE_SECRET='1')
        stream = self.socket('attempt')
        self.frame(stream)
        self.send(stream, op='prepare', attempt_id='host', profile='tool', wall_seconds=30,
                  argv=[base64.b64encode(b'/bin/true').decode()],
                  secrets=[dict(id='token', data=base64.b64encode(b'v').decode())])
        self.assertEqual(stream.recv(1000), b'')
        self.assertTrue(self.control('status')['warm'])
        self.control('stop')
        child.wait(timeout=6)

    def test_a_session_that_misstates_the_share_is_refused(self):
        # D7, staged mode: a guest claiming a share, or a controller too old
        # to say, never serves an attempt.
        for live in ('1', 'omit'):
            with self.subTest(live=live):
                child = self.launch(LIVE_SHARE=live)
                stderr = self.assert_exit(child, 125)
                self.assertIn('live', stderr)
                self.assertFalse((self.root / 'data/vm/attempt.sock').exists())

    def test_a_live_workspace_on_a_folding_volume_refuses_before_boot(self):
        workspace = self.root / 'workspace'
        workspace.mkdir()
        child = self.launch(args=('--live-workspace', str(workspace)), RECORD=str(self.root / 'record.ndjson'))
        self.assertIn('folds case', self.assert_exit(child, 125))
        self.assertEqual(self.recorded(), [], 'the custodian was started for a refused share')

    def case_sensitive_workspace(self):
        """A workspace on a small case-sensitive APFS volume (the Mac's
        default volume folds case and is refused), under a unique name."""
        name = 'UKAI-SERVE-' + uuid.uuid4().hex[:12].upper()
        image = self.root / 'share.dmg'
        subprocess.run(['hdiutil', 'create', '-size', '16m', '-fs', 'Case-sensitive APFS', '-volname', name,
                        str(image)], check=True, capture_output=True)
        volume = Path('/Volumes') / name
        subprocess.run(['hdiutil', 'attach', '-nobrowse', '-mountpoint', str(volume), str(image)],
                       check=True, capture_output=True)
        self.addCleanup(subprocess.run, ['hdiutil', 'detach', str(volume)], capture_output=True)
        workspace = volume / 'ws'
        workspace.mkdir()
        (workspace / 'file.txt').write_text('x')
        return workspace

    def test_a_live_workspace_is_attached_stated_and_never_staged(self):
        workspace = self.case_sensitive_workspace()
        record = str(self.root / 'record.ndjson')
        child = self.launch(args=('--live-workspace', str(workspace)), RECORD=record)
        start = self.wait_recorded(lambda frame: 'helper_argv' in frame)[0]
        self.assertEqual(start['helper_argv'][-1], str(workspace.resolve()))
        status = self.control('status')
        self.assertEqual(status['live_workspace'], str(workspace.resolve()))
        self.assertIs(status['live_workspace_facts']['case_fold'], False)
        stream = self.socket('attempt')
        self.frame(stream)
        self.send(stream, op='prepare', attempt_id='host', profile='tool', wall_seconds=30,
                  argv=[base64.b64encode(b'/bin/true').decode()], secrets=[])
        self.assertEqual(self.frame(stream)['event'], 'prepared')
        self.send(stream, op='put', path='file.txt', executable=False, data=base64.b64encode(b'y').decode())
        self.assertEqual(stream.recv(1000), b'', 'a live service staged a file')
        self.assertNotIn('put', [frame.get('op') for frame in self.recorded()])
        self.control('stop')
        child.wait(timeout=6)
        # D7: a guest that did not mount the attached share is refused.
        (self.root / 'record.ndjson').unlink()
        child = self.launch(args=('--live-workspace', str(workspace)), LIVE_SHARE='0')
        self.assertIn('did not mount the live workspace share', self.assert_exit(child, 125))

    def test_a_guest_that_powered_itself_off_is_named(self):
        child = self.launch(POWEROFF_REASON='live_share_mount_failed')
        stderr = self.assert_exit(child, 125)
        self.assertIn('guest poweroff: live_share_mount_failed', stderr)

    def test_a_suspended_service_keeps_its_custody_lease(self):
        child = self.launch()
        self.assertTrue(self.control('status')['warm'])
        custodian = int(subprocess.run(['pgrep', '-P', str(child.pid)], capture_output=True,
                                       text=True, check=True).stdout.split()[0])
        # A Ctrl-Z of the group stops the custodian too, and nothing orders
        # who runs first after the resume: here the service does, so its
        # first look finds no acknowledgement. Shorter than the stand-in
        # custodian's own 3 s lease, longer than the service's 1.5 s
        # acknowledgement budget: only the wake-gap reset saves it.
        os.kill(custodian, signal.SIGSTOP)
        child.send_signal(signal.SIGSTOP)
        time.sleep(2.2)
        child.send_signal(signal.SIGCONT)
        time.sleep(.1)
        os.kill(custodian, signal.SIGCONT)
        time.sleep(.5)
        self.assertIsNone(child.poll(), child.stderr.read1().decode() if child.poll() is not None else '')
        self.assertTrue(self.control('status')['warm'])
        self.control('stop')
        child.wait(timeout=6)

    def test_failed_boot_evidence_is_kept_but_bounded(self):
        runtime = self.root / 'data/vm'
        runtime.mkdir(parents=True)
        old = []
        for index in range(5):
            boot = runtime / f'vm-old-{index}'
            boot.mkdir()
            stamp = time.time() - 3600 + index * 60
            os.utime(boot, (stamp, stamp))
            old.append(boot)
        child = self.launch(ACK_MODE='silent')
        self.assertIn('evidence retained at', self.assert_exit(child, 125))
        boots = sorted(path.name for path in runtime.iterdir() if path.name.startswith('vm-'))
        self.assertEqual(len(boots), 3, boots)
        self.assertIn('vm-old-4', boots)
        self.assertIn('vm-old-3', boots)
        self.assertEqual(len([name for name in boots if not name.startswith('vm-old-')]), 1)

    def test_version_and_doctor_report_the_package_version(self):
        version = json.loads(subprocess.run([str(BINARY), 'version'], env=self.env, capture_output=True,
                                            timeout=6, check=True).stdout)
        expected = os.environ.get('UKAI_VM_EXPECTED_VERSION')
        if expected:
            self.assertEqual(version['version'], expected)
        else:
            self.assertTrue(version['version'].endswith('-dev'), version)
        doctor = subprocess.run([str(BINARY), 'doctor'], env=self.env, capture_output=True, timeout=10)
        self.assertEqual(json.loads(doctor.stdout)['version'], version['version'])

    def test_status_prints_object_and_absent_stop_prints_once(self):
        child = self.launch()
        self.control('status')
        status = subprocess.run([str(BINARY), 'status'], env=self.env, capture_output=True, timeout=4)
        self.assertEqual(json.loads(status.stdout)['event'], 'status')
        self.control('stop')
        child.wait(timeout=6)
        stopped = subprocess.run([str(BINARY), 'stop'], env=self.env, capture_output=True, timeout=4)
        self.assertEqual(stopped.stdout.decode().strip(), 'ukai-vm: no VM is running')


if __name__ == '__main__':
    unittest.main()
