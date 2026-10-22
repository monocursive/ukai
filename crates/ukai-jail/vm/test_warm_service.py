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

def emit(value):
    print(json.dumps(value), flush=True)

def guest(value, split=False):
    raw = (json.dumps(value) + '\n').encode()
    for offset in range(0, len(raw), 65536 if split else len(raw)):
        emit(dict(event='data', data=base64.b64encode(raw[offset:offset+65536] if split else raw).decode()))

guest(dict(event='ready', kernel='stand-in-kernel'))
sessions = 0
for line in sys.stdin:
    message = json.loads(line)
    if message['op'] == 'stop':
        emit(dict(event='stopped'))
        break
    for raw in base64.b64decode(message['data']).splitlines():
        request = json.loads(raw)
        op = request['op']
        if op == 'session':
            sessions += 1
            if sessions > 1:
                guest(dict(event='error', message='duplicate session'))
                sys.exit(125)
            guest(dict(event='session', kernel='stand-in-kernel'))
            if os.environ.get('EXIT_AFTER_SESSION') == '1': sys.exit(1)
        elif op == 'reset':
            guest(dict(event='reset'))
        elif op == 'cancel2':
            guest(dict(event='cancelled'))
        elif op == 'put':
            guest(dict(event='put', path=request['path']))
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
            guest(dict(event='done', exit_code=0, binding=binding))
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

    def launch(self, idle=600, **env):
        child = subprocess.Popen([str(BINARY), 'serve', '--idle-seconds', str(idle)],
                                 env=dict(self.env, **env), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.children.append(child)
        return child

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

    def attempt(self):
        stream = self.socket('attempt')
        ready = self.frame(stream)
        self.send(stream, op='prepare', attempt_id='host-attempt', profile='tool',
                  wall_seconds=30, argv=[base64.b64encode(b'/bin/true').decode()], secrets=[])
        self.assertEqual(self.frame(stream)['event'], 'prepared')
        self.send(stream, op='run')
        self.assertEqual(self.frame(stream)['event'], 'released')
        return stream, ready

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
                child.wait(timeout=6)

    def test_ack_invalid_or_absent_terminates_within_bound(self):
        for mode in ('invalid', 'silent'):
            with self.subTest(mode=mode):
                child = self.launch(ACK_MODE=mode)
                child.wait(timeout=6)

    def test_helper_death_and_stop_during_silent_attempt_are_bounded(self):
        child = self.launch(EXIT_AFTER_SESSION='1')
        child.wait(timeout=6)
        child = self.launch()
        stream = self.socket('attempt')
        self.frame(stream)  # never send prepare
        self.control('stop')
        child.wait(timeout=6)

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
                     warm=False, attempt_live=False, kernel=None, disk_sha256='d'*64,
                     helper_sha256='h'*64, custodian_sha256='c'*64, seed_sha256='s'*64,
                     vsock_port=1024, idle_seconds=600)
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
