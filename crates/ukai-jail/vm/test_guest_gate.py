"""Real pipe/exec controls and Linux pidfd setup-cleanup regressions."""
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from guest_harness import GuestHarness, hold, load_guest


class GateWireTests(unittest.TestCase):
    def setUp(self):
        self.guest = load_guest()
        temporary = tempfile.TemporaryDirectory(prefix='ukai-gate-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_constructor_failure_closes_both_pipe_descriptors(self):
        descriptors = os.pipe()
        with mock.patch.object(self.guest.os, 'pipe', return_value=descriptors), \
             mock.patch.object(self.guest.os, 'set_blocking', side_effect=OSError('synthetic setup failure')):
            with self.assertRaises(OSError): self.guest.AttemptGate()
        for descriptor in descriptors:
            with self.assertRaises(OSError) as error: os.fstat(descriptor)
            self.assertEqual(error.exception.errno, errno.EBADF)

    def spawn(self, code, args=(), environment=None, cwd=None, account=None):
        gate = self.guest.AttemptGate()
        self.assertLess(gate.reader, 1024)
        identity = os.fstat(gate.reader)
        command = [os.fsencode(sys.executable), b'-I', b'-S', b'-c', code.encode(), *args]
        env = {b'PATH': b'/usr/bin:/bin', b'LANG': b'C.UTF-8'}
        env.update(environment or {})
        options = {} if account is None else dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
        process = subprocess.Popen(gate.command(command), pass_fds=(gate.reader,), close_fds=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, cwd=cwd, **options)
        gate.close('reader')
        def close():
            gate.close('reader'); gate.close('writer')
            if gate.pin is not None: gate.pin.close()
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=2)
        self.addCleanup(close)
        return gate, process, (identity.st_dev, identity.st_ino)

    def test_exact_byte_argv_environment_and_same_pid_exec(self):
        code = "import json,os,sys;print(json.dumps({'pid':os.getpid(),'argv':[os.fsencode(v).hex() for v in sys.argv[1:]],'value':os.environb[b'GATE_BYTES'].hex(),'environment':{k.hex():v.hex() for k,v in os.environb.items()}}))"
        values = [b'\xff\xfe', b' spaces\n$() ', b'', b'--literal']
        gate, process, _ = self.spawn(code, values, {b'GATE_BYTES': b'\xfe\x80 literal\n'})
        self.assertFalse(select.select([process.stdout], [], [], .05)[0])
        os.write(gate.writer, b'R'); gate.close('writer')
        out, err = process.communicate(timeout=3)
        self.assertEqual((process.returncode, err), (0, b''))
        result = json.loads(out)
        environment = result.pop('environment')
        if sys.platform.startswith('linux'):
            self.assertEqual(environment, {k.hex(): v.hex() for k,v in {
                b'PATH':b'/usr/bin:/bin',b'LANG':b'C.UTF-8',b'GATE_BYTES':b'\xfe\x80 literal\n'}.items()})
        # Apple's /usr/bin/python3 is a CLT launcher that may add SDK metadata;
        # the Linux row above exercises the actual guest interpreter contract.
        self.assertEqual(result, {'pid': process.pid, 'argv': [v.hex() for v in values],
                                  'value': b'\xfe\x80 literal\n'.hex()})

    def test_eof_wrong_or_multiple_bytes_never_execute(self):
        for wire in (b'', b'X', b'RR'):
            with self.subTest(wire=wire):
                gate, process, _ = self.spawn("print('SHOULD_NOT_EXECUTE')")
                if wire: os.write(gate.writer, wire)
                gate.close('writer')
                out, err = process.communicate(timeout=3)
                self.assertEqual((process.returncode, out, err),
                                 (125, b'', b'UKAI_CGROUP_JOIN_REFUSED\n'))

    def test_isolated_helper_ignores_workspace_and_python_environment(self):
        marker = self.root/'imported'
        poison = f"open({str(marker)!r},'w').write('unsafe import');raise RuntimeError('poison')"
        for module in ('sitecustomize.py', 'select.py', 'time.py'):
            (self.root/module).write_text(poison)
        gate, process, _ = self.spawn("print('SAFE')", environment={
            b'PYTHONPATH': os.fsencode(self.root), b'PYTHONSTARTUP': os.fsencode(self.root/'sitecustomize.py')}, cwd=self.root)
        os.write(gate.writer, b'R'); gate.close('writer')
        out, err = process.communicate(timeout=3)
        self.assertEqual((process.returncode, out, err), (0, b'SAFE\n', b''))
        self.assertFalse(marker.exists())

    def test_gate_and_other_inheritable_descriptors_absent_after_exec(self):
        extra = os.open(self.root/'private', os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, extra)
        os.set_inheritable(extra, True)
        external = os.fstat(extra)
        code = """import json,os
found=[]
for fd in range(3,1024):
 try:
  s=os.fstat(fd);found.append([s.st_dev,s.st_ino])
 except OSError:pass
print(json.dumps(found))
"""
        gate, process, identity = self.spawn(code)
        self.assertLess(extra, 1024)
        os.write(gate.writer, b'R'); gate.close('writer')
        out, err = process.communicate(timeout=3)
        self.assertEqual((process.returncode, err), (0, b''))
        self.assertNotIn(list(identity), json.loads(out))
        self.assertNotIn([external.st_dev, external.st_ino], json.loads(out))


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'),
                     'requires actual Linux procfs and pidfd signaling')
class LinuxGateTests(GateWireTests):
    def held(self, process, identity):
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            try:
                for fd in (Path('/proc')/str(process.pid)/'fd').iterdir():
                    info = fd.stat()
                    if (info.st_dev, info.st_ino) != identity: continue
                    flags = next(line.split()[1] for line in
                                 (fd.parent.parent/'fdinfo'/fd.name).read_text().splitlines()
                                 if line.startswith('flags:'))
                    if int(flags, 8) & os.O_CLOEXEC:
                        return
            except (FileNotFoundError, ProcessLookupError):
                pass
            self.assertIsNone(process.poll(), 'gate exited before release')
            time.sleep(.005)
        self.fail('gate never restored close-on-exec on its held read descriptor')

    def test_held_gate_has_no_children_before_same_pid_exec(self):
        gate, process, identity = self.spawn("import os;print(os.getpid())")
        gate.attach(process)
        self.held(process, identity)
        self.assertEqual((Path('/proc')/str(process.pid)/'task'/str(process.pid)/'children').read_text().strip(), '')
        self.assertFalse(select.select([process.stdout], [], [], 0)[0])
        gate.release()
        out, err = process.communicate(timeout=3)
        self.assertEqual((process.returncode, err, int(out)), (0, b'', process.pid))

    def test_absolute_timeout_refuses_without_exec(self):
        gate, process, identity = self.spawn("print('SHOULD_NOT_EXECUTE')")
        self.held(process, identity)
        started = time.monotonic()
        out, err = process.communicate(timeout=12)
        self.assertLess(time.monotonic()-started, 11)
        self.assertEqual((process.returncode, out, err), (125, b'', b'UKAI_CGROUP_JOIN_REFUSED\n'))

    def test_setup_failure_kills_only_captured_pidfd_and_reaps(self):
        gate, process, identity = self.spawn("print('SHOULD_NOT_EXECUTE')")
        with mock.patch.object(process, 'kill', side_effect=AssertionError('numeric PID signal')):
            with self.assertRaisesRegex(OSError, 'setup failure'):
                with gate:
                    gate.attach(process); self.held(process, identity)
                    raise OSError('setup failure')
        self.assertIsNotNone(process.returncode)
        self.assertEqual(process.stdout.read(), b'')
        self.assertIsNone(gate.pin.fd)

    def test_pidfd_open_failure_uses_eof_refusal_and_bounded_reap(self):
        gate, process, _ = self.spawn("print('SHOULD_NOT_EXECUTE')")
        with mock.patch.object(self.guest, 'AttemptProcessPin', side_effect=OSError(errno.EMFILE, 'synthetic')):
            with self.assertRaises(OSError):
                with gate: gate.attach(process)
        self.assertEqual(process.returncode, 125)
        self.assertEqual(process.stdout.read(), b'')

    def test_post_release_setup_error_handles_already_reaped_process(self):
        gate, process, _ = self.spawn("print('finished')")
        with self.assertRaisesRegex(OSError, 'send failure'):
            with gate:
                gate.attach(process); gate.release()
                process.communicate(timeout=3)  # Equivalent to Monitor.poll reaping.
                self.assertEqual(process.returncode, 0)
                raise OSError('send failure')
        self.assertIsNone(gate.pin.fd)

    def test_release_to_dead_reader_refuses_and_closes_pin(self):
        gate, process, _ = self.spawn("print('SHOULD_NOT_EXECUTE')")
        with self.assertRaises(BrokenPipeError):
            with gate:
                gate.attach(process); gate.pin.kill()
                out, _ = process.communicate(timeout=3)
                self.assertEqual(out, b'')
                gate.release()
        self.assertFalse(gate.released)
        self.assertIsNone(gate.pin.fd)

    @unittest.skipUnless(os.geteuid() == 0, 'requires root to sample a separate synthetic workload UID')
    def test_monitor_initializes_before_release_and_observes_actual_child(self):
        import guest_exposure
        import pwd
        uid = 60000
        with self.assertRaises(KeyError): pwd.getpwuid(uid)
        account = types.SimpleNamespace(pw_uid=uid, pw_gid=uid)
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal(): continue
            try: status = (entry/'status').read_bytes()
            except (FileNotFoundError, ProcessLookupError): continue
            ids = next(line.split()[1:] for line in status.splitlines() if line.startswith(b'Uid:'))
            self.assertNotIn(str(uid).encode(), ids, 'synthetic workload UID is already occupied')
        token = b'UKAI_PUBLIC_GATE_CONTROL'
        code = "import os,time;print('READY',flush=True);time.sleep(2.5)"
        gate, process, identity = self.spawn(code, environment={b'PUBLIC_GATE_CANARY': token}, account=account, cwd='/tmp')
        gate.attach(process); self.held(process, identity)
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        monitor = guest_exposure.Monitor('/proc', boot, process, account.pw_uid, [], str(Path(sys.executable).resolve()), [token])
        self.addCleanup(monitor.discard)
        self.assertIsNotNone(monitor.sampler)
        self.assertIsNone(process.poll())
        released = time.monotonic_ns(); gate.release()
        self.assertTrue(select.select([process.stdout], [], [], 3)[0])
        self.assertEqual(process.stdout.readline(), b'READY\n')
        process_identity = (process.pid, monitor.supervisor[1])
        before = {channel: monitor.sampler.program_identity_counts.get(process_identity, {}).get(channel, {}).get('readable', 0)
                  for channel in ('environment', 'argv')}
        ticks_before = monitor.sampler.ticks
        out, err = process.communicate(timeout=4)
        self.assertTrue(monitor.stop(), 'sampler worker did not join')
        self.assertEqual((process.returncode, out, err), (0, b'', b''))
        self.assertLess(monitor.started, released)
        sampled = monitor.sampler
        self.assertEqual(set(sampled.identities), {process_identity})
        self.assertGreaterEqual(sampled.ticks-ticks_before, 2)
        self.assertEqual(dict(sampled.errors), {})
        for channel in ('environment', 'argv'):
            self.assertGreater(sampled.program_identity_counts[process_identity][channel]['readable'], before[channel])
        self.assertTrue(sampled.hits)
        self.assertTrue(all((hit['pid'], hit['starttime']) == process_identity for hit in sampled.hits))
        # This is an actual positive canary component control, never a
        # fabricated receipt or qualification of a native vendor attempt.


class ControllerGateTests(unittest.TestCase):
    def test_model_does_not_execute_until_real_gate_byte(self):
        h = GuestHarness(self, scenarios=[hold()])
        h.session()
        original = h.guest.move_into_attempt_cgroup
        observed = []
        def moved(path, pid):
            jail = h.subprocess.jails[0]
            self.assertIsNone(jail.poll()); self.assertFalse(jail.started)
            original(path, pid); observed.append(pid)
        h.guest.move_into_attempt_cgroup = moved
        h.run2(); h.expect('running')
        jail = h.started_jail()
        self.assertEqual(observed, [jail.pid]); self.assertTrue(jail.released)
        h.send(op='cancel2'); h.expect('cancelled')

    def test_native_outer_gate_then_prepared_monitor_and_managed_release(self):
        from test_guest_native import NativeControllerTests
        h = NativeControllerTests.create(self, scenarios=[hold()])
        NativeControllerTests.prepare(self, h); NativeControllerTests.secret(self, h)
        order = []
        pin, move, monitor, gate = (h.guest.AttemptProcessPin, h.guest.move_into_attempt_cgroup,
                                   h.guest.guest_exposure.Monitor, h.guest.AttemptGate)
        h.guest.AttemptProcessPin = lambda p: (order.append('pin'), pin(p))[1]
        h.guest.move_into_attempt_cgroup = lambda c,p: (order.append('move'), move(c,p))[1]
        def observe(*args, **kwargs):
            jail = h.subprocess.jails[0]
            self.assertTrue(jail.released); self.assertTrue(jail.initialized)
            self.assertFalse(jail.started)
            self.assertIn('/app.slice/ukai-jail-', jail.process.cgroup)
            self.assertEqual(kwargs['prepared_process'],
                             (jail.held_workload.pid, jail.held_workload.starttime))
            order.append('monitor')
            return monitor(*args, **kwargs)
        h.guest.guest_exposure = types.SimpleNamespace(**vars(h.guest.guest_exposure))
        h.guest.guest_exposure.Monitor = observe
        class OrderedGate(gate):
            def release(inner):
                order.append('outer_release')
                return super().release()
        h.guest.AttemptGate = OrderedGate
        NativeControllerTests.launch(self, h); h.expect('running')
        self.assertEqual(order[:3], ['pin', 'move', 'outer_release'])
        self.assertTrue(h.started_jail().released)
        self.assertEqual(order, ['pin', 'move', 'outer_release', 'monitor'])
        h.send(op='cancel2'); h.expect('cancelled')

    def test_failed_cgroup_move_never_releases_or_executes(self):
        h = GuestHarness(self, scenarios=[hold()]); h.session()
        def fail(*args): raise OSError('synthetic cgroup move failure')
        h.guest.move_into_attempt_cgroup = fail
        h.run2(); h.ended(raise_error=False)
        self.assertIsInstance(h.error, OSError)
        jail = h.subprocess.jails[0]
        self.assertFalse(jail.released); self.assertFalse(jail.started)
        self.assertFalse(jail.process.alive)


if __name__ == '__main__':
    unittest.main()
