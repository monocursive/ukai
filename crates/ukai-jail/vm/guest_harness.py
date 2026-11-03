"""Drive guest.py's `main()` without a VM: a socketpair for the vsock, a
model of the kernel's cgroup and /proc interfaces, a scripted stand-in for
the Linux jail, and a virtual clock.

The model keeps the facts the controller reads in files, in the kernel's
own formats (`cgroup.events`, `/proc/<pid>/status`, `/proc/<pid>/cgroup`),
so the controller's parsing and decisions run unchanged; only the four
acting hooks (`make_cgroup`, `cgroup_kill`, `remove_cgroup`, and
`subprocess`) are the model's. The stand-in jail behaves like the measured
Linux jail (K111/K113 guest receipts): once the controller has moved it
into the attempt cgroup it moves itself into
`user@<uid>.service/app.slice/ukai-jail-<pid>-<hex>.scope` and runs its
workload in a leaf directly under `user@<uid>.service`.

What the model cannot show is listed in the module docstring of
test_guest_main.py and is the live phase's to measure.
"""
import base64
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import types
from unittest import mock

GUEST = Path(__file__).with_name('guest.py')
_instances = itertools.count()


class PoweredOff(BaseException):
    """What the patched `poweroff` raises: the controller's own exits are
    exceptions to it only once it has decided to end the guest."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def load_guest():
    """A fresh guest module: its globals (the live-share switch, the
    attempt counter, the staged TOML) never leak between tests."""
    spec = importlib.util.spec_from_file_location(f'guest_under_test_{next(_instances)}', GUEST)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Clock:
    """Virtual CLOCK_BOOTTIME: it moves only when the controller sleeps or a
    test advances it, so bounded waits are measured without waiting. A wait
    that sleeps past `RUNAWAY` virtual seconds is an unbounded one: it fails
    the test at once instead of hanging the suite."""

    RUNAWAY = 600

    def __init__(self):
        self.start = self.now = 1000.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(float(seconds), 0.001)
        if self.now - self.start > self.RUNAWAY:
            raise AssertionError('a controller wait ran past every budget (virtual clock runaway)')

    def advance(self, seconds):
        self.now += seconds


class Process:
    def __init__(self, pid, uid, cgroup, exe, unkillable=False):
        self.pid, self.uid, self.cgroup, self.exe = pid, uid, cgroup, exe
        self.unkillable = unkillable
        self.alive = True
        self.killed = False


def within(member, boundary):
    return member == boundary or member.startswith(boundary + '/')


class Kernel:
    """The cgroup tree and /proc the controller sees, kept in files."""

    def __init__(self, root, uid):
        self.root = Path(root)
        self.cgroups = self.root / 'cgroup'
        self.proc = self.root / 'proc'
        self.uid = uid
        self.processes = {}
        self.pids = itertools.count(200)
        self.kills = []
        self.lock = threading.RLock()
        self.cgroups.mkdir(parents=True)
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('guest-boot-0001\n')
        for path in ('user.slice', f'user.slice/user-{uid}.slice', self.delegated,
                     f'{self.delegated}/init.scope', f'{self.delegated}/session.slice',
                     f'{self.delegated}/session.slice/dbus.service', f'{self.delegated}/app.slice'):
            self.make_cgroup(self.cgroups / path)
        # The user manager's own processes (prepare.py's lingering account):
        # they must survive every attempt's stop.
        self.manager = self.spawn(uid, f'{self.delegated}/init.scope', '/usr/lib/systemd/systemd')
        self.sd_pam = self.spawn(uid, f'{self.delegated}/init.scope', '/usr/lib/systemd/systemd-executor')
        self.bus = self.spawn(uid, f'{self.delegated}/session.slice/dbus.service', '/usr/bin/dbus-daemon')

    @property
    def delegated(self):
        return f'user.slice/user-{self.uid}.slice/user@{self.uid}.service'

    def relative(self, path):
        return str(Path(path).relative_to(self.cgroups))

    # -- the hooks guest.py calls ------------------------------------------

    def make_cgroup(self, path):
        path = Path(path)
        path.mkdir()
        (path / 'cgroup.events').write_text('populated 0\nfrozen 0\n')
        (path / 'cgroup.kill').write_text('')
        (path / 'cgroup.procs').write_text('')
        (path / 'cgroup.controllers').write_text('cpu memory pids\n')
        (path / 'cgroup.subtree_control').write_text('')

    def kill(self, path):
        with self.lock:
            boundary = self.relative(path)
            if not (Path(path) / 'cgroup.kill').exists():
                raise FileNotFoundError(str(path))
            self.kills.append(boundary)
            for process in list(self.processes.values()):
                if process.alive and within(process.cgroup, boundary) and not process.unkillable:
                    process.killed = True
                    self.exit(process)
            self.refresh()

    def remove(self, path):
        with self.lock:
            boundary = self.relative(path)
            if any(p.alive and within(p.cgroup, boundary) for p in self.processes.values()):
                raise OSError(16, 'Device or resource busy')
            if any(child.is_dir() for child in Path(path).iterdir()):
                raise OSError(39, 'Directory not empty')
            shutil.rmtree(path)

    # -- the model's own operations ----------------------------------------

    def ensure(self, cgroup):
        directory = self.cgroups / cgroup
        for path in [*reversed(directory.parents), directory]:
            if path.is_relative_to(self.cgroups) and path != self.cgroups and not path.exists():
                self.make_cgroup(path)

    def spawn(self, uid, cgroup, exe, unkillable=False):
        with self.lock:
            self.ensure(cgroup)
            process = Process(next(self.pids), uid, cgroup, exe, unkillable)
            self.processes[process.pid] = process
            self.write_proc(process)
            self.refresh()
            return process

    def move(self, process, cgroup):
        with self.lock:
            self.ensure(cgroup)
            process.cgroup = cgroup
            self.write_proc(process)
            self.refresh()

    def exit(self, process):
        with self.lock:
            process.alive = False
            shutil.rmtree(self.proc / str(process.pid), ignore_errors=True)
            self.refresh()

    def write_proc(self, process):
        directory = self.proc / str(process.pid)
        directory.mkdir(exist_ok=True)
        uid = process.uid
        (directory / 'status').write_text(
            f'Name:\t{Path(process.exe).name}\nState:\tS (sleeping)\n'
            f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        (directory / 'cgroup').write_text(f'0::/{process.cgroup}\n')

    def refresh(self):
        live = [p.cgroup for p in self.processes.values() if p.alive]
        for events in self.cgroups.rglob('cgroup.events'):
            boundary = self.relative(events.parent)
            populated = any(within(member, boundary) for member in live)
            events.write_text(f'populated {int(populated)}\nfrozen 0\n')

    def alive_in(self, cgroup_prefix):
        return [p for p in self.processes.values() if p.alive and within(p.cgroup, cgroup_prefix)]


def argv_digest(argv):
    preimage = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(argv))
    preimage += b''.join(struct.pack('>Q', len(value)) + value for value in argv)
    return 'sha256:' + hashlib.sha256(preimage).hexdigest()


class FakeJail:
    """One `subprocess.Popen` of the join wrapper + guest jail."""

    def __init__(self, kernel, argv, scenario, **kwargs):
        self.kernel = kernel
        self.argv = [os.fsencode(part) for part in argv]
        self.kwargs = kwargs
        self.scenario = scenario
        out_read, self.out_write = os.pipe()
        err_read, self.err_write = os.pipe()
        self.stdout = os.fdopen(out_read, 'rb', buffering=0)
        self.stderr = os.fdopen(err_read, 'rb', buffering=0)
        self.returncode = None
        self.started = False
        # The wrapper starts in the controller's own service cgroup.
        self.process = kernel.spawn(kwargs['user'], 'system.slice/ukai-vm.service', '/bin/sh')
        self.pid = self.process.pid
        self.children = []

    # The parts of the command the jail reads.
    def command(self):
        return self.argv[self.argv.index(b'join-cgroup') + 2:]

    def option(self, name):
        command = self.command()
        return command[command.index(name) + 1]

    def workload_argv(self):
        command = self.command()
        return command[command.index(b'--') + 1:]

    def attempt_cgroup(self):
        return Path(os.fsdecode(self.argv[self.argv.index(b'join-cgroup') + 1]))

    def write(self, stream, data):
        os.write(self.out_write if stream == 'stdout' else self.err_write, data)

    def close_streams(self):
        for fd in (self.out_write, self.err_write):
            try:
                os.close(fd)
            except OSError:
                pass

    def exit(self, code):
        for child in self.children:
            if child.alive:
                self.kernel.exit(child)
        self.kernel.exit(self.process)
        self.close_streams()
        self.returncode = code

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        if not self.process.alive:
            self.close_streams()
            self.returncode = -9
            return self.returncode
        if not self.started:
            self.first_poll()
            self.started = True
        return self.returncode

    def first_poll(self):
        attempt = self.attempt_cgroup()
        joined = (attempt / 'cgroup.procs').read_text().split()
        if str(self.pid) not in joined:
            # The real wrapper waits ten seconds for the move, then exits.
            self.write('stderr', f'CGROUP_JOIN_TIMEOUT:{attempt}\n'.encode())
            self.exit(124)
            return
        self.kernel.move(self.process, self.kernel.relative(attempt))
        # The supervisor's own step (platform/linux/scope.rs): outside the
        # delegated subtree, it asks the user manager for a scope and moves
        # itself there.
        self.kernel.move(self.process, f'{self.kernel.delegated}/app.slice/'
                                       f'ukai-jail-{self.pid}-0123456789abcdef.scope')
        self.scenario(self)

    def wait(self, timeout=None):
        raise AssertionError('the controller must never wait unbounded on the jail')

    # -- what a scenario can do ----------------------------------------------

    def workload(self, unkillable=False):
        """A workload child in the jail's execution leaf, as the receipts
        record it: directly under user@<uid>.service."""
        child = self.kernel.spawn(self.process.uid, f'{self.kernel.delegated}/ukai-att_{self.pid}.leaf',
                                  '/usr/bin/sleep', unkillable=unkillable)
        self.children.append(child)
        return child

    def write_receipt(self, profile=None, boot_id=None):
        argv = self.workload_argv()
        receipt = {'schema': 'ukai.jail.receipt/1', 'attempt_id': f'att_guest_{self.pid}',
                   'argv_digest': argv_digest(argv),
                   'policy': {'name': profile or os.fsdecode(self.option(b'--profile'))},
                   'process': {'identity': {'value': {'boot_id': boot_id or 'guest-boot-0001'}}}}
        path = Path(os.fsdecode(self.option(b'--receipt')))
        path.write_text(json.dumps(receipt))


def complete(code=0, stdout=b'guest stdout\n', workspace_file=None, leftover=None):
    """A jail that runs, writes its receipt and exits. `leftover` names a
    cgroup (under the user manager) where it leaves a process of the
    workload account behind, as an escaped daemon would."""
    def scenario(jail):
        jail.workload()
        jail.write('stdout', stdout)
        if workspace_file is not None:
            (Path(jail.kwargs['cwd']) / workspace_file).write_text('written by the workload\n')
        jail.write_receipt()
        if leftover is not None:
            jail.kernel.spawn(jail.process.uid, f'{jail.kernel.delegated}/{leftover}', '/usr/bin/sleep')
        jail.exit(code)
    return scenario


def hold(unkillable=False):
    """A jail that runs until it is killed."""
    def scenario(jail):
        jail.workload(unkillable=unkillable)
    return scenario


class FakeSubprocess:
    DEVNULL = subprocess.DEVNULL
    PIPE = subprocess.PIPE
    SubprocessError = subprocess.SubprocessError
    TimeoutExpired = subprocess.TimeoutExpired
    CalledProcessError = subprocess.CalledProcessError
    CompletedProcess = subprocess.CompletedProcess

    def __init__(self, harness):
        self.harness = harness
        self.jails = []
        self.runs = []

    def Popen(self, argv, **kwargs):  # noqa: N802 - the subprocess spelling
        scenario = self.harness.scenarios.pop(0) if self.harness.scenarios else complete()
        jail = FakeJail(self.harness.kernel, argv, scenario, **kwargs)
        self.jails.append(jail)
        return jail

    def run(self, argv, **kwargs):
        self.runs.append((list(argv), kwargs))
        if argv[:1] == ['mount']:
            if self.harness.mount_result == 'ok':
                self.harness.mounted = True
                return subprocess.CompletedProcess(argv, 0)
            raise subprocess.CalledProcessError(32, argv)
        return subprocess.CompletedProcess(argv, 0)


class FakeListener:
    def __init__(self, conn, cid):
        self.conn, self.cid = conn, cid

    def accept(self):
        return self.conn, (self.cid, 1024)


class GuestHarness:
    """One booted guest controller, its host end, and the model around it.

    `share` is None (no device: the staged mode), 'mounts' (device present,
    mount works) or 'fails' (device present, mount fails)."""

    def __init__(self, test, share=None, peer_cid=2, scenarios=(), start=True):
        self.test = test
        temporary = tempfile.TemporaryDirectory(prefix='ukai-guest-')
        test.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.clock = Clock()
        self.uid, self.gid = os.getuid(), os.getgid()
        self.kernel = Kernel(self.root / 'sys', self.uid)
        self.home = self.root / 'home/ukai'
        self.home.mkdir(parents=True)
        self.account = types.SimpleNamespace(pw_name='ukai', pw_uid=self.uid, pw_gid=self.gid,
                                             pw_dir=str(self.home))
        self.secrets = self.root / 'run/ukai-vm/credentials'
        self.scenarios = list(scenarios)
        self.mounted = False
        self.mount_result = 'ok' if share == 'mounts' else 'fails'
        virtio = self.root / 'sys/bus/virtio/devices'
        (virtio / 'virtio0').mkdir(parents=True)
        (virtio / 'virtio0/device').write_text('0x0001\n')  # the network adapter
        if share is not None:
            (virtio / 'virtio1').mkdir()
            (virtio / 'virtio1/device').write_text('0x001a\n')  # VIRTIO_ID_FS
        self.audits = []
        self.notifies = []
        self.reason = None
        self.error = None
        g = self.guest = load_guest()
        g.CGROUP_ROOT = self.kernel.cgroups
        g.PROC_ROOT = self.kernel.proc
        g.VIRTIO_DEVICES = virtio
        g.WORKSPACE = self.home / 'workspace'
        g.EVIDENCE = self.home / 'evidence'
        g.CONFIG_DIR = self.root / 'config'
        g.SHARE_MOUNT = self.root / 'mnt/workspace'
        g.make_cgroup = self.kernel.make_cgroup
        g.cgroup_kill = self.kernel.kill
        g.remove_cgroup = self.kernel.remove
        g.subprocess = self.subprocess = FakeSubprocess(self)
        g.pwd = types.SimpleNamespace(getpwnam=lambda name: self.account)
        g.clock = self.clock.clock
        g.time = types.SimpleNamespace(sleep=self.clock.sleep)
        g.audit = lambda event, **fields: self.audits.append((event, fields))
        g.notify = lambda: self.notifies.append(self.clock.now)
        g.share_mounted = lambda: self.mounted
        g.poweroff = self._poweroff
        patcher = mock.patch.dict(os.environ, {'UKAI_VM_SECRETS': str(self.secrets)})
        patcher.start()
        test.addCleanup(patcher.stop)
        self.host, guest_end = socket.socketpair()
        self.host.settimeout(10)
        self._guest_end = guest_end
        g.vsock_listener = lambda: FakeListener(guest_end, peer_cid)
        self.buffer = b''
        self.thread = threading.Thread(target=self._run, daemon=True)
        test.addCleanup(self.close)
        if start:
            self.thread.start()

    def _poweroff(self, reason):
        self.audits.append(('poweroff', {'reason': reason}))
        raise PoweredOff(reason)

    def _run(self):
        try:
            self.guest.main()
        except PoweredOff as off:
            self.reason = off.reason
        except BaseException as error:  # the test reports it
            self.error = error
        finally:
            self._guest_end.close()

    def close(self):
        self.host.close()
        self.thread.join(timeout=10)
        for jail in self.subprocess.jails:
            jail.close_streams()
            for stream in (jail.stdout, jail.stderr):
                stream.close()

    def started_jail(self, index=0):
        """The `index`th jail once the controller has polled it (its first
        poll plays the wrapper's join and the supervisor's scope move)."""
        deadline = time.monotonic() + 10
        while len(self.subprocess.jails) <= index or not self.subprocess.jails[index].started:
            if time.monotonic() > deadline:
                self.test.fail('the controller never polled its jail')
            time.sleep(.005)
        return self.subprocess.jails[index]

    # -- the host's side of the vsock --------------------------------------

    def send(self, **frame):
        self.host.sendall(json.dumps(frame).encode() + b'\n')

    def frame(self):
        while b'\n' not in self.buffer:
            chunk = self.host.recv(65536)
            if not chunk:
                return None
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        return json.loads(line)

    def expect(self, event):
        """The next `event` frame, skipping output frames; fails the test with
        the guest's poweroff reason if the guest ends first."""
        seen = []
        while True:
            frame = self.frame()
            if frame is None:
                self.thread.join(timeout=10)
                self.test.fail(f'guest ended before {event!r}: poweroff={self.reason!r} '
                               f'error={self.error!r} after {[f["event"] for f in seen]}')
            seen.append(frame)
            if frame['event'] == event:
                frame['_seen'] = seen
                return frame
            if frame['event'] == 'error' and event != 'error':
                self.test.fail(f'guest error before {event!r}: {frame}')

    def ended(self, raise_error=True):
        """The guest's poweroff reason, once it ends (reading to EOF)."""
        while self.frame() is not None:
            pass
        self.thread.join(timeout=10)
        self.test.assertFalse(self.thread.is_alive(), 'the controller did not end')
        if self.error is not None and raise_error:
            raise self.error
        return self.reason

    def session(self):
        ready = self.expect('ready')
        self.send(op='session')
        return ready, self.expect('session')

    def run2(self, profile='tool', argv=(b'/bin/true',), **extra):
        self.send(op='run2', attempt_id='host-attempt', boot_id='vm-boot', profile=profile,
                  wall_seconds=30, argv=[base64.b64encode(a).decode() for a in argv], **extra)
