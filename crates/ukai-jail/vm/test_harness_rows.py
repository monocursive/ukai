"""Every live harness's PASS predicate goes red on the failure it claims to detect.

One mutation table per harness: a passing observation, then each failure the
row exists to catch, applied one at a time, must fail the predicate it names.
Where the 2026-11-02/03 evidence committed a vacuous measurement, the old
observation is replayed and must now fail. No VM boots; services are fakes.

    python3 -s -E -m unittest test_harness_rows
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import capabilities
import claude_vm_row
import fault_matrix
import gate_rows
import harness
import proxy_measurement
import vault_measurement
import warm_live
from test_harness import EVIDENCE, FakeAttemptServer, probe_line, receipt_frame

T = 'tag01'
_GUARDS = []
_CREATED = []
_REAL_MKDTEMP = tempfile.mkdtemp


def _tracked_mkdtemp(*args, **kwargs):
    path = _REAL_MKDTEMP(*args, **kwargs)
    _CREATED.append(path)
    return path


def setUpModule():
    """No test here may reach past loopback: every probe aims at a closed loopback
    port, and the host reachability control is a fake. The harnesses' own
    mkdtemp()s stay in the system temp dir (a unix socket path has 104 bytes
    on macOS), so each one this process makes is recorded and removed after
    the module: exactly those, never anything else in a shared temp dir."""
    closed = __import__('socket').socket()
    closed.bind(('127.0.0.1', 0))
    port = closed.getsockname()[1]
    closed.close()
    for patcher in (mock.patch.object(tempfile, 'mkdtemp', _tracked_mkdtemp),
                    mock.patch.object(harness, 'PROBE_TARGET', ('127.0.0.1', port)),
                    mock.patch.object(harness, 'host_reachability',
                                      lambda *a, **k: {'answers': True, 'result': 'connected', 'fake': True})):
        patcher.start()
        _GUARDS.append(patcher)


def tearDownModule():
    while _GUARDS:
        _GUARDS.pop().stop()
    while _CREATED:
        shutil.rmtree(_CREATED.pop(), ignore_errors=True)


def assert_vm_client(case, argv, environment):
    """Every harness `ukai-jail run --vm`: S1's carried shape, or the host refuses."""
    if 'run' not in argv or '--vm' not in argv:
        return
    case.assertEqual(environment.get('LANG'), 'C.UTF-8')
    for name in ('TERM', 'TZ', 'UKAI_VM_GUEST_NAT'):
        case.assertNotIn(name, environment)
    case.assertFalse([name for name in environment if name.startswith('LC_')])
    case.assertEqual(argv[argv.index('--terminal') + 1], 'detach')
    walls = [argv[i + 1] for i, word in enumerate(argv) if word == '--limit']
    case.assertEqual(len(walls), 1, argv)
    case.assertRegex(walls[0], r'^wall=([1-9]\d?|[12]\d\d|300)s$')
    case.assertFalse({'--ro', '--rw'} & set(argv[:argv.index('--')]))


def record(stdout='', exit_code=0, receipt=None, timings=None, **extra):
    return {'stdout': stdout, 'stderr': '', 'exit_code': exit_code, 'error': None, 'receipt': receipt,
            'timings_ms': timings or {'released_to_done': 100.0, 'connect_to_released': 20.0}, **extra}


def limits(**hits):
    return {'applied': {'limits': [{'key': key, 'hit': value} for key, value in hits.items()]}}


def mutated(base, **changes):
    value = copy.deepcopy(base)
    value.update(changes)
    return value


class CapabilityTables(unittest.TestCase):
    FS = [f'/etc/ukai-cap-{T}', f'/usr/local/bin/ukai-cap-{T}', f'/ukai-cap-{T}']

    def good(self):
        fs = {'tag': T, 'paths': {path: {'open': 'EROFS', 'exists_after': False} for path in self.FS},
              'reads': {**{path: 'ENOENT' for path in capabilities.READ_OUTSIDE},
                        **{path: 'read' for path in capabilities.read_controls(T)}}}
        mem = ''.join(f'UKAI_MEM_PROBE {T} {n}\n' for n in range(16, 481, 16))
        return {
            'wall': record(f'start-{T}\n', 143, {**limits(wall=True), 'outcome': {'cause': 'wall_expiry'}},
                           {'released_to_done': 5100.0}),
            'pids': record('UKAI_PIDS_PROBE ' + json.dumps({'tag': T, 'forked': 61, 'fork_error': 'EAGAIN',
                                                            'pids.max': None, 'pids.current': None}) + '\n',
                           0, {**limits(pids=True), 'errors': []}),
            'mem': record(mem, 137, {**limits(mem=True), 'outcome': {'cause': 'memory_oom'}}),
            'containment': record('UKAI_FS_PROBE ' + json.dumps(fs) + '\n'),
            'network_none': record(probe_line(T, dns='unresolved--3') + '\n', 0,
                                   {'applied': {'network': {'mode': 'none'}}}),
            'workspace': record(f'wrote-{T}\n'),
        }

    def judge(self, results, status=None, reachability=None, host=f'live-{T}\n', git=True, exit_code=0):
        measured = {'tag': T, 'fs_paths': self.FS, 'results': results, 'host_workspace_file': host,
                    'reachability': reachability or {'answers': True}}
        return capabilities.judge(measured, status or {'guest_nat': True}, git, exit_code)

    def test_the_good_observation_passes(self):
        facts, summary = self.judge(self.good())
        self.assertEqual(summary['outcome'], 'PASS', facts)

    def test_every_mutation_fails_its_capability(self):
        good = self.good()
        table = [
            ('wall', 'workload outlived the wall', mutated(good['wall'], stdout=f'start-{T}\nnever-{T}\n')),
            ('wall', 'exit zero', mutated(good['wall'], exit_code=0)),
            ('wall', 'receipt names no wall', mutated(good['wall'], receipt={})),
            ('wall', 'ended long before the wall', mutated(good['wall'], timings_ms={'released_to_done': 900.0})),
            ('pids', 'fork failed with another errno', mutated(good['pids'], stdout=good['pids']['stdout'].replace('EAGAIN', 'ENOMEM'))),
            ('pids', 'stopped well before the limit (32, as 2026-11-02)', mutated(good['pids'], stdout=good['pids']['stdout'].replace('"forked": 61', '"forked": 32'))),
            ('pids', 'more forks than the limit allows', mutated(good['pids'], stdout=good['pids']['stdout'].replace('"forked": 61', '"forked": 64'))),
            ('pids', 'the jail lost evidence', mutated(good['pids'], exit_code=1, stdout=good['pids']['stdout'] + 'ukai-jail: error evidence_lost at reconciling (entry_abandoned)\n')),
            ('pids', 'receipt errors', mutated(good['pids'], receipt={**limits(pids=True), 'errors': [{'code': 'x'}]})),
            ('pids', 'cgroup limit is not the guest limit', mutated(good['pids'], stdout=good['pids']['stdout'].replace('"pids.max": null', '"pids.max": "128"'))),
            ('pids', 'receipt names no pids hit', mutated(good['pids'], receipt={'errors': []})),
            ('mem', 'not killed', mutated(good['mem'], exit_code=0)),
            ('mem', 'killed early, not at the limit', mutated(good['mem'], stdout=f'UKAI_MEM_PROBE {T} 16\nUKAI_MEM_PROBE {T} 32\n')),
            ('mem', 'any exit 137 without the receipt', mutated(good['mem'], receipt={})),
            ('mem', 'allocated past the limit', mutated(good['mem'], stdout=good['mem']['stdout'] + f'UKAI_MEM_PROBE {T} 528\n')),
            ('mem', 'unbounded', mutated(good['mem'], stdout=good['mem']['stdout'] + f'UKAI_MEM_UNBOUNDED {T} 1024\n')),
            ('containment', 'a write was created', mutated(good['containment'], stdout=good['containment']['stdout'].replace('"EROFS", "exists_after": false}', '"created", "exists_after": true}', 1))),
            ('containment', 'a path not probed', mutated(good['containment'], stdout='')),
            ('containment', 'a read outside the grants succeeded (writes-only, as 2026-11-02)', mutated(good['containment'], stdout=good['containment']['stdout'].replace('"/var/lib/ukai-vm": "ENOENT"', '"/var/lib/ukai-vm": "read"'))),
            ('containment', 'the read control failed (the probe could not read at all)', mutated(good['containment'], stdout=good['containment']['stdout'].replace('"/usr/bin/python3": "read"', '"/usr/bin/python3": "ENOENT"'))),
            ('wall', 'the controller backstop at wall + 10 s', mutated(good['wall'], timings_ms={'released_to_done': 15200.0})),
            ('wall', 'a hit without the wall_expiry cause', mutated(good['wall'], receipt=limits(wall=True))),
            ('network_none', 'egress connected', mutated(good['network_none'], stdout=probe_line(T, egress='connected', dns='unresolved--3'))),
            ('network_none', 'the /dev/tcp text of 2026-11-02', mutated(good['network_none'], stdout='net_refused\ndns_refused\n')),
            ('network_none', 'positive control failed', mutated(good['network_none'], stdout=probe_line(T, control='ECONNREFUSED', dns='unresolved--3'))),
            ('network_none', 'dns resolved', mutated(good['network_none'], stdout=probe_line(T, dns='resolved'))),
            ('network_none', 'receipt network not none', mutated(good['network_none'], receipt={'applied': {'network': {'mode': 'proxy'}}})),
        ]
        for capability, name, changed in table:
            with self.subTest(f'{capability}: {name}'):
                results = copy.deepcopy(good)
                results[capability] = changed
                facts, summary = self.judge(results)
                self.assertFalse(summary[capability], facts[capability])
                self.assertEqual(summary['outcome'], 'FAIL')

    def test_context_mutations(self):
        for name, kwargs, key in [
                ('no NAT attached', {'status': {'guest_nat': False}}, 'network_none'),
                ('target dead from the host', {'reachability': {'answers': False}}, 'network_none'),
                ('stale workspace file', {'host': 'live-OLDRUN\n'}, 'workspace'),
                ('protected .git changed', {'git': False}, 'git_config_untouched'),
                ('serve custody failure', {'exit_code': 125}, 'service_stopped_cleanly')]:
            with self.subTest(name):
                _, summary = self.judge(self.good(), **kwargs)
                self.assertFalse(summary[key])
                self.assertEqual(summary['outcome'], 'FAIL')

    def test_the_committed_2026_11_02_capability_evidence_now_fails(self):
        old = json.loads((EVIDENCE / 'macos-vm-warm-2026-11-02/capabilities.json').read_text())['results']
        pids = record(old['pids']['stdout'], old['pids']['exit'])
        self.assertFalse(all(capabilities.judge_pids(pids, T).values()))
        mem = record(old['mem']['stdout'], old['mem']['exit'])
        self.assertFalse(capabilities.judge_mem(mem, T)['receipt_records_the_oom'])
        network = record(old['network_none']['stdout'], old['network_none']['exit'])
        self.assertFalse(capabilities.judge_network(network, T, {'guest_nat': True}, {'answers': True})[
            'probe_denied_after_positive_control'])

    def test_measure_reads_this_runs_host_file(self):
        workspace = Path(tempfile.mkdtemp(prefix='cap-flow-'))
        self.addCleanup(shutil.rmtree, workspace, True)

        def script(index, request, send, channel):
            argv = [base64.b64decode(word).decode() for word in request['argv']]
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            if argv[:2] == ['/bin/sh', '-c'] and 'capability-' in argv[2]:
                (workspace / f'capability-{T}.txt').write_text(f'live-{T}\n')
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        service = mock.Mock(connect=server.connect)
        measured = capabilities.measure(service, workspace, T, {'answers': True})
        self.assertEqual(sorted(measured['results']), sorted(['wall', 'pids', 'mem', 'containment', 'network_none', 'workspace']))
        self.assertEqual(measured['host_workspace_file'], f'live-{T}\n')
        pids_argv = None
        self.assertEqual(capabilities.plan(T)[1][1][2][0], harness.PYTHON)
        del pids_argv


class ProbeSourceRuns(unittest.TestCase):
    """The capability probes' real sources, run on this host under safe bounds."""

    def run_probe(self, argv, **kwargs):
        argv = [sys.executable if word == harness.PYTHON else word for word in argv]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, **kwargs)

    def test_the_fs_probe_tells_refusals_from_reads(self):
        root = Path(tempfile.mkdtemp(prefix='fsprobe-'))
        self.addCleanup(lambda: (root.joinpath('locked').chmod(0o755), shutil.rmtree(root, True)))
        (root / 'locked').mkdir()
        (root / 'locked').chmod(0o555)
        (root / 'readable').write_text('x')
        write = [str(root / 'locked' / 'w')]
        read = [str(root / 'absent')]
        control = [str(root / 'readable'), str(root)]
        done = self.run_probe(capabilities.fs_probe_argv(T, write, read, control))
        facts = capabilities.judge_containment(record(done.stdout), T, write, read, control)
        self.assertTrue(all(facts.values()), (facts, done.stderr))
        flipped = capabilities.judge_containment(record(done.stdout), T, write, control, read)
        self.assertFalse(flipped[f'read_refused:{root / "readable"}'])

    def test_the_mem_probe_reports_and_flags_an_unbounded_run(self):
        done = self.run_probe([harness.PYTHON, '-I', '-c', capabilities.MEM_PROBE, T, '32'])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f'UKAI_MEM_PROBE {T} 64', done.stdout)
        facts = capabilities.judge_mem(record(done.stdout, 0), T)
        self.assertFalse(facts['never_unbounded'])
        self.assertFalse(facts['sigkilled'])

    def test_the_pids_probe_counts_forks_until_eagain(self):
        import resource
        users = subprocess.run(['ps', '-U', str(os.getuid()), '-o', 'pid='], capture_output=True, text=True)
        cap = len(users.stdout.split()) + 12

        def limit():  # in the probe's child only: its own forks fail past the cap
            resource.setrlimit(resource.RLIMIT_NPROC, (cap, cap))
        done = self.run_probe([harness.PYTHON, '-I', '-c', capabilities.PIDS_PROBE, T], preexec_fn=limit)
        probe = capabilities.tagged(done.stdout, 'UKAI_PIDS_PROBE', T)
        self.assertIsNotNone(probe, done.stderr)
        self.assertEqual(probe['fork_error'], 'EAGAIN')
        self.assertGreater(probe['forked'], 0)
        self.assertLess(probe['forked'], 64)


class WarmLiveTables(unittest.TestCase):
    def good(self, count=20):
        records = []
        for index in range(count):
            records.append({
                'index': index, 'exit_code': 0, 'error': None, 'boot_id': 'vm-one',
                'binding': {'guest_boot_id': 'guest-one'}, 'receipt_digest_ok': True,
                'stdout': f'git_write_refused-{index}\n' + probe_line(f'{T}-{index}') + f'\nout-{index}\n',
                'host_write': f'warm-{index}-{T}\n', 'git_config_after': warm_live.SENTINEL,
                'probe': harness.probe_verdict(probe_line(f'{T}-{index}'), f'{T}-{index}'),
                'receipt_network': 'none', 'timings_ms': {'connect_to_released': 15.0}})
        return records

    def judge(self, records, **kwargs):
        options = dict(budget_ms=1000.0, status={'guest_nat': False}, service_exit=0,
                       git_config_text=warm_live.SENTINEL)
        options.update(kwargs)
        return warm_live.judge(records, T, **options)[1]

    def test_the_good_run_passes(self):
        verdict = self.judge(self.good())
        self.assertEqual(verdict['outcome'], 'PASS', verdict['failed'])
        self.assertIn('not ukai-jail run --vm', verdict['k108_client'])

    def test_every_mutation_fails(self):
        def at(index, **changes):
            records = self.good()
            records[index].update(changes)
            return records

        table = [
            ('a stale attempt file from an earlier run', at(3, host_write=f'warm-3-OLDRUN\n'), 'every_granted_write_reached_host'),
            ('a granted write missing', at(5, host_write=None), 'every_granted_write_reached_host'),
            ('GIT_ALLOWED printed (the old && precedence)', at(2, stdout=self.good()[2]['stdout'] + 'GIT_WRITE_ALLOWED-2\n'), 'every_protected_write_tried_and_refused'),
            ('the protected write never tried', at(2, stdout=probe_line(f'{T}-2')), 'every_protected_write_tried_and_refused'),
            ('.git changed during one attempt', at(7, git_config_after='denied\n'), 'protected_git_never_reached'),
            ('egress allowed', at(1, probe=harness.probe_verdict(probe_line(f'{T}-1', egress='connected'), f'{T}-1')), 'every_attempt_network_denied'),
            ('the /dev/tcp text', at(1, probe=harness.probe_verdict('net_denied', f'{T}-1')), 'every_attempt_network_denied'),
            ('a second serve boot', at(9, boot_id='vm-two'), 'warm_reuse_one_serve_boot'),
            ('a second guest kernel boot', at(9, binding={'guest_boot_id': 'guest-two'}), 'warm_reuse_one_guest_boot'),
            ('one attempt over the 1 s budget', at(11, timings_ms={'connect_to_released': 1000.1}), 'k108_every_attempt_within_budget'),
            ('a release never seen', at(11, timings_ms={'connect_to_released': None}), 'k108_every_attempt_within_budget'),
            ('a failed attempt', at(4, exit_code=1), 'every_attempt_exit_zero'),
            ('an unverified receipt', at(4, receipt_digest_ok=False), 'every_receipt_verified'),
            ('receipt network not none', at(4, receipt_network='proxy'), 'every_receipt_network_none'),
            ('nineteen runs', self.good(19), 'k108_twenty_runs'),
        ]
        for name, records, gate in table:
            with self.subTest(name):
                verdict = self.judge(records)
                self.assertEqual(verdict['outcome'], 'FAIL')
                self.assertIn(gate, verdict['failed'])

    def test_first_attempt_plus_one_second_is_not_the_budget(self):
        # The old reading: initial 14.9 ms, so anything up to 1014.9 ms passed.
        records = self.good()
        records[0]['timings_ms'] = {'connect_to_released': 14.9}
        records[5]['timings_ms'] = {'connect_to_released': 1010.0}
        self.assertIn('k108_every_attempt_within_budget', self.judge(records)['failed'])

    def test_context_and_real_client_mutations(self):
        self.assertIn('guest_nat_as_requested', self.judge(self.good(), requested_nat=True)['failed'])
        self.assertIn('protected_git_never_reached', self.judge(self.good(), git_config_text='x')['failed'])
        self.assertIn('service_stopped_cleanly', self.judge(self.good(), service_exit=125)['failed'])
        runs = [{'index': i, 'exit': 0, 'exec_to_first_write_ms': 400.0} for i in range(20)]
        self.assertEqual(self.judge(self.good(), real_client=runs)['outcome'], 'PASS')
        slow = copy.deepcopy(runs)
        slow[3]['exec_to_first_write_ms'] = 1500.0
        self.assertEqual(self.judge(self.good(), real_client=slow)['outcome'], 'FAIL')
        refused = copy.deepcopy(runs)
        refused[0].update(exit=125, exec_to_first_write_ms=None)
        self.assertEqual(self.judge(self.good(), real_client=refused)['outcome'], 'FAIL')

    def test_one_attempt_judges_the_host_after_the_attempt(self):
        workspace = Path(tempfile.mkdtemp(prefix='warm-flow-'))
        self.addCleanup(shutil.rmtree, workspace, True)
        harness.protected_sentinel(workspace, warm_live.SENTINEL)
        (workspace / 'attempt-0.txt').write_text('warm-0-OLDRUN\n')

        def script(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            text = (f'git_write_refused-0\n' + probe_line(f'{T}-0') + '\n').encode()
            send(event='stdout', data=base64.b64encode(text).decode())
            send(**receipt_frame({'applied': {'network': {'mode': 'none'}}}))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        result = warm_live.one_attempt(mock.Mock(connect=server.connect), workspace, 0, T)
        facts = warm_live.attempt_facts(result, T)
        self.assertFalse(facts['granted_write_on_host'], 'a stale file from another run must not count')
        self.assertTrue(facts['network_denied'] and facts['protected_git_unchanged'] and facts['receipt_verified'])
        self.assertNotIn('receipt', result)

    def test_the_real_client_is_timed_to_its_first_host_write(self):
        workspace = Path(tempfile.mkdtemp(prefix='warm-real-'))
        self.addCleanup(shutil.rmtree, workspace, True)
        fake = workspace / 'fake-jail'
        fake.write_text('#!/bin/sh\n'
                        'while [ "$1" != "--" ]; do [ "$1" = "--workspace" ] && cd "$2"; shift; done; shift\n'
                        'sleep 0.2; exec "$@"\n')
        fake.chmod(0o755)
        runs = warm_live.real_client_attempts(fake, dict(os.environ), workspace, 2, T)
        self.assertEqual([run['exit'] for run in runs], [0, 0])
        for run in runs:
            self.assertGreaterEqual(run['exec_to_first_write_ms'], 150.0)


FAKE_SERVE = r"""
import base64, hashlib, json, os, re, socket, sys, threading, uuid
from pathlib import Path
args = sys.argv[1:]
assert args[0] == 'serve'
workspace = Path(args[args.index('--live-workspace') + 1])
mode = os.environ.get('FAKE_MODE', 'good')
if mode == 'die':
    sys.stderr.write('fake: custody failed at boot\n')
    sys.exit(125)
runtime = Path(os.environ['UKAI_DATA_DIR']) / 'vm'
runtime.mkdir(parents=True, exist_ok=True)
boot = 'vm-' + str(uuid.uuid4())
stop = threading.Event()
sys.stderr.write('fake serve up; inherited UKAI_VM_GUEST_NAT=%r\n' % os.environ.get('UKAI_VM_GUEST_NAT'))
sys.stderr.flush()

def listen(name):
    path = runtime / (name + '.sock')
    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(8)
    return server

def lines(stream):
    buffer = b''
    while True:
        while b'\n' not in buffer:
            chunk = stream.recv(65536)
            if not chunk:
                return
            buffer += chunk
        line, buffer = buffer.split(b'\n', 1)
        yield json.loads(line)

def send(stream, **value):
    stream.sendall((json.dumps(value) + '\n').encode())

def control(server):
    while not stop.is_set():
        stream, _ = server.accept()
        for request in lines(stream):
            if request['op'] == 'status':
                send(stream, event='status', boot_id=boot, warm=True, attempt_live=False,
                     guest_nat='--guest-nat' in args, live_workspace=str(workspace))
            elif request['op'] == 'stop':
                send(stream, event='stopping')
                stop.set()
            break
        stream.close()
    os._exit(0)

def attempt(server):
    count = 0
    while True:
        stream, _ = server.accept()
        send(stream, event='ready', boot_id=boot)
        frames = lines(stream)
        prepare = next(frames)
        send(stream, event='prepared', kernel='fake', staged_secrets=[])
        next(frames)
        send(stream, event='released', supervisor_pid=100 + count)
        script = base64.b64decode(prepare['argv'][2]).decode()
        index, tag = re.search(r"warm-(\d+)-(\w+)\\n' > attempt-", script).groups()
        if not (mode == 'skip-write' and index == '3'):
            (workspace / f'attempt-{index}.txt').write_text(f'warm-{index}-{tag}\n')
        probe = {'nonce': f'{tag}-{index}', 'control': 'connected', 'control_accepted': True,
                 'egress': 'connected' if mode == 'egress' else 'ENETUNREACH'}
        text = f'git_write_refused-{index}\nUKAI_NET_PROBE {json.dumps(probe)}\nout-{index}\n'
        send(stream, event='stdout', data=base64.b64encode(text.encode()).decode())
        receipt = json.dumps({'applied': {'network': {'mode': 'none'}}}).encode()
        send(stream, event='bound_receipt', sha256=hashlib.sha256(receipt).hexdigest(),
             data=base64.b64encode(receipt).decode(), binding={'guest_boot_id': 'guest-1'})
        send(stream, event='done', exit_code=0)
        stream.close()
        count += 1

threading.Thread(target=attempt, args=(listen('attempt'),), daemon=True).start()
control(listen('control'))
"""


class FakeServeFlows(unittest.TestCase):
    """warm_live.main and harness.Service against an executable stand-in for `ukai-vm serve`."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='fake-serve-flow-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.binary = self.root / 'ukai-vm'
        self.binary.write_text(f'#!{sys.executable}\n' + FAKE_SERVE)
        self.binary.chmod(0o755)
        self.workspace = self.root / 'ws'
        self.workspace.mkdir()
        harness.mark_workspace(self.workspace)
        self.image = self.root / 'image'
        self.image.mkdir()
        # The run's data dirs stay in the system temp dir (a unix socket path
        # has 104 bytes on macOS); the ones this test made are removed after it.
        before = set(Path(tempfile.gettempdir()).glob('ukai-warm-live-*'))
        self.addCleanup(lambda: [shutil.rmtree(path, True) for path in
                                 set(Path(tempfile.gettempdir()).glob('ukai-warm-live-*')) - before])

    def warm_live(self, mode, out='out'):
        (self.workspace / 'attempt-3.txt').write_text('warm-3-STALE\n')  # an earlier run's file
        with mock.patch.dict(os.environ, {'FAKE_MODE': mode, 'UKAI_VM_GUEST_NAT': '1'}), mock.patch('builtins.print'):
            code = warm_live.main(['--image', str(self.image), '--workspace', str(self.workspace),
                                   '--out', str(self.root / out), '--ukai-vm', str(self.binary)])
        return code, json.loads((self.root / out / 'warm-live.json').read_text())

    def test_a_good_service_passes_end_to_end(self):
        code, record = self.warm_live('good')
        self.assertEqual(code, 0, record['failed'])
        self.assertEqual(record['attempts_run'], 20)
        self.assertEqual(record['binary']['sha256'], harness.sha256_file(self.binary))
        self.assertIn('attempt-3.txt', record['workspace_cleaned'])
        self.assertIn("UKAI_VM_GUEST_NAT=None", record['service_stderr'])
        self.assertIs(record['guest_nat'], False)

    def test_a_missing_write_is_not_masked_by_a_stale_file(self):
        code, record = self.warm_live('skip-write')
        self.assertEqual(code, 1)
        self.assertIn('every_granted_write_reached_host', record['failed'])

    def test_egress_fails_the_run(self):
        code, record = self.warm_live('egress')
        self.assertEqual(code, 1)
        self.assertIn('every_attempt_network_denied', record['failed'])

    def test_a_second_run_never_overwrites_the_first(self):
        self.warm_live('good')
        before = (self.root / 'out' / 'warm-live.json').read_bytes()
        with self.assertRaisesRegex(harness.HarnessError, 'previous run'), mock.patch('builtins.print'):
            warm_live.main(['--image', str(self.image), '--workspace', str(self.workspace),
                            '--out', str(self.root / 'out'), '--ukai-vm', str(self.binary)])
        self.assertEqual((self.root / 'out' / 'warm-live.json').read_bytes(), before)

    def test_an_unmarked_workspace_is_never_cleaned(self):
        plain = self.root / 'plain'
        plain.mkdir()
        (plain / 'precious').write_text('keep')
        with self.assertRaisesRegex(harness.HarnessError, 'harness.py mark'):
            warm_live.main(['--image', str(self.image), '--workspace', str(plain),
                            '--out', str(self.root / 'out2'), '--ukai-vm', str(self.binary)])
        self.assertEqual((plain / 'precious').read_text(), 'keep')
        self.assertFalse((self.root / 'out2').exists())

    def test_a_service_that_dies_at_boot_is_named_with_its_stderr(self):
        data = self.root / 'data'
        data.mkdir()
        with mock.patch.dict(os.environ, {'FAKE_MODE': 'die'}):
            with self.assertRaisesRegex(harness.HarnessError, 'custody failed at boot'):
                with harness.Service(self.binary, self.image, self.workspace, data):
                    pass


FAKE_GUEST_SERVE = r"""
import base64, hashlib, json, os, re, select, signal, socket, subprocess, sys, threading, time, uuid
from pathlib import Path
args = sys.argv[1:]
workspace = Path(args[args.index('--live-workspace') + 1])
runtime = Path(os.environ['UKAI_DATA_DIR']) / 'vm'
runtime.mkdir(parents=True, exist_ok=True)
boot = 'vm-' + str(uuid.uuid4())
guest_boot = str(uuid.uuid4())
(runtime.parent / 'boot_id').write_text(guest_boot + '\n')
shim = runtime.parent / 'shim'
shim.mkdir()
(shim / 'date').write_text('#!/bin/sh\nexec %s -c "import time; print(time.time_ns())"\n' % sys.executable)
(shim / 'date').chmod(0o755)
state = {'live': False}

def listen(name):
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(runtime / (name + '.sock')))
    server.listen(8)
    return server

def frames(stream):
    buffer = b''
    while True:
        while b'\n' not in buffer:
            chunk = stream.recv(65536)
            if not chunk:
                return
            buffer += chunk
        line, buffer = buffer.split(b'\n', 1)
        yield json.loads(line)

def send(stream, **value):
    stream.sendall((json.dumps(value) + '\n').encode())

def control(server):
    while True:
        stream, _ = server.accept()
        request = next(frames(stream))
        if request['op'] == 'status':
            send(stream, event='status', boot_id=boot, warm=True, attempt_live=state['live'],
                 guest_nat='--guest-nat' in args)
            stream.close()
        else:
            send(stream, event='stopping')
            stream.close()
            os._exit(0)

def attempt(stream):
    send(stream, event='ready', boot_id=boot)
    reader = frames(stream)
    prepare = next(reader)
    ids = [secret['id'] for secret in prepare['secrets']]
    if len(set(ids)) != len(ids):
        stream.close()
        return
    send(stream, event='prepared', kernel='fake',
         staged_secrets=[[i, '/run/ukai-vm/credentials/' + i] for i in ids])
    next(reader)
    argv = [base64.b64decode(word).decode() for word in prepare['argv']]
    argv = [word.replace('/proc/sys/kernel/random/boot_id', str(runtime.parent / 'boot_id')) for word in argv]
    argv = [sys.executable if word == '/usr/bin/python3' else word for word in argv]
    # This fake runs workloads on the test host: no probe may leave it.
    if any(re.search(r'\b(?!127\.)\d+\.\d+\.\d+\.\d+\b', word) for word in argv):
        sys.stderr.write('fake guest: refusing an argv with a non-loopback address\n')
        os._exit(3)
    process = subprocess.Popen(argv, cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=dict(os.environ, PATH=f'{shim}:/usr/bin:/bin'), start_new_session=True)
    state['live'] = True
    send(stream, event='released', supervisor_pid=process.pid)
    deadline = time.monotonic() + prepare['wall_seconds']
    out = b''
    while process.poll() is None:
        ready, _, _ = select.select([stream, process.stdout], [], [], 0.05)
        if stream in ready and not stream.recv(1, socket.MSG_PEEK):
            os.killpg(process.pid, signal.SIGKILL)   # the lease: EOF cancels the attempt
            process.wait()
            state['live'] = False
            return
        if process.stdout in ready:
            out += os.read(process.stdout.fileno(), 65536)
        if time.monotonic() > deadline:
            os.killpg(process.pid, signal.SIGKILL)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    out += process.stdout.read()
    send(stream, event='stdout', data=base64.b64encode(out).decode())
    receipt = json.dumps({'applied': {'network': {'mode': 'none'}}}).encode()
    send(stream, event='bound_receipt', sha256=hashlib.sha256(receipt).hexdigest(),
         data=base64.b64encode(receipt).decode(), binding={'guest_boot_id': guest_boot})
    send(stream, event='done', exit_code=process.returncode)
    state['live'] = False
    stream.close()

def attempts(server):
    while True:
        stream, _ = server.accept()
        try:
            attempt(stream)
        except (OSError, StopIteration):
            state['live'] = False

threading.Thread(target=attempts, args=(listen('attempt'),), daemon=True).start()
control(listen('control'))
"""


class FaultMatrixMechanics(unittest.TestCase):
    """The real case code against a fake serve whose 'guest' runs the workload locally."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='fm-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        binary = self.root / 'ukai-vm'
        binary.write_text(f'#!{sys.executable}\n' + FAKE_GUEST_SERVE)
        binary.chmod(0o755)
        workspace = self.root / 'ws'
        workspace.mkdir()
        harness.mark_workspace(workspace)
        self.context = {'home': self.root, 'workspace': workspace, 'binary': binary}
        before = set(Path(tempfile.gettempdir()).glob('fault-*'))
        self.addCleanup(lambda: [shutil.rmtree(path, True) for path in
                                 set(Path(tempfile.gettempdir()).glob('fault-*')) - before])

    def run_case(self, case):
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        port = closed.getsockname()[1]
        closed.close()
        with mock.patch.object(fault_matrix, 'SUSPEND_SECONDS', 1.5), \
                mock.patch.object(fault_matrix, 'END_BOUND_SECONDS', 5.0), \
                mock.patch.object(harness, 'PROBE_TARGET', ('127.0.0.1', port)):
            return fault_matrix.run_case(self.context, case)

    def assert_passes(self, case):
        result = self.run_case(case)
        self.assertEqual(result['outcome'], 'PASS', (result.get('error'), result.get('failed'),
                                                     result.get('observations')))
        self.assertTrue(result['checked_before_cleanup'])
        self.assertEqual(result['cleanup']['service_exit'], 0)
        return result

    def test_eof_cancels_only_that_attempt(self):
        self.assert_passes('eof')

    def test_a_killed_client_ends_its_attempt(self):
        self.assert_passes('client-kill')

    def test_a_ctrl_z_does_not(self):
        result = self.assert_passes('client-ctrl-z')
        self.assertTrue(result['observations']['client_state_while_stopped'].startswith('T'))

    def test_a_brief_serve_group_stop_does_not(self):
        self.assert_passes('serve-group-stop')

    def test_secrets_then_a_duplicate_then_the_same_boot(self):
        result = self.assert_passes('secrets')
        self.assertEqual(result['observations']['probe']['egress'], 'ECONNREFUSED')


class MainFlows(unittest.TestCase):
    """Each remaining main() end to end, with its live dependencies faked."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='mains-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / 'home'
        (self.home / 'bin').mkdir(parents=True)
        for name in ('ukai-vm', 'ukai-jail'):
            (self.home / 'bin' / name).write_text('#!/bin/sh\n')
            (self.home / 'bin' / name).chmod(0o755)
        self.workspace = self.root / 'ws'
        self.workspace.mkdir()
        harness.mark_workspace(self.workspace)
        (self.workspace / 'stale').write_text('old')

    def test_capabilities_main_records_a_judged_run(self):
        workspace = self.workspace

        def script(index, request, send, channel):
            argv = [base64.b64decode(word).decode() for word in request['argv']]
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            if argv[0] == '/bin/sh' and 'capability-' in argv[2]:
                tag = argv[2].split('capability-')[1].split('.txt')[0]
                (workspace / f'capability-{tag}.txt').write_text(f'live-{tag}\n')
                send(event='stdout', data=base64.b64encode(f'wrote-{tag}\n'.encode()).decode())
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)

        class FakeService:
            def __init__(self, binary, home, ws, data, extra=()):
                self.extra = extra
                self.warm_status = {'warm': True, 'boot_id': 'vm-c', 'guest_nat': '--guest-nat' in extra}
                self.child = mock.Mock(returncode=0)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            connect = staticmethod(server.connect)

            def stderr_text(self):
                return ''
        with mock.patch.object(harness, 'Service', FakeService), mock.patch('builtins.print'), \
                mock.patch.dict(os.environ, {'UKAI_VM_BINARY': str(self.home / 'bin/ukai-vm')}):
            code = capabilities.main([str(self.home), str(self.workspace), str(self.root / 'out')])
        record = json.loads((self.root / 'out' / 'capabilities.json').read_text())
        self.assertEqual(code, 1)  # the fake answers nothing a capability needs
        self.assertEqual(record['summary']['outcome'], 'FAIL')
        self.assertTrue(record['summary']['workspace'])
        self.assertFalse(record['summary']['pids'])
        self.assertEqual(record['workspace_cleaned'], ['stale'])
        self.assertTrue(record['reachability']['fake'])
        import re as regex
        self.assertEqual(sorted(record['measurements']), sorted(capabilities.REQUIREMENTS.values()))
        for requirement, entry in record['measurements'].items():
            self.assertRegex(entry['measured_at'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
            self.assertIs(entry['verdict'], record['summary'][entry['capability']])
        self.assertTrue(regex.match(r'^\d{4}-', record['measured_at']))

    def fake_cli(self, boots=('vm-1', 'vm-1', 'vm-1'), echo=None, secret=None, refuse=False):
        runs = []

        def run(argv, env=None, **kwargs):
            runs.append(list(argv))
            assert_vm_client(self, list(argv), env)
            if argv[-1] == 'stop':
                return subprocess.CompletedProcess(argv, 0, '', '')
            if refuse:
                return subprocess.CompletedProcess(argv, 125, '', 'ukai-jail: refused: vm:not-measured:network_none')
            data = Path(env['UKAI_DATA_DIR'])
            index = len(list((data / 'attempts').glob('att_*'))) if (data / 'attempts').exists() else 0
            attempt = data / 'attempts' / f'att_{index}'
            (attempt / 'evidence').mkdir(parents=True)
            profile = argv[argv.index('--profile') + 1]
            mode = 'proxy' if profile == 'agent' else 'none'
            guest = {'applied': {'network': {'mode': mode}},
                     'credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True}]}
            (attempt / 'jail.json').write_text(json.dumps({'phase': 'settled', 'outcome': {'code': 0},
                                                           'lifetime': {'tree_empty': True},
                                                           'policy': {'name': profile}}))
            (attempt / 'evidence/jail.json').write_text(json.dumps(guest))
            (attempt / 'vm-transport.json').write_text(json.dumps({'boot_id': boots[min(index, len(boots) - 1)]}))
            (attempt / 'evidence/vm-binding.json').write_text(json.dumps({'guest_boot_id': 'g-1'}))
            (data / 'vm' / 'vm-1' / 'image').mkdir(parents=True, exist_ok=True)
            (data / 'vm' / 'vm-1' / 'image' / 'base.raw').write_bytes(b'\0' * 4096)
            script = argv[-1]
            stdout = ''
            if 'GITHUB' in script or 'EXAMPLE' in script:
                allowed = argv[argv.index('--allow-host') + 1]
                first, second = ('GITHUB', 'EXAMPLE') if allowed == 'api.github.com' else ('EXAMPLE', 'GITHUB')
                stdout = f'{first}_ANSWERED 200\n{second}_REFUSED URLError\n'
            elif argv[-6:-5] == [harness.PYTHON] or harness.PYTHON in argv:
                tag = argv[argv.index(harness.PYTHON) + 4]
                stdout = probe_line(tag, egress='ECONNREFUSED') + '\n'
            elif 'PLACEHOLDER' in script:
                import urllib.request
                request = urllib.request.Request(echo, headers={'x-test-token': secret.decode()})
                urllib.request.urlopen(request, timeout=5).read()
                stdout = f'PLACEHOLDER {"e" * 64} 41\nECHO 200 echo\n'
            return subprocess.CompletedProcess(argv, 0, stdout, '')
        return run, runs

    def test_proxy_main_measures_the_same_boot(self):
        for boots, outcome in ((('vm-1', 'vm-1', 'vm-1'), 'PASS'), (('vm-1', 'vm-1', 'vm-2'), 'FAIL')):
            with self.subTest(boots=boots):
                run, _ = self.fake_cli(boots)
                out = self.root / f'proxy-{outcome}'
                with mock.patch.object(proxy_measurement.subprocess, 'run', run), mock.patch('builtins.print'):
                    code = proxy_measurement.main([str(self.home), str(self.workspace), str(out),
                                                   '--ukai-jail', str(self.home / 'bin/ukai-jail')])
                record = json.loads((out / 'proxy-policy.json').read_text())
                self.assertEqual(record['outcome'], outcome, record['facts'])
                self.assertEqual(code, 0 if outcome == 'PASS' else 1)

    def test_proxy_main_records_a_refusal_never_a_pass(self):
        run, _ = self.fake_cli(refuse=True)
        with mock.patch.object(proxy_measurement.subprocess, 'run', run), mock.patch('builtins.print'):
            code = proxy_measurement.main([str(self.home), str(self.workspace), str(self.root / 'refused'),
                                           '--ukai-jail', str(self.home / 'bin/ukai-jail')])
        record = json.loads((self.root / 'refused' / 'proxy-policy.json').read_text())
        self.assertEqual((code, record['outcome'], record['refusals']), (1, 'REFUSED', ['vm:not-measured:network_none']))

    def test_vault_main_judges_injection_and_never_records_the_value(self):
        port_holder = {}
        real_server = vault_measurement.http.server.HTTPServer

        def loopback_server(address, handler):
            server = real_server(('127.0.0.1', 0), handler)
            port_holder['port'] = server.server_address[1]
            return server
        vault_measurement.Echo.received.clear()

        def run(argv, env=None, **kwargs):
            inner, _ = self.fake_cli(echo=f"http://127.0.0.1:{port_holder['port']}/echo",
                                     secret=vault_measurement.SECRET)
            return inner(argv, env=env, **kwargs)
        with mock.patch.object(vault_measurement, 'mac_address', lambda: '127.0.0.1'), \
                mock.patch.object(vault_measurement.http.server, 'HTTPServer', loopback_server), \
                mock.patch.object(vault_measurement.subprocess, 'run', run), mock.patch('builtins.print'):
            code = vault_measurement.main([str(self.home), str(self.workspace), str(self.root / 'vault'),
                                           '--ukai-jail', str(self.home / 'bin/ukai-jail')])
        text = (self.root / 'vault' / 'vault-consumption.json').read_text()
        record = json.loads(text)
        self.assertEqual(record['outcome'], 'PASS', record['facts'])
        self.assertEqual(code, 0)
        self.assertNotIn(vault_measurement.SECRET.decode(), text)
        self.assertNotIn('127.0.0.1', text)
        self.assertEqual(record['observed']['disk_scan'], 'clean')


class GateRowFlows(unittest.TestCase):
    """row_k109/row_k111/row_k112 end to end with the CLI and the serve faked."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='rowflow-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.workspace = self.root / 'ws'
        self.workspace.mkdir()
        harness.mark_workspace(self.workspace)
        self.home = self.root / 'home'
        (self.home / 'bin').mkdir(parents=True)

    def test_row_k109_with_a_refusing_guest(self):
        workspace = self.workspace

        def script(index, request, send, channel):
            argv = [base64.b64decode(word).decode() for word in request['argv']]
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            if argv[0] == '/bin/sh':
                tag = argv[2].split('granted-')[1].split('\\')[0]
                (workspace / 'k109-granted.txt').write_text(f'granted-{tag}\n')
                text = f'wrote-{tag}\ngit_write_refused-{tag}\n'
            else:
                tag, paths = argv[4], json.loads(argv[5])['write']
                text = 'UKAI_FS_PROBE ' + json.dumps({'tag': tag, 'reads': {}, 'paths': {
                    path: {'open': 'EROFS', 'exists_after': False} for path in paths}}) + '\n'
            send(event='stdout', data=base64.b64encode(text.encode()).decode())
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        service = mock.MagicMock(connect=server.connect, child=mock.Mock(returncode=0))
        service.__enter__.return_value = service
        with mock.patch.object(harness, 'Service', return_value=service):
            row = gate_rows.row_k109(Path('/x/ukai-vm'), self.home, self.workspace)
        self.assertEqual(row['outcome'], 'PASS', row)

    def test_row_k111_and_k112_through_the_cli(self):
        attempt_source = EVIDENCE / 'macos-vm-installed-2026-11-03/k111-attempt'
        binding = json.loads((attempt_source / 'evidence/vm-binding.json').read_text())
        transport = json.loads((attempt_source / 'vm-transport.json').read_text())
        line = (f"vm: guest-reported facts in evidence/jail.json · boot {transport['boot_id']} "
                f"· image {transport['image']['disk_sha256'][:16]} · vsock {transport['vsock_port']} "
                f"· receipt sha256:{transport['guest_receipt_sha256'][:16]}\nukai-jail: network: none\n")
        calls = []

        def run(argv, env=None, **kwargs):
            calls.append(list(argv))
            if 'script' not in argv:
                assert_vm_client(self, list(argv), env)
            else:
                assert_vm_client(self, list(argv[3:]), env)
            data = Path(env['UKAI_DATA_DIR'])
            if 'kernel-bound' in argv:
                attempt = data / 'attempts' / 'att_k112'
                attempt.mkdir(parents=True)
                (attempt / 'jail.json').write_text(json.dumps({'phase': 'refused',
                                                               'policy': {'requirements': ['owner_loss_termination']}}))
                (attempt / 'policy.json').write_text(json.dumps({'snapshot': {'lifetime_boundary': 'kernel-bound'}}))
                return subprocess.CompletedProcess(argv, 125, '', 'ukai-jail: refused [unsupported]')
            if 'run' in argv and '--vm' in argv:
                shutil.copytree(attempt_source, data / 'attempts' / binding['attempt_id'])
                (self.workspace / 'k111.txt').write_text('row-k111\n')
                return subprocess.CompletedProcess(argv, 0, line, '')
            if 'tail' in argv:
                return subprocess.CompletedProcess(argv, 0, line, '')
            return subprocess.CompletedProcess(argv, 0, '', '')
        out = self.root / 'out'
        out.mkdir()
        with mock.patch.object(gate_rows.subprocess, 'run', run):
            k111 = gate_rows.row_k111(self.home, self.workspace, Path('/x/ukai-jail'), out)
            k112 = gate_rows.row_k112(self.home, Path('/x/ukai-jail'), self.workspace)
        # The committed host receipt says network `pending` / observer not attached: D5 fails it.
        self.assertEqual(k111['outcome'], 'FAIL')
        self.assertEqual([key for key, value in k111.items() if value is False], ['host_receipt_never_contradicts_guest'])
        self.assertTrue((out / 'k111-tail-summary.txt').read_text().startswith('vm: guest-reported'))
        self.assertTrue(any(call[-1] == 'stop' for call in calls))
        self.assertEqual(k112['outcome'], 'PASS', k112)
        markers = [call[-1] for call in calls if 'kernel-bound' in call]
        self.assertEqual(len(markers), 3)
        self.assertTrue(all('k112-ran-' in marker for marker in markers))

    def test_row_k111_records_a_not_measured_refusal(self):
        def run(argv, env=None, **kwargs):
            if 'run' in argv:
                return subprocess.CompletedProcess(argv, 125, 'ukai-jail: refused: vm:not-measured:limit:wall\n', '')
            return subprocess.CompletedProcess(argv, 0, '', '')
        out = self.root / 'out-refused'
        out.mkdir()
        with mock.patch.object(gate_rows.subprocess, 'run', run):
            row = gate_rows.row_k111(self.home, self.workspace, Path('/x/ukai-jail'), out)
        self.assertEqual((row['outcome'], row['refusals']), ('REFUSED', ['vm:not-measured:limit:wall']))


def same_boot(**extra):
    return {'serve_boot': 'vm-1', 'guest_boot': 'g-1', 'next_exit': 0, 'next_serve_boot': 'vm-1',
            'next_guest_boot': 'g-1', **extra}


FAULT_GOOD = {
    'client-kill': same_boot(released=True, beating=True, killed_at=10.0, beats_quiet=True, last_beat_at=12.0,
                             client_exit=-9, status_after={'warm': True}),
    'client-ctrl-z': same_boot(released=True, beating=True, client_state_while_stopped='T', beats_during_stop=True,
                               done_exit=0, workload_finished=True),
    'serve-kill': {'released': True, 'beating': True, 'identified': True, 'a_done': False, 'a_ended': True,
                   'b_done': False, 'b_ended': True, 'killed_at': 10.0, 'beats_quiet': True, 'last_beat_at': 10.3,
                   'gone_seconds': {'serve': 0.1, 'custodian': 1.0, 'vz': 1.0, 'vm': 2.0},
                   'sockets_unanswered': True, 'workspace_survived': True},
    'all-suspended': {'released': True, 'beating': True, 'every_controller_stopped': True, 'wall': 10,
                      'released_at': 100.0, 'stopped_at': 102.0, 'last_beat_at': 110.1, 'beats_quiet': True,
                      'quiet_before_resume': True, 'guest_beat_span_s': 9.9},
    'secrets': same_boot(staged=[('api/token', '/run/ukai-vm/credentials/api/token'),
                                 ('nested/id/two', '/run/ukai-vm/credentials/nested/id/two')],
                         first_exit=0, probe_denied=True, duplicate_prepared=False,
                         duplicate_error='StreamEnded: ...'),
    'eof': same_boot(released=True, beating=True, eof_at=10.0, beats_quiet=True, last_beat_at=10.5,
                     status_after={'warm': True}),
    'serve-group-stop': same_boot(released=True, beating=True, beats_during_stop=True, done_exit=0,
                                  workload_finished=True, status_boot_after='vm-1'),
}
FAULT_GOOD['custodian-kill'] = FAULT_GOOD['serve-kill']
FAULT_GOOD['vz-kill'] = FAULT_GOOD['serve-kill']

BOOT_MUTATIONS = [('another serve boot after', {'next_serve_boot': 'vm-2'}, 'next_attempt_same_serve_boot'),
                  ('another guest kernel boot after', {'next_guest_boot': 'g-2'}, 'next_attempt_same_guest_boot'),
                  ('no guest boot measured', {'guest_boot': None}, 'next_attempt_same_guest_boot'),
                  ('the next attempt failed', {'next_exit': None}, 'next_attempt_exit_zero')]

FAULT_MUTATIONS = {
    'client-kill': BOOT_MUTATIONS + [
        ('workload kept beating after the kill', {'beats_quiet': False}, 'workload_stopped_after_kill'),
        ('beats stopped only long after', {'last_beat_at': 40.0}, 'workload_stopped_after_kill'),
        ('workload finished before the kill (old A)', {'beating': False}, 'workload_beating_before_kill'),
        ('service died with the client', {'status_after': {}}, 'service_still_warm'),
        ('client exited cleanly instead of dying', {'client_exit': 0}, 'client_died')],
    'client-ctrl-z': BOOT_MUTATIONS + [
        ('client never stopped (orphaned-group SIGTSTP)', {'client_state_while_stopped': 'Ss'}, 'client_was_stopped'),
        ('no workload spanned the stop (old B)', {'beats_during_stop': False}, 'workload_continued_while_client_stopped'),
        ('attempt ended by the stop', {'done_exit': None}, 'attempt_completed_after_resume'),
        ('workload cut short', {'workload_finished': False}, 'attempt_completed_after_resume')],
    'serve-kill': [
        ('running attempt got done (workload finished first, old A)', {'a_done': True}, 'running_attempt_ended_without_done'),
        ('queued attempt was served', {'b_done': True}, 'queued_attempt_ended_without_done'),
        ('queued client hung and was killed by cleanup', {'b_ended': False}, 'queued_attempt_ended_without_done'),
        ('beats continued', {'beats_quiet': False}, 'workload_stopped_after_kill'),
        ('VZ client survived', {'gone_seconds': {'serve': 0.1, 'custodian': 1.0, 'vz': None, 'vm': 2.0}}, 'vz_gone'),
        ('VM service survived', {'gone_seconds': {'serve': 0.1, 'custodian': 1.0, 'vz': 1.0, 'vm': None}}, 'vm_service_gone'),
        ('custodian survived', {'gone_seconds': {'serve': 0.1, 'custodian': None, 'vz': 1.0, 'vm': 2.0}}, 'custodian_gone'),
        ('serve survived', {'gone_seconds': {'serve': None, 'custodian': 1.0, 'vz': 1.0, 'vm': 2.0}}, 'serve_gone'),
        ('a socket still answers', {'sockets_unanswered': False}, 'sockets_unanswered'),
        ('workspace lost', {'workspace_survived': False}, 'workspace_survived'),
        ('processes not identified', {'identified': False}, 'one_custodian_vz_and_vm_identified')],
    'all-suspended': [
        ('a controller kept running', {'every_controller_stopped': False}, 'every_controller_stopped'),
        ('beats froze at the stop (share frozen: inconclusive)', {'last_beat_at': 102.2}, 'workload_ran_on_after_the_stop'),
        ('beats never ended', {'beats_quiet': False}, 'beats_ended_while_suspended'),
        ('checked after resume', {'quiet_before_resume': False}, 'beats_ended_while_suspended'),
        ('ended long after the wall', {'last_beat_at': 125.0}, 'ended_at_the_guest_wall_deadline'),
        ('guest clock ran past the wall', {'guest_beat_span_s': 20.0}, 'guest_clock_agrees')],
    'secrets': BOOT_MUTATIONS + [
        ('one value acked', {'staged': [('api/token', '/run/ukai-vm/credentials/api/token')]}, 'two_values_acked'),
        ('a value staged on disk', {'staged': [('api/token', '/var/lib/x/api/token'),
                                               ('nested/id/two', '/run/ukai-vm/credentials/nested/id/two')]},
         'paths_in_tmpfs_root'),
        ('duplicate id accepted', {'duplicate_prepared': True}, 'duplicate_id_refused_before_prepared'),
        ('egress not denied', {'probe_denied': False}, 'network_denied_with_nat')],
    'eof': BOOT_MUTATIONS + [
        ('workload finished before the EOF (old C)', {'beating': False}, 'workload_beating_before_eof'),
        ('workload outlived the EOF', {'beats_quiet': False}, 'workload_stopped_after_eof'),
        ('session went down', {'status_after': {'warm': False}}, 'service_still_warm')],
    'serve-group-stop': BOOT_MUTATIONS + [
        ('no workload spanned the stop (old B)', {'beats_during_stop': False}, 'workload_spanned_the_stop'),
        ('the serve rebooted across the stop', {'status_boot_after': 'vm-2'}, 'serve_boot_unchanged_after_resume'),
        ('attempt lost', {'done_exit': None}, 'attempt_completed_after_resume')],
}
FAULT_MUTATIONS['custodian-kill'] = FAULT_MUTATIONS['serve-kill']
FAULT_MUTATIONS['vz-kill'] = FAULT_MUTATIONS['serve-kill']


class FaultMatrixTables(unittest.TestCase):
    def test_every_case_passes_on_its_good_observation(self):
        self.assertEqual(sorted(FAULT_GOOD), sorted(fault_matrix.CASES))
        for case in fault_matrix.CASES:
            with self.subTest(case):
                result = fault_matrix.judge(case, FAULT_GOOD[case])
                self.assertEqual(result['outcome'], 'PASS', result['failed'])

    def test_every_mutation_fails_its_fact(self):
        for case, mutations in FAULT_MUTATIONS.items():
            for name, changes, fact in mutations:
                with self.subTest(f'{case}: {name}'):
                    result = fault_matrix.judge(case, mutated(FAULT_GOOD[case], **changes))
                    self.assertEqual(result['outcome'], 'FAIL')
                    self.assertIn(fact, result['failed'])

    def test_the_k110_clause_is_covered_sentence_by_sentence(self):
        clause = ("Killing the host `ukai-jail` ends that attempt through its lease, and `Ctrl-Z` of it does not. "
                  "Killing the custodian, the VZ client or `ukai-vm` ends the VM service and every attempt. "
                  "With every host controller suspended, the guest's wall deadline ends the attempt. "
                  "All are checked before any test cleanup.")
        mapping = json.loads(json.dumps({'client-kill': 'host ukai-jail killed', 'client-ctrl-z': 'Ctrl-Z',
                                         'custodian-kill': 'custodian', 'vz-kill': 'VZ client',
                                         'serve-kill': 'ukai-vm', 'all-suspended': 'every host controller'}))
        for case in mapping:
            self.assertIn(case, fault_matrix.CASES)
            self.assertIn(case, fault_matrix.__doc__)
        self.assertIn('All are checked before any test cleanup', fault_matrix.__doc__)
        self.assertTrue(clause)

    def test_the_verdict_is_taken_before_cleanup(self):
        order = []

        class FakeRun:
            def __init__(self, context, case):
                self.cleanup = {}

            def tear_down(self):
                order.append('cleanup')
                self.cleanup['started_at'] = time.monotonic()

        def case(run, obs):
            obs.update(FAULT_GOOD['eof'])
            order.append('observed')

        real_judge = fault_matrix.judge

        def judged(name, obs):
            order.append('judged')
            return real_judge(name, obs)
        with mock.patch.object(fault_matrix, 'Run', FakeRun), \
                mock.patch.object(fault_matrix, 'case_eof', case), \
                mock.patch.object(fault_matrix, 'judge', judged):
            result = fault_matrix.run_case({}, 'eof')
        self.assertEqual(order, ['observed', 'judged', 'cleanup'])
        self.assertEqual(result['outcome'], 'PASS')
        self.assertTrue(result['checked_before_cleanup'])

    def test_a_case_error_is_a_result_and_still_cleans_up(self):
        cleaned = []

        class FakeRun:
            def __init__(self, context, case):
                self.cleanup = {}

            def tear_down(self):
                cleaned.append(True)
                self.cleanup['started_at'] = 1e18

        def boom(run, obs):
            raise harness.HarnessError('no unique vz process')
        with mock.patch.object(fault_matrix, 'Run', FakeRun), mock.patch.object(fault_matrix, 'case_eof', boom):
            result = fault_matrix.run_case({}, 'eof')
        self.assertEqual(result['outcome'], 'ERROR')
        self.assertEqual(cleaned, [True])


class GateRowTables(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix='rows-ws-'))
        self.addCleanup(shutil.rmtree, self.workspace, True)

    def k109(self, tag='t9', host=None, granted=None, git=None, created=False, service_exit=0):
        (self.workspace / 'k109-granted.txt').write_text(host if host is not None else f'granted-{tag}\n')
        git_config = harness.protected_sentinel(self.workspace, git or gate_rows.SENTINEL)
        outside = [f'/etc/ukai-k109-{tag}', f'/usr/local/bin/ukai-k109-{tag}', f'/ukai-k109-{tag}']
        fs = {'tag': tag, 'paths': {path: {'open': 'created' if created and index == 0 else 'EROFS',
                                           'exists_after': created and index == 0}
                                    for index, path in enumerate(outside)}}
        granted = granted if granted is not None else record(f'wrote-{tag}\ngit_write_refused-{tag}\n')
        refused = record('UKAI_FS_PROBE ' + json.dumps(fs) + '\n')
        return gate_rows.judge_k109(tag, granted, refused, outside, self.workspace, git_config, service_exit)

    def test_k109_table(self):
        self.assertEqual(self.k109()['outcome'], 'PASS')
        for name, kwargs, key in [
                ('a previous run\'s granted file', {'host': 'granted-OLDRUN\n'}, 'granted_write_on_host'),
                ('the protected write allowed', {'granted': record('wrote-t9\nGIT_WRITE_ALLOWED-t9\n')}, 'git_write_tried_and_refused'),
                ('.git changed', {'git': 'forged'}, 'git_config_unchanged'),
                ('an outside write landed', {'created': True}, 'outside_writes_refused_and_absent'),
                ('custody failure', {'service_exit': 125}, 'service_stopped_cleanly')]:
            with self.subTest(name):
                row = self.k109(**kwargs)
                self.assertFalse(row[key])
                self.assertEqual(row['outcome'], 'FAIL')

    def k111_attempt(self):
        attempt = Path(tempfile.mkdtemp(prefix='rows-k111-')) / 'att_76c9e855-522c-42ad-b4a2-27e0b620d9cf'
        self.addCleanup(shutil.rmtree, attempt.parent, True)
        shutil.copytree(EVIDENCE / 'macos-vm-installed-2026-11-03/k111-attempt', attempt)
        binding = json.loads((attempt / 'evidence/vm-binding.json').read_text())
        if binding.get('attempt_id') != attempt.name:
            attempt = attempt.rename(attempt.parent / binding['attempt_id'])
        (self.workspace / 'k111.txt').write_text('row-k111\n')
        return attempt

    def summary_text(self, attempt, network='none', classes='6/6 classes active, no gaps'):
        transport = json.loads((attempt / 'vm-transport.json').read_text())
        return (f"vm: guest-reported facts in evidence/jail.json · boot {transport['boot_id']} "
                f"· image {transport['image']['disk_sha256'][:16]} · vsock {transport['vsock_port']} "
                f"· receipt sha256:{transport['guest_receipt_sha256'][:16]}\n"
                f"ukai-jail: network: {network}\nukai-jail: evidence: {classes}\n")

    def test_k111_on_the_committed_evidence_fails_on_the_host_receipt(self):
        attempt = self.k111_attempt()
        text = self.summary_text(attempt)
        row, detail = gate_rows.judge_k111(attempt, self.workspace, 0, text, text,
                                           ['/bin/sh', '-c', gate_rows.K111_SCRIPT])
        self.assertTrue(row['binding_argv_digest_is_this_argv'])
        self.assertTrue(row['guest_receipt_argv_digest_is_this_argv'])
        self.assertTrue(row['digest_matches_record'])
        self.assertFalse(row['host_receipt_never_contradicts_guest'], detail['contradictions'])
        self.assertEqual(row['outcome'], 'FAIL')

    def fixed_attempt(self):
        attempt = self.k111_attempt()
        host = json.loads((attempt / 'jail.json').read_text())
        guest = json.loads((attempt / 'evidence/jail.json').read_text())
        for key in ('platform', 'exec_observed', 'applied', 'observer', 'coverage', 'outcome'):
            host[key] = guest.get(key)  # S1's mirroring (GuestFacts::CARRIED)
        (attempt / 'jail.json').write_text(json.dumps(host))
        return attempt

    def test_k111_table(self):
        argv = ['/bin/sh', '-c', gate_rows.K111_SCRIPT]
        attempt = self.fixed_attempt()
        text = self.summary_text(attempt)
        row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv)
        self.assertEqual(row['outcome'], 'PASS', row)
        for name, call, key in [
                ('another argv', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, text, text, ['/bin/sh', '-c', 'other']), 'binding_argv_digest_is_this_argv'),
                ('the stored summary lacks the line', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, text, 'nothing', argv), 'tail_summary_transport_line_from_record'),
                ('the run summary lacks the line', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, 'nothing', text, argv), 'run_summary_transport_line_from_record'),
                ('the client failed', lambda: gate_rows.judge_k111(attempt, self.workspace, 1, text, text, argv), 'run_exit_zero')]:
            with self.subTest(name):
                row, _ = call()
                self.assertFalse(row[key])
                self.assertEqual(row['outcome'], 'FAIL')
        guest = attempt / 'evidence/jail.json'
        guest.write_bytes(guest.read_bytes() + b' ')
        row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv)
        self.assertFalse(row['digest_matches_record'])

    def test_k112_workload_marker_lives_in_the_workspace(self):
        self.assertFalse(gate_rows.workload_ran(self.workspace, 'k112-ran-vm-x'))
        (self.workspace / 'k112-ran-vm-x').write_text('')
        self.assertTrue(gate_rows.workload_ran(self.workspace, 'k112-ran-vm-x'))
        (self.workspace / 'k112-ran-vm-x').unlink()
        (self.workspace / 'k112-ran-vm-x-abs').write_text('')
        self.assertTrue(gate_rows.workload_ran(self.workspace, 'k112-ran-vm-x'))

    def test_k112_table(self):
        lane = {'exit': 125, 'phase': 'refused', 'stderr': 'refused [unsupported]', 'workload_ran': False,
                'lifetime_boundary': 'kernel-bound', 'requirements_name_owner_loss': True, 'boot_attempted': False}
        self.assertEqual(gate_rows.judge_k112(lane, lane, lane)['outcome'], 'PASS')
        for name, changes, key, which in [
                ('the workload ran', {'workload_ran': True}, 'native_dev_refused', 'dev'),
                ('it ran to completion', {'exit': 0, 'phase': 'settled'}, 'native_shipped_refused', 'shipped'),
                ('another refusal class', {'stderr': 'refused [host_setup]'}, 'native_shipped_refused', 'shipped'),
                ('a boot was attempted', {'boot_attempted': True}, 'vm_refused_before_boot', 'vm'),
                ('the key never reached the policy', {'lifetime_boundary': None}, 'vm_refused_before_boot', 'vm')]:
            with self.subTest(name):
                lanes = {'shipped': lane, 'dev': lane, 'vm': lane}
                lanes[which] = mutated(lane, **changes)
                row = gate_rows.judge_k112(lanes['shipped'], lanes['dev'], lanes['vm'])
                self.assertFalse(row[key])
                self.assertEqual(row['outcome'], 'FAIL')

    def test_main_exits_nonzero_when_a_row_fails(self):
        root = Path(tempfile.mkdtemp(prefix='rows-main-'))
        self.addCleanup(shutil.rmtree, root, True)
        home = root / 'home'
        (home / 'bin').mkdir(parents=True)
        for name in ('ukai-vm', 'ukai-jail'):
            (home / 'bin' / name).write_text('#!/bin/sh\n')
            (home / 'bin' / name).chmod(0o755)
        workspace = root / 'ws'
        workspace.mkdir()
        harness.mark_workspace(workspace)
        for outcome, expected in (('FAIL', 1), ('PASS', 0)):
            with self.subTest(outcome), \
                    mock.patch.object(gate_rows, 'row_k109', return_value={'outcome': 'PASS'}), \
                    mock.patch.object(gate_rows, 'row_k111', return_value={'outcome': outcome}), \
                    mock.patch.object(gate_rows, 'row_k112', return_value={'outcome': 'PASS'}), \
                    mock.patch('builtins.print'):
                code = gate_rows.main([str(home), str(workspace), str(root / f'out-{outcome}'),
                                       str(home / 'bin' / 'ukai-jail')])
                self.assertEqual(code, expected)


class VaultTables(unittest.TestCase):
    def good(self):
        return {'run_exit': 0, 'header': vault_measurement.SECRET.decode(),
                'placeholder': {'sha256': 'f' * 64, 'length': 40},
                'guest_credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True}],
                'guest_network_mode': 'proxy', 'phase': 'settled', 'exit': 0, 'tree_empty': True,
                'leaks': [], 'files_scanned': 12, 'client_output_leak': False, 'disk_scan': 'clean',
                'sync_exit': 0}

    def test_table(self):
        self.assertEqual(vault_measurement.judge(self.good())[1], 'PASS')
        secret_hash = hashlib.sha256(vault_measurement.SECRET).hexdigest()
        for name, changes, key in [
                ('no injection', {'header': None}, 'header_injected'),
                ('the child held the value', {'placeholder': {'sha256': secret_hash, 'length': 33}}, 'child_saw_a_placeholder'),
                ('no placeholder seen', {'placeholder': None}, 'child_saw_a_placeholder'),
                ('an empty placeholder', {'placeholder': {'sha256': 'f' * 64, 'length': 0}}, 'child_saw_a_placeholder'),
                ('a staged mode', {'guest_credentials': [{'id': 'test', 'mode': 'copy_rw', 'never_staged': True}]}, 'guest_credential_vault_never_staged'),
                ('staged into the attempt', {'guest_credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': False}]}, 'guest_credential_vault_never_staged'),
                ('no credential record', {'guest_credentials': []}, 'guest_credential_vault_never_staged'),
                ('a leak in an export', {'leaks': ['/x/trace.ndjson']}, 'no_value_in_any_export'),
                ('nothing scanned', {'files_scanned': 0}, 'no_value_in_any_export'),
                ('the client printed it', {'client_output_leak': True}, 'no_value_in_client_output'),
                ('on the guest disk', {'disk_scan': 'value-present'}, 'guest_disk_scanned_clean'),
                ('disk never scanned', {'disk_scan': 'not-checked: 0 boot disks found'}, 'guest_disk_scanned_clean'),
                ('caches not flushed', {'sync_exit': 1}, 'guest_disk_scanned_clean'),
                ('not proxied', {'guest_network_mode': 'none'}, 'guest_network_proxy')]:
            with self.subTest(name):
                facts, outcome = vault_measurement.judge(mutated(self.good(), **changes))
                self.assertFalse(facts[key])
                self.assertEqual(outcome, 'FAIL')

    def test_the_leak_scan_covers_every_record_and_has_no_size_cap(self):
        root = Path(tempfile.mkdtemp(prefix='vault-scan-'))
        self.addCleanup(shutil.rmtree, root, True)
        attempt = root / 'attempts' / 'att_1'
        (attempt / 'evidence').mkdir(parents=True)
        secret = vault_measurement.SECRET
        for name in ('jail.json', 'policy.json', 'trace.ndjson', 'evidence/jail.json'):
            (attempt / name).write_bytes(b'{}')
        (attempt / 'trace.ndjson').write_bytes(b'x' * 3_000_000 + secret)
        (attempt / 'policy.json').write_bytes(b'{"v": "' + secret + b'"}')
        outside = root.parent / f'{root.name}-outside'
        outside.write_bytes(secret)
        self.addCleanup(outside.unlink)
        (attempt / 'link').symlink_to(outside)
        hits, scanned = vault_measurement.leak_scan([root], secret)
        self.assertEqual([Path(hit).name for hit in hits], ['policy.json', 'trace.ndjson'])
        self.assertEqual(scanned, 4)

    def test_a_value_across_a_chunk_boundary_is_found(self):
        path = Path(tempfile.mkdtemp(prefix='vault-chunk-')) / 'f'
        self.addCleanup(shutil.rmtree, path.parent, True)
        path.write_bytes(b'abcdefg' + b'SECRETVALUE' + b'xyz')
        self.assertTrue(vault_measurement.file_holds(path, b'SECRETVALUE', chunk=8))
        self.assertFalse(vault_measurement.file_holds(path, b'SECRETVALUX', chunk=8))


class ProxyTables(unittest.TestCase):
    def good(self):
        runs = [{'stdout': 'GITHUB_ANSWERED 200\nEXAMPLE_REFUSED URLError\n'},
                {'stdout': 'EXAMPLE_ANSWERED 200\nGITHUB_REFUSED URLError\n'},
                {'stdout': probe_line(T) + '\n'}]
        base = {'phase': 'settled', 'tree_empty': True, 'serve_boot': 'vm-1', 'guest_boot': 'g-1'}
        records = [dict(base, guest_network={'mode': 'proxy'}), dict(base, guest_network={'mode': 'proxy'}),
                   dict(base, guest_network={'mode': 'none'})]
        return runs, records

    def test_table(self):
        runs, records = self.good()
        self.assertEqual(proxy_measurement.judge(runs, records, T)[1], 'PASS')

        def with_record(index, **changes):
            changed = copy.deepcopy(records)
            changed[index].update(changes)
            return runs, changed

        def with_run(index, stdout):
            changed = copy.deepcopy(runs)
            changed[index]['stdout'] = stdout
            return changed, records
        for name, (r, rec), key in [
                ('the refuted "same guest" (vm-574c66b2 vs vm-b22ef488)', with_record(2, serve_boot='vm-b22ef488'), 'same_serve_boot'),
                ('another guest kernel boot', with_record(1, guest_boot='g-2'), 'same_guest_boot'),
                ('the /dev/tcp text', with_run(2, 'net_refused\n'), 'offline_probe_denied'),
                ('re-armed set not applied', with_run(1, 'EXAMPLE_REFUSED URLError\nGITHUB_ANSWERED 200\n'), 'rearmed_allowed_answers'),
                ('old host still allowed', with_run(1, 'EXAMPLE_ANSWERED 200\nGITHUB_ANSWERED 200\n'), 'rearmed_old_host_refused'),
                ('denied host answered', with_run(0, 'GITHUB_ANSWERED 200\nEXAMPLE_ANSWERED 200\n'), 'first_denied_refused'),
                ('offline attempt proxied', with_record(2, guest_network={'mode': 'proxy'}), 'offline_attempt_none')]:
            with self.subTest(name):
                facts, outcome = proxy_measurement.judge(r, rec, T)
                self.assertFalse(facts[key])
                self.assertEqual(outcome, 'FAIL')
        facts, outcome = proxy_measurement.judge(runs, records[:2], T)
        self.assertEqual(outcome, 'FAIL')


class ClaudeRowTests(unittest.TestCase):
    NOW = 1_800_000_000

    def test_token_selection_keeps_a_margin(self):
        margin = claude_vm_row.EXPIRY_MARGIN_SECONDS * 1000
        now = self.NOW * 1000
        soon = {'accessToken': 'a', 'expiresAt': now + margin - 1}
        later = {'accessToken': 'b', 'expiresAt': now + margin + 60_000}
        latest = {'accessToken': 'c', 'expiresAt': now + margin + 120_000}
        self.assertIsNone(claude_vm_row.select_token([soon], now))
        self.assertEqual(claude_vm_row.select_token([soon, later, latest], now)['accessToken'], 'c')
        self.assertIsNone(claude_vm_row.select_token([{'expiresAt': now + 10 * margin}], now))

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='k113-test-')).resolve()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home = self.root / 'home'
        (self.home / 'bin').mkdir(parents=True)
        self.jail = self.home / 'bin' / 'ukai-jail'
        self.jail.write_text('#!/bin/sh\n')
        self.jail.chmod(0o755)
        self.workspace = self.root / 'ws'
        self.workspace.mkdir()
        harness.mark_workspace(self.workspace)
        (self.workspace / 'claude').write_bytes(b'fake claude')
        self.digest = hashlib.sha256(b'fake claude').hexdigest()
        self.token = 'sk-ant-oat01-' + 'Q' * 40
        self.calls = []

    def fake_run(self, tail_has_line=True, run_raises=None, refused=False):
        guest = {'platform': {'os': 'linux'}, 'applied': {'network': {'mode': 'proxy'}},
                 'observer': {'attached': True},
                 'coverage': {name: {'status': 'active'} for name in harness.SUMMARY_CLASSES}}
        guest_bytes = json.dumps(guest).encode()
        transport = {'schema': 'ukai.jail.vm-transport/1', 'boot_id': 'vm-x', 'vsock_port': 1024,
                     'image': {'disk_sha256': 'a' * 64},
                     'guest_receipt_sha256': hashlib.sha256(guest_bytes).hexdigest()}
        line = (f"vm: guest-reported facts in evidence/jail.json · boot vm-x · image {'a' * 16} "
                f"· vsock 1024 · receipt sha256:{transport['guest_receipt_sha256'][:16]}\n")
        good_tail = line + 'ukai-jail: network: allowed api.anthropic.com (3)\nukai-jail: evidence: 6/6 classes active, no gaps\n'

        def run(argv, env=None, **kwargs):
            self.calls.append(list(argv))
            assert_vm_client(self, list(argv), env)
            for word in argv:
                self.assertNotIn(self.token, str(word))
            if refused and 'run' in argv and '--vm' in argv:
                return subprocess.CompletedProcess(argv, 125, '', 'ukai-jail: refused [unsupported]: vm:not-measured:limit:wall')
            if 'run' in argv and '--vm' in argv:
                source = Path((Path(env['UKAI_CONFIG_DIR']) / 'launch/claude-vm.toml').read_text()
                              .split('source = "', 1)[1].split('"', 1)[0])
                self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                self.assertEqual(source.read_text(), self.token)
                if run_raises is not None:
                    raise run_raises
                attempt = Path(env['UKAI_DATA_DIR']) / 'attempts' / 'att_1'
                (attempt / 'evidence').mkdir(parents=True)
                (attempt / 'jail.json').write_text(json.dumps({
                    **guest, 'phase': 'settled', 'outcome': {'code': 0}, 'lifetime': {'tree_empty': True}}))
                (attempt / 'vm-transport.json').write_text(json.dumps(transport))
                (attempt / 'evidence/jail.json').write_bytes(guest_bytes)
                (self.workspace / 'k113-marker.txt').write_text('contained\n')
                result = '{"type":"result","subtype":"success","is_error":false,"result":"done"}\n'
                # The run's own terminal always carries the transport line.
                return subprocess.CompletedProcess(argv, 0, result + good_tail, '')
            if 'tail' in argv:
                return subprocess.CompletedProcess(argv, 0, good_tail if tail_has_line else 'no summary\n', '')
            return subprocess.CompletedProcess(argv, 0, '', '')
        return run

    def main(self, out='out', **kwargs):
        sections = [{'accessToken': self.token, 'expiresAt': (self.NOW + 7200) * 1000}]
        self.temp = self.root / 'tmp'
        self.temp.mkdir(exist_ok=True)
        # Every mkdtemp of the run lands here, so a leaked token file is this test's, and is found.
        with mock.patch.object(claude_vm_row, 'CLAUDE_SHA256', self.digest), mock.patch('builtins.print'), \
                mock.patch.object(tempfile, 'tempdir', str(self.temp)):
            return claude_vm_row.main([str(self.home), str(self.workspace), str(self.root / out), str(self.jail)],
                                      now=lambda: self.NOW, candidates=lambda: sections,
                                      run=self.fake_run(**kwargs))

    def token_files(self):
        self.assertTrue(any(self.temp.glob('k113-*')), 'the run made no temp dirs here')
        return [path for path in self.temp.rglob('*') if path.is_file()
                and self.token in path.read_text(errors='replace')]

    def test_a_good_run_passes_and_leaves_no_token(self):
        self.assertEqual(self.main(), 0)
        row = json.loads((self.root / 'out' / 'k113-claude.json').read_text())
        self.assertEqual(row['outcome'], 'PASS', row['facts'])
        self.assertTrue(row['token_source_removed'])
        self.assertEqual(self.token_files(), [])
        self.assertTrue(any(call[-1] == 'stop' for call in self.calls))
        self.assertNotIn(self.token, json.dumps(row))

    def test_the_summary_is_judged_on_tail_alone(self):
        self.assertEqual(self.main(tail_has_line=False), 1)
        row = json.loads((self.root / 'out' / 'k113-claude.json').read_text())
        self.assertFalse(row['facts']['tail_summary_transport_line_from_record'])
        self.assertTrue(row['run_summary_facts']['transport_line_from_record'])

    def test_a_timeout_still_stops_the_service_and_removes_the_token(self):
        self.assertEqual(self.main(run_raises=subprocess.TimeoutExpired('script', 420)), 1)
        self.assertTrue(any(call[-1] == 'stop' for call in self.calls))
        self.assertEqual(self.token_files(), [])

    def test_an_exception_still_stops_the_service_and_removes_the_token(self):
        with self.assertRaises(RuntimeError):
            self.main(run_raises=RuntimeError('client crashed'))
        self.assertTrue(any(call[-1] == 'stop' for call in self.calls))
        self.assertEqual(self.token_files(), [])

    def test_a_not_measured_refusal_is_recorded_never_passed(self):
        self.assertEqual(self.main(refused=True), 1)
        row = json.loads((self.root / 'out' / 'k113-claude.json').read_text())
        self.assertEqual(row['outcome'], 'REFUSED')
        self.assertEqual(row['refusals'], ['vm:not-measured:limit:wall'])
        self.assertEqual(self.token_files(), [])

    def test_a_previous_output_directory_is_never_reused(self):
        (self.root / 'out').mkdir()
        (self.root / 'out' / 'k113-claude.json').write_text('the 401 run')
        with self.assertRaisesRegex(harness.HarnessError, 'previous run'):
            self.main()
        self.assertEqual((self.root / 'out' / 'k113-claude.json').read_text(), 'the 401 run')
        self.assertEqual(self.calls, [])

    def test_a_token_in_any_output_fails(self):
        row = {'phase': 'settled', 'exit': 0, 'tree_empty': True,
               'agent_result': {'subtype': 'success', 'is_error': False}, 'marker_content': 'contained\n',
               'guest_receipt_linux': True, 'token_in_exports': [], 'files_scanned': 3, 'token_in_outputs': [],
               'tail_summary_exit': 0,
               'tail_summary_facts': {'transport_line_present': True, 'transport_line_from_record': True,
                                      'network_line_is_the_guests': True, 'observer_classes_are_the_guests': True,
                                      'observer_attachment_is_the_guests': True}}
        self.assertEqual(claude_vm_row.judge(row)[1], 'PASS')
        for name, changes, key in [
                ('stdout tail', {'token_in_outputs': ['stdout']}, 'token_in_no_output'),
                ('an exported file', {'token_in_exports': ['/w/trace.ndjson']}, 'token_in_no_export'),
                ('nothing scanned', {'files_scanned': 0}, 'token_in_no_export'),
                ('network not the guest\'s', {'tail_summary_facts': dict(row['tail_summary_facts'], network_line_is_the_guests=False)}, 'tail_summary_network_line_is_the_guests'),
                ('observer classes not the guest\'s', {'tail_summary_facts': dict(row['tail_summary_facts'], observer_classes_are_the_guests=False)}, 'tail_summary_observer_classes_are_the_guests'),
                ('marker wrong', {'marker_content': 'contained'}, 'marker_on_host')]:
            with self.subTest(name):
                facts, outcome = claude_vm_row.judge(mutated(row, **changes))
                self.assertFalse(facts[key])
                self.assertEqual(outcome, 'FAIL')


if __name__ == '__main__':
    unittest.main()
