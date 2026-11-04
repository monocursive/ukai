"""Every live harness's PASS predicate goes red on the failure it claims to detect.

One mutation table per harness: a passing observation, then each failure the
row exists to catch, applied one at a time, must fail the predicate it names.
Where the 2026-11-02/03 evidence committed a vacuous measurement, the old
observation is replayed and must now fail. No VM boots; services are fakes.

    python3 -s -E -m unittest test_harness_rows
"""
import ast
import base64
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import types
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
from test_harness import EVIDENCE, HERE, FakeAttemptServer, bound_frame, probe_line

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


# The receipt's applied limits as guest.py's jail records them: the requested
# value in canonical form, applied, through which control, and the hit.
LIMIT_ENTRIES = {'wall': ('5000', 'boottime-deadline'), 'pids': ('64', 'pids.max'),
                 'mem': (str(512 * 1024 * 1024), 'memory.max')}


def limit_entry(key, hit=True, **changes):
    requested, mechanism = LIMIT_ENTRIES[key]
    return {'key': key, 'requested': requested, 'required': True, 'applied': True, 'mechanism': mechanism,
            'scope': 'attempt', 'hit': hit, **changes}


def limits(**hits):
    return {'applied': {'limits': [limit_entry(key, value) for key, value in hits.items()]}}


def bind(base, attempt_id, argv=('/bin/sh', '-c', 'x'), profile='tool', boot='vm-1', guest_boot='g-1'):
    """`base` with a verified receipt bound to exactly this attempt (harness.receipt_bound)."""
    value = copy.deepcopy(base)
    digest = harness.argv_digest(list(argv))
    value.update(attempt_id=attempt_id, argv_digest=digest, profile=profile, boot_id=boot, receipt_digest_ok=True,
                 binding={'attempt_id': attempt_id, 'argv_digest': digest, 'profile': profile, 'boot_id': boot,
                          'guest_attempt_id': 'att_' + attempt_id, 'guest_boot_id': guest_boot})
    value['receipt'] = dict(value.get('receipt') or {}, argv_digest=digest)
    return value


def route_line(tag, status='HTTP/1.1 200 Connection established', target=None):
    """The route control's verdict line (harness.ROUTE_SOURCE)."""
    return 'UKAI_ROUTE_CONTROL ' + json.dumps({'nonce': tag, 'target': list(target or harness.PROBE_TARGET),
                                               'status_line': status})


def mutated(base, **changes):
    value = copy.deepcopy(base)
    value.update(changes)
    return value


def with_receipt(base, receipt):
    """`base` with another receipt, still bound to its attempt (its argv digest kept)."""
    return mutated(base, receipt=dict(receipt, argv_digest=base['receipt']['argv_digest']))


def rebound(base, **binding):
    value = copy.deepcopy(base)
    value['binding'].update(binding)
    return value


# ---------------------------------------------------------------------------
# Passing observations of the 2026-11-04 guest measurements (capabilities.py),
# each shaped as rc.5's receipt and the stop-ready guest's frames are.
# ---------------------------------------------------------------------------

POLICY = {'policy': {'requirements': sorted(capabilities.REQUIREMENTS.values())}}
TREE_ROOT = {'pid': 2, 'pgrp': 2, 'session': 1}
GOOD_STOP = {'boundaries': ['ukai-attempts.slice/attempt-3', 'app.slice/ukai-jail-9.scope'],
             'populated_before_kill': [], 'live_before_kill': [], 'strays_killed': []}
TRACE_OPERATION = {'exec': 'proc.exec', 'fs.write': 'fs.create', 'fs.deny': 'fs.deny', 'net': 'net.connect'}


def tagged_line(name, value):
    return f'{name} {json.dumps(value, sort_keys=True)}\n'


def tree_members():
    def proc(ppid, pgrp, session, state='S', ignored=False):
        return {'state': state, 'ppid': ppid, 'pgrp': pgrp, 'session': session, 'sigterm_ignored': ignored}
    return {'normal': {'pid': 10, 'beats': 2, 'proc': proc(2, 2, 1)},
            'sigterm_ignored': {'pid': 11, 'beats': 2, 'proc': proc(2, 2, 1, ignored=True)},
            'setsid': {'pid': 12, 'beats': 2, 'proc': proc(2, 12, 12)},
            'daemon': {'pid': 14, 'beats': 2, 'proc': proc(1, 13, 13)},
            'stopped': {'pid': 15, 'beats': 2, 'proc': proc(2, 2, 1, state='T')},
            'own_pgid': {'pid': 16, 'beats': 2, 'proc': proc(2, 16, 1)}}


def tree_record(path):
    probe = {'tag': T, 'path': path, 'root': TREE_ROOT, 'members': tree_members()}
    lifetime = {'boundary': 'pid_namespace', 'tree_empty': True, 'verification_scope': 'attempt_tree',
                'integrity': 'verified'}
    if path == 'exit':
        # A left-behind tree settles as evidence_lost with exit 1 (stop-audit-2):
        # recorded in notes, never required.
        receipt = {**POLICY, 'lifetime': lifetime, 'outcome': {'kind': 'exited', 'code': 0, 'cause': None},
                   'errors': [{'code': 'evidence_lost'}]}
        exit_code = 1
    else:
        receipt = {**POLICY, **limits(wall=True), 'lifetime': lifetime,
                   'outcome': {'kind': 'signaled', 'signal': 15, 'cause': 'wall_expiry'}, 'errors': []}
        exit_code = 143
    return record(tagged_line('UKAI_TREE_PROBE', probe), exit_code, receipt, guest_stop=copy.deepcopy(GOOD_STOP),
                  files=[])


def tree_watch():
    kinds = capabilities.TREE_KINDS
    return {'markers': {kind: f'{member["pid"]}\n' for kind, member in tree_members().items()},
            'during': [{kind: 1 for kind in kinds}, {kind: 2 for kind in kinds},
                       {kind: 2 if kind == 'stopped' else 4 for kind in kinds}],
            'at_done': {kind: 2 if kind == 'stopped' else 5 for kind in kinds},
            'settled_from': {kind: 2 if kind == 'stopped' else 5 for kind in kinds},
            'settled_to': {kind: 2 if kind == 'stopped' else 5 for kind in kinds}}


def trace_file(counts, extra=()):
    """An evidence trace with `counts[class]` audit results, plus events no
    class counts (a wrapper note, a proxy result)."""
    lines = [{'source': 'wrapper', 'stage': 'result', 'operation': 'note'},
             {'source': 'proxy', 'stage': 'result', 'operation': 'net.connect'}, *extra]
    for cls, count in counts.items():
        lines += [{'source': 'audit', 'stage': 'result', 'operation': TRACE_OPERATION[cls]}] * (count or 0)
    text = ''.join(json.dumps(line) + '\n' for line in lines)
    return {'group': 'evidence', 'path': 'trace.ndjson', 'executable': False,
            'sha256': hashlib.sha256(text.encode()).hexdigest(), 'text': text}


def coverage(counts, degraded=()):
    entries = {}
    for cls, count in counts.items():
        if cls in degraded:
            entries[cls] = {'status': 'degraded', 'sources': ['audit'], 'observed_count': None,
                            'gaps': [{'classes': list(degraded), 'source': 'audit', 'reason': 'entry_abandoned'}]}
        else:
            entries[cls] = {'status': 'active', 'sources': ['audit'], 'observed_count': count, 'gaps': []}
    return entries


OBSERVER = {'backend': 'ptrace', 'set': 'linux-closed-v1', 'attached': True, 'gaps': []}


def observe_record(name):
    label, rounds = capabilities.observe_label(T, name), capabilities.OBSERVE_ROUNDS[name][1]
    probe = {'tag': label, 'rounds': rounds,
             'execs': [{'argv': argv, 'returncode': code} for _ in range(rounds) for argv, code in capabilities.OBSERVE_EXECS],
             'writes': ['written'] * rounds, 'denied_writes': [{'open': 'EROFS', 'exists_after': False}] * rounds,
             'connects': ['ENETUNREACH'] * rounds}
    if name == 'observe_background':
        probe['background_started'] = True
        # exec and fs.deny lost at settlement (as stop-audit-2); fs.write
        # complete: the round's write, the marker and five beats, plus one.
        counts = {'exec': None, 'fs.write': 8, 'fs.deny': None, 'net': 1}
        receipt = {**POLICY, 'observer': OBSERVER, 'coverage': coverage(counts, ('exec', 'fs.deny')),
                   'errors': [{'code': 'evidence_lost'}]}
        return record(tagged_line('UKAI_OBSERVE_PROBE', probe), 1, receipt,
                      files=[trace_file({'exec': 3, 'fs.write': 8, 'fs.deny': 0, 'net': 1})], guest_stop=GOOD_STOP)
    # python3's own exec and exit, then each round's operations.
    counts = {cls: (2 if cls == 'exec' else 0) + rounds * capabilities.PER_ROUND[cls]
              for cls in capabilities.AUDIT_CLASSES}
    receipt = {**POLICY, 'observer': OBSERVER, 'coverage': coverage(counts), 'errors': []}
    return record(tagged_line('UKAI_OBSERVE_PROBE', probe), 0, receipt, files=[trace_file(counts)],
                  guest_stop=GOOD_STOP)


def observe_host(name):
    label, rounds = capabilities.observe_label(T, name), capabilities.OBSERVE_ROUNDS[name][1]
    view = {'writes': {f'obs-{label}-{index}.txt': f'observed-{label}-{index}\n' for index in range(rounds)}}
    if name == 'observe_background':
        view.update(marker='77\n', beats=5)
    return view


def syscall_record():
    calls = {label: answer for label, _, _, answer, _ in capabilities.SYSCALL_DENIED}
    calls.update({label: answer for label, _, _, answer in capabilities.SYSCALL_CONTROLS})
    probe = {'tag': T, 'machine': 'aarch64', 'platform': 'linux', 'calls': calls,
             'status': {'Seccomp': '2', 'Seccomp_filters': '2', 'NoNewPrivs': '1'}}
    receipt = {**POLICY, 'errors': [], 'lifetime': {'native': {'details': {
        'seccomp_filters': {'expected': 2, 'observed': 2}}}}}
    return record(tagged_line('UKAI_SYSCALL_PROBE', probe), 0, receipt, guest_stop=GOOD_STOP, files=[])


def protected_views(profile):
    """(record, before, after) of a protected_coverage attempt that held."""
    layout = capabilities.protected_layout(T, profile)
    probe_tag = f'{T}-{profile}'
    before = {name: {'kind': 'absent'} for name in capabilities.protected_names(layout, probe_tag)}
    inode = iter(range(100, 10000))
    for path in layout['files'] + layout['file_mirrors']:
        before[path] = {'kind': 'file', 'mode': '0o644', 'ino': next(inode), 'sha256': 'sha-' + path}
    for path in layout['dirs'] + layout['dir_mirrors']:
        before[path] = {'kind': 'dir', 'mode': '0o755', 'ino': next(inode), 'entries': ['HEAD', 'config']}
    after = copy.deepcopy(before)
    made = sorted(f'{prefix}-{probe_tag}' for prefix in ('new', 'newdir', 'link'))
    for path in layout['file_mirrors']:
        after[path] = {'kind': 'absent'}
    for path in layout['dir_mirrors']:
        after[path] = {'kind': 'absent'}
        after[path + '-moved'] = {'kind': 'dir', 'mode': '0o700', 'ino': before[path]['ino'],
                                  'entries': sorted(made + ['HEAD', 'config'])}
    control = layout['absent_control']
    if control:
        for op, kind in capabilities.ABSENT_CONTROL_KINDS.items():
            after[f'{control}-{op}'] = {'kind': kind, 'mode': '0o755', 'ino': next(inode)}
        after[f'{control}-mkdir/new-{probe_tag}'] = {'kind': 'file', 'mode': '0o644', 'ino': next(inode),
                                                     'sha256': 'x'}
    for path, text in layout['creates'].items():
        after[path] = {'kind': 'file', 'mode': '0o644', 'ino': next(inode),
                       'sha256': hashlib.sha256(text.encode()).hexdigest()}
    probe = {'tag': probe_tag, 'cwd': capabilities.WORKSPACE_MOUNT,
             'files': {path: {'read': before[path]['sha256'], **{op: 'EROFS' for op in capabilities.PROTECT_FILE_OPS}}
                       for path in layout['files']},
             'dirs': {path: {'list': before[path]['entries'], **{op: 'EROFS' for op in capabilities.PROTECT_DIR_OPS}}
                      for path in layout['dirs']},
             'file_mirrors': {path: {'read': before[path]['sha256'], **{op: 'ok' for op in capabilities.PROTECT_FILE_OPS}}
                              for path in layout['file_mirrors']},
             'dir_mirrors': {path: {'list': before[path]['entries'], **{op: 'ok' for op in capabilities.PROTECT_DIR_OPS}}
                             for path in layout['dir_mirrors']},
             'absent': {path: {'seen_as': 'dir', 'mkdir': 'EEXIST', 'create_file': 'EEXIST', 'symlink': 'EEXIST',
                               'rename_onto': 'EBUSY', 'create_inside': 'EROFS'} for path in layout['absent']},
             'absent_controls': {op: 'ok' for op in capabilities.ABSENT_OPS} if control else {},
             'creates': {path: 'ok' for path in layout['creates']}}
    mounts = [{'path': '/', 'mode': 'ro'}, {'path': capabilities.WORKSPACE_MOUNT, 'mode': 'rw'}]
    mounts += [{'path': f'{capabilities.WORKSPACE_MOUNT}/{path}', 'mode': 'ro'} for path in layout['mounts']]
    receipt = {**POLICY, 'errors': [], 'applied': {'filesystem': {'protected_coverage': 'existing_and_root',
                                                                  'mounts': mounts}}}
    return (record(tagged_line('UKAI_PROTECT_PROBE', probe), 0, receipt, guest_stop=GOOD_STOP, files=[]),
            before, after)


def proxy_record():
    host, port = harness.PROBE_TARGET
    connected = {'connect': 'connected', 'accepted': True}
    probe = {'tag': T, 'environment': dict(capabilities.PROXY_ENVIRONMENT), 'loopback_control': connected,
             'unix_control': connected, 'direct': 'ENETUNREACH', 'proxy_socket': 'EACCES',
             # the first try's upstream connect failed: recorded, then retried
             'allowed': [{'target': [host, port], 'status_line': 'HTTP/1.1 502 Bad Gateway', 'reason': 'connect_failed'},
                         {'target': [host, port], 'status_line': 'HTTP/1.1 200 Connection established'}],
             'refused': {label: {'target': [h, p], 'status_line': 'HTTP/1.1 403 Forbidden',
                                 'reason': 'host_not_allowed'} for label, h, p in capabilities.proxy_refused()}}
    receipt = {**POLICY, 'errors': [], 'applied': {'network': {'mode': 'proxy', 'allowed_hosts': [harness.route_rule()]}},
               'coverage': {'proxy.net': {'status': 'active', 'sources': ['proxy'], 'observed_count': 5, 'gaps': []}}}
    return record(tagged_line('UKAI_PROXY_PROBE', probe), 0, receipt, guest_stop=GOOD_STOP, files=[])


AGENT_ATTEMPTS = ('route_control', 'protected_agent', 'network_proxy')


def good_results():
    fs_paths = [f'/etc/ukai-cap-{T}', f'/usr/local/bin/ukai-cap-{T}', f'/ukai-cap-{T}']
    fs = {'tag': T, 'paths': {path: {'open': 'EROFS', 'exists_after': False} for path in fs_paths},
          'reads': {**{path: 'ENOENT' for path in capabilities.READ_OUTSIDE},
                    **{path: 'read' for path in capabilities.read_controls(T)}}}
    mem = ''.join(f'UKAI_MEM_PROBE {T} {n}\n' for n in range(16, 481, 16))
    results = {
        'wall': record(f'start-{T}\n', 143, {**limits(wall=True), 'outcome': {'cause': 'wall_expiry'}},
                       {'released_to_done': 5100.0}),
        'pids': record('UKAI_PIDS_PROBE ' + json.dumps({'tag': T, 'forked': 61, 'fork_error': 'EAGAIN',
                                                        'pids.max': None, 'pids.current': None}) + '\n',
                       0, {**limits(pids=True), 'errors': []}),
        'mem': record(mem, 137, {**limits(mem=True), 'outcome': {'cause': 'memory_oom'}}),
        'containment': record('UKAI_FS_PROBE ' + json.dumps(fs) + '\n'),
        'network_none': record(probe_line(T, dns='unresolved--3') + '\n', 0,
                               {'applied': {'network': {'mode': 'none'}}}),
        'route_control': record(route_line(capabilities.route_tag(T)) + '\n', 0,
                                {'applied': {'network': {'mode': 'proxy'}}}),
        'workspace': record(f'wrote-{T}\n'),
        'tree_termination': tree_record('exit'),
        'tree_wall': tree_record('wall'),
        'closed_set_observation': observe_record('closed_set_observation'),
        'observe_3': observe_record('observe_3'),
        'observe_background': observe_record('observe_background'),
        'syscall_filter': syscall_record(),
        'protected_coverage': protected_views('tool')[0],
        'protected_agent': protected_views('agent')[0],
        'network_proxy': proxy_record(),
    }
    bound = {}
    for index, (name, value) in enumerate(results.items()):
        bound[name] = bind(value, f'cap-{name}-{T}', profile='agent' if name in AGENT_ATTEMPTS else 'tool')
        bound[name]['started_at'] = f'2026-11-03T10:00:{index:02d}Z'
    return bound


def good_views():
    """The host-side views measure() takes beside the attempt records."""
    protected = {}
    for name, profile in capabilities.PROTECT_PROFILES.items():
        _, before, after = protected_views(profile)
        protected[name] = {'before': before, 'after': after}
    return {'tree_watch': {name: tree_watch() for name in capabilities.TREE_PATHS},
            'observe_host': {name: observe_host(name) for name in capabilities.OBSERVE_ROUNDS},
            'protected': protected}


def judge_measured(results, views=None, status=None, reachability=None, host=f'live-{T}\n', git=True,
                   exit_code=0):
    measured = {'tag': T, 'fs_paths': CapabilityTables.FS, 'results': results, 'host_workspace_file': host,
                'reachability': reachability or {'answers': True}, **(views or good_views())}
    return capabilities.judge(measured, status or {'guest_nat': True}, git, exit_code)


class CapabilityTables(unittest.TestCase):
    FS = [f'/etc/ukai-cap-{T}', f'/usr/local/bin/ukai-cap-{T}', f'/ukai-cap-{T}']

    def good(self):
        return good_results()

    def judge(self, results, status=None, reachability=None, host=f'live-{T}\n', git=True, exit_code=0):
        return judge_measured(results, None, status, reachability, host, git, exit_code)

    def test_the_good_observation_passes(self):
        facts, summary = self.judge(self.good())
        self.assertEqual(summary['outcome'], 'PASS', facts)

    def test_every_mutation_fails_its_capability(self):
        good = self.good()
        pids_out = good['pids']['stdout']
        fs_out = good['containment']['stdout']

        def pids_limit(**changes):
            return with_receipt(good['pids'], {'applied': {'limits': [limit_entry('pids', **changes)]},
                                               'errors': []})

        def mem_limit(**changes):
            return with_receipt(good['mem'], {'applied': {'limits': [limit_entry('mem', **changes)]}})
        table = [
            ('wall', 'workload outlived the wall', mutated(good['wall'], stdout=f'start-{T}\nnever-{T}\n'), 'later_output_absent'),
            ('wall', 'the workload never started', mutated(good['wall'], stdout=''), 'later_output_absent'),
            ('wall', 'exit zero', mutated(good['wall'], exit_code=0), 'nonzero_exit'),
            ('wall', 'receipt names no wall', with_receipt(good['wall'], {'outcome': {'cause': 'wall_expiry'}}), 'receipt_records_the_wall_hit'),
            ('wall', 'an expiry cause without the wall hit', with_receipt(good['wall'], {**limits(wall=False), 'outcome': {'cause': 'wall_expiry'}}), 'receipt_records_the_wall_hit'),
            ('wall', 'ended long before the wall', mutated(good['wall'], timings_ms={'released_to_done': 900.0}), 'ended_by_the_jail_not_the_backstop'),
            ('wall', 'the controller backstop at wall + 10 s', mutated(good['wall'], timings_ms={'released_to_done': 15200.0}), 'ended_by_the_jail_not_the_backstop'),
            ('wall', 'a hit without the wall_expiry cause', with_receipt(good['wall'], limits(wall=True)), 'receipt_cause_is_wall_expiry'),
            # Reviewer FX10: a receipt is evidence for its own attempt only.
            ('wall', 'a receipt bound to another attempt', rebound(good['wall'], attempt_id='cap-wall-OTHER'), 'receipt_bound_to_this_attempt'),
            ('wall', 'a receipt whose digest failed', mutated(good['wall'], receipt_digest_ok=False), 'receipt_bound_to_this_attempt'),
            ('wall', 'a receipt for another argv', mutated(good['wall'], receipt={**good['wall']['receipt'], 'argv_digest': 'sha256:other'}), 'receipt_bound_to_this_attempt'),
            ('pids', 'fork failed with another errno', mutated(good['pids'], stdout=pids_out.replace('EAGAIN', 'ENOMEM')), 'fork_failed_with_eagain'),
            ('pids', 'stopped well before the limit (32, as 2026-11-02)', mutated(good['pids'], stdout=pids_out.replace('"forked": 61', '"forked": 32')), 'stopped_at_the_limit_not_before'),
            ('pids', 'more forks than the limit allows', mutated(good['pids'], stdout=pids_out.replace('"forked": 61', '"forked": 64')), 'stopped_at_the_limit_not_before'),
            ('pids', 'the jail lost evidence', mutated(good['pids'], exit_code=1, stdout=pids_out + 'ukai-jail: error evidence_lost at reconciling (entry_abandoned)\n'), 'attempt_settled_without_jail_error'),
            ('pids', 'a nonzero exit without a jail error line', mutated(good['pids'], exit_code=1), 'attempt_settled_without_jail_error'),
            ('pids', 'receipt errors', with_receipt(good['pids'], {**limits(pids=True), 'errors': [{'code': 'x'}]}), 'attempt_settled_without_jail_error'),
            ('pids', 'cgroup limit is not the guest limit', mutated(good['pids'], stdout=pids_out.replace('"pids.max": null', '"pids.max": "128"')), 'cgroup_limit_is_the_guest_limit'),
            ('pids', 'receipt names no pids hit', pids_limit(hit=False), 'receipt_records_the_pids_hit'),
            # Reviewer FX11: EAGAIN at ~61 forks says nothing without the receipt's 64.
            ('pids', 'the receipt applied another pids limit', pids_limit(requested='128'), 'receipt_applied_the_guest_limit'),
            ('pids', 'the receipt says pids was not applied', pids_limit(applied=False), 'receipt_applied_the_guest_limit'),
            ('pids', 'pids enforced by another mechanism', pids_limit(mechanism='rlimit'), 'receipt_applied_the_guest_limit'),
            ('pids', 'two pids probe lines', mutated(good['pids'], stdout=pids_out + pids_out), ('fork_failed_with_eagain', 'stopped_at_the_limit_not_before')),
            ('mem', 'not killed', mutated(good['mem'], exit_code=0), 'sigkilled'),
            ('mem', 'killed by another signal', mutated(good['mem'], exit_code=143), 'sigkilled'),
            ('mem', 'failed without a signal', mutated(good['mem'], exit_code=1), 'sigkilled'),
            ('mem', 'killed early, not at the limit', mutated(good['mem'], stdout=f'UKAI_MEM_PROBE {T} 16\nUKAI_MEM_PROBE {T} 32\n'), 'killed_near_the_limit'),
            ('mem', 'any exit 137 without the receipt', with_receipt(good['mem'], limits(mem=False)), 'receipt_records_the_oom'),
            ('mem', 'the receipt applied another mem limit', mem_limit(requested=str(1024 * 1024 * 1024)), 'receipt_applied_the_guest_limit'),
            ('mem', 'mem not applied', mem_limit(applied=False), 'receipt_applied_the_guest_limit'),
            ('mem', 'allocated past the limit', mutated(good['mem'], stdout=good['mem']['stdout'] + f'UKAI_MEM_PROBE {T} 528\n'), 'killed_near_the_limit'),
            ('mem', 'unbounded', mutated(good['mem'], stdout=good['mem']['stdout'] + f'UKAI_MEM_UNBOUNDED {T} 1024\n'), 'never_unbounded'),
            ('containment', 'a write was created', mutated(good['containment'], stdout=fs_out.replace('"EROFS", "exists_after": false}', '"created", "exists_after": true}', 1)), f'write_refused:{self.FS[0]}'),
            ('containment', 'a refusal that left the file behind', mutated(good['containment'], stdout=fs_out.replace('"EROFS", "exists_after": false}', '"EROFS", "exists_after": true}', 1)), f'write_refused:{self.FS[0]}'),
            ('containment', 'a path not probed', mutated(good['containment'], stdout=''),
             ('every_path_probed', *[f'write_refused:{path}' for path in self.FS],
              *[f'read_refused:{path}' for path in capabilities.READ_OUTSIDE],
              *[f'control_read:{path}' for path in capabilities.read_controls(T)])),
            ('containment', 'the probe reported another write set', mutated(good['containment'], stdout=fs_out.replace('{"/etc/', '{"/var/extra": {"open": "EROFS", "exists_after": false}, "/etc/', 1)), 'every_path_probed'),
            ('containment', 'the probe reported another read set', mutated(good['containment'], stdout=fs_out.replace('"reads": {', '"reads": {"/extra": "ENOENT", ', 1)), 'every_path_probed'),
            ('containment', 'a read outside the grants succeeded (writes-only, as 2026-11-02)', mutated(good['containment'], stdout=fs_out.replace('"/var/lib/ukai-vm": "ENOENT"', '"/var/lib/ukai-vm": "read"')), 'read_refused:/var/lib/ukai-vm'),
            ('containment', 'the read control failed (the probe could not read at all)', mutated(good['containment'], stdout=fs_out.replace('"/usr/bin/python3": "read"', '"/usr/bin/python3": "ENOENT"')), 'control_read:/usr/bin/python3'),
            ('network_none', 'egress connected', mutated(good['network_none'], stdout=probe_line(T, egress='connected', dns='unresolved--3')), 'probe_denied_after_positive_control'),
            ('network_none', 'the /dev/tcp text of 2026-11-02', mutated(good['network_none'], stdout='net_refused\ndns_refused\n'), ('probe_denied_after_positive_control', 'dns_unresolved')),
            ('network_none', 'positive control failed', mutated(good['network_none'], stdout=probe_line(T, control='ECONNREFUSED', dns='unresolved--3')), 'probe_denied_after_positive_control'),
            # Reviewer FX9: only the jail's own errno is a denial.
            ('network_none', 'a refusal (a peer answered)', mutated(good['network_none'], stdout=probe_line(T, egress='ECONNREFUSED', dns='unresolved--3')), 'probe_denied_after_positive_control'),
            ('network_none', 'a timeout', mutated(good['network_none'], stdout=probe_line(T, egress='timeout', dns='unresolved--3')), 'probe_denied_after_positive_control'),
            ('network_none', 'dns resolved', mutated(good['network_none'], stdout=probe_line(T, dns='resolved')), 'dns_unresolved'),
            ('network_none', 'receipt network not none', with_receipt(good['network_none'], {'applied': {'network': {'mode': 'proxy'}}}), 'receipt_network_none'),
            ('network_none', 'the probe receipt is another attempt\'s', rebound(good['network_none'], attempt_id='x'), 'receipt_bound_to_this_attempt'),
            ('route_control', 'the route control was refused by its proxy', mutated(good['route_control'], stdout=route_line(capabilities.route_tag(T), 'HTTP/1.1 403 Forbidden')), 'route_control_reached_the_target'),
            ('route_control', 'the route control printed nothing', mutated(good['route_control'], stdout=''), 'route_control_reached_the_target'),
            ('route_control', 'the route control ran on another guest boot', rebound(good['route_control'], guest_boot_id='g-2'), 'route_control_on_the_same_guest_boot'),
            ('route_control', 'the route control receipt is another attempt\'s', rebound(good['route_control'], attempt_id='x'), 'route_control_receipt_bound'),
            ('workspace', 'nothing written', mutated(good['workspace'], stdout=''), 'wrote'),
            ('workspace', 'an unbound receipt', mutated(good['workspace'], receipt_digest_ok=False), 'receipt_bound_to_this_attempt'),
        ]
        for name in ('wall', 'pids', 'mem', 'containment'):
            table.append((name, 'a receipt bound to another attempt', rebound(good[name], attempt_id='other'),
                          'receipt_bound_to_this_attempt'))
        for capability, name, changed, expected in table:
            with self.subTest(f'{capability}: {name}'):
                expected = (expected,) if isinstance(expected, str) else expected
                results = copy.deepcopy(good)
                results[capability] = changed
                facts, summary = self.judge(results)
                judged = 'network_none' if capability == 'route_control' else capability
                self.assertIs(facts[judged][expected[0]], False, facts[judged])
                self.assertEqual({key for key, value in facts[judged].items() if value is not True}, set(expected))
                self.assertFalse(summary[judged])
                self.assertEqual(summary['outcome'], 'FAIL')

    def test_context_mutations(self):
        no_route = self.good()
        del no_route['route_control']
        for name, kwargs, key in [
                # Reviewer FX4: `unshare -rn` (no route at all) gives the same errno.
                ('no NAT attached', {'status': {'guest_nat': False}}, 'network_none'),
                ('target dead from the host', {'reachability': {'answers': False}}, 'network_none'),
                ('no route control at all', {'results': no_route}, 'network_none'),
                ('stale workspace file', {'host': 'live-OLDRUN\n'}, 'workspace'),
                ('protected .git changed', {'git': False}, 'git_config_untouched'),
                ('serve custody failure', {'exit_code': 125}, 'service_stopped_cleanly')]:
            with self.subTest(name):
                results = kwargs.pop('results', self.good())
                _, summary = self.judge(results, **kwargs)
                self.assertFalse(summary[key])
                self.assertEqual(summary['outcome'], 'FAIL')

    def test_tagged_takes_exactly_one_line(self):
        # Reviewer C24.
        line = 'UKAI_X ' + json.dumps({'tag': T, 'n': 1}) + '\n'
        self.assertEqual(capabilities.tagged(line, 'UKAI_X', T), {'tag': T, 'n': 1})
        self.assertIsNone(capabilities.tagged(line + line, 'UKAI_X', T))
        self.assertIsNone(capabilities.tagged(line, 'UKAI_X', 'other'))

    def test_measurements_carry_each_capabilitys_own_attempt(self):
        # Reviewer C23 and C27: each requirement's own attempt and time, and
        # the shared conditions (the protected .git, the clean stop) gate all.
        good = self.good()
        measured = {'results': good}
        _, summary = self.judge(good)
        entries = capabilities.measurements(measured, summary)
        for entry in entries.values():
            name = entry['capability']
            self.assertIs(entry['verdict'], True)
            self.assertEqual(entry['measured_at'], good[name]['started_at'])
            self.assertEqual(entry['attempt_id'], good[name]['attempt_id'])
        self.assertEqual(entries['network_none']['control_attempt_id'], good['route_control']['attempt_id'])
        self.assertEqual(len({entry['measured_at'] for entry in entries.values()}), len(entries))
        for shared in ('git_config_untouched', 'service_stopped_cleanly'):
            with self.subTest(shared):
                spoiled = dict(summary, **{shared: False})
                self.assertFalse(any(entry['verdict'] for entry in capabilities.measurements(measured, spoiled).values()))

    def test_the_committed_2026_11_02_capability_evidence_now_fails(self):
        old = json.loads((EVIDENCE / 'macos-vm-warm-2026-11-02/capabilities.json').read_text())['results']
        pids = record(old['pids']['stdout'], old['pids']['exit'])
        self.assertFalse(all(capabilities.judge_pids(pids, T).values()))
        mem = record(old['mem']['stdout'], old['mem']['exit'])
        self.assertFalse(capabilities.judge_mem(mem, T)['receipt_records_the_oom'])
        network = record(old['network_none']['stdout'], old['network_none']['exit'])
        self.assertFalse(capabilities.judge_network(network, T, {'guest_nat': True}, {'answers': True}, None)[
            'probe_denied_after_positive_control'])

    def test_measure_reads_this_runs_host_file(self):
        workspace = Path(tempfile.mkdtemp(prefix='cap-flow-'))
        self.addCleanup(shutil.rmtree, workspace, True)
        requests = {}

        def script(index, request, send, channel):
            argv = [base64.b64decode(word).decode() for word in request['argv']]
            requests[request['attempt_id']] = request
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            if argv[:2] == ['/bin/sh', '-c'] and 'capability-' in argv[2]:
                (workspace / f'capability-{T}.txt').write_text(f'live-{T}\n')
            if argv[3:4] == [capabilities.TREE_PROBE]:
                # The tree fixture's members, as the share would show them.
                for kind in capabilities.TREE_KINDS:
                    marker, beat = capabilities.tree_files(T, argv[5], kind)
                    (workspace / marker).write_text('42\n')
                    (workspace / beat).write_text('beat\n' * 3)
            if argv[3:4] == [capabilities.PROTECT_PROBE]:
                # A guest that protected nothing: a seeded protected file is changed.
                (workspace / f'pc-{T}-tool/repo/.git/config').write_text('forged\n')
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        service = mock.Mock(connect=server.connect)
        measured = capabilities.measure(service, workspace, T, {'answers': True}, sleep=lambda seconds: None)
        names = [name for name, *_ in capabilities.plan(T)[1]]
        self.assertEqual(sorted(measured['results']), sorted(names))
        self.assertEqual(sorted(requests), sorted(f'cap-{name}-{T}' for name in names))
        self.assertEqual(measured['host_workspace_file'], f'live-{T}\n')
        self.assertEqual(capabilities.plan(T)[1][1][2][0], harness.PYTHON)
        route = requests[f'cap-route_control-{T}']
        self.assertEqual((route['profile'], route['allow_hosts']), ('agent', [harness.route_rule()]))
        self.assertEqual([base64.b64decode(word).decode() for word in route['argv']],
                         harness.route_argv(capabilities.route_tag(T)))
        agent = {f'cap-route_control-{T}': [harness.route_rule()], f'cap-network_proxy-{T}': [harness.route_rule()],
                 f'cap-protected_agent-{T}': None}
        for attempt_id, request in requests.items():
            expected = ('agent', agent[attempt_id]) if attempt_id in agent else ('tool', None)
            self.assertEqual((request['profile'], request.get('allow_hosts')), expected, attempt_id)
        # The host's own views: the tree's markers and beats, and the protected
        # paths seeded before and read again after their attempt.
        for name in capabilities.TREE_PATHS:
            watch = measured['tree_watch'][name]
            self.assertEqual(set(watch['markers'].values()), {'42\n'})
            self.assertEqual(watch['settled_to'], {kind: 3 for kind in capabilities.TREE_KINDS})
        view = measured['protected']['protected_coverage']
        path = f'pc-{T}-tool/repo/.git/config'
        self.assertEqual(view['before'][path]['kind'], 'file')
        self.assertNotEqual(view['before'][path]['sha256'], view['after'][path]['sha256'])
        self.assertEqual(measured['observe_host']['closed_set_observation'], {'writes': {}})
        facts, _ = judge_measured(measured['results'], {key: measured[key] for key in
                                                         ('tree_watch', 'observe_host', 'protected')})
        self.assertFalse(facts['protected_coverage'][f'tool:unchanged_on_host:{path}'])
        self.assertTrue(facts['tree_termination']['exit:every_member_beat'])
        self.assertFalse(facts['tree_termination']['exit:guest_stop_reported'])


def reprobe(result, name, tag, change):
    """Rewrite one attempt's tagged probe line through `change(probe)`."""
    probe = copy.deepcopy(capabilities.tagged(result['stdout'], name, tag))
    change(probe)
    result['stdout'] = tagged_line(name, probe)


def other_policy(receipt):
    receipt['policy'] = {'requirements': ['limit:wall']}


class GuestMeasurementMutations(unittest.TestCase):
    """The five 2026-11-04 measurements: the good observation passes, and for
    EVERY fact some mutation flips that fact alone and fails the verdict."""

    def assert_table(self, capability, table):
        good, views = good_results(), good_views()
        facts, summary = judge_measured(good, views)
        self.assertTrue(summary[capability], [key for key, value in facts[capability].items() if value is not True])
        alone = set()
        for name, change, expected in table:
            with self.subTest(f'{capability}: {name}'):
                results, changed = copy.deepcopy(good), copy.deepcopy(views)
                change(results, changed)
                expected = {expected} if isinstance(expected, str) else set(expected)
                judged, verdicts = judge_measured(results, changed)
                self.assertEqual({key for key, value in judged[capability].items() if value is not True}, expected)
                self.assertFalse(verdicts[capability])
                self.assertEqual(verdicts['outcome'], 'FAIL')
                alone |= expected if len(expected) == 1 else set()
        self.assertEqual(sorted(set(facts[capability]) - alone), [], 'facts no mutation flips alone')

    def test_tree_termination(self):
        table = []
        unconfirm = {'normal': {'ppid': 1}, 'sigterm_ignored': {'sigterm_ignored': False}, 'setsid': {'session': 1},
                     'daemon': {'session': 14, 'pgrp': 14}, 'stopped': {'state': 'S'}, 'own_pgid': {'pgrp': 2}}
        for name, path in capabilities.TREE_PATHS.items():
            def fact(key, path=path):
                return f'{path}:{key}'

            def probe(change, name=name):
                return lambda r, v: reprobe(r[name], 'UKAI_TREE_PROBE', T, change)

            def receipt(change, name=name):
                return lambda r, v: change(r[name]['receipt'])

            def watch(change, name=name):
                return lambda r, v: change(v['tree_watch'][name])

            def stop(change, name=name):
                return lambda r, v: change(r[name]['guest_stop'])
            ended = 'ended_by_target_exit' if path == 'exit' else 'ended_by_wall_expiry'
            table += [
                ('a receipt bound to another attempt', lambda r, v, name=name: r[name]['binding'].update(attempt_id='x'),
                 fact('receipt_bound_to_this_attempt')),
                ('a policy without tree_termination', receipt(other_policy), fact('policy_requires_tree_termination')),
                ('the probe ran the other end path',
                 probe(lambda p, path=path: p.update(path='wall' if path == 'exit' else 'exit')),
                 fact('probe_reported_this_path')),
                ('no probe line at all', lambda r, v, name=name: r[name].update(stdout=''),
                 [fact('probe_reported_this_path'), fact('every_marker_seen'),
                  *[fact(f'kind_confirmed:{kind}') for kind in capabilities.TREE_KINDS]]),
                ('the host never saw a marker', watch(lambda w: w['markers'].update(daemon=None)), fact('every_marker_seen')),
                ('a marker naming another process', watch(lambda w: w['markers'].update(normal='99\n')),
                 fact('every_marker_seen')),
                ('a member beat only once', watch(lambda w: w['at_done'].update(own_pgid=1)), fact('every_member_beat')),
                ('no beat file reached the host', watch(lambda w: w['at_done'].update(setsid=None)), fact('every_member_beat')),
                ('the share showed no growth while the attempt ran', watch(lambda w: w.update(during=w['during'][-1:])),
                 fact('growth_seen_during_the_attempt')),
                ('one member never grew', watch(lambda w: [sample.update(sigterm_ignored=3) for sample in w['during']]),
                 fact('growth_seen_during_the_attempt')),
                ('a SIGTERM-ignoring member beat after settlement',
                 watch(lambda w: w['settled_to'].update(sigterm_ignored=w['settled_to']['sigterm_ignored'] + 2)),
                 fact('no_beat_after_settlement')),
                ('the daemon beat after settlement', watch(lambda w: w['settled_to'].update(daemon=9)),
                 fact('no_beat_after_settlement')),
                ('no settle sample', watch(lambda w: w.update(settled_from={}, settled_to={})),
                 fact('no_beat_after_settlement')),
                ('the receipt says the tree was not empty', receipt(lambda x: x['lifetime'].update(tree_empty=False)),
                 fact('receipt_tree_empty')),
                ('integrity not verified', receipt(lambda x: x['lifetime'].update(integrity='unverified')),
                 fact('receipt_integrity_verified')),
                ('another boundary', receipt(lambda x: x['lifetime'].update(boundary='process_group')),
                 fact('receipt_boundary_pid_namespace')),
                ('another verification scope', receipt(lambda x: x['lifetime'].update(verification_scope='target_only')),
                 fact('receipt_scope_attempt_tree')),
                ('no guest stop report', lambda r, v, name=name: r[name].update(guest_stop=None),
                 [fact('guest_stop_reported'), fact('guest_stop_covered_the_attempt_cgroup'),
                  fact('guest_stop_found_no_populated_boundary'), fact('guest_stop_found_no_live_process'),
                  fact('guest_stop_killed_no_stray')]),
                ('a malformed stop report', stop(lambda s: s['boundaries'].append(7)), fact('guest_stop_reported')),
                ('a stop that never looked at the attempt cgroup',
                 stop(lambda s: s.update(boundaries=['app.slice/ukai-jail-9.scope'])),
                 fact('guest_stop_covered_the_attempt_cgroup')),
                ('the attempt cgroup still held a process',
                 stop(lambda s: s.update(populated_before_kill=['ukai-attempts.slice/attempt-3'])),
                 fact('guest_stop_found_no_populated_boundary')),
                ('a workload process outlived the jail',
                 stop(lambda s: s.update(live_before_kill=[[812, 'ukai-attempts.slice/attempt-3']])),
                 fact('guest_stop_found_no_live_process')),
                ('the stop killed a stray', stop(lambda s: s.update(strays_killed=[[812, None]])),
                 fact('guest_stop_killed_no_stray')),
            ]
            for kind, changes in unconfirm.items():
                table.append((f'/proc does not confirm {kind}',
                              probe(lambda p, kind=kind, changes=changes: p['members'][kind]['proc'].update(changes)),
                              fact(f'kind_confirmed:{kind}')))
            if path == 'exit':
                table.append(('the target did not exit 0 by itself',
                              receipt(lambda x: x.update(outcome={'kind': 'exited', 'code': 1, 'cause': None})),
                              fact(ended)))
            else:
                table += [('no wall hit', receipt(lambda x: x['applied'].update(limits=[limit_entry('wall', hit=False)])),
                           fact(ended)),
                          ('ended by something other than the wall',
                           receipt(lambda x: x.update(outcome={'kind': 'signaled', 'signal': 9, 'cause': None})),
                           fact(ended))]
        self.assertTrue(capabilities.NOT_MEASURED['tree_termination']['cancel'])
        self.assert_table('tree_termination', table)

    def test_observation(self):
        table = []
        for name in ('closed_set_observation', 'observe_3'):
            short, rounds = capabilities.OBSERVE_ROUNDS[name]
            label = capabilities.observe_label(T, name)

            def fact(key, short=short):
                return f'{short}:{key}'

            def probe(change, name=name, label=label):
                return lambda r, v: reprobe(r[name], 'UKAI_OBSERVE_PROBE', label, change)

            def receipt(change, name=name):
                return lambda r, v: change(r[name]['receipt'])
            table += [
                ('a receipt bound to another attempt', lambda r, v, name=name: r[name]['binding'].update(attempt_id='x'),
                 fact('receipt_bound_to_this_attempt')),
                ('a policy without closed_set_observation', receipt(other_policy),
                 fact('policy_requires_closed_set_observation')),
                ('observer not attached', receipt(lambda x: x.update(observer={**OBSERVER, 'attached': False})),
                 fact('observer_attached')),
                ('another observer set', receipt(lambda x: x.update(observer={**OBSERVER, 'set': 'linux-open'})),
                 fact('observer_set_linux_closed_v1')),
                ('observer gaps', receipt(lambda x: x.update(observer={**OBSERVER, 'gaps': [{'reason': 'x'}]})),
                 fact('observer_without_gaps')),
                ('an exec answered otherwise', probe(lambda p: p['execs'][-1].update(returncode=0)),
                 fact('fixture_ran_every_round')),
                ('a round missing', probe(lambda p: p.update(rounds=rounds + 1)), fact('fixture_ran_every_round')),
                ('the granted write failed', probe(lambda p: p['writes'].__setitem__(0, 'EROFS')),
                 fact('granted_writes_written')),
                ('the denied write was created',
                 probe(lambda p: p['denied_writes'].__setitem__(0, {'open': 'created', 'exists_after': True})),
                 fact('denied_writes_refused')),
                ('a connect a peer refused', probe(lambda p: p['connects'].__setitem__(0, 'ECONNREFUSED')),
                 fact('connects_refused_by_the_namespace')),
                ('the host has another run\'s bytes',
                 lambda r, v, name=name, label=label: v['observe_host'][name]['writes'].update(
                     {f'obs-{label}-0.txt': 'observed-OLD-0\n'}),
                 fact('host_has_the_granted_writes')),
                ('no trace forwarded', lambda r, v, name=name: r[name].update(files=[]),
                 fact('trace_counts_match_the_receipt')),
                ('a trace that counts fewer than the receipt',
                 lambda r, v, name=name, rounds=rounds: r[name].update(files=[trace_file(
                     {'exec': 2, 'fs.write': rounds, 'fs.deny': rounds, 'net': rounds})]),
                 fact('trace_counts_match_the_receipt')),
                ('the attempt failed', lambda r, v, name=name: r[name].update(exit_code=1),
                 fact('settled_without_error')),
                ('receipt errors', receipt(lambda x: x.update(errors=[{'code': 'evidence_lost'}])),
                 fact('settled_without_error')),
            ]
            for cls in capabilities.AUDIT_CLASSES:
                table.append((f'{cls} active with a gap',
                              receipt(lambda x, cls=cls: x['coverage'].__setitem__(
                                  cls, {**x['coverage'][cls], 'gaps': [{'classes': [cls]}]})),
                              fact(f'class_counted:{cls}')))

        def grown(cls):
            def change(results, views):
                result = results['observe_3']
                result['receipt']['coverage'][cls] = dict(result['receipt']['coverage'][cls])
                result['receipt']['coverage'][cls]['observed_count'] += 1
                result['files'] = [trace_file({name: entry['observed_count']
                                               for name, entry in result['receipt']['coverage'].items()})]
            return change
        for cls in capabilities.AUDIT_CLASSES:
            table.append((f'{cls} grew by one more than the extra rounds did', grown(cls), f'count_growth:{cls}'))

        def background(change):
            return lambda r, v: change(r['observe_background']['receipt'])
        table += [
            ('bg: a receipt bound to another attempt',
             lambda r, v: r['observe_background']['binding'].update(attempt_id='x'), 'bg:receipt_bound_to_this_attempt'),
            ('bg: a policy without closed_set_observation', background(other_policy),
             'bg:policy_requires_closed_set_observation'),
            ('bg: observer not attached', background(lambda x: x.update(observer={**OBSERVER, 'attached': False})),
             'bg:observer_attached'),
            ('bg: another set', background(lambda x: x.update(observer={**OBSERVER, 'set': None})),
             'bg:observer_set_linux_closed_v1'),
            ('bg: observer gaps', background(lambda x: x.update(observer={**OBSERVER, 'gaps': [{}]})),
             'bg:observer_without_gaps'),
            ('bg: the host never saw the descendant', lambda r, v: v['observe_host']['observe_background'].update(marker=None),
             'bg:descendant_started'),
            ('bg: the descendant never beat', lambda r, v: v['observe_host']['observe_background'].update(beats=0),
             'bg:descendant_started'),
            ('bg: a loss the errors do not name', background(lambda x: x.update(errors=[])),
             'bg:loss_named_in_the_receipt_errors'),
            ('bg: a complete fs.write that misses beats',
             lambda r, v: (r['observe_background']['receipt']['coverage'].__setitem__(
                 'fs.write', {'status': 'active', 'sources': ['audit'], 'observed_count': 3, 'gaps': []}),
                 r['observe_background'].update(files=[trace_file({'exec': 3, 'fs.write': 3, 'fs.deny': 0, 'net': 1})])),
             'bg:fs_write_accounts_for_every_beat'),
            ('bg: a trace that disagrees with a complete class',
             lambda r, v: r['observe_background'].update(files=[trace_file({'exec': 3, 'fs.write': 8, 'net': 2})]),
             'bg:trace_counts_match_every_complete_class'),
        ]
        for cls in ('exec', 'fs.deny'):
            table.append((f'bg: {cls} degraded without naming its gap',
                          background(lambda x, cls=cls: x['coverage'].__setitem__(cls, {**x['coverage'][cls], 'gaps': []})),
                          f'bg:no_silent_loss:{cls}'))
        for cls in ('fs.write', 'net'):
            table.append((f'bg: {cls} active yet gapped',
                          background(lambda x, cls=cls: x['coverage'].__setitem__(
                              cls, {**x['coverage'][cls], 'gaps': [{'classes': [cls]}]})),
                          f'bg:no_silent_loss:{cls}'))
        table.append(('bg: a degraded class that kept a count',
                      background(lambda x: x['coverage'].__setitem__('exec', {**x['coverage']['exec'], 'observed_count': 3})),
                      'bg:no_silent_loss:exec'))
        self.assert_table('closed_set_observation', table)

    def test_syscall_filter(self):
        def probe(change):
            return lambda r, v: reprobe(r['syscall_filter'], 'UKAI_SYSCALL_PROBE', T, change)

        def receipt(change):
            return lambda r, v: change(r['syscall_filter']['receipt'])
        table = [
            ('a receipt bound to another attempt', lambda r, v: r['syscall_filter']['binding'].update(attempt_id='x'),
             'receipt_bound_to_this_attempt'),
            ('a policy without syscall_filter', receipt(other_policy), 'policy_requires_syscall_filter'),
            ('another machine', probe(lambda p: p.update(machine='x86_64')), 'probe_ran_on_linux_aarch64'),
            ('a probe that skipped', probe(lambda p: p.update(skipped='not linux aarch64')), 'probe_ran_on_linux_aarch64'),
            ('a call nobody asked for', probe(lambda p: p['calls'].update(extra='ok')), 'every_call_made'),
            ('no seccomp filter mode', probe(lambda p: p['status'].update(Seccomp='0')), 'seccomp_filter_mode'),
            ('no no_new_privs', probe(lambda p: p['status'].update(NoNewPrivs='0')), 'no_new_privs'),
            ('a filter stack the receipt does not name', probe(lambda p: p['status'].update(Seccomp_filters='3')),
             'filters_match_the_receipt'),
            ('the receipt missed a filter',
             receipt(lambda x: x.update(lifetime={'native': {'details': {'seccomp_filters': {'expected': 3, 'observed': 2}}}})),
             'filters_match_the_receipt'),
            ('the attempt failed', lambda r, v: r['syscall_filter'].update(exit_code=1),
             'attempt_settled_without_jail_error'),
        ]
        for label, _, _, _, kernel in capabilities.SYSCALL_DENIED:
            table.append((f'{label} answered as an unfiltered kernel would',
                          probe(lambda p, label=label, kernel=kernel: p['calls'].update({label: kernel})),
                          f'denied:{label}'))
        for label, _, _, _ in capabilities.SYSCALL_CONTROLS:
            table.append((f'{label} filtered too (the control failed)',
                          probe(lambda p, label=label: p['calls'].update({label: 'EPERM'})), f'control:{label}'))
        self.assert_table('syscall_filter', table)

    def test_protected_coverage(self):
        table = []
        for name, profile in capabilities.PROTECT_PROFILES.items():
            layout = capabilities.protected_layout(T, profile)
            probe_tag = f'{T}-{profile}'

            def fact(key, profile=profile):
                return f'{profile}:{key}'

            def probe(change, name=name, probe_tag=probe_tag):
                return lambda r, v: reprobe(r[name], 'UKAI_PROTECT_PROBE', probe_tag, change)

            def receipt(change, name=name):
                return lambda r, v: change(r[name]['receipt'])

            def after(path, change, name=name):
                return lambda r, v: v['protected'][name]['after'].__setitem__(
                    path, change(copy.deepcopy(v['protected'][name]['after'][path]), v['protected'][name]['before']))
            table += [
                ('a receipt bound to another attempt', lambda r, v, name=name: r[name]['binding'].update(attempt_id='x'),
                 fact('receipt_bound_to_this_attempt')),
                ('a policy without protected_coverage', receipt(other_policy), fact('policy_requires_protected_coverage')),
                ('another coverage', receipt(lambda x: x['applied']['filesystem'].update(protected_coverage='existing')),
                 fact('receipt_names_existing_and_root')),
                ('the probe ran elsewhere', probe(lambda p: p.update(cwd='/tmp')), fact('probe_ran_in_the_workspace')),
            ]
            for path in layout['mounts']:
                table.append((f'no read-only mount for {path}',
                              receipt(lambda x, path=path: x['applied']['filesystem'].update(mounts=[
                                  entry for entry in x['applied']['filesystem']['mounts']
                                  if entry['path'] != f'{capabilities.WORKSPACE_MOUNT}/{path}'])),
                              fact(f'receipt_mounts_read_only:{path}')))
            for path in layout['files']:
                table += [
                    (f'{path}: the probe read other bytes', probe(lambda p, path=path: p['files'][path].update(read='x')),
                     fact(f'saw_the_bytes:{path}')),
                    (f'{path}: a write succeeded', probe(lambda p, path=path: p['files'][path].update(write='ok')),
                     fact(f'refused:{path}')),
                    (f'{path}: a rename refused with ENOENT', probe(lambda p, path=path: p['files'][path].update(
                        rename_away='ENOENT')), fact(f'refused:{path}')),
                    (f'{path}: its bytes changed on the host', after(path, lambda e, b: {**e, 'sha256': 'changed'}),
                     fact(f'unchanged_on_host:{path}')),
                    (f'{path}: replaced (another inode)', after(path, lambda e, b: {**e, 'ino': 1}),
                     fact(f'unchanged_on_host:{path}')),
                    (f'{path}: moved aside on the host', after(path + '.moved', lambda e, b: {'kind': 'file'}),
                     fact(f'unchanged_on_host:{path}')),
                ]
            for path in layout['dirs']:
                table += [
                    (f'{path}: the probe listed another directory', probe(lambda p, path=path: p['dirs'][path].update(
                        list=[])), fact(f'saw_the_listing:{path}')),
                    (f'{path}: a mkdir inside succeeded', probe(lambda p, path=path: p['dirs'][path].update(
                        mkdir_inside='ok')), fact(f'refused:{path}')),
                    (f'{path}: an entry appeared on the host',
                     after(f'{path}/new-{probe_tag}', lambda e, b: {'kind': 'file'}), fact(f'unchanged_on_host:{path}')),
                    (f'{path}: its mode changed', after(path, lambda e, b: {**e, 'mode': '0o700'}),
                     fact(f'unchanged_on_host:{path}')),
                ]
            for path in layout['file_mirrors']:
                table += [
                    (f'{path}: the control read other bytes',
                     probe(lambda p, path=path: p['file_mirrors'][path].update(read='x')),
                     fact(f'control_saw_the_bytes:{path}')),
                    (f'{path}: the control could not unlink',
                     probe(lambda p, path=path: p['file_mirrors'][path].update(unlink='EROFS')),
                     fact(f'control_succeeded:{path}')),
                    (f'{path}: the host still has it', after(path, lambda e, b, path=path: b[path]),
                     fact(f'control_effect_on_host:{path}')),
                ]
            for path in layout['dir_mirrors']:
                table += [
                    (f'{path}: the control listed another directory',
                     probe(lambda p, path=path: p['dir_mirrors'][path].update(list=['x'])),
                     fact(f'control_saw_the_listing:{path}')),
                    (f'{path}: the control could not chmod',
                     probe(lambda p, path=path: p['dir_mirrors'][path].update(chmod='EROFS')),
                     fact(f'control_succeeded:{path}')),
                    (f'{path}: the moved control kept its mode',
                     after(path + '-moved', lambda e, b: {**e, 'mode': '0o755'}), fact(f'control_effect_on_host:{path}')),
                ]
            for path in layout['absent']:
                table += [
                    (f'{path}: the absent literal was created',
                     probe(lambda p, path=path: p['absent'][path].update(mkdir='ok')), fact(f'absent_refused:{path}')),
                    (f'{path}: left on the host', after(path, lambda e, b: {'kind': 'dir', 'entries': []}),
                     fact(f'still_absent_on_host:{path}')),
                ]
            if layout['absent_control']:
                control = layout['absent_control']
                table += [
                    ('the absent control could not symlink', probe(lambda p: p['absent_controls'].update(symlink='EPERM')),
                     fact('absent_control_succeeded')),
                    ('the absent control left no symlink', after(f'{control}-symlink', lambda e, b: {'kind': 'absent'}),
                     fact('absent_control_effect_on_host')),
                ]
            for path in layout['creates']:
                table.append((f'{path}: the ordinary create failed',
                              probe(lambda p, path=path: p['creates'].update({path: 'EROFS'})), fact(f'created:{path}')))
                table.append((f'{path}: other bytes on the host', after(path, lambda e, b: {**e, 'sha256': 'x'}),
                              fact(f'created:{path}')))
        self.assert_table('protected_coverage', table)

    def test_network_proxy(self):
        host, port = harness.PROBE_TARGET

        def probe(change):
            return lambda r, v: reprobe(r['network_proxy'], 'UKAI_PROXY_PROBE', T, change)

        def receipt(change):
            return lambda r, v: change(r['network_proxy']['receipt'])

        def tries(*statuses):
            # The receipt counts each try, so only the try record changes.
            def change(results, views):
                reprobe(results['network_proxy'], 'UKAI_PROXY_PROBE', T, lambda p: p.update(
                    allowed=[{'target': [host, port], 'status_line': status} for status in statuses]))
                results['network_proxy']['receipt']['coverage']['proxy.net'] = {
                    'status': 'active', 'observed_count': len(statuses) + 3, 'gaps': []}
            return change
        ok, bad = 'HTTP/1.1 200 Connection established', 'HTTP/1.1 502 Bad Gateway'
        table = [
            ('a receipt bound to another attempt', lambda r, v: r['network_proxy']['binding'].update(attempt_id='x'),
             'receipt_bound_to_this_attempt'),
            ('a policy without network_proxy', receipt(other_policy), 'policy_requires_network_proxy'),
            ('another allow set', receipt(lambda x: x['applied'].update(network={
                'mode': 'proxy', 'allowed_hosts': [harness.route_rule(), 'example.com:443']})),
             'receipt_applied_proxy_with_exactly_the_target'),
            ('network none', receipt(lambda x: x['applied'].update(network={'mode': 'none', 'allowed_hosts': []})),
             'receipt_applied_proxy_with_exactly_the_target'),
            ('a request the proxy did not count', receipt(lambda x: x['coverage'].update({'proxy.net': {
                'status': 'active', 'observed_count': 4, 'gaps': []}})), 'receipt_counted_every_request'),
            ('proxy.net degraded', receipt(lambda x: x['coverage'].update({'proxy.net': {
                'status': 'degraded', 'observed_count': None, 'gaps': [{}]}})), 'receipt_counted_every_request'),
            ('NO_PROXY set', probe(lambda p: p['environment'].update(NO_PROXY='localhost')), 'environment_is_the_bridges'),
            ('the loopback control failed', probe(lambda p: p.update(loopback_control={'connect': 'ECONNREFUSED',
                                                                                         'accepted': False})),
             'loopback_control_connected'),
            ('a direct connect reached the target', probe(lambda p: p.update(direct='connected')), 'direct_connect_denied'),
            ('a direct connect timed out', probe(lambda p: p.update(direct='timeout')), 'direct_connect_denied'),
            ('the AF_UNIX control failed', probe(lambda p: p.update(unix_control={'connect': 'connected',
                                                                                   'accepted': False})),
             'unix_control_connected'),
            ('the workload reached the proxy socket', probe(lambda p: p.update(proxy_socket='connected')),
             'proxy_socket_refused'),
            ('the proxy socket was absent', probe(lambda p: p.update(proxy_socket='ENOENT')), 'proxy_socket_refused'),
            ('a try after success', tries(ok, ok), 'every_try_recorded'),
            ('more tries than allowed', tries(bad, bad, bad, ok), 'every_try_recorded'),
            ('never reached in every try', tries(bad, bad, bad), 'allowed_target_reached'),
            ('the attempt failed', lambda r, v: r['network_proxy'].update(exit_code=1),
             'attempt_settled_without_jail_error'),
        ]
        for label, _, _ in capabilities.proxy_refused():
            table += [(f'{label} tunnelled', probe(lambda p, label=label: p['refused'][label].update(
                status_line=ok, reason=None)), f'refused:{label}'),
                (f'{label} refused for another reason', probe(lambda p, label=label: p['refused'][label].update(
                    reason='connect_failed')), f'refused:{label}')]
        self.assert_table('network_proxy', table)

    def test_measurements_list_every_attempt_and_what_was_not_measured(self):
        results = good_results()
        _, summary = judge_measured(results)
        entries = capabilities.measurements({'results': results}, summary)
        for capability, attempts in capabilities.CAPABILITY_ATTEMPTS.items():
            entry = entries[capabilities.REQUIREMENTS[capability]]
            self.assertEqual(entry['attempt_ids'], [results[name]['attempt_id'] for name in attempts])
            self.assertEqual(entry['attempt_id'], results[capability]['attempt_id'])
        tree = entries['tree_termination']
        self.assertEqual(tree['not_measured'], capabilities.NOT_MEASURED['tree_termination'])
        # The exit path's evidence_lost and exit 1 are recorded, never required.
        self.assertTrue(tree['verdict'])
        self.assertEqual(tree['notes']['tree_termination']['exit_code'], 1)
        self.assertEqual(tree['notes']['tree_termination']['receipt_errors'], ['evidence_lost'])
        self.assertEqual(entries['syscall_filter']['attempt_ids'], [results['syscall_filter']['attempt_id']])

    def test_this_worktrees_attempt_record_fails_the_tree(self):
        # A record without the guest's stop report (no `stop` in done) backs
        # no tree_termination, whatever else holds.
        results = good_results()
        for name in capabilities.TREE_PATHS:
            del results[name]['guest_stop']
        facts, summary = judge_measured(results)
        self.assertFalse(summary['tree_termination'])
        self.assertFalse(facts['tree_termination']['exit:guest_stop_reported'])

    def test_watch_tree_samples_while_the_attempt_runs_then_settles(self):
        workspace = Path(tempfile.mkdtemp(prefix='tree-watch-'))
        self.addCleanup(shutil.rmtree, workspace, True)
        files = {kind: capabilities.tree_files(T, 'exit', kind) for kind in capabilities.TREE_KINDS}
        for kind, (marker, _) in files.items():
            (workspace / marker).write_text('5\n')

        def run():
            for beat in range(3):
                for _, path in files.values():
                    with open(workspace / path, 'a') as output:
                        output.write('beat\n')
                time.sleep(0.25)
            return {'attempt_id': 'x', 'started_at': 'now'}
        sleeps = []
        with mock.patch.object(capabilities, 'TREE_SETTLE_SECONDS', 0.0), \
                mock.patch.object(capabilities, 'TREE_SHARE_GRACE', 0.0):
            result, watch = capabilities.watch_tree(run, workspace, T, 'exit', sleeps.append)
        self.assertEqual(result['attempt_id'], 'x')
        self.assertEqual(sleeps, [0.0, 0.0])
        self.assertGreaterEqual(len({sample['normal'] for sample in watch['during']}), 2)
        self.assertEqual(watch['at_done'], {kind: 3 for kind in capabilities.TREE_KINDS})
        self.assertEqual(watch['settled_from'], watch['settled_to'])
        self.assertEqual(watch['markers']['daemon'], '5\n')

        def broken():
            raise RuntimeError('connect failed')
        with self.assertRaises(RuntimeError):
            capabilities.watch_tree(broken, workspace, T, 'exit', sleeps.append)

    def test_the_host_snapshot_reads_kind_mode_bytes_and_listing(self):
        root = Path(tempfile.mkdtemp(prefix='host-entry-'))
        self.addCleanup(shutil.rmtree, root, True)
        (root / 'd').mkdir()
        (root / 'd' / 'f').write_text('x')
        (root / 'l').symlink_to('/tmp')
        self.assertEqual(capabilities.host_entry(root / 'absent'), {'kind': 'absent'})
        self.assertEqual(capabilities.host_entry(root / 'd')['entries'], ['f'])
        self.assertEqual(capabilities.host_entry(root / 'd' / 'f')['sha256'], hashlib.sha256(b'x').hexdigest())
        self.assertEqual(capabilities.host_entry(root / 'l')['kind'], 'symlink')


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
        observed = bind(record(done.stdout), 'fs')
        facts = capabilities.judge_containment(observed, T, write, read, control)
        self.assertTrue(all(facts.values()), (facts, done.stderr))
        flipped = capabilities.judge_containment(observed, T, write, control, read)
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
        # RLIMIT_NPROC counts this user's processes on macOS but its tasks
        # (every thread, this test runner's included) on Linux.
        tasks = ['-L', '-o', 'lwp='] if sys.platform.startswith('linux') else ['-o', 'pid=']
        users = subprocess.run(['ps', '-U', str(os.getuid()), *tasks], capture_output=True, text=True)
        cap = len(users.stdout.split()) + 12

        def limit():  # in the probe's child only: its own forks fail past the cap
            resource.setrlimit(resource.RLIMIT_NPROC, (cap, cap))
        done = self.run_probe([harness.PYTHON, '-I', '-c', capabilities.PIDS_PROBE, T], preexec_fn=limit)
        probe = capabilities.tagged(done.stdout, 'UKAI_PIDS_PROBE', T)
        self.assertIsNotNone(probe, done.stderr)
        self.assertEqual(probe['fork_error'], 'EAGAIN')
        self.assertGreater(probe['forked'], 0)
        self.assertLess(probe['forked'], 64)

    def test_the_syscall_probe_calls_nothing_off_linux_aarch64(self):
        done = self.run_probe(capabilities.syscall_argv(T))
        probe = capabilities.tagged(done.stdout, 'UKAI_SYSCALL_PROBE', T)
        self.assertIsNotNone(probe, done.stderr)
        if sys.platform.startswith('linux') and os.uname().machine == 'aarch64':
            self.skipTest('this host would make the calls')
        self.assertEqual((probe['skipped'], probe['calls']), ('not linux aarch64', {}))
        self.assertFalse(capabilities.judge_syscall(bind(record(done.stdout), 's'), T)['probe_ran_on_linux_aarch64'])

    def test_the_observe_probe_reports_each_operation(self):
        cwd = Path(tempfile.mkdtemp(prefix='observe-'))
        self.addCleanup(shutil.rmtree, cwd, True)
        name = 'observe_3'
        label = capabilities.observe_label(T, name)
        done = self.run_probe(capabilities.observe_argv(T, name), cwd=cwd)
        probe = capabilities.tagged(done.stdout, 'UKAI_OBSERVE_PROBE', label)
        self.assertIsNotNone(probe, done.stderr)
        self.assertEqual(probe['execs'], [{'argv': argv, 'returncode': code} for _ in range(3)
                                          for argv, code in capabilities.OBSERVE_EXECS])
        self.assertEqual(probe['writes'], ['written'] * 3)
        self.assertEqual(capabilities.observe_view(cwd, T, name)['writes'],
                         {f'obs-{label}-{i}.txt': f'observed-{label}-{i}\n' for i in range(3)})
        # This host's /etc refuses an unprivileged create; its loopback target
        # (setUpModule) refuses the connect: a peer's answer, not a namespace's.
        for entry in probe['denied_writes']:
            self.assertIn(entry['open'], capabilities.DENIED_WRITE_ERRNOS)
            self.assertFalse(entry['exists_after'])
        self.assertEqual(probe['connects'], ['ECONNREFUSED'] * 3)
        facts = capabilities.judge_observe_run(bind(record(done.stdout), 'o'), T, name,
                                               capabilities.observe_view(cwd, T, name))
        self.assertTrue(facts['fixture_ran_every_round'] and facts['host_has_the_granted_writes'])
        self.assertFalse(facts['connects_refused_by_the_namespace'])

    def test_the_protect_probe_against_a_workspace_that_protects_nothing(self):
        # Every protected operation succeeds here, so every refusal fact is
        # false while every control (and the host's view of it) holds.
        cwd = Path(tempfile.mkdtemp(prefix='protect-'))
        self.addCleanup(shutil.rmtree, cwd, True)
        harness.protected_sentinel(cwd)
        layout = capabilities.protected_layout(T, 'tool')
        capabilities.seed_protected(cwd, layout)
        before = capabilities.protected_snapshot(cwd, layout, f'{T}-tool')
        done = self.run_probe(capabilities.protect_argv(T, 'tool'), cwd=cwd)
        self.assertIsNotNone(capabilities.tagged(done.stdout, 'UKAI_PROTECT_PROBE', f'{T}-tool'), done.stderr)
        after = capabilities.protected_snapshot(cwd, layout, f'{T}-tool')
        facts = capabilities.judge_protected(bind(record(done.stdout), 'p'), T, 'tool', before, after)
        for key, value in facts.items():
            with self.subTest(key):
                if key.startswith(('control_', 'absent_control_', 'created:', 'saw_the_')):
                    self.assertIs(value, True)
                elif key.startswith(('refused:', 'unchanged_on_host:', 'absent_refused:', 'still_absent_on_host:')):
                    self.assertIs(value, False)

    def test_the_proxy_probe_records_its_controls_and_every_try(self):
        cwd = Path(tempfile.mkdtemp(prefix='proxy-'))
        self.addCleanup(shutil.rmtree, cwd, True)
        environment = {key: value for key, value in os.environ.items() if 'proxy' not in key.lower()}
        done = self.run_probe(capabilities.proxy_argv(T), cwd=cwd, env=environment)
        probe = capabilities.tagged(done.stdout, 'UKAI_PROXY_PROBE', T)
        self.assertIsNotNone(probe, done.stderr)
        self.assertEqual(probe['loopback_control'], {'connect': 'connected', 'accepted': True})
        self.assertEqual(probe['unix_control'], {'connect': 'connected', 'accepted': True})
        self.assertEqual(probe['direct'], 'ECONNREFUSED')
        self.assertEqual(probe['proxy_socket'], 'ENOENT')
        self.assertEqual(len(probe['allowed']), capabilities.PROXY_TRIES)
        self.assertTrue(all('no http proxy' in reply['error'] for reply in probe['allowed']))
        self.assertEqual(sorted(probe['refused']), sorted(label for label, *_ in capabilities.proxy_refused()))
        self.assertEqual(set(probe['environment'].values()), {None})
        facts = capabilities.judge_proxy(bind(record(done.stdout), 'x'), T)
        self.assertTrue(facts['loopback_control_connected'] and facts['every_try_recorded'])
        self.assertFalse(facts['allowed_target_reached'] or facts['direct_connect_denied'])

    def test_the_tree_probe_starts_every_kind(self):
        cwd = Path(tempfile.mkdtemp(prefix='tree-'))
        self.addCleanup(shutil.rmtree, cwd, True)
        files = {kind: capabilities.tree_files(T, 'exit', kind) for kind in capabilities.TREE_KINDS}

        def reap():
            for marker, _ in files.values():
                pid = capabilities.marker_pid(capabilities.read_text(cwd / marker))
                if pid:
                    with contextlib.suppress(OSError):
                        os.kill(pid, signal.SIGKILL)
        self.addCleanup(reap)
        argv = capabilities.tree_argv(T, 'exit')[:-1] + ['0']   # no hold
        done = self.run_probe(argv, cwd=cwd)
        probe = capabilities.tagged(done.stdout, 'UKAI_TREE_PROBE', T)
        self.assertIsNotNone(probe, done.stderr)
        self.assertEqual(probe['path'], 'exit')
        for kind, (marker, _) in files.items():
            with self.subTest(kind):
                self.assertEqual(capabilities.marker_pid(capabilities.read_text(cwd / marker)),
                                 probe['members'][kind]['pid'])
                self.assertGreaterEqual(probe['members'][kind]['beats'], capabilities.TREE_MIN_BEATS)
        if sys.platform.startswith('linux'):
            for kind in capabilities.TREE_KINDS:
                self.assertTrue(capabilities.kind_confirmed(kind, probe['members'][kind], probe['root']), kind)


class WarmLiveTables(unittest.TestCase):
    def good(self, count=20):
        records = []
        for index in range(count):
            records.append({
                'index': index, 'exit_code': 0, 'error': None, 'boot_id': 'vm-one',
                'binding': {'guest_boot_id': 'guest-one'}, 'receipt_digest_ok': True, 'receipt_bound': True,
                'stdout': f'git_write_refused-{index}\n' + probe_line(f'{T}-{index}') + f'\nout-{index}\n',
                'host_write': f'warm-{index}-{T}\n', 'git_config_after': warm_live.SENTINEL,
                'probe': harness.probe_verdict(probe_line(f'{T}-{index}'), f'{T}-{index}'),
                'receipt_network': 'none', 'timings_ms': {'connect_to_released': 15.0}})
        return records

    def route(self, **changes):
        value = {'attempt_id': f'warm-route-{T}', 'boot_id': 'vm-one', 'binding': {'guest_boot_id': 'guest-one'},
                 'receipt_bound': True, 'error': None,
                 'route': harness.route_verdict(route_line(f'{T}-route'), f'{T}-route')}
        value.update(changes)
        return value

    def judge(self, records, **kwargs):
        options = dict(budget_ms=1000.0, status={'guest_nat': True}, service_exit=0,
                       git_config_text=warm_live.SENTINEL, route=self.route())
        options.update(kwargs)
        return warm_live.judge(records, T, **options)[1]

    def test_the_good_run_passes(self):
        verdict = self.judge(self.good())
        self.assertEqual(verdict['outcome'], 'PASS', verdict['failed'])
        self.assertIn('not ukai-jail run --vm', verdict['k108_client'])
        self.assertEqual(verdict['route_control']['attempt_id'], f'warm-route-{T}')

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
            ('egress allowed', at(1, probe=harness.probe_verdict(probe_line(f'{T}-1', egress='connected'), f'{T}-1')), 'every_attempt_saw_the_jails_denial'),
            ('a refusal is not the jail', at(1, probe=harness.probe_verdict(probe_line(f'{T}-1', egress='ECONNREFUSED'), f'{T}-1')), 'every_attempt_saw_the_jails_denial'),
            ('the /dev/tcp text', at(1, probe=harness.probe_verdict('net_denied', f'{T}-1')), 'every_attempt_network_denied'),
            ('a second serve boot', at(9, boot_id='vm-two'), 'warm_reuse_one_serve_boot'),
            ('a second guest kernel boot', at(9, binding={'guest_boot_id': 'guest-two'}), 'warm_reuse_one_guest_boot'),
            ('one attempt over the 1 s budget', at(11, timings_ms={'connect_to_released': 1000.1}), 'k108_every_attempt_within_budget'),
            ('a release never seen', at(11, timings_ms={'connect_to_released': None}), 'k108_every_attempt_within_budget'),
            ('a failed attempt', at(4, exit_code=1), 'every_attempt_exit_zero'),
            ('an unverified receipt', at(4, receipt_digest_ok=False), 'every_receipt_verified'),
            ('a receipt bound to another attempt', at(4, receipt_bound=False), 'every_receipt_verified'),
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

    def test_a_denial_without_a_route_is_not_the_jails(self):
        # Reviewer FX4: with no NAT, or no route control reaching the target
        # on the same guest boot, every ENETUNREACH could be `unshare -rn`.
        for name, kwargs, gate in [
                ('no NAT attached', {'status': {'guest_nat': False}}, 'guest_nat_attached'),
                ('NAT unknown', {'status': {}}, 'guest_nat_attached'),
                ('no route control', {'route': None}, 'route_control_reached_the_target'),
                ('the route control never reached the target',
                 {'route': self.route(route=harness.route_verdict(route_line(f'{T}-route', 'HTTP/1.1 502 Bad Gateway'), f'{T}-route'))},
                 'route_control_reached_the_target'),
                ('the route control on another guest boot', {'route': self.route(binding={'guest_boot_id': 'guest-two'})},
                 'route_control_on_the_same_guest_boot'),
                ('the route control receipt is another attempt\'s', {'route': self.route(receipt_bound=False)},
                 'route_control_receipt_bound')]:
            with self.subTest(name):
                verdict = self.judge(self.good(), **kwargs)
                self.assertEqual(verdict['outcome'], 'FAIL')
                self.assertIn(gate, verdict['failed'])
                self.assertIn('every_attempt_network_denied', verdict['failed'])

    def test_a_refused_real_client_is_refused_never_a_pass(self):
        # S1's F11d: a real client refused for its standard input (or any
        # vm: refusal) makes the row REFUSED, unless a warm gate failed.
        runs = [{'index': i, 'exit': 0, 'exec_to_first_write_ms': 400.0, 'refusals': []} for i in range(20)]
        runs[0].update(exit=125, exec_to_first_write_ms=None, refusals=['--vm: standard input is a pipe'])
        verdict = self.judge(self.good(), real_client=runs)
        self.assertEqual(verdict['outcome'], 'REFUSED')
        self.assertEqual(verdict['k108_real_client']['refusals'], ['--vm: standard input is a pipe'])
        self.assertEqual(self.judge(self.good(), real_client=runs, service_exit=125)['outcome'], 'FAIL')

    def test_context_and_real_client_mutations(self):
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
        # Reviewer W13: a real client that failed AFTER its first write is no pass.
        failed = copy.deepcopy(runs)
        failed[6]['exit'] = 1
        verdict = self.judge(self.good(), real_client=failed)
        self.assertFalse(verdict['k108_real_client']['every_run_exit_zero'])
        self.assertEqual(verdict['outcome'], 'FAIL')

    def test_the_attempt_script_tells_a_refused_write_from_an_allowed_one(self):
        # Reviewer W15: the real script under /bin/sh, against a writable and
        # a read-only .git: exactly one of the two markers each time.
        root = Path(tempfile.mkdtemp(prefix='warm-script-'))
        self.addCleanup(lambda: ((root / '.git').chmod(0o755), shutil.rmtree(root, True)))
        harness.protected_sentinel(root, warm_live.SENTINEL)
        if os.geteuid() == 0:
            self.skipTest('a read-only directory does not stop root')
        with mock.patch.object(harness, 'probe_shell', lambda *a, **k: 'true'):
            script = warm_live.attempt_script(4, T)
        allowed = subprocess.run(['/bin/sh', '-c', script], cwd=root, capture_output=True, text=True, timeout=30)
        self.assertIn('GIT_WRITE_ALLOWED-4', allowed.stdout)
        self.assertNotIn('git_write_refused-4', allowed.stdout)
        (root / '.git' / 'config').write_text(warm_live.SENTINEL)
        (root / '.git' / 'config').chmod(0o444)
        (root / '.git').chmod(0o555)
        refused = subprocess.run(['/bin/sh', '-c', script], cwd=root, capture_output=True, text=True, timeout=30)
        self.assertIn('git_write_refused-4', refused.stdout)
        self.assertNotIn('GIT_WRITE_ALLOWED-4', refused.stdout)
        self.assertEqual((root / 'attempt-4.txt').read_text(), f'warm-4-{T}\n')
        facts = warm_live.attempt_facts({'index': 4, 'stdout': allowed.stdout, 'probe': {'denied': True}}, T)
        self.assertFalse(facts['protected_write_tried_and_refused'])

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
            send(**bound_frame(request, {'applied': {'network': {'mode': 'none'}}}))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        result = warm_live.one_attempt(mock.Mock(connect=server.connect), workspace, 0, T)
        facts = warm_live.attempt_facts(result, T)
        self.assertFalse(facts['granted_write_on_host'], 'a stale file from another run must not count')
        self.assertTrue(facts['probe_saw_the_jails_denial'] and facts['protected_git_unchanged']
                        and facts['receipt_verified'] and facts['receipt_network_none'])
        self.assertNotIn('receipt', result)

        def elsewhere(index, request, send, channel):
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            send(**bound_frame(dict(request, attempt_id='warm-0-OTHER'), {'applied': {'network': {'mode': 'none'}}}))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(elsewhere)
        self.addCleanup(server.close)
        result = warm_live.one_attempt(mock.Mock(connect=server.connect), workspace, 0, T)
        self.assertFalse(warm_live.attempt_facts(result, T)['receipt_verified'])

    def test_the_route_control_asks_the_proxy_for_the_probe_target(self):
        seen = []

        def script(index, request, send, channel):
            seen.append(request)
            send(event='prepared', kernel='k')
            channel.frame()
            send(event='released', supervisor_pid=1)
            send(event='stdout', data=base64.b64encode((route_line(f'{T}-route') + '\n').encode()).decode())
            send(**bound_frame(request, {'applied': {'network': {'mode': 'proxy'}}}))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        route = warm_live.route_control(mock.Mock(connect=server.connect), T)
        self.assertTrue(route['route']['reached'])
        self.assertTrue(route['receipt_bound'])
        self.assertNotIn('receipt', route)
        self.assertEqual((seen[0]['profile'], seen[0]['allow_hosts']), ('agent', [harness.route_rule()]))

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


# guest.py's receipt binding for a prepare request (harness.argv_digest's preimage).
FAKE_BINDING = r"""
import base64, hashlib, json, struct

def argv_digest(words):
    preimage = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(words))
    preimage += b''.join(struct.pack('>Q', len(word)) + word for word in words)
    return 'sha256:' + hashlib.sha256(preimage).hexdigest()

def bound_receipt(prepare, boot, guest_boot, receipt):
    digest = argv_digest([base64.b64decode(word) for word in prepare['argv']])
    raw = json.dumps(dict(receipt, argv_digest=digest)).encode()
    return {'event': 'bound_receipt', 'sha256': hashlib.sha256(raw).hexdigest(),
            'data': base64.b64encode(raw).decode(),
            'binding': {'attempt_id': prepare['attempt_id'], 'boot_id': boot, 'profile': prepare['profile'],
                        'argv_digest': digest, 'guest_attempt_id': 'att_' + prepare['attempt_id'],
                        'guest_boot_id': guest_boot}}
"""

FAKE_SERVE = FAKE_BINDING + r"""
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
        words = [base64.b64decode(word).decode() for word in prepare['argv']]
        if prepare['profile'] == 'agent':
            # The route control: the guest proxy tunnels to an allowed target
            # (connecting nowhere here); with no route it answers 502.
            nonce, host, port = words[4], words[5], int(words[6])
            reached = f'{host}:{port}' in prepare.get('allow_hosts', []) and mode != 'noroute'
            line = {'nonce': nonce, 'target': [host, port],
                    'status_line': 'HTTP/1.1 200 Connection established' if reached else 'HTTP/1.1 502 Bad Gateway'}
            text = 'UKAI_ROUTE_CONTROL ' + json.dumps(line) + '\n'
            send(stream, event='stdout', data=base64.b64encode(text.encode()).decode())
            stream.sendall((json.dumps(bound_receipt(prepare, boot, 'guest-1', {'applied': {'network': {'mode': 'proxy'}}})) + '\n').encode())
            send(stream, event='done', exit_code=0)
            stream.close()
            count += 1
            continue
        script = words[2]
        index, tag = re.search(r"warm-(\d+)-(\w+)\\n' > attempt-", script).groups()
        if not (mode == 'skip-write' and index == '3'):
            (workspace / f'attempt-{index}.txt').write_text(f'warm-{index}-{tag}\n')
        probe = {'nonce': f'{tag}-{index}', 'control': 'connected', 'control_accepted': True,
                 'egress': 'connected' if mode == 'egress' else 'ENETUNREACH'}
        text = f'git_write_refused-{index}\nUKAI_NET_PROBE {json.dumps(probe)}\nout-{index}\n'
        send(stream, event='stdout', data=base64.b64encode(text.encode()).decode())
        frame = bound_receipt(prepare, boot, 'guest-1', {'applied': {'network': {'mode': 'none'}}})
        if mode == 'unbound' and index == '6':
            frame['binding']['attempt_id'] = 'warm-6-someone-else'
        stream.sendall((json.dumps(frame) + '\n').encode())
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
        # The NAT adapter is always attached, by flag, never by environment.
        self.assertIs(record['guest_nat'], True)
        self.assertTrue(record['route_control_reached_the_target'])
        self.assertEqual(record['route_control']['attempt_id'], f"warm-route-{record['attempts'][0]['attempt_id'].split('-')[-1]}")
        self.assertNotIn(str(self.root), json.dumps(record), 'a record carries no absolute temp path')

    def test_a_guest_without_a_route_fails(self):
        # Reviewer FX4 end to end: every probe sees ENETUNREACH, but the
        # guest itself reaches nothing, so the denial is not the jail's.
        code, record = self.warm_live('noroute')
        self.assertEqual(code, 1)
        self.assertTrue(record['every_attempt_saw_the_jails_denial'])
        self.assertEqual(record['failed'], ['route_control_reached_the_target', 'every_attempt_network_denied'])

    def test_a_receipt_bound_elsewhere_fails(self):
        code, record = self.warm_live('unbound')
        self.assertEqual(code, 1)
        self.assertEqual(record['failed'], ['every_receipt_verified'])

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


FAKE_GUEST_SERVE = FAKE_BINDING + r"""
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

def proxy(allowed):
    # The guest jail's proxy, faked on loopback: a CONNECT to an allowed
    # target is answered 200 (tunnelling nowhere), any other 403.
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(4)

    def serve():
        while True:
            stream, _ = listener.accept()
            head = b''
            while b'\r\n\r\n' not in head:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                head += chunk
            target = head.split(b'\r\n', 1)[0].decode().split(' ')[1]
            if os.environ.get('FAKE_NO_ROUTE'):
                status = '502 Bad Gateway'   # a guest with no route: the upstream connect failed
            else:
                status = '200 Connection established' if target in allowed else '403 Forbidden'
            stream.sendall(('HTTP/1.1 %s\r\n\r\n' % status).encode())
            stream.close()
    threading.Thread(target=serve, daemon=True).start()
    return 'http://127.0.0.1:%d' % listener.getsockname()[1]

def control(server):
    while True:
        stream, _ = server.accept()
        request = next(frames(stream))
        if request['op'] == 'status':
            send(stream, event='status', boot_id=boot, warm=True, attempt_live=state['live'],
                 guest_nat='--guest-nat' in args and not os.environ.get('FAKE_NO_NAT'))
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
    environment = {key: value for key, value in os.environ.items() if 'proxy' not in key.lower()}
    environment['PATH'] = f'{shim}:/usr/bin:/bin'
    if prepare['profile'] == 'agent':
        environment['HTTPS_PROXY'] = proxy(prepare.get('allow_hosts') or [])
    process = subprocess.Popen(argv, cwd=workspace, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env=environment, start_new_session=True)
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
    mode = 'proxy' if prepare['profile'] == 'agent' else 'none'
    receipt = bound_receipt(prepare, boot, guest_boot, {'applied': {'network': {'mode': mode}}})
    state['receipts'] = state.get('receipts', 0) + 1
    if os.environ.get('FAKE_UNBOUND_FIRST') and state['receipts'] == 1:
        receipt['binding']['attempt_id'] = 'another-attempt'   # the first receipt names some other attempt
    stream.sendall((json.dumps(receipt) + '\n').encode())
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


class VmClientStandardInput(unittest.TestCase):
    """S1's F11d: `ukai-jail run --vm` refuses, before any contact, a
    standard input that is not a terminal, /dev/null or closed; every
    harness `--vm` client runs with stdin=subprocess.DEVNULL."""

    SPAWNERS = {'run', 'Popen', 'call', 'check_call', 'check_output'}

    def spawns(self, source):
        """(each process spawn whose argv holds a '--vm' constant, every
        '--vm' constant in the module, the constants those argvs hold)."""
        tree = ast.parse(source)
        constants = [node for node in ast.walk(tree)
                     if isinstance(node, ast.Constant) and node.value == '--vm']
        spawns, covered = {}, set()
        for function in ast.walk(tree):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            assigned = {}
            for node in ast.walk(function):
                targets = node.targets if isinstance(node, ast.Assign) else (
                    [node.target] if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else [])
                for target in targets:
                    if isinstance(target, ast.Name) and node.value is not None:
                        assigned.setdefault(target.id, []).append(node.value)
            for call in ast.walk(function):
                if not isinstance(call, ast.Call):
                    continue
                func = call.func
                name = func.id if isinstance(func, ast.Name) else (
                    func.attr if isinstance(func, ast.Attribute) else None)
                if name not in self.SPAWNERS:
                    continue
                command = call.args[0] if call.args else next(
                    (k.value for k in call.keywords if k.arg == 'args'), None)
                if command is None:
                    continue
                parts = [command] + (assigned.get(command.id, []) if isinstance(command, ast.Name) else [])
                held = {id(node) for part in parts for node in ast.walk(part)
                        if isinstance(node, ast.Constant) and node.value == '--vm'}
                if held:
                    stdin = next((k.value for k in call.keywords if k.arg == 'stdin'), None)
                    spawns[id(call)] = (call.lineno, stdin is not None and ast.unparse(stdin))
                    covered |= held
        return list(spawns.values()), constants, covered

    def test_every_vm_invocation_passes_devnull(self):
        sites = 0
        # Every module here but the tests: a new --vm client is checked too.
        for path in sorted(p for p in HERE.glob('*.py') if not p.name.startswith('test_')):
            module = path.stem
            with self.subTest(module):
                source = path.read_text()
                spawns, constants, covered = self.spawns(source)
                # A '--vm' constant no spawn's argv holds is an invocation this
                # check cannot see (built elsewhere): refuse it outright.
                self.assertEqual([c.lineno for c in constants if id(c) not in covered], [])
                for line, stdin in spawns:
                    self.assertEqual(stdin, 'subprocess.DEVNULL', f'{module}.py:{line}')
                sites += len(spawns)
        # fault_matrix 1, proxy_measurement 1, vault_measurement 2, warm_live 1,
        # gate_rows 2 (K111 under script(1), K112 both lanes), claude_vm_row 1.
        self.assertEqual(sites, 8)

    def test_the_check_sees_a_missing_or_other_stdin(self):
        for text, expected in [
                ("def f(j):\n    subprocess.run([j, 'run', '--vm'], env={})\n", [(2, False)]),
                ("def f(j):\n    c = [j, 'run', *(['--vm'] if x else [])]\n    subprocess.Popen(c, stdin=sys.stdin)\n",
                 [(3, 'sys.stdin')]),
                ("def f(j, run):\n    run(['script', '-q', '/dev/null', j, 'run', '--vm'], stdin=subprocess.DEVNULL)\n",
                 [(2, 'subprocess.DEVNULL')])]:
            with self.subTest(text):
                spawns, constants, covered = self.spawns(text)
                self.assertEqual(spawns, expected)
                self.assertEqual(len(covered), len(constants))
        _, constants, covered = self.spawns("ARGV = ['run', '--vm']\ndef f():\n    subprocess.run(ARGV)\n")
        self.assertEqual(len(constants), 1)
        self.assertEqual(covered, set())

    def test_two_clients_run_with_a_pipe_as_the_harness_stdin(self):
        root = Path(tempfile.mkdtemp(prefix='stdin-')).resolve()
        self.addCleanup(shutil.rmtree, root, True)
        jail = root / 'ukai-jail'
        jail.write_text(f'#!{sys.executable}\n' + FAKE_STDIN_JAIL)
        jail.chmod(0o755)
        workspace = root / 'ws'
        workspace.mkdir()
        environment = {'PATH': '/usr/bin:/bin'}
        read, write = os.pipe()
        saved = os.dup(0)
        os.dup2(read, 0)
        try:
            refused = subprocess.run([str(jail), 'run', '--vm', '--workspace', str(workspace), '--', '/usr/bin/true'],
                                     env=environment, capture_output=True, text=True)
            ran = proxy_measurement.run_vm(jail, environment, workspace, 'tool', [], ['/bin/sh', '-c', 'echo ran'])
            timed = warm_live.real_client_attempts(jail, environment, workspace, 1, 'stdin')
        finally:
            os.dup2(saved, 0)
            os.close(saved)
            os.close(read)
            os.close(write)
        # The fake refuses an inherited pipe as S1's client does ...
        self.assertEqual(refused.returncode, 125)
        self.assertEqual(harness.vm_refusals(refused.stderr), ['--vm: standard input is a pipe'])
        # ... and the harness clients never hand it one.
        self.assertEqual((ran['exit'], ran['stdout']), (0, 'ran\n'), ran['stderr'])
        self.assertEqual((timed[0]['exit'], timed[0]['refusals']), (0, []), timed[0]['stderr_tail'])
        self.assertIsNotNone(timed[0]['exec_to_first_write_ms'])


FAKE_STDIN_JAIL = r'''
import os, stat, subprocess, sys
args = sys.argv[1:]
# S1's F11d, faked: standard input must be a terminal, /dev/null or closed.
try:
    status = os.fstat(0)
except OSError:
    status = None
if status is not None and not os.isatty(0) and not (
        stat.S_ISCHR(status.st_mode) and status.st_rdev == os.stat('/dev/null').st_rdev):
    kind = 'a pipe' if stat.S_ISFIFO(status.st_mode) else 'neither a terminal nor /dev/null'
    sys.stderr.write("ukai-jail: refused at preparing [invalid_config]: --vm: standard input is %s, "
                     "and the guest jail's standard input is /dev/null: nothing written to it would "
                     "reach the target; run with `</dev/null`, or without --vm\n" % kind)
    sys.exit(125)
workspace = args[args.index('--workspace') + 1]
sys.exit(subprocess.run(args[args.index('--') + 1:], cwd=workspace, stdin=subprocess.DEVNULL).returncode)
'''


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

    def run_case(self, case, **patches):
        closed = socket.socket()
        closed.bind(('127.0.0.1', 0))
        port = closed.getsockname()[1]
        closed.close()
        # This fake 'guest' has no network namespace: its probe meets a closed
        # loopback port, ECONNREFUSED, where the jail would give ENETUNREACH.
        # Only here is a refusal counted as the denial; the verdict tables
        # (and harness.DENIAL_ERRNOS itself) keep it inconclusive.
        with mock.patch.object(fault_matrix, 'SUSPEND_SECONDS', 1.5), \
                mock.patch.object(fault_matrix, 'END_BOUND_SECONDS', 5.0), \
                mock.patch.object(harness, 'DENIAL_ERRNOS', ('ENETUNREACH', 'ECONNREFUSED')), \
                mock.patch.object(harness, 'PROBE_TARGET', ('127.0.0.1', port)), \
                mock.patch.multiple(fault_matrix, **patches) if patches else contextlib.nullcontext():
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

    def test_a_client_dead_before_the_kill_is_recorded_as_dead(self):
        # Mutation R21: 'alive at the kill' is read from the process, never assumed.
        original = fault_matrix.started

        def started_then_died(run, obs, client, watch, *rest):
            original(run, obs, client, watch, *rest)
            client.process.kill()
            client.process.wait()
        result = self.run_case('client-kill', started=started_then_died)
        self.assertNotEqual(result['outcome'], 'PASS')
        self.assertIs(result['observations']['client_alive_at_kill'], False)

    def test_a_resumed_attempt_with_an_unbound_receipt_fails(self):
        # Mutation R22 (and its serve-group-stop twin): the stand-in client's own
        # receipt must name its attempt; the follow-up attempt's stays bound.
        for case in ('client-ctrl-z', 'serve-group-stop'):
            with self.subTest(case), mock.patch.dict(os.environ, {'FAKE_UNBOUND_FIRST': '1'}):
                result = self.run_case(case)
                self.assertEqual(result['outcome'], 'FAIL', result.get('error'))
                self.assertEqual(result['failed'], ['resumed_attempt_receipt_bound'])

    def test_a_ctrl_z_does_not(self):
        result = self.assert_passes('client-ctrl-z')
        self.assertTrue(result['observations']['client_state_while_stopped'].startswith('T'))

    def test_a_brief_serve_group_stop_does_not(self):
        self.assert_passes('serve-group-stop')

    def test_secrets_without_nat_or_a_route_fail(self):
        # Reviewer FX4/F36 through the real case code: the fake guest's
        # probe still sees its 'denial', but the guest has no NAT, or no route.
        for variable in ('FAKE_NO_NAT', 'FAKE_NO_ROUTE'):
            with self.subTest(variable), mock.patch.dict(os.environ, {variable: '1'}):
                result = self.run_case('secrets')
                self.assertEqual(result['outcome'], 'FAIL', result.get('error'))
                self.assertEqual(result['failed'], ['network_denied_with_nat'])

    def test_a_ctrl_z_that_never_stopped_the_client_fails(self):
        # Reviewer F37: the client's own process state is read, never assumed.
        def no_stop(run, pgid, sig=signal.SIGSTOP):
            run.stopped_groups.append(pgid)
        with mock.patch.object(fault_matrix.Run, 'stop_group', no_stop):
            result = self.run_case('client-ctrl-z')
        self.assertEqual(result['outcome'], 'FAIL', result.get('error'))
        self.assertEqual(result['failed'], ['client_was_stopped'])

    def test_secrets_then_a_duplicate_then_the_same_boot(self):
        result = self.assert_passes('secrets')
        self.assertEqual(result['observations']['probe']['egress'], 'ECONNREFUSED')
        self.assertTrue(result['observations']['route']['reached'])
        self.assertEqual(set(result['observations']['network_denial'].values()), {True})


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

    def capabilities_main(self, out, touch_git=False):
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
                if touch_git:
                    (workspace / '.git' / 'config').write_text('forged\n')
            send(**bound_frame(request, boot_id='vm-fake'))
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
                mock.patch.dict(os.environ, {'UKAI_VM_BINARY': str(self.home / 'bin/ukai-vm')}), \
                mock.patch.object(capabilities, 'TREE_SETTLE_SECONDS', 0.0), \
                mock.patch.object(capabilities, 'TREE_SHARE_GRACE', 0.0):
            code = capabilities.main([str(self.home), str(self.workspace), str(self.root / out)])
        return code, json.loads((self.root / out / 'capabilities.json').read_text())

    def test_capabilities_main_records_a_judged_run(self):
        code, record = self.capabilities_main('out')
        self.assertEqual(code, 1)  # the fake answers nothing a capability needs
        self.assertEqual(record['summary']['outcome'], 'FAIL')
        self.assertTrue(record['summary']['workspace'])
        self.assertTrue(record['summary']['git_config_untouched'])
        self.assertFalse(record['summary']['pids'])
        self.assertEqual(record['workspace_cleaned'], ['stale'])
        self.assertTrue(record['reachability']['fake'])
        self.assertTrue(record['status']['guest_nat'])
        self.assertEqual(sorted(record['measurements']), sorted(capabilities.REQUIREMENTS.values()))
        for entry in record['measurements'].values():
            self.assertRegex(entry['measured_at'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$')
            self.assertIs(entry['verdict'], record['summary'][entry['capability']])
            self.assertEqual(entry['measured_at'], record['results'][entry['capability']]['started_at'])
        self.assertRegex(record['measured_at'], r'^\d{4}-')

    def test_capabilities_main_sees_the_protected_git_change(self):
        # Reviewer C25: the protected .git/config is read back after the run.
        code, record = self.capabilities_main('out-git', touch_git=True)
        self.assertEqual(code, 1)
        self.assertFalse(record['summary']['git_config_untouched'])
        self.assertTrue(record['summary']['workspace'])

    def fake_cli(self, boots=('vm-1', 'vm-1', 'vm-1'), echo=None, secret=None, refuse=False, leak=None,
                 stderr='', unbound=None, noroute=False):
        """`ukai-jail run --vm` faked: each run leaves an attempt directory as
        S1/S2 write it, its receipt bound to the workload argv it was given."""
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
            workload = argv[argv.index('--') + 1:]
            digest = harness.argv_digest(workload)
            boot = boots[min(index, len(boots) - 1)]
            mode = 'proxy' if profile == 'agent' else 'none'
            guest = {'applied': {'network': {'mode': mode}}, 'argv_digest': digest, 'attempt_id': f'att_guest{index}',
                     'credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True}]}
            raw = json.dumps(guest).encode()
            (attempt / 'jail.json').write_text(json.dumps({'phase': 'settled', 'outcome': {'code': 0},
                                                           'lifetime': {'tree_empty': True},
                                                           'policy': {'name': profile}}))
            (attempt / 'evidence/jail.json').write_bytes(raw)
            (attempt / 'vm-transport.json').write_text(json.dumps({
                'boot_id': boot, 'guest_receipt_sha256': hashlib.sha256(raw).hexdigest()}))
            (attempt / 'evidence/vm-binding.json').write_text(json.dumps({
                'attempt_id': attempt.name if unbound != index else 'att_other', 'argv_digest': digest,
                'boot_id': boot, 'profile': profile, 'guest_boot_id': 'g-1'}))
            (data / 'vm' / boot / 'image').mkdir(parents=True, exist_ok=True)
            (data / 'vm' / boot / 'image' / 'base.raw').write_bytes(b'\0' * 4096)
            script = workload[-1]
            stdout = ''
            if 'GITHUB' in script or 'EXAMPLE' in script:
                allowed = argv[argv.index('--allow-host') + 1]
                first, second = ('GITHUB', 'EXAMPLE') if allowed == 'api.github.com' else ('EXAMPLE', 'GITHUB')
                stdout = f'{first}_ANSWERED 200\n{second}_REFUSED URLError\n'
                route = re.search(r"' (\S+-route) ", script)
                if route:
                    hosts = [argv[i + 1] for i, word in enumerate(argv) if word == '--allow-host']
                    self.assertIn(harness.route_rule(), hosts)
                    stdout += route_line(route.group(1), 'HTTP/1.1 502 Bad Gateway' if noroute else
                                         'HTTP/1.1 200 Connection established') + '\n'
            elif workload[0] == harness.PYTHON:
                # The fake guest jail's denial: the jail's own errno.
                stdout = probe_line(workload[4]) + '\n'
            elif 'PLACEHOLDER' in script:
                import urllib.request
                request = urllib.request.Request(echo, headers={'x-test-token': secret.decode()})
                urllib.request.urlopen(request, timeout=5).read()
                value = f"vault:{guest['attempt_id']}:test"
                stdout = (f'PLACEHOLDER {hashlib.sha256(value.encode()).hexdigest()} {len(value)} {value}\n'
                          'ECHO 200 echo\n')
                if leak is not None:
                    (self.workspace / 'leaked.txt').write_bytes(b'x' + leak + b'x')
            return subprocess.CompletedProcess(argv, 0, stdout, stderr)
        return run, runs

    def proxy_main(self, out, run, reachability=None):
        reach = reachability or {'answers': True, 'fake': True}
        with mock.patch.object(proxy_measurement.subprocess, 'run', run), mock.patch('builtins.print'), \
                mock.patch.object(harness, 'host_reachability', lambda *a, **k: reach):
            code = proxy_measurement.main([str(self.home), str(self.workspace), str(out),
                                           '--ukai-jail', str(self.home / 'bin/ukai-jail')])
        return code, json.loads((out / 'proxy-policy.json').read_text())

    def test_proxy_main_measures_the_same_boot(self):
        for boots, outcome in ((('vm-1', 'vm-1', 'vm-1'), 'PASS'), (('vm-1', 'vm-1', 'vm-2'), 'FAIL')):
            with self.subTest(boots=boots):
                run, _ = self.fake_cli(boots)
                code, record = self.proxy_main(self.root / f'proxy-{outcome}', run)
                self.assertEqual(record['outcome'], outcome, record['facts'])
                self.assertEqual(code, 0 if outcome == 'PASS' else 1)
                if outcome == 'FAIL':
                    self.assertEqual([k for k, v in record['facts'].items() if v is not True], ['same_serve_boot'])

    def test_proxy_main_needs_the_route_bound_receipts_and_a_live_target(self):
        for name, kwargs, reachability, failed in [
                ('the guest reaches nothing', {'noroute': True}, None, ['route_control_reached_the_target']),
                ('a receipt bound to another attempt', {'unbound': 1}, None, ['every_receipt_bound']),
                # Reviewer P6: a target nobody answers proves no denial.
                ('the probe target is dead from the host', {}, {'answers': False}, ['probe_target_answers_from_host'])]:
            with self.subTest(name):
                run, _ = self.fake_cli(**kwargs)
                code, record = self.proxy_main(self.root / f'proxy-{len(name)}', run, reachability)
                self.assertEqual((code, record['outcome']), (1, 'FAIL'))
                self.assertEqual([k for k, v in record['facts'].items() if v is not True], failed)

    def test_proxy_main_records_a_refusal_never_a_pass(self):
        run, _ = self.fake_cli(refuse=True)
        with mock.patch.object(proxy_measurement.subprocess, 'run', run), mock.patch('builtins.print'):
            code = proxy_measurement.main([str(self.home), str(self.workspace), str(self.root / 'refused'),
                                           '--ukai-jail', str(self.home / 'bin/ukai-jail')])
        record = json.loads((self.root / 'refused' / 'proxy-policy.json').read_text())
        self.assertEqual((code, record['outcome'], record['refusals']), (1, 'REFUSED', ['vm:not-measured:network_none']))

    def vault_main(self, out='vault', **kwargs):
        port_holder = {}
        real_server = vault_measurement.http.server.HTTPServer

        def loopback_server(address, handler):
            server = real_server(('127.0.0.1', 0), handler)
            port_holder['port'] = server.server_address[1]
            return server
        vault_measurement.Echo.received.clear()

        def run(argv, env=None, **options):
            inner, _ = self.fake_cli(echo=f"http://127.0.0.1:{port_holder['port']}/echo",
                                     secret=vault_measurement.SECRET, **kwargs)
            return inner(argv, env=env, **options)
        with mock.patch.object(vault_measurement, 'mac_address', lambda: '127.0.0.1'), \
                mock.patch.object(vault_measurement.http.server, 'HTTPServer', loopback_server), \
                mock.patch.object(vault_measurement.subprocess, 'run', run), mock.patch('builtins.print'):
            code = vault_measurement.main([str(self.home), str(self.workspace), str(self.root / out),
                                           '--ukai-jail', str(self.home / 'bin/ukai-jail')])
        text = (self.root / out / 'vault-consumption.json').read_text()
        return code, text, json.loads(text)

    def test_vault_main_judges_injection_and_never_records_the_value(self):
        # The client's own stderr names the echo address: the record redacts it (reviewer V7).
        code, text, record = self.vault_main(stderr='fetching from 127.0.0.1\n')
        self.assertEqual(record['outcome'], 'PASS', record['facts'])
        self.assertEqual(code, 0)
        self.assertNotIn(vault_measurement.SECRET.decode(), text)
        self.assertNotIn('127.0.0.1', text)
        self.assertIn('<mac-address>', record['observed']['stderr'])
        self.assertEqual(record['observed']['disk_scan'], 'clean')
        self.assertEqual(record['observed']['disk_scanned'], 'vm/vm-1/image/base.raw')
        self.assertTrue(record['observed']['receipt_bound'])

    def test_vault_main_fails_on_a_leak_another_boot_or_a_refusal(self):
        # Reviewer V8: the workspace is scanned too.
        code, text, record = self.vault_main(out='vault-leak', leak=vault_measurement.SECRET)
        self.assertEqual((code, record['outcome']), (1, 'FAIL'))
        self.assertEqual([k for k, v in record['facts'].items() if v is not True], ['no_value_in_any_export'])
        self.assertEqual([Path(hit).name for hit in record['observed']['leaks']], ['leaked.txt'])
        self.assertNotIn(vault_measurement.SECRET.decode(), text)
        # Reviewer FX/F-15: the disk scanned is the vault attempt's own boot's.
        code, _, record = self.vault_main(out='vault-boots', boots=('vm-1', 'vm-2'))
        self.assertEqual((code, record['outcome']), (1, 'FAIL'))
        self.assertEqual([k for k, v in record['facts'].items() if v is not True],
                         ['guest_disk_scanned_clean', 'sync_on_the_vault_attempts_boot'])
        # Reviewer V11: a refusal is the outcome even when every fact holds.
        code, _, record = self.vault_main(out='vault-refused', stderr='ukai-jail: refused: vm:not-measured:vault\n')
        self.assertEqual((code, record['outcome'], record['observed']['refusals']),
                         (1, 'REFUSED', ['vm:not-measured:vault']))
        self.assertTrue(all(record['facts'].values()))

    def test_vault_source_is_gone_when_stop_raises(self):
        # Reviewer FX1 (vault): the value's source file goes before `ukai-vm stop`.
        temp = self.root / 'vault-tmp'
        temp.mkdir()
        port_holder = {}
        real_server = vault_measurement.http.server.HTTPServer

        def loopback_server(address, handler):
            server = real_server(('127.0.0.1', 0), handler)
            port_holder['port'] = server.server_address[1]
            return server
        vault_measurement.Echo.received.clear()

        def run(argv, env=None, **options):
            if argv[-1] == 'stop':
                raise subprocess.TimeoutExpired(argv, 60)
            inner, _ = self.fake_cli(echo=f"http://127.0.0.1:{port_holder['port']}/echo",
                                     secret=vault_measurement.SECRET)
            return inner(argv, env=env, **options)
        with mock.patch.object(vault_measurement, 'mac_address', lambda: '127.0.0.1'), \
                mock.patch.object(vault_measurement.http.server, 'HTTPServer', loopback_server), \
                mock.patch.object(vault_measurement.subprocess, 'run', run), mock.patch('builtins.print'), \
                mock.patch.object(tempfile, 'tempdir', str(temp)):
            vault_measurement.main([str(self.home), str(self.workspace), str(self.root / 'vault-stop'),
                                    '--ukai-jail', str(self.home / 'bin/ukai-jail')])
        record = json.loads((self.root / 'vault-stop' / 'vault-consumption.json').read_text())
        self.assertEqual(record['observed']['stop_error'].split(':')[0], 'TimeoutExpired')
        self.assertFalse(list(temp.glob('vault-src-*')))
        held = [path for path in temp.rglob('*') if path.is_file() and vault_measurement.SECRET in path.read_bytes()]
        self.assertEqual(held, [])


def k111_attempt_dir(attempt, argv, contradict=False, boot='vm-b'):
    """A `run --vm` attempt directory as S1/S2 write it, bound to `argv`;
    returns the summary text the client prints for it."""
    (attempt / 'evidence').mkdir(parents=True)
    digest = harness.argv_digest(argv)
    guest = {'platform': {'os': 'linux', 'kernel': '6.12', 'arch': 'aarch64'}, 'argv_digest': digest,
             'attempt_id': 'att_guest', 'applied': {'network': {'mode': 'none'}}, 'observer': {'attached': True},
             'coverage': {name: {'status': 'active'} for name in harness.SUMMARY_CLASSES}, 'outcome': {'code': 0}}
    raw = json.dumps(guest).encode()
    (attempt / 'evidence/jail.json').write_bytes(raw)
    sha = hashlib.sha256(raw).hexdigest()
    (attempt / 'evidence/vm-binding.json').write_text(json.dumps({
        'attempt_id': attempt.name, 'profile': 'tool', 'argv_digest': digest, 'boot_id': boot,
        'guest_boot_id': 'g-1', 'guest_attempt_id': 'att_guest'}))
    transport = {'schema': 'ukai.jail.vm-transport/1', 'boot_id': boot, 'image': {'disk_sha256': 'ab' * 32},
                 'vsock_port': 1024, 'guest_receipt_sha256': sha}
    (attempt / 'vm-transport.json').write_text(json.dumps(transport))
    stored = {**guest, 'phase': 'settled', 'lifetime': {'tree_empty': True}}
    if contradict:
        stored['applied'] = {'network': {'mode': 'pending'}}
    (attempt / 'jail.json').write_text(json.dumps(stored))
    return (f'ukai-jail: vm: guest-reported facts in evidence/jail.json · boot {boot} · image {"ab" * 8} · '
            f'vsock 1024 · receipt sha256:{sha[:16]}\nukai-jail: network: none\n'
            f'ukai-jail: evidence: 6/6 classes active, no gaps\n')


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

    def k109(self, bound=True):
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
            send(**bound_frame(request if bound or index == 0 else dict(request, attempt_id='other')))
            send(event='done', exit_code=0)
        server = FakeAttemptServer(script)
        self.addCleanup(server.close)
        service = mock.MagicMock(connect=server.connect, child=mock.Mock(returncode=0))
        service.__enter__.return_value = service
        with mock.patch.object(harness, 'Service', return_value=service):
            return gate_rows.row_k109(Path('/x/ukai-vm'), self.home, self.workspace)

    def test_row_k109_with_a_refusing_guest(self):
        row = self.k109()
        self.assertEqual(row['outcome'], 'PASS', row)
        row = self.k109(bound=False)
        self.assertEqual(row['outcome'], 'FAIL')
        self.assertFalse(row['outside_writes_refused_and_absent'])
        self.assertFalse(row['containment']['receipt_bound_to_this_attempt'])

    def k111_run(self, calls, contradict=False, refusal=''):
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
                self.assertFalse((self.workspace / 'stale.txt').exists(), 'the row cleans its workspace first')
                workload = argv[argv.index('--') + 1:]
                tag = workload[2].split('row-k111-')[1].split('\\')[0]
                self.summary = k111_attempt_dir(data / 'attempts' / 'att_k111', workload, contradict)
                (self.workspace / 'k111.txt').write_text(f'row-k111-{tag}\n')
                return subprocess.CompletedProcess(argv, 0, self.summary + refusal, '')
            if 'tail' in argv:
                return subprocess.CompletedProcess(argv, 0, self.summary, '')
            return subprocess.CompletedProcess(argv, 0, '', '')
        return run

    def test_row_k111_and_k112_through_the_cli(self):
        calls = []
        out = self.root / 'out'
        out.mkdir()
        (self.workspace / 'stale.txt').write_text('an earlier run')
        with mock.patch.object(gate_rows.subprocess, 'run', self.k111_run(calls)):
            k111 = gate_rows.row_k111(self.home, self.workspace, Path('/x/ukai-jail'), out)
            k112 = gate_rows.row_k112(self.home, Path('/x/ukai-jail'), self.workspace)
        self.assertEqual(k111['outcome'], 'PASS', [key for key, value in k111.items() if value is False])
        self.assertTrue((out / 'k111-tail-summary.txt').read_text().startswith('ukai-jail: vm: guest-reported'))
        self.assertTrue((out / 'k111-attempt' / 'evidence' / 'jail.json').is_file())
        self.assertTrue(any(call[-1] == 'stop' for call in calls))
        self.assertEqual(k112['outcome'], 'PASS', k112)
        markers = [call[-1] for call in calls if 'kernel-bound' in call]
        self.assertEqual(len(markers), 3)
        self.assertTrue(all('k112-ran-' in marker for marker in markers))
        runs = [call for call in calls if 'run' in call and '--vm' in call and 'kernel-bound' not in call]
        self.assertEqual(len(runs), 1)
        self.assertRegex(runs[0][-1], r'^printf "row-k111-[0-9a-f]+\\n" > k111\.txt; echo row-k111-done$')

    def test_row_k111_fails_on_a_contradicting_host_receipt(self):
        out = self.root / 'out-contradict'
        out.mkdir()
        with mock.patch.object(gate_rows.subprocess, 'run', self.k111_run([], contradict=True)):
            k111 = gate_rows.row_k111(self.home, self.workspace, Path('/x/ukai-jail'), out)
        self.assertEqual(k111['outcome'], 'FAIL')
        self.assertEqual([key for key, value in k111.items() if value is False], ['host_receipt_never_contradicts_guest'])

    def test_row_k111_with_a_refusal_and_an_attempt_is_refused(self):
        # Reviewer G18: a refusal on the terminal is the outcome even when an
        # attempt directory exists and its records would pass.
        out = self.root / 'out-refusal'
        out.mkdir()
        with mock.patch.object(gate_rows.subprocess, 'run',
                               self.k111_run([], refusal='ukai-jail: refused: vm:not-measured:limit:wall\n')):
            row = gate_rows.row_k111(self.home, self.workspace, Path('/x/ukai-jail'), out)
        self.assertEqual((row['outcome'], row['refusals']), ('REFUSED', ['vm:not-measured:limit:wall']))
        self.assertTrue(row['digest_matches_record'])

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
            'next_guest_boot': 'g-1', 'next_receipt_bound': True, **extra}


DENIAL = {'probe_saw_the_jails_denial': True, 'guest_nat_attached': True, 'route_control_reached_the_target': True,
          'route_control_on_the_same_guest_boot': True, 'route_control_receipt_bound': True}

FAULT_GOOD = {
    'client-kill': same_boot(released=True, beating=True, killed_at=10.0, beats_quiet=True, last_beat_at=12.0,
                             client_alive_at_kill=True, client_exit=-9, client_exit_seconds=0.05,
                             status_after={'warm': True}),
    'client-ctrl-z': same_boot(released=True, beating=True, client_state_while_stopped='T', beats_during_stop=True,
                               done_exit=0, workload_finished=True, receipt_bound=True),
    'serve-kill': {'released': True, 'beating': True, 'identified': True, 'a_done': False, 'a_ended': True,
                   'b_done': False, 'b_ended': True, 'killed_at': 10.0, 'beats_quiet': True, 'last_beat_at': 10.3,
                   'a_open_at_kill': True, 'b_open_at_kill': True, 'a_ended_at': 10.4, 'b_ended_at': 10.4,
                   'gone_seconds': {'serve': 0.1, 'custodian': 1.0, 'vz': 1.0, 'vm': 2.0},
                   'sockets_unanswered': True, 'workspace_survived': True},
    'all-suspended': {'released': True, 'beating': True, 'every_controller_stopped': True, 'wall': 10,
                      'released_at': 100.0, 'stopped_at': 102.0, 'last_beat_at': 110.1, 'beats_quiet': True,
                      'quiet_before_resume': True, 'guest_beat_span_s': 9.9},
    'secrets': same_boot(staged=[('api/token', '/run/ukai-vm/credentials/api/token'),
                                 ('nested/id/two', '/run/ukai-vm/credentials/nested/id/two')],
                         first_exit=0, first_receipt_bound=True, network_denial=DENIAL,
                         duplicate_prepared=False, duplicate_error='StreamEnded: ...'),
    'eof': same_boot(released=True, beating=True, eof_at=10.0, beats_quiet=True, last_beat_at=10.5,
                     status_after={'warm': True}),
    'serve-group-stop': same_boot(released=True, beating=True, beats_during_stop=True, done_exit=0,
                                  workload_finished=True, status_boot_after='vm-1', receipt_bound=True),
}
FAULT_GOOD['custodian-kill'] = FAULT_GOOD['serve-kill']
FAULT_GOOD['vz-kill'] = FAULT_GOOD['serve-kill']

BOOT_MUTATIONS = [('another serve boot after', {'next_serve_boot': 'vm-2'}, 'next_attempt_same_serve_boot'),
                  ('another guest kernel boot after', {'next_guest_boot': 'g-2'}, 'next_attempt_same_guest_boot'),
                  ('no guest boot measured', {'guest_boot': None}, 'next_attempt_same_guest_boot'),
                  ('the next attempt failed', {'next_exit': None}, 'next_attempt_exit_zero'),
                  ('the next attempt\'s receipt is not its own', {'next_receipt_bound': False},
                   'next_attempt_receipt_bound')]

FAULT_MUTATIONS = {
    'client-kill': BOOT_MUTATIONS + [
        ('workload kept beating after the kill', {'beats_quiet': False}, 'workload_stopped_after_kill'),
        ('beats stopped only long after', {'last_beat_at': 40.0}, 'workload_stopped_after_kill'),
        ('workload finished before the kill (old A)', {'beating': False}, 'workload_beating_before_kill'),
        ('service died with the client', {'status_after': {}}, 'service_still_warm'),
        # Reviewer F-7: the death must be our SIGKILL's.
        ('client exited cleanly instead of dying', {'client_exit': 0}, 'client_died_of_our_sigkill'),
        ('client died of another signal', {'client_exit': -15}, 'client_died_of_our_sigkill'),
        ('client died only at the safety kill', {'client_exit_seconds': 10.2}, 'client_died_of_our_sigkill'),
        ('client exit never seen', {'client_exit': None, 'client_exit_seconds': None}, 'client_died_of_our_sigkill'),
        ('client already dead at the kill', {'client_alive_at_kill': False}, 'client_alive_at_the_kill')],
    'client-ctrl-z': BOOT_MUTATIONS + [
        ('client never stopped (orphaned-group SIGTSTP)', {'client_state_while_stopped': 'Ss'}, 'client_was_stopped'),
        ('no workload spanned the stop (old B)', {'beats_during_stop': False}, 'workload_continued_while_client_stopped'),
        ('attempt ended by the stop', {'done_exit': None}, 'attempt_completed_after_resume'),
        ('workload cut short', {'workload_finished': False}, 'attempt_completed_after_resume'),
        ('the resumed attempt\'s receipt is not its own', {'receipt_bound': False}, 'resumed_attempt_receipt_bound')],
    'serve-kill': [
        ('running attempt got done (workload finished first, old A)', {'a_done': True}, 'running_attempt_ended_without_done'),
        ('running client hung and was killed by cleanup', {'a_ended': False}, 'running_attempt_ended_without_done'),
        ('queued attempt was served', {'b_done': True}, 'queued_attempt_ended_without_done'),
        ('queued client hung and was killed by cleanup', {'b_ended': False}, 'queued_attempt_ended_without_done'),
        # Reviewer FX3: a queued client that errored BEFORE the kill proves nothing about it.
        ('queued attempt ended before the kill', {'b_ended_at': 9.0}, 'queued_attempt_open_until_the_kill'),
        ('queued attempt already closed at the kill', {'b_open_at_kill': False}, 'queued_attempt_open_until_the_kill'),
        ('running attempt ended before the kill', {'a_ended_at': 9.5}, 'running_attempt_open_until_the_kill'),
        ('running attempt never seen ending', {'a_ended_at': None}, 'running_attempt_open_until_the_kill'),
        ('running attempt already closed at the kill', {'a_open_at_kill': False}, 'running_attempt_open_until_the_kill'),
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
        ('ended well before the wall deadline', {'last_beat_at': 108.0}, 'ended_at_the_guest_wall_deadline'),
        ('guest clock ran past the wall', {'guest_beat_span_s': 20.0}, 'guest_clock_agrees')],
    'secrets': BOOT_MUTATIONS + [
        ('one value acked', {'staged': [('api/token', '/run/ukai-vm/credentials/api/token')]}, 'two_values_acked'),
        ('a value staged on disk', {'staged': [('api/token', '/var/lib/x/api/token'),
                                               ('nested/id/two', '/run/ukai-vm/credentials/nested/id/two')]},
         'paths_in_tmpfs_root'),
        ('duplicate id accepted', {'duplicate_prepared': True}, 'duplicate_id_refused_before_prepared'),
        ('the first attempt\'s receipt is not its own', {'first_receipt_bound': False}, 'first_attempt_receipt_bound'),
        ('no denial measured', {'network_denial': {}}, 'network_denied_with_nat')] + [
        (f'network denial: {fact} false', {'network_denial': dict(DENIAL, **{fact: False})}, 'network_denied_with_nat')
        for fact in DENIAL],
    'eof': BOOT_MUTATIONS + [
        ('workload finished before the EOF (old C)', {'beating': False}, 'workload_beating_before_eof'),
        ('workload outlived the EOF', {'beats_quiet': False}, 'workload_stopped_after_eof'),
        ('session went down', {'status_after': {'warm': False}}, 'service_still_warm')],
    'serve-group-stop': BOOT_MUTATIONS + [
        ('no workload spanned the stop (old B)', {'beats_during_stop': False}, 'workload_spanned_the_stop'),
        ('the serve rebooted across the stop', {'status_boot_after': 'vm-2'}, 'serve_boot_unchanged_after_resume'),
        ('attempt lost', {'done_exit': None}, 'attempt_completed_after_resume'),
        ('the resumed attempt\'s receipt is not its own', {'receipt_bound': False}, 'resumed_attempt_receipt_bound')],
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

    def test_the_matrix_passes_only_when_complete_and_judged_first(self):
        # Reviewer F29: a subset of the cases is never the matrix's PASS.
        passed = {'outcome': 'PASS', 'checked_before_cleanup': True}
        every = {case: dict(passed) for case in fault_matrix.CASES}
        self.assertEqual(fault_matrix.matrix_outcome(every, list(fault_matrix.CASES)), 'PASS')
        self.assertEqual(fault_matrix.matrix_outcome({'eof': dict(passed)}, ['eof']), 'FAIL')
        self.assertEqual(fault_matrix.matrix_outcome({}, []), 'FAIL')
        late = dict(every, eof={'outcome': 'PASS', 'checked_before_cleanup': False})
        self.assertEqual(fault_matrix.matrix_outcome(late, list(fault_matrix.CASES)), 'FAIL')
        refused = dict(every, eof={'outcome': 'REFUSED', 'checked_before_cleanup': True})
        self.assertEqual(fault_matrix.matrix_outcome(refused, list(fault_matrix.CASES)), 'FAIL')

    def test_beats_while_stopped_counts_only_changes_after_the_settle(self):
        # Reviewer F33: the share is polled through the stop, and a beat
        # already in flight at the stop is not one.
        now = [100.0]

        class Watch:
            polls, asked, changes = 0, [], []

            def poll(self):
                Watch.polls += 1

            def changed_since(self, moment):
                Watch.asked.append(moment)
                return list(Watch.changes)

        def sleep(seconds):
            now[0] += seconds
        self.assertFalse(fault_matrix.beats_while_stopped(Watch(), 100.0, 1.0, clock=lambda: now[0], sleep=sleep))
        self.assertEqual(Watch.asked, [100.5])
        self.assertGreaterEqual(Watch.polls, 19)
        Watch.changes = ['hb-x-0']
        now[0] = 200.0
        self.assertTrue(fault_matrix.beats_while_stopped(Watch(), 200.0, 1.0, settle=0.25,
                                                         clock=lambda: now[0], sleep=sleep))
        self.assertEqual(Watch.asked[-1], 200.25)

    def test_each_boot_starts_from_a_clean_workspace(self):
        # Reviewer F34b: an earlier case's beat files never count for this one.
        workspace = Path(tempfile.mkdtemp(prefix='fm-clean-'))
        self.addCleanup(shutil.rmtree, workspace, True)
        harness.mark_workspace(workspace)
        (workspace / 'hb-old-0').write_text('1')
        with mock.patch.object(harness, 'Service') as service, \
                mock.patch.object(harness, 'identity', return_value='ident'):
            service.return_value.wait_warm.return_value = {'boot_id': 'vm-1'}
            run = fault_matrix.Run({'home': workspace, 'workspace': workspace, 'binary': workspace}, 'eof')
            self.assertEqual(run.boot(nat=True), {'boot_id': 'vm-1'})
        self.assertFalse((workspace / 'hb-old-0').exists())
        self.assertTrue((workspace / harness.WORKSPACE_MARKER).exists())
        self.assertEqual(service.call_args.kwargs['extra'], ('--guest-nat',))

    def test_the_real_client_is_a_job_of_this_session(self):
        # Reviewer F32: its own process group in THIS session, so a Ctrl-Z
        # stops it (a group in a new session is orphaned: SIGTSTP is discarded).
        root = Path(tempfile.mkdtemp(prefix='fm-real-'))
        self.addCleanup(shutil.rmtree, root, True)
        jail = root / 'ukai-jail'
        jail.write_text('#!/bin/sh\nexec sleep 30\n')
        jail.chmod(0o755)
        run = types.SimpleNamespace(context={'home': root, 'workspace': root}, data=root, processes=[])
        process = fault_matrix.real_client(jail)(run, 'm', 'true', 20)
        self.addCleanup(lambda: (process.kill(), process.communicate()))
        self.assertEqual(run.processes, [process])
        self.assertEqual(os.getpgid(process.pid), process.pid)
        self.assertEqual(os.getsid(process.pid), os.getsid(0))

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

    def k109(self, tag='t9', host=None, granted=None, git=None, created=False, service_exit=0, refused=None):
        (self.workspace / 'k109-granted.txt').write_text(host if host is not None else f'granted-{tag}\n')
        git_config = harness.protected_sentinel(self.workspace, git or gate_rows.SENTINEL)
        outside = [f'/etc/ukai-k109-{tag}', f'/usr/local/bin/ukai-k109-{tag}', f'/ukai-k109-{tag}']
        fs = {'tag': tag, 'paths': {path: {'open': 'created' if created and index == 0 else 'EROFS',
                                           'exists_after': created and index == 0}
                                    for index, path in enumerate(outside)}}
        granted = granted if granted is not None else self.granted(tag)
        refused = refused if refused is not None else bind(record('UKAI_FS_PROBE ' + json.dumps(fs) + '\n'),
                                                           f'row-outside-{tag}')
        return gate_rows.judge_k109(tag, granted, refused, outside, self.workspace, git_config, service_exit)

    def granted(self, tag='t9', stdout=None):
        return bind(record(stdout if stdout is not None else f'wrote-{tag}\ngit_write_refused-{tag}\n'),
                    f'row-granted-{tag}')

    def test_k109_table(self):
        self.assertEqual(self.k109()['outcome'], 'PASS')
        for name, kwargs, key in [
                ('a previous run\'s granted file', {'host': 'granted-OLDRUN\n'}, 'granted_write_on_host'),
                ('the protected write allowed', {'granted': self.granted(stdout='wrote-t9\nGIT_WRITE_ALLOWED-t9\n')}, 'git_write_tried_and_refused'),
                ('.git changed', {'git': 'forged'}, 'git_config_unchanged'),
                ('an outside write landed', {'created': True}, 'outside_writes_refused_and_absent'),
                ('the granted receipt is another attempt\'s', {'granted': rebound(self.granted(), attempt_id='x')}, 'granted_receipt_bound'),
                ('the outside probe\'s receipt is another attempt\'s',
                 {'refused': rebound(bind(record(''), 'row-outside-t9'), attempt_id='x')}, 'outside_writes_refused_and_absent'),
                ('the granted attempt failed', {'granted': mutated(self.granted(), exit_code=1)}, 'granted_exit_zero'),
                ('custody failure', {'service_exit': 125}, 'service_stopped_cleanly')]:
            with self.subTest(name):
                row = self.k109(**kwargs)
                self.assertFalse(row[key])
                self.assertEqual(row['outcome'], 'FAIL')

    # The committed 2026-11-03 attempt ran the round-1 script, before the nonce.
    OLD_K111_ARGV = ['/bin/sh', '-c', 'printf "row-k111\\n" > k111.txt; echo row-k111-done']

    def k111_attempt(self, tag=T):
        attempt = Path(tempfile.mkdtemp(prefix='rows-k111-')) / 'att_76c9e855-522c-42ad-b4a2-27e0b620d9cf'
        self.addCleanup(shutil.rmtree, attempt.parent, True)
        shutil.copytree(EVIDENCE / 'macos-vm-installed-2026-11-03/k111-attempt', attempt)
        binding = json.loads((attempt / 'evidence/vm-binding.json').read_text())
        if binding.get('attempt_id') != attempt.name:
            attempt = attempt.rename(attempt.parent / binding['attempt_id'])
        (self.workspace / 'k111.txt').write_text(f'row-k111-{tag}\n')
        return attempt

    # The committed guest receipt: five classes active (proxy.net unsupported under mode none).
    def summary_text(self, attempt, network='none', classes='5/6 classes active, no gaps'):
        transport = json.loads((attempt / 'vm-transport.json').read_text())
        return (f"vm: guest-reported facts in evidence/jail.json · boot {transport['boot_id']} "
                f"· image {transport['image']['disk_sha256'][:16]} · vsock {transport['vsock_port']} "
                f"· receipt sha256:{transport['guest_receipt_sha256'][:16]}\n"
                f"ukai-jail: network: {network}\nukai-jail: evidence: {classes}\n")

    def test_k111_on_the_committed_evidence_fails_on_the_host_receipt(self):
        attempt = self.k111_attempt()
        text = self.summary_text(attempt)
        row, detail = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, self.OLD_K111_ARGV, T)
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

    def rewrite_json(self, path, **changes):
        value = json.loads(path.read_text())
        value.update(changes)
        path.write_text(json.dumps(value))

    def failing(self, row):
        return [key for key, value in row.items() if value is False]

    def test_k111_table(self):
        argv = self.OLD_K111_ARGV
        attempt = self.fixed_attempt()
        text = self.summary_text(attempt)
        row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv, T)
        self.assertEqual(row['outcome'], 'PASS', row)
        for name, call, keys in [
                ('another argv', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, text, text, ['/bin/sh', '-c', 'other'], T),
                 ['binding_argv_digest_is_this_argv', 'guest_receipt_argv_digest_is_this_argv']),
                ('the stored summary lacks the line', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, text, 'nothing', argv, T),
                 ['tail_summary_transport_line_present', 'tail_summary_transport_line_from_record',
                  'tail_summary_network_line_is_the_guests', 'tail_summary_observer_classes_are_the_guests',
                  'tail_summary_observer_attachment_is_the_guests']),
                ('the run summary lacks the line', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, 'nothing', text, argv, T),
                 ['run_summary_transport_line_present', 'run_summary_transport_line_from_record',
                  'run_summary_network_line_is_the_guests', 'run_summary_observer_classes_are_the_guests',
                  'run_summary_observer_attachment_is_the_guests']),
                ('an earlier run\'s workspace file', lambda: gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv, 'OTHER'),
                 ['granted_write_on_host']),
                ('the client failed', lambda: gate_rows.judge_k111(attempt, self.workspace, 1, text, text, argv, T), ['run_exit_zero'])]:
            with self.subTest(name):
                row, _ = call()
                self.assertEqual(self.failing(row), keys)
                self.assertEqual(row['outcome'], 'FAIL')

    def test_k111_gates_every_summary_fact(self):
        # Reviewer F-1 (fx_k111): a summary printing the HOST's facts (network
        # not applied, 0/6 classes, observer not attached) never passes.
        attempt = self.fixed_attempt()
        good = self.summary_text(attempt)
        host_facts = self.summary_text(attempt, network='not applied', classes='0/6 classes active · observer not attached')
        for which, run_text, tail_text in (('run', host_facts, good), ('tail', good, host_facts)):
            with self.subTest(which):
                row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, run_text, tail_text, self.OLD_K111_ARGV, T)
                self.assertEqual(self.failing(row), [f'{which}_summary_network_line_is_the_guests',
                                                     f'{which}_summary_observer_classes_are_the_guests',
                                                     f'{which}_summary_observer_attachment_is_the_guests'])
        for which, changed, fact in (
                ('network', self.summary_text(attempt, network='host, not observed'), 'network_line_is_the_guests'),
                ('classes', self.summary_text(attempt, classes='6/6 classes active'), 'observer_classes_are_the_guests'),
                ('attachment', self.summary_text(attempt, classes='5/6 classes active · observer not attached'),
                 'observer_attachment_is_the_guests')):
            with self.subTest(which):
                row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, good, changed, self.OLD_K111_ARGV, T)
                self.assertEqual(self.failing(row), [f'tail_summary_{fact}'])

    def test_k111_binding_and_receipt_mutations(self):
        # Reviewer G7, G8, G13: each binding field on its own.
        argv = self.OLD_K111_ARGV
        for name, path, changes, keys in [
                ('bound to another attempt', 'evidence/vm-binding.json', {'attempt_id': 'att_other'}, ['binding_matches_attempt']),
                ('bound to another profile', 'evidence/vm-binding.json', {'profile': 'agent'}, ['binding_profile_tool']),
                ('bound to another serve boot', 'evidence/vm-binding.json', {'boot_id': 'vm-other'}, ['guest_boot_bound']),
                ('no serve boot in the binding', 'evidence/vm-binding.json', {'boot_id': None}, ['guest_boot_bound']),
                ('another argv in the binding', 'evidence/vm-binding.json', {'argv_digest': 'sha256:other'}, ['binding_argv_digest_is_this_argv'])]:
            with self.subTest(name):
                attempt = self.fixed_attempt()
                text = self.summary_text(attempt)
                self.rewrite_json(attempt / path, **changes)
                row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv, T)
                self.assertEqual(self.failing(row), keys)
        # The guest receipt's own argv digest: rewritten with its transport
        # digest (and the summary lines) kept consistent, so only it fails.
        attempt = self.fixed_attempt()
        guest_path = attempt / 'evidence/jail.json'
        self.rewrite_json(guest_path, argv_digest='sha256:other')
        self.rewrite_json(attempt / 'vm-transport.json', guest_receipt_sha256=harness.sha256_file(guest_path))
        text = self.summary_text(attempt)
        row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv, T)
        self.assertEqual(self.failing(row), ['guest_receipt_argv_digest_is_this_argv'])
        guest_path.write_bytes(guest_path.read_bytes() + b' ')
        row, _ = gate_rows.judge_k111(attempt, self.workspace, 0, text, text, argv, T)
        self.assertIn('digest_matches_record', self.failing(row))

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
                ('refused with another exit status', {'exit': 1}, 'native_shipped_refused', 'shipped'),
                ('the requirements never name owner loss', {'requirements_name_owner_loss': False}, 'native_dev_refused', 'dev'),
                ('a boot was attempted', {'boot_attempted': True}, 'vm_refused_before_boot', 'vm'),
                ('the key never reached the policy', {'lifetime_boundary': None}, 'vm_refused_before_boot', 'vm')]:
            with self.subTest(name):
                lanes = {'shipped': lane, 'dev': lane, 'vm': lane}
                lanes[which] = mutated(lane, **changes)
                row = gate_rows.judge_k112(lanes['shipped'], lanes['dev'], lanes['vm'])
                self.assertFalse(row[key])
                self.assertEqual(row['outcome'], 'FAIL')
        # S1's F11d: a lane refused for its standard input never reached the
        # kernel-bound check; the row records that, never a pass or a fail.
        stdin = mutated(lane, stderr='refused [invalid_config]: --vm: standard input is a pipe, ...',
                        lifetime_boundary=None, refusals=['--vm: standard input is a pipe'])
        row = gate_rows.judge_k112(lane, lane, stdin)
        self.assertFalse(row['vm_refused_before_boot'])
        self.assertEqual(row['outcome'], 'REFUSED')

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


def seen_as(value):
    """What fetch_script prints for a variable holding `value` (bytes)."""
    text = value.decode()
    shown = text if re.fullmatch(vault_measurement.PLACEHOLDER_SHAPE, text) else None
    return {'sha256': hashlib.sha256(value).hexdigest(), 'length': len(text), 'value': shown}


class VaultTables(unittest.TestCase):
    GUEST_ATTEMPT = 'att_0b5c'

    def good(self):
        return {'run_exit': 0, 'header': vault_measurement.SECRET.decode(),
                'placeholder': seen_as(f'vault:{self.GUEST_ATTEMPT}:test'.encode()),
                'guest_attempt_id': self.GUEST_ATTEMPT, 'receipt_bound': True, 'same_boot': True,
                'guest_credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True}],
                'guest_network_mode': 'proxy', 'phase': 'settled', 'exit': 0, 'tree_empty': True,
                'leaks': [], 'files_scanned': 12, 'client_output_leak': False, 'disk_scan': 'clean',
                'sync_exit': 0}

    def test_table(self):
        self.assertEqual(vault_measurement.judge(self.good())[1], 'PASS')
        secret = vault_measurement.SECRET
        for name, changes, key in [
                ('no injection', {'header': None}, 'header_injected'),
                ('the child held the value', {'placeholder': seen_as(secret)}, 'child_saw_a_placeholder'),
                # Reviewer FX2: the value plus a newline was a "placeholder" by length and hash.
                ('the child held the value and a newline', {'placeholder': seen_as(secret + b'\n')}, 'child_saw_a_placeholder'),
                ('no placeholder seen', {'placeholder': None}, 'child_saw_a_placeholder'),
                ('an empty placeholder', {'placeholder': seen_as(b'')}, 'child_saw_a_placeholder'),
                ('another attempt\'s placeholder', {'placeholder': seen_as(b'vault:att_other:test')}, 'child_saw_a_placeholder'),
                ('another credential\'s placeholder', {'placeholder': seen_as(f'vault:{self.GUEST_ATTEMPT}:other'.encode())}, 'child_saw_a_placeholder'),
                ('a placeholder carrying the value', {'placeholder': seen_as(f'vault:{secret.decode()}:test'.encode()),
                                                      'guest_attempt_id': secret.decode()}, 'child_saw_a_placeholder'),
                ('a printed value its hash disowns', {'placeholder': dict(seen_as(f'vault:{self.GUEST_ATTEMPT}:test'.encode()), sha256='0' * 64)}, 'child_saw_a_placeholder'),
                ('a printed value its length disowns', {'placeholder': dict(seen_as(f'vault:{self.GUEST_ATTEMPT}:test'.encode()), length=3)}, 'child_saw_a_placeholder'),
                ('no guest attempt id', {'guest_attempt_id': None}, 'child_saw_a_placeholder'),
                ('a staged mode', {'guest_credentials': [{'id': 'test', 'mode': 'copy_rw', 'never_staged': True}]}, 'guest_credential_vault_never_staged'),
                ('staged into the attempt', {'guest_credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': False}]}, 'guest_credential_vault_never_staged'),
                ('no credential record', {'guest_credentials': []}, 'guest_credential_vault_never_staged'),
                ('the receipt is another attempt\'s', {'receipt_bound': False}, 'receipt_bound_to_this_attempt'),
                ('a leak in an export', {'leaks': ['/x/trace.ndjson']}, 'no_value_in_any_export'),
                ('nothing scanned', {'files_scanned': 0}, 'no_value_in_any_export'),
                ('the client printed it', {'client_output_leak': True}, 'no_value_in_client_output'),
                ('on the guest disk', {'disk_scan': 'value-present'}, 'guest_disk_scanned_clean'),
                ('disk never scanned', {'disk_scan': 'not-checked: 0 boot disks found'}, 'guest_disk_scanned_clean'),
                ('caches not flushed', {'sync_exit': 1}, 'guest_disk_scanned_clean'),
                ('the sync ran on another boot', {'same_boot': False}, 'sync_on_the_vault_attempts_boot'),
                ('not proxied', {'guest_network_mode': 'none'}, 'guest_network_proxy')]:
            with self.subTest(name):
                facts, outcome = vault_measurement.judge(mutated(self.good(), **changes))
                self.assertEqual([k for k, v in facts.items() if v is not True], [key])
                self.assertEqual(outcome, 'FAIL')

    def test_the_child_prints_only_a_placeholder_shaped_value(self):
        script = vault_measurement.fetch_script('127.0.0.1', 9)
        source = script.split('python3 -c "', 1)[1].rsplit('"', 1)[0].split('; req = ')[0]
        for value, shown in ((f'vault:{self.GUEST_ATTEMPT}:test', True), (vault_measurement.SECRET.decode(), False),
                             (f'vault:a:test\n{vault_measurement.SECRET.decode()}', False), ('', False)):
            with self.subTest(value=value[:20]):
                done = subprocess.run([sys.executable, '-I', '-c', source], capture_output=True, text=True,
                                      env={'UKAI_VAULT_TEST': value}, timeout=30)
                seen = vault_measurement.placeholder(done.stdout)
                self.assertEqual(seen['value'], value if shown else None, done.stderr)
                self.assertEqual((seen['sha256'], seen['length']), (hashlib.sha256(value.encode()).hexdigest(), len(value)))
                self.assertNotIn(vault_measurement.SECRET.decode(), done.stdout)

    def test_redact_removes_the_address(self):
        # Reviewer V7.
        self.assertEqual(vault_measurement.redact('http://10.0.0.7:8080/echo', '10.0.0.7'), 'http://<mac-address>:8080/echo')
        self.assertEqual(vault_measurement.redact(42, '10.0.0.7'), '42')
        self.assertEqual(vault_measurement.redact('x', None), 'x')

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
        runs = [{'stdout': 'GITHUB_ANSWERED 200\nEXAMPLE_REFUSED URLError\n' + route_line(f'{T}-route') + '\n'},
                {'stdout': 'EXAMPLE_ANSWERED 200\nGITHUB_REFUSED URLError\n'},
                {'stdout': probe_line(T) + '\n'}]
        base = {'phase': 'settled', 'tree_empty': True, 'serve_boot': 'vm-1', 'guest_boot': 'g-1', 'bound': True}
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
        first = runs[0]['stdout']
        for name, (r, rec), keys in [
                ('the refuted "same guest" (vm-574c66b2 vs vm-b22ef488)', with_record(2, serve_boot='vm-b22ef488'), ['same_serve_boot']),
                ('another guest kernel boot', with_record(1, guest_boot='g-2'), ['same_guest_boot']),
                ('the /dev/tcp text', with_run(2, 'net_refused\n'), ['offline_probe_denied']),
                ('a refusal is not the jail\'s denial', with_run(2, probe_line(T, egress='ECONNREFUSED')), ['offline_probe_denied']),
                ('re-armed set not applied', with_run(1, 'EXAMPLE_REFUSED URLError\nGITHUB_ANSWERED 200\n'), ['rearmed_allowed_answers', 'rearmed_old_host_refused']),
                ('old host still allowed', with_run(1, 'EXAMPLE_ANSWERED 200\nGITHUB_ANSWERED 200\n'), ['rearmed_old_host_refused']),
                ('denied host answered', with_run(0, first.replace('EXAMPLE_REFUSED URLError', 'EXAMPLE_ANSWERED 200')), ['first_denied_refused']),
                ('allowed host refused', with_run(0, first.replace('GITHUB_ANSWERED 200', 'GITHUB_REFUSED URLError')), ['first_allowed_answers']),
                # F-2: the guest's own route to the probe target, on this boot.
                ('the route control never reached the target', with_run(0, first.replace('200 Connection established', '502 Bad Gateway')), ['route_control_reached_the_target']),
                ('no route control', with_run(0, 'GITHUB_ANSWERED 200\nEXAMPLE_REFUSED URLError\n'), ['route_control_reached_the_target']),
                ('offline attempt proxied', with_record(2, guest_network={'mode': 'proxy'}), ['offline_attempt_none']),
                # Reviewer P7 and P10.
                ('an agent attempt not proxied', with_record(0, guest_network={'mode': 'none'}), ['agent_attempts_proxy']),
                ('an attempt not settled', with_record(1, phase='refused'), ['every_attempt_settled']),
                ('a tree left behind', with_record(2, tree_empty=False), ['every_attempt_settled']),
                ('a receipt bound to another argv', with_record(1, bound=False), ['every_receipt_bound'])]:
            with self.subTest(name):
                facts, outcome = proxy_measurement.judge(r, rec, T)
                self.assertEqual([key for key, value in facts.items() if value is not True], keys)
                self.assertEqual(outcome, 'FAIL')
        # Reviewer P3: two attempt records are not three, whatever they say.
        facts, outcome = proxy_measurement.judge(runs, records[:2], T)
        self.assertFalse(facts['three_attempts_recorded'])
        self.assertEqual(outcome, 'FAIL')
        facts, outcome = proxy_measurement.judge(runs, records + records[:1], T)
        self.assertFalse(facts['three_attempts_recorded'])

    def test_attempt_records_bind_each_attempt_to_its_argv(self):
        root = Path(tempfile.mkdtemp(prefix='proxy-records-'))
        self.addCleanup(shutil.rmtree, root, True)
        argvs = [['/bin/sh', '-c', 'one'], ['/bin/sh', '-c', 'two']]
        for index, argv in enumerate(argvs):
            k111_attempt_dir(root / 'attempts' / f'att_{index}', argv)
            os.utime(root / 'attempts' / f'att_{index}' / 'jail.json', (1000 + index, 1000 + index))
        self.assertEqual([r['bound'] for r in proxy_measurement.attempt_records(root, argvs)], [True, True])
        self.assertEqual([r['bound'] for r in proxy_measurement.attempt_records(root, argvs[::-1])], [False, False])
        self.assertEqual([r['bound'] for r in proxy_measurement.attempt_records(root, argvs[:1])], [True, False])


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

    def fake_run(self, tail_has_line=True, run_raises=None, refused=False, stop_raises=None, leak_to=None,
                 print_token=False, contradict=False, tail_exit=0):
        guest = {'platform': {'os': 'linux'}, 'applied': {'network': {'mode': 'proxy'}},
                 'observer': {'attached': True}, 'outcome': {'code': 0},
                 'coverage': {name: {'status': 'active'} for name in harness.SUMMARY_CLASSES}}
        line = None
        good_tail = None

        def run(argv, env=None, **kwargs):
            nonlocal line, good_tail
            self.calls.append(list(argv))
            assert_vm_client(self, list(argv), env)
            for word in argv:
                self.assertNotIn(self.token, str(word))
            if argv[-1] == 'stop' and stop_raises is not None:
                raise stop_raises
            if refused and 'run' in argv and '--vm' in argv:
                return subprocess.CompletedProcess(argv, 125, '', 'ukai-jail: refused [unsupported]: vm:not-measured:limit:wall')
            if 'run' in argv and '--vm' in argv:
                source = Path((Path(env['UKAI_CONFIG_DIR']) / 'launch/claude-vm.toml').read_text()
                              .split('source = "', 1)[1].split('"', 1)[0])
                self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                self.assertEqual(source.read_text(), self.token)
                if run_raises is not None:
                    raise run_raises
                data = Path(env['UKAI_DATA_DIR'])
                attempt = data / 'attempts' / 'att_1'
                (attempt / 'evidence').mkdir(parents=True)
                workload = argv[argv.index('--') + 1:]
                guest_bytes = json.dumps(dict(guest, argv_digest=harness.argv_digest(workload))).encode()
                transport = {'schema': 'ukai.jail.vm-transport/1', 'boot_id': 'vm-x', 'vsock_port': 1024,
                             'image': {'disk_sha256': 'a' * 64},
                             'guest_receipt_sha256': hashlib.sha256(guest_bytes).hexdigest()}
                line = (f"vm: guest-reported facts in evidence/jail.json · boot vm-x · image {'a' * 16} "
                        f"· vsock 1024 · receipt sha256:{transport['guest_receipt_sha256'][:16]}\n")
                good_tail = (line + 'ukai-jail: network: allowed api.anthropic.com (3)\n'
                             'ukai-jail: evidence: 6/6 classes active, no gaps\n')
                stored = {**guest, 'phase': 'settled', 'lifetime': {'tree_empty': True}}
                if contradict:
                    stored['applied'] = {'network': {'mode': 'pending'}}
                (attempt / 'jail.json').write_text(json.dumps(stored))
                (attempt / 'vm-transport.json').write_text(json.dumps(transport))
                (attempt / 'evidence/jail.json').write_bytes(guest_bytes)
                (attempt / 'evidence/vm-binding.json').write_text(json.dumps({
                    'attempt_id': 'att_1', 'profile': 'agent', 'argv_digest': harness.argv_digest(workload),
                    'boot_id': 'vm-x', 'guest_boot_id': 'g-1'}))
                (self.workspace / 'k113-marker.txt').write_text('contained\n')
                if leak_to == 'data':
                    (data / 'vm').mkdir(exist_ok=True)
                    (data / 'vm' / 'console.log').write_text('boot … ' + self.token)
                elif leak_to == 'workspace':
                    (self.workspace / 'notes.txt').write_text(self.token)
                result = '{"type":"result","subtype":"success","is_error":false,"result":"done"}\n'
                if print_token:
                    result += f'debug: {self.token}\n'
                # The run's own terminal always carries the transport line.
                return subprocess.CompletedProcess(argv, 0, result + good_tail, '')
            if 'tail' in argv:
                return subprocess.CompletedProcess(argv, tail_exit, good_tail if tail_has_line else 'no summary\n', '')
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

    def row(self, out='out'):
        return json.loads((self.root / out / 'k113-claude.json').read_text())

    def token_files(self):
        self.assertTrue(any(self.temp.glob('k113-*')), 'the run made no temp dirs here')
        return [path for path in self.temp.rglob('*') if path.is_file()
                and self.token in path.read_text(errors='replace')]

    def test_a_good_run_passes_and_leaves_no_token(self):
        self.assertEqual(self.main(), 0)
        row = self.row()
        self.assertEqual(row['outcome'], 'PASS', row['facts'])
        self.assertTrue(row['token_source_removed'])
        self.assertTrue(row['receipt_bound'])
        self.assertEqual(self.token_files(), [])
        self.assertTrue(any(call[-1] == 'stop' for call in self.calls))
        self.assertNotIn(self.token, json.dumps(row))

    def test_the_summary_is_judged_on_tail_alone(self):
        self.assertEqual(self.main(tail_has_line=False), 1)
        row = self.row()
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

    def test_the_token_is_gone_when_stop_raises(self):
        # Reviewer FX1: `ukai-vm stop` raising (or timing out) once left the token file.
        self.assertEqual(self.main(stop_raises=subprocess.TimeoutExpired(['ukai-vm', 'stop'], 60)), 0)
        self.assertEqual(self.row()['stop_error'], 'TimeoutExpired')
        self.assertTrue(self.row()['token_source_removed'])
        self.assertEqual(self.token_files(), [])
        with self.assertRaises(RuntimeError):
            self.main(out='out-raise', stop_raises=RuntimeError('stop crashed'))
        self.assertEqual(self.token_files(), [])
        self.assertFalse([path for path in self.temp.glob('k113-vault-*')])

    def test_a_not_measured_refusal_is_recorded_never_passed(self):
        self.assertEqual(self.main(refused=True), 1)
        row = self.row()
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

    def test_a_staged_binary_of_another_digest_refuses(self):
        # Reviewer K12.
        (self.workspace / 'claude').write_bytes(b'another claude')
        with self.assertRaisesRegex(harness.HarnessError, 'does not match its manifest digest'):
            self.main()
        self.assertEqual(self.calls, [])

    def test_a_printed_token_fails_and_never_reaches_a_file(self):
        # Reviewer K8: the run's texts are scanned in memory, then redacted
        # before they are written.
        self.assertEqual(self.main(print_token=True), 1)
        row = self.row()
        self.assertEqual(row['token_in_outputs'], ['stdout'])
        self.assertEqual(row['token_in_exports'], [])
        self.assertIn('<token>', (self.root / 'out' / 'k113-run-stdout.txt').read_text())
        for path in (self.root / 'out').rglob('*'):
            if path.is_file():
                self.assertNotIn(self.token, path.read_text(errors='replace'), path)

    def test_a_token_in_the_data_dir_or_workspace_fails(self):
        # Reviewer K11: the scan covers the data directory and the workspace,
        # not only what was copied out.
        for where in ('data', 'workspace'):
            with self.subTest(where):
                self.assertEqual(self.main(out=f'out-{where}', leak_to=where), 1)
                row = self.row(f'out-{where}')
                self.assertEqual(len(row['token_in_exports']), 1, row['token_in_exports'])
                self.assertFalse(row['facts']['token_in_no_export'])
                (self.workspace / 'notes.txt').unlink(missing_ok=True)

    def test_a_contradicting_host_receipt_fails(self):
        self.assertEqual(self.main(contradict=True), 1)
        self.assertEqual([k for k, v in self.row()['facts'].items() if v is not True],
                         ['host_receipt_never_contradicts_guest'])

    def test_a_token_in_any_output_fails(self):
        row = {'phase': 'settled', 'exit': 0, 'tree_empty': True,
               'agent_result': {'subtype': 'success', 'is_error': False}, 'marker_content': 'contained\n',
               'guest_receipt_linux': True, 'token_in_exports': [], 'files_scanned': 3, 'token_in_outputs': [],
               'tail_summary_exit': 0, 'receipt_bound': True, 'host_receipt_contradictions': [],
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
                ('no tail summary facts at all', {'tail_summary_facts': None}, 'tail_summary_transport_line_from_record'),
                ('tail --summary failed', {'tail_summary_exit': 1}, 'tail_summary_ran'),
                ('the agent errored', {'agent_result': {'subtype': 'success', 'is_error': True}}, 'agent_succeeded'),
                ('the agent ran out of turns', {'agent_result': {'subtype': 'error_max_turns', 'is_error': False}}, 'agent_succeeded'),
                ('no agent result', {'agent_result': None}, 'agent_succeeded'),
                ('the receipt is another attempt\'s', {'receipt_bound': False}, 'receipt_bound_to_this_attempt'),
                ('host receipt contradicts the guest', {'host_receipt_contradictions': [{'field': 'applied.network'}]}, 'host_receipt_never_contradicts_guest'),
                ('marker wrong', {'marker_content': 'contained'}, 'marker_on_host')]:
            with self.subTest(name):
                facts, outcome = claude_vm_row.judge(mutated(row, **changes))
                self.assertEqual([k for k, v in facts.items() if v is not True], [key])
                self.assertEqual(outcome, 'FAIL')


if __name__ == '__main__':
    unittest.main()
