#!/usr/bin/env python3
"""Pre-release guest capability measurements (vm/README's requirement).

Before `run --vm` may report any capability as available, each claim the
guest jail makes for an attempt must be MEASURED on the prepared image,
through the warm service, with the live share attached. This suite runs one
boot and one attempt per capability; an unmeasured capability is recorded
as such, never assumed.

Every verdict reads facts, not shell exit statuses: the guest jail's own
receipt (limit hits, outcome cause, applied network), a probe's tagged JSON
line printed by python3 inside the attempt, or the host's view of the share.

Capabilities measured (the limits guest.py's run_command applies):
  wall            the guest jail ends an attempt at its wall deadline
                  (receipt: wall hit / wall_expiry; host: released->done spans
                  the wall, the workload's later output never appears)
  pids            a fork storm stops at the pids limit with EAGAIN, not
                  before (the count of successful forks is within PIDS_SLACK
                  of the limit), and the attempt settles without a jail error
  mem             an allocation beyond the mem limit is OOM-killed near the
                  limit: SIGKILL (137), the receipt's mem hit or memory_oom,
                  and the last reported allocation between half the limit and
                  the limit
  containment     writes to /etc, /usr/local/bin and the guest's root refuse
                  with a filesystem errno and leave nothing behind
  network_none    with the NAT adapter attached (control status guest_nat),
                  the egress probe (harness.py, D9) is denied after its
                  loopback positive control connected, DNS does not resolve,
                  the receipt's applied network is `none`, and the probe
                  target answers from the host
  workspace       a granted write reaches the host with this run's bytes

Usage: UKAI_VM_BINARY=<ukai-vm under test> capabilities.py <home> <workspace> <out>
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

PIDS_SLACK = 8
MEM_FLOOR_FRACTION = 0.5
FS_REFUSALS = {'EROFS', 'EACCES', 'EPERM', 'ENOENT'}

PIDS_PROBE = r'''
import errno, json, os, signal, sys, time
record = {'tag': sys.argv[1]}
for name in ('pids.max', 'pids.current'):
    try:
        with open('/sys/fs/cgroup/' + name) as source:
            record[name] = source.read().strip()
    except OSError:
        record[name] = None
children, failure = [], None
while len(children) < 4096:
    try:
        pid = os.fork()
    except OSError as error:
        failure = errno.errorcode.get(error.errno, str(error.errno))
        break
    if pid == 0:
        time.sleep(120)
        os._exit(0)
    children.append(pid)
record['forked'] = len(children)
record['fork_error'] = failure
for pid in children:
    os.kill(pid, signal.SIGKILL)
for pid in children:
    os.waitpid(pid, 0)
print('UKAI_PIDS_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''

MEM_PROBE = r'''
import sys
tag, limit = sys.argv[1], int(sys.argv[2])
chunk, blocks = 16 * 1024 * 1024, []
while len(blocks) * 16 < 2 * limit:
    block = bytearray(chunk)
    for offset in range(0, chunk, 4096):
        block[offset] = 1
    blocks.append(block)
    print('UKAI_MEM_PROBE %s %d' % (tag, len(blocks) * 16), flush=True)
print('UKAI_MEM_UNBOUNDED %s %d' % (tag, len(blocks) * 16), flush=True)
'''

FS_PROBE = r'''
import errno, json, os, sys
record = {'tag': sys.argv[1], 'paths': {}}
for path in sys.argv[2:]:
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        result = 'created'
    except OSError as error:
        result = errno.errorcode.get(error.errno, str(error.errno))
    record['paths'][path] = {'open': result, 'exists_after': os.path.lexists(path)}
print('UKAI_FS_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def tagged(stdout, name, tag):
    """The one `name {json}` line whose tag is `tag`, or None (none or several)."""
    found = []
    for line in stdout.splitlines():
        if line.startswith(name + ' '):
            try:
                record = json.loads(line[len(name) + 1:])
            except ValueError:
                continue
            if isinstance(record, dict) and record.get('tag') == tag:
                found.append(record)
    return found[0] if len(found) == 1 else None


def outcome(record):
    return ((record.get('receipt') or {}).get('outcome')) or {}


def judge_wall(record, tag, wall):
    limit = harness.receipt_limit(record.get('receipt'), 'wall') or {}
    elapsed = record['timings_ms'].get('released_to_done')
    facts = {
        'later_output_absent': f'never-{tag}' not in record['stdout'] and f'start-{tag}' in record['stdout'],
        'nonzero_exit': record.get('exit_code') not in (0, None),
        'receipt_records_the_wall': limit.get('hit') is True or outcome(record).get('cause') == 'wall_expiry',
        'ended_near_the_wall': elapsed is not None and (wall - 1) * 1000 <= elapsed < 25_000,
    }
    return facts


def judge_pids(record, tag):
    probe = tagged(record['stdout'], 'UKAI_PIDS_PROBE', tag) or {}
    forked = probe.get('forked')
    limit = harness.GUEST_PIDS_LIMIT
    expected_max = probe.get('pids.max')
    facts = {
        'fork_failed_with_eagain': probe.get('fork_error') == 'EAGAIN',
        'stopped_at_the_limit_not_before': isinstance(forked, int) and limit - PIDS_SLACK <= forked < limit,
        'cgroup_limit_is_the_guest_limit': expected_max in (None, str(limit)),
        'attempt_settled_without_jail_error': (record.get('exit_code') == 0 and not record.get('error')
                                               and not harness.jail_error_lines(record['stdout'] + record['stderr'])
                                               and not (record.get('receipt') or {}).get('errors')),
        'receipt_records_the_pids_hit': (harness.receipt_limit(record.get('receipt'), 'pids') or {}).get('hit') is True,
    }
    if isinstance(forked, int) and probe.get('pids.current') and str(probe.get('pids.current')).isdigit():
        # Where the probe can read its own cgroup, the forks fill it exactly.
        facts['forks_fill_the_cgroup'] = abs(forked + int(probe['pids.current']) - limit) <= 1
    return facts


def judge_mem(record, tag):
    reported = [int(line.split()[2]) for line in record['stdout'].splitlines()
                if line.startswith(f'UKAI_MEM_PROBE {tag} ') and line.split()[2].isdigit()]
    last = reported[-1] if reported else None
    limit = harness.GUEST_MEM_LIMIT_MIB
    facts = {
        'sigkilled': record.get('exit_code') == 137,
        'never_unbounded': f'UKAI_MEM_UNBOUNDED {tag}' not in record['stdout'],
        'receipt_records_the_oom': ((harness.receipt_limit(record.get('receipt'), 'mem') or {}).get('hit') is True
                                    or outcome(record).get('cause') == 'memory_oom'),
        'killed_near_the_limit': last is not None and limit * MEM_FLOOR_FRACTION <= last < limit,
    }
    return facts


def judge_containment(record, tag, paths):
    probe = tagged(record['stdout'], 'UKAI_FS_PROBE', tag) or {}
    results = probe.get('paths') or {}
    facts = {'every_path_probed': sorted(results) == sorted(paths)}
    for path in paths:
        entry = results.get(path) or {}
        facts[f'refused:{path}'] = entry.get('open') in FS_REFUSALS and entry.get('exists_after') is False
    return facts


def judge_network(record, tag, status, reachability):
    probe = harness.probe_verdict(record['stdout'], tag)
    network = (((record.get('receipt') or {}).get('applied') or {}).get('network') or {})
    return {
        'nat_attached': (status or {}).get('guest_nat') is True,
        'probe_denied_after_positive_control': probe['denied'],
        'dns_unresolved': probe.get('dns') not in (None, 'resolved'),
        'receipt_network_none': network.get('mode') == 'none',
        'target_answers_from_host': (reachability or {}).get('answers') is True,
    }


def judge_workspace(record, tag, host_text):
    return {'wrote': f'wrote-{tag}' in record['stdout'],
            'host_has_this_runs_bytes': host_text == f'live-{tag}\n'}


def plan(tag):
    """(name, wall, argv) per capability; argv is plain text, encoded later."""
    fs_paths = [f'/etc/ukai-cap-{tag}', f'/usr/local/bin/ukai-cap-{tag}', f'/ukai-cap-{tag}']
    return fs_paths, [
        ('wall', 5, harness.sh(f'echo start-{tag}; sleep 30; echo never-{tag}')),
        ('pids', 30, [harness.PYTHON, '-I', '-c', PIDS_PROBE, tag]),
        ('mem', 60, [harness.PYTHON, '-I', '-c', MEM_PROBE, tag, str(harness.GUEST_MEM_LIMIT_MIB)]),
        ('containment', 30, [harness.PYTHON, '-I', '-c', FS_PROBE, tag, *fs_paths]),
        ('network_none', 30, harness.probe_argv(tag, dns='example.com')),
        ('workspace', 30, harness.sh(f'printf "live-{tag}\\n" > capability-{tag}.txt; echo wrote-{tag}')),
    ]


def measure(service, workspace, tag, reachability):
    """Run every capability attempt on one warm boot; nothing judged here."""
    fs_paths, attempts = plan(tag)
    results = {}
    for name, wall, argv in attempts:
        results[name] = harness.run_attempt(service.connect, f'cap-{name}-{tag}', argv, wall=wall)
    host_file = Path(workspace) / f'capability-{tag}.txt'
    return {'tag': tag, 'fs_paths': fs_paths, 'results': results,
            'host_workspace_file': host_file.read_text() if host_file.is_file() else None,
            'reachability': reachability}


def judge(measured, status, git_config_untouched, service_exit):
    tag, results = measured['tag'], measured['results']
    walls = dict((name, wall) for name, wall, _ in plan(tag)[1])
    facts = {
        'wall': judge_wall(results['wall'], tag, walls['wall']),
        'pids': judge_pids(results['pids'], tag),
        'mem': judge_mem(results['mem'], tag),
        'containment': judge_containment(results['containment'], tag, measured['fs_paths']),
        'network_none': judge_network(results['network_none'], tag, status, measured['reachability']),
        'workspace': judge_workspace(results['workspace'], tag, measured['host_workspace_file']),
    }
    summary = {name: all(value is True for value in checks.values()) for name, checks in facts.items()}
    summary['git_config_untouched'] = git_config_untouched is True
    summary['service_stopped_cleanly'] = service_exit == 0
    summary['outcome'] = 'PASS' if all(summary.values()) else 'FAIL'
    return facts, summary


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    home = Path(argv[0]).resolve(strict=True)
    workspace = harness.guarded_workspace(argv[1])
    binary = harness.required_binary('UKAI_VM_BINARY')
    out = harness.fresh_out_dir(argv[2])
    removed = harness.clean_workspace(workspace)
    git_config = harness.protected_sentinel(workspace)
    tag = harness.nonce()
    reachability = harness.host_reachability()
    data = tempfile.mkdtemp(prefix='cap-')
    with harness.Service(binary, home, workspace, data, extra=('--guest-nat',)) as service:
        status = service.warm_status
        measured = measure(service, workspace, tag, reachability)
    git_untouched = git_config.read_text() == '[core]\n'
    facts, summary = judge(measured, status, git_untouched, service.child.returncode)
    record = {'schema': 'ukai.vm.capabilities/2', 'binary': harness.fingerprint(binary),
              'status': status, 'workspace_cleaned': removed, 'facts': facts,
              'summary': summary, 'service_exit': service.child.returncode,
              'service_stderr': service.stderr_text()[-2000:], **measured}
    harness.write_json(out / 'capabilities.json', record)
    print(json.dumps(summary))
    return 0 if summary['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
