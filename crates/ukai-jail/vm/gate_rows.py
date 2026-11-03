#!/usr/bin/env python3
"""The K109/K111/K112 rows against an INSTALLED ukai-vm package.

K108 (warm reuse) and K110 (fault matrix) run through their own harnesses
(warm_live.py, fault_matrix.py) and K113 through claude_vm_row.py; this one
covers the rows that need the CLI or the row's own probes:

  K109  one warm boot on the installed service: a granted write reaches the
        host with this run's exact bytes, while writes outside the grants
        (the protected .git) and outside the share (/etc, /usr/local/bin,
        the guest's root) refuse with a filesystem errno and leave nothing;
  K111  one attempt through `ukai-jail run --vm` (the client boots the
        installed service itself): evidence/jail.json is the guest's Linux
        receipt whose SHA-256 the transport record carries; vm-binding.json
        ties it to this host attempt, its boot, its profile AND the argv
        digest of exactly the argv this harness passed (as does the guest
        receipt's own argv_digest); no host-receipt field contradicts the
        guest receipt (D5); and both the run's summary and `tail --summary`
        carry a transport line whose values are the transport record's, a
        network line stating the guest receipt's applied mode, and an
        evidence line counting the guest's active classes and its observer
        attachment (every fact summary_facts computes is gated); the
        workload writes this run's nonce, so an earlier run's file cannot
        count;
  K112  the kernel-bound key refuses in every lane: native (as shipped and
        dev-enabled) and this build's installed --vm backend, all with
        `unsupported`, all before any process or boot (the workload would
        have touched a file in this workspace; none exists);
  K113  only the summary mechanism; the row is claude_vm_row.py's.

The exit status is 0 only when K109, K111 and K112 all pass.

Usage: gate_rows.py <installed-root> <workspace> <out> <ukai-jail>
"""
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capabilities  # noqa: E402
import harness  # noqa: E402

SENTINEL = '[core]\n'


def k111_script(tag):
    return f'printf "row-k111-{tag}\\n" > k111.txt; echo row-k111-done'


def row_k109(binary, home, workspace):
    """Granted writes reach the host; writes outside grants and share don't."""
    harness.clean_workspace(workspace)
    git_config = harness.protected_sentinel(workspace, SENTINEL)
    tag = harness.nonce()
    outside = [f'/etc/ukai-k109-{tag}', f'/usr/local/bin/ukai-k109-{tag}', f'/ukai-k109-{tag}']
    data = tempfile.mkdtemp(prefix='row-k109-')
    with harness.Service(binary, home, workspace, data) as service:
        granted = harness.run_attempt(
            service.connect, f'row-granted-{tag}',
            harness.sh(f'printf "granted-{tag}\\n" > k109-granted.txt; echo wrote-{tag}\n'
                       f'if printf forged > .git/config 2>/dev/null; then echo GIT_WRITE_ALLOWED-{tag}; '
                       f'else echo git_write_refused-{tag}; fi'))
        refused = harness.run_attempt(
            service.connect, f'row-outside-{tag}', capabilities.fs_probe_argv(tag, outside))
    return judge_k109(tag, granted, refused, outside, workspace, git_config, service.child.returncode)


def judge_k109(tag, granted, refused, outside, workspace, git_config, service_exit):
    on_host = Path(workspace) / 'k109-granted.txt'
    containment = capabilities.judge_containment(refused, tag, outside)
    row = {
        'granted_write_on_host': on_host.is_file() and on_host.read_text() == f'granted-{tag}\n',
        'granted_exit_zero': granted.get('exit_code') == 0 and not granted.get('error'),
        'granted_receipt_bound': harness.receipt_bound(granted),
        'git_write_tried_and_refused': (f'git_write_refused-{tag}' in granted['stdout']
                                        and f'GIT_WRITE_ALLOWED-{tag}' not in granted['stdout']),
        'git_config_unchanged': git_config.read_text() == SENTINEL,
        'outside_writes_refused_and_absent': all(value is True for value in containment.values()),
        'outside_exit_zero': refused.get('exit_code') == 0 and not refused.get('error'),
        'service_stopped_cleanly': service_exit == 0,
    }
    row['containment'] = containment
    row['workspace_listing'] = sorted(p.name for p in Path(workspace).iterdir())
    row['outcome'] = 'PASS' if all(value is True for key, value in row.items()
                                   if isinstance(value, bool)) else 'FAIL'
    return row


def cli_environment(home, data, config=None):
    """A `run --vm` client's environment (harness.vm_client_environment: LANG=C.UTF-8, no TERM/TZ)."""
    values = {'PATH': f'{home}/bin:/usr/bin:/bin', 'UKAI_VM_HOME': home, 'UKAI_DATA_DIR': data}
    if config is not None:
        values['UKAI_CONFIG_DIR'] = config
    return harness.vm_client_environment(**values)


def read_json(path):
    return json.loads(Path(path).read_text()) if Path(path).is_file() else {}


def judge_k111(attempt, workspace, run_exit, terminal, tail_summary, argv, tag):
    guest_path = attempt / 'evidence/jail.json'
    guest = read_json(guest_path)
    binding = read_json(attempt / 'evidence/vm-binding.json')
    transport = read_json(attempt / 'vm-transport.json')
    stored = read_json(attempt / 'jail.json')
    expected_argv = harness.argv_digest(argv)
    guest_digest = hashlib.sha256(guest_path.read_bytes()).hexdigest() if guest_path.is_file() else None
    row = {
        'run_exit_zero': run_exit == 0,
        'settled': stored.get('phase') == 'settled',
        'exit_zero': (stored.get('outcome') or {}).get('code') == 0,
        'tree_empty': (stored.get('lifetime') or {}).get('tree_empty') is True,
        'granted_write_on_host': (Path(workspace) / 'k111.txt').is_file()
        and (Path(workspace) / 'k111.txt').read_text() == f'row-k111-{tag}\n',
        'guest_receipt_is_linux': (guest.get('platform') or {}).get('os') == 'linux',
        'digest_matches_record': bool(transport.get('guest_receipt_sha256')) and guest_digest == transport['guest_receipt_sha256'],
        'binding_matches_attempt': binding.get('attempt_id') == attempt.name,
        'binding_profile_tool': binding.get('profile') == 'tool',
        'binding_argv_digest_is_this_argv': binding.get('argv_digest') == expected_argv,
        'guest_receipt_argv_digest_is_this_argv': guest.get('argv_digest') == expected_argv,
        'guest_boot_bound': bool(binding.get('boot_id')) and binding.get('boot_id') == transport.get('boot_id'),
        'host_receipt_never_contradicts_guest': not harness.receipt_contradictions(stored, guest),
    }
    run_summary = harness.summary_facts(terminal, guest, transport)
    stored_summary = harness.summary_facts(tail_summary, guest, transport)
    # Every fact the record computes is a gate (F-1): the transport line, the
    # guest's network line, its class count and its observer attachment.
    for prefix, facts in (('run_summary', run_summary), ('tail_summary', stored_summary)):
        for name, value in facts.items():
            row[f'{prefix}_{name}'] = value is True
    detail = {'expected_argv_digest': expected_argv, 'binding': binding,
              'contradictions': harness.receipt_contradictions(stored, guest),
              'run_summary_facts': run_summary, 'tail_summary_facts': stored_summary,
              'attempt_id': attempt.name, 'transport_schema': transport.get('schema')}
    row['outcome'] = 'PASS' if all(value is True for value in row.values()) else 'FAIL'
    return row, detail


def row_k111(home, workspace, jail, out):
    """One `run --vm` attempt: receipt digest, binding, argv digest, transport line."""
    harness.clean_workspace(workspace)
    data = Path(tempfile.mkdtemp(prefix='row-k111-'))
    config = Path(tempfile.mkdtemp(prefix='row-k111-cfg-'))
    os.chmod(config, 0o700)
    environment = cli_environment(home, data, config)
    tag = harness.nonce()
    argv = ['/bin/sh', '-c', k111_script(tag)]
    started = time.monotonic()
    # script(1) gives the supervisor a real terminal, the only condition
    # under which the summary and its transport line print.
    try:
        run = subprocess.run(['script', '-q', '/dev/null', str(jail), 'run', '--vm',
                              '--terminal', 'detach', '--profile', 'tool', *harness.vm_wall(20),
                              '--workspace', str(workspace), '--', *argv],
                             env=environment, capture_output=True, text=True, timeout=420)
        run_exit, terminal = run.returncode, run.stdout + '\n' + run.stderr
    except subprocess.TimeoutExpired as error:
        run_exit, terminal = None, f'timeout: {error}'
    elapsed = round(time.monotonic() - started, 1)
    attempts = sorted((data / 'attempts').glob('att_*'), key=lambda p: p.stat().st_mtime)
    tail = ''
    if attempts:
        summary = subprocess.run([str(jail), 'tail', '--summary', '--attempt', attempts[-1].name],
                                 env=environment, capture_output=True, text=True, timeout=60)
        tail = summary.stdout + summary.stderr
    stop = subprocess.run([str(Path(home) / 'bin/ukai-vm'), 'stop'], env=environment,
                          capture_output=True, text=True, timeout=60)
    refusals = harness.vm_refusals(terminal)
    if not attempts:
        return {'outcome': 'REFUSED' if refusals else 'FAIL', 'refusals': refusals,
                'run_exit': run_exit, 'elapsed_s': elapsed, 'terminal_tail': terminal[-800:]}
    shutil.copytree(attempts[-1], out / 'k111-attempt')
    row, detail = judge_k111(attempts[-1], workspace, run_exit, terminal, tail, argv, tag)
    (out / 'k111-tail-summary.txt').write_text(tail)
    if refusals:
        # A refusal (vm:not-measured until the live phase fills the host's
        # table) is recorded as what it is, never as a pass.
        row['outcome'] = 'REFUSED'
    return {**row, 'refusals': refusals, 'elapsed_s': elapsed, 'stop_exit': stop.returncode,
            'detail': detail, 'terminal_tail': terminal[-1200:]}


def kernel_bound_run(jail, environment, workspace, lane):
    data = Path(tempfile.mkdtemp(prefix='row-k112-'))
    config = Path(tempfile.mkdtemp(prefix='row-k112-cfg-'))
    os.chmod(config, 0o700)
    # A real HOME and a private config dir: the state-path checks refuse a
    # homeless run for reasons that have nothing to do with this row.
    environment = dict(environment, HOME=os.environ['HOME'],
                       UKAI_DATA_DIR=str(data), UKAI_CONFIG_DIR=str(config))
    marker = f'k112-ran-{lane}-{harness.nonce()}'
    command = [str(jail), 'run', *(['--vm'] if lane == 'vm' else []), '--lifetime', 'kernel-bound',
               '--terminal', 'detach', '--profile', 'tool', *harness.vm_wall(20),
               '--workspace', str(workspace), '--',
               '/bin/sh', '-c', f'touch {marker}; touch {shlex.quote(str(Path(workspace) / marker))}-abs 2>/dev/null; true']
    started = time.monotonic()
    run = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=300)
    receipt, lifetime = None, None
    for jail_json in sorted((data / 'attempts').glob('att_*/jail.json'),
                            key=lambda p: p.stat().st_mtime, reverse=True):
        receipt = json.loads(jail_json.read_text())
        lifetime = read_json(jail_json.parent / 'policy.json').get('snapshot', {}).get('lifetime_boundary')
        break
    return {
        'exit': run.returncode,
        'elapsed_s': round(time.monotonic() - started, 1),
        'stderr': run.stderr.strip()[-300:],
        'phase': receipt.get('phase') if receipt else None,
        'requirements_name_owner_loss': bool(receipt and 'owner_loss_termination' in json.dumps(
            (receipt.get('policy') or {}).get('requirements', []))),
        'lifetime_boundary': lifetime,
        'workload_marker': marker,
        'workload_ran': workload_ran(workspace, marker),
        'boot_attempted': (data / 'vm').exists(),
        'refusals': harness.vm_refusals(run.stderr),
    }


def workload_ran(workspace, marker):
    """The K112 workload touches `marker` in its workspace (relative, and absolute)."""
    return any((Path(workspace) / name).exists() for name in (marker, marker + '-abs'))


def judge_k112(shipped, dev, vm):
    def refused(lane):
        return (lane['exit'] == 125 and lane['phase'] == 'refused'
                and '[unsupported]' in lane['stderr'] and not lane['workload_ran']
                and lane['lifetime_boundary'] == 'kernel-bound' and lane['requirements_name_owner_loss'])
    row = {'native_shipped_refused': refused(shipped), 'native_dev_refused': refused(dev),
           'vm_refused_before_boot': refused(vm) and not vm['boot_attempted']}
    row['outcome'] = 'PASS' if all(row.values()) else 'FAIL'
    return row


def row_k112(home, jail, workspace):
    """The kernel-bound key refuses in the native and --vm lanes."""
    harness.clean_workspace(workspace)
    shipped = kernel_bound_run(jail, {'PATH': '/usr/bin:/bin'}, workspace, 'shipped')
    dev = kernel_bound_run(jail, {'PATH': '/usr/bin:/bin', 'UKAI_JAIL_MACOS_NATIVE': 'dev'},
                           workspace, 'dev')
    vm = kernel_bound_run(jail, cli_environment(home, tempfile.mkdtemp(prefix='row-k112-vm-')),
                          workspace, 'vm')
    row = judge_k112(shipped, dev, vm)
    row.update({'native_shipped': shipped, 'native_dev': dev, 'vm_installed': vm,
                'linux_none_refusal': 'K112.2 (portable): ukai-jail/tests/vm_tier.rs'})
    return row


def row_k113(k111_row):
    """Only the mechanism; the row is claude_vm_row.py's (J18 §9.4 conditions)."""
    detail = k111_row.get('detail') or {}
    return {'mechanism_tail_summary_transport_line': (detail.get('tail_summary_facts') or {}).get(
                'transport_line_from_record') is True,
            'note': 'K113 is judged by claude_vm_row.py, not here',
            'outcome': 'NOT_JUDGED_HERE'}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    home = Path(argv[0]).resolve(strict=True)
    workspace = harness.guarded_workspace(argv[1])
    out = harness.fresh_out_dir(argv[2])
    jail = harness.required_binary('UKAI_JAIL_BINARY', argv[3])
    binary = harness.required_binary('UKAI_VM_BINARY', str(home / 'bin' / 'ukai-vm'))
    rows = {'K109': row_k109(binary, home, workspace)}
    harness.write_json(out / 'k109.json', rows['K109'])
    rows['K111'] = row_k111(home, workspace, jail, out)
    harness.write_json(out / 'k111.json', rows['K111'])
    rows['K112'] = row_k112(home, jail, workspace)
    harness.write_json(out / 'k112.json', rows['K112'])
    rows['K113'] = row_k113(rows['K111'])
    summary = {name: row.get('outcome') for name, row in rows.items()}
    harness.write_json(out / 'rows.json', {'binaries': {'ukai-jail': harness.fingerprint(jail),
                                                        'ukai-vm': harness.fingerprint(binary)},
                                           'rows': rows, 'summary': summary})
    print(json.dumps(summary))
    return 0 if all(summary[name] == 'PASS' for name in ('K109', 'K111', 'K112')) else 1


if __name__ == '__main__':
    sys.exit(main())
