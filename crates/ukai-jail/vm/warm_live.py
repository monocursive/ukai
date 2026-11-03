#!/usr/bin/env python3
"""K108 and K109's live claim against a warm `ukai-vm serve` with a live share.

One warm boot, N attempts over the attempt socket (the §6 protocol), each
writing through the virtio-fs share to the host workspace. Per attempt the
host checks, right after the attempt and in a workspace this run cleaned:
the granted write holds this run's bytes, the protected `.git/config` still
holds its sentinel, the attempt tried that protected write and reported the
refusal, the egress probe (harness.py, D9) failed with the jail's denial
errno after its loopback positive control, and the guest receipt arrived
with a matching digest, bound to that attempt. Warm reuse means one serve
boot id AND one guest kernel boot id throughout.

The guest NAT adapter is always attached, and one route control attempt
(agent profile, allowed exactly the probe target) runs on the same boot
after the N: its proxy, outside the jail's network namespace, must reach
the target, so the N denials are the jail's and not a guest without a route
(harness.network_denial). The route control is not one of the N and is not
timed for K108.

K108 (jail-macos §9.3): "a second attempt in a running guest is released
within initial 1 s of the guest jail's own release time, over 20 runs".
`initial` is the spec's tunable-default keyword (§0), so the budget is 1 s
(--budget-ms, recorded), not "the first attempt plus 1 s". Each attempt's
connect->released spans the whole host path INCLUDING the guest jail's own
release, so it bounds the overhead the clause limits from above; every
attempt must be within the budget. The path is THIS script's Python client
on the attempt socket, not `ukai-jail run --vm`, and the record says so.
With --ukai-jail, the real client is timed too: each `ukai-jail run --vm`
against this warm service, from exec to its workload's first write showing
on the host through the share (an upper bound on that client's release).
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

SENTINEL = '[core]\n'
PYTHON_CLIENT = 'python attempt-socket client (warm_live.py), not ukai-jail run --vm'


def attempt_script(index, tag):
    return (f"printf 'warm-{index}-{tag}\\n' > attempt-{index}.txt\n"
            f"if printf 'denied\\n' > .git/config 2>/dev/null; "
            f"then echo GIT_WRITE_ALLOWED-{index}; else echo git_write_refused-{index}; fi\n"
            f"{harness.probe_shell(f'{tag}-{index}')}\n"
            f"echo out-{index}\n")


def one_attempt(service, workspace, index, tag):
    record = harness.run_attempt(service.connect, f'warm-{index}-{tag}',
                                 harness.sh(attempt_script(index, tag)), wall=30)
    host = Path(workspace) / f'attempt-{index}.txt'
    record['index'] = index
    record['host_write'] = host.read_text() if host.is_file() else None
    record['git_config_after'] = (Path(workspace) / '.git' / 'config').read_text()
    record['probe'] = harness.probe_verdict(record['stdout'], f'{tag}-{index}')
    record['receipt_bound'] = harness.receipt_bound(record)
    receipt = record.pop('receipt', None) or {}
    record['receipt_network'] = ((receipt.get('applied') or {}).get('network') or {}).get('mode')
    return record


def attempt_facts(record, tag):
    index = record['index']
    return {
        'exit_zero': record.get('exit_code') == 0 and not record.get('error'),
        'receipt_verified': record.get('receipt_digest_ok') is True and record.get('receipt_bound') is True,
        'granted_write_on_host': record.get('host_write') == f'warm-{index}-{tag}\n',
        'protected_write_tried_and_refused': (f'git_write_refused-{index}' in record['stdout']
                                              and f'GIT_WRITE_ALLOWED-{index}' not in record['stdout']),
        'protected_git_unchanged': record.get('git_config_after') == SENTINEL,
        'probe_saw_the_jails_denial': record['probe']['denied'],
        'receipt_network_none': record.get('receipt_network') == 'none',
    }


def route_control(service, tag):
    """The same-boot route control: an agent attempt asks its proxy for the probe target."""
    record = harness.run_attempt(service.connect, f'warm-route-{tag}', harness.route_argv(f'{tag}-route'),
                                 profile='agent', wall=30, allow_hosts=[harness.route_rule()])
    record['route'] = harness.route_verdict(record['stdout'], f'{tag}-route')
    record['receipt_bound'] = harness.receipt_bound(record)
    record.pop('receipt', None)
    return record


def real_client_attempts(jail, environment, workspace, count, tag, poll=0.002, clock=time.monotonic):
    """Time `ukai-jail run --vm` from exec to its workload's first host-visible write."""
    runs = []
    for index in range(count):
        marker = Path(workspace) / f'released-{tag}-{index}'
        argv = [str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                *harness.vm_wall(20), '--workspace', str(workspace), '--',
                '/bin/sh', '-c', f'printf x > released-{tag}-{index}']
        started = clock()
        child = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        seen = None
        while child.poll() is None and seen is None:
            if marker.exists():
                seen = clock()
            else:
                time.sleep(poll)
        if seen is None and marker.exists():
            seen = clock()  # landed between the last poll and exit: an upper bound still
        try:
            stdout, stderr = child.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
        runs.append({'index': index, 'exit': child.returncode,
                     'exec_to_first_write_ms': None if seen is None else round((seen - started) * 1000, 1),
                     'refusals': harness.vm_refusals(stderr),
                     'stderr_tail': stderr[-600:], 'stdout_tail': stdout[-300:]})
    return runs


GATES = ('warm_reuse_one_serve_boot', 'warm_reuse_one_guest_boot', 'every_attempt_exit_zero',
         'every_receipt_verified', 'every_granted_write_reached_host',
         'every_protected_write_tried_and_refused', 'protected_git_never_reached',
         'every_attempt_saw_the_jails_denial', 'guest_nat_attached', 'route_control_reached_the_target',
         'route_control_on_the_same_guest_boot', 'route_control_receipt_bound',
         'every_attempt_network_denied', 'every_receipt_network_none',
         'k108_every_attempt_within_budget', 'k108_twenty_runs', 'service_stopped_cleanly')


def judge(results, tag, budget_ms, status, service_exit, git_config_text, route, real_client=None):
    per_attempt = [attempt_facts(record, tag) for record in results]
    serve_boots = {record.get('boot_id') for record in results}
    guest_boots = {harness.guest_boot(record) for record in results}
    latencies = [record['timings_ms'].get('connect_to_released') for record in results]
    route = route or {}
    # The jail's denial: every probe saw its errno, on a guest with NAT and a
    # route to the same target (the route control, same guest boot).
    denials = [harness.network_denial(record['probe'], route.get('route'), (status or {}).get('guest_nat'),
                                      harness.guest_boot(record), harness.guest_boot(route),
                                      route.get('receipt_bound'))
               for record in results]
    verdict = {
        'attempts_run': len(results),
        'warm_reuse_one_serve_boot': len(serve_boots) == 1 and None not in serve_boots,
        'warm_reuse_one_guest_boot': len(guest_boots) == 1 and None not in guest_boots,
        'every_attempt_exit_zero': all(f['exit_zero'] for f in per_attempt),
        'every_receipt_verified': all(f['receipt_verified'] for f in per_attempt),
        'every_granted_write_reached_host': all(f['granted_write_on_host'] for f in per_attempt),
        'every_protected_write_tried_and_refused': all(f['protected_write_tried_and_refused'] for f in per_attempt),
        'protected_git_never_reached': all(f['protected_git_unchanged'] for f in per_attempt)
        and git_config_text == SENTINEL,
        'every_attempt_saw_the_jails_denial': bool(denials) and all(
            d['probe_saw_the_jails_denial'] for d in denials),
        'guest_nat': (status or {}).get('guest_nat'),
        'guest_nat_attached': (status or {}).get('guest_nat') is True,
        'route_control': {key: route.get(key) for key in ('attempt_id', 'route', 'boot_id', 'error')},
        'route_control_reached_the_target': bool(denials) and all(
            d['route_control_reached_the_target'] for d in denials),
        'route_control_on_the_same_guest_boot': bool(denials) and all(
            d['route_control_on_the_same_guest_boot'] for d in denials),
        'route_control_receipt_bound': bool(denials) and all(d['route_control_receipt_bound'] for d in denials),
        'every_attempt_network_denied': bool(denials) and all(all(d.values()) for d in denials),
        'every_receipt_network_none': all(f['receipt_network_none'] for f in per_attempt),
        'k108_client': PYTHON_CLIENT,
        'k108_measure': 'connect->released per attempt, including the guest jail\'s own release',
        'k108_budget_ms': budget_ms,
        'k108_latencies_ms': latencies,
        'k108_max_ms': max((value for value in latencies if value is not None), default=None),
        'k108_every_attempt_within_budget': bool(latencies) and all(
            value is not None and value <= budget_ms for value in latencies),
        'k108_twenty_runs': len(results) >= 20,
        'service_stopped_cleanly': service_exit == 0,
    }
    if real_client is not None:
        times = [run['exec_to_first_write_ms'] for run in real_client]
        verdict['k108_real_client'] = {
            'client': 'ukai-jail run --vm',
            'runs': real_client,
            'every_run_exit_zero': all(run['exit'] == 0 for run in real_client),
            'every_run_within_budget': bool(times) and all(t is not None and t <= budget_ms for t in times),
            'refusals': sorted({code for run in real_client for code in run.get('refusals', [])}),
        }
    else:
        verdict['k108_real_client'] = 'not_run: pass --ukai-jail to time the real client'
    passed = all(verdict[key] is True for key in GATES)
    if isinstance(verdict['k108_real_client'], dict):
        passed = (passed and verdict['k108_real_client']['every_run_exit_zero']
                  and verdict['k108_real_client']['every_run_within_budget'])
    verdict['failed'] = [key for key in GATES if verdict[key] is not True]
    verdict['outcome'] = 'PASS' if passed else 'FAIL'
    if (not verdict['failed'] and isinstance(verdict['k108_real_client'], dict)
            and verdict['k108_real_client']['refusals']):
        verdict['outcome'] = 'REFUSED'  # the real client refused: recorded as what it is, never a pass
    return per_attempt, verdict


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--attempts', type=int, default=20)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--ukai-vm', help='the ukai-vm under test (default: $UKAI_VM_BINARY)')
    parser.add_argument('--ukai-jail', help='also time this real `ukai-jail run --vm` client')
    parser.add_argument('--real-attempts', type=int, default=20)
    parser.add_argument('--budget-ms', type=float, default=1000.0,
                        help="K108's `initial 1 s` (jail-macos §9.3); a tunable default, recorded")
    args = parser.parse_args(argv)
    binary = harness.required_binary('UKAI_VM_BINARY', args.ukai_vm)
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.ukai_jail) if args.ukai_jail else None
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    removed = harness.clean_workspace(workspace)
    git_config = harness.protected_sentinel(workspace, SENTINEL)
    tag = harness.nonce()
    root = Path(tempfile.mkdtemp(prefix='ukai-warm-live-'))
    data = root / 'data'
    data.mkdir()
    real = None
    # The NAT adapter is always attached: a denial is the jail's only where
    # the guest itself has a route (the jail stays the policy gate).
    with harness.Service(binary, args.image.resolve(strict=True), workspace, data,
                         extra=('--guest-nat',)) as service:
        status = service.warm_status
        results = [one_attempt(service, workspace, index, tag) for index in range(args.attempts)]
        route = route_control(service, tag)
        if jail is not None:
            config = Path(tempfile.mkdtemp(prefix='ukai-warm-live-cfg-'))
            os.chmod(config, 0o700)
            environment = harness.vm_client_environment(UKAI_VM_HOME=args.image.resolve(),
                                                        UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
            real = real_client_attempts(jail, environment, workspace, args.real_attempts, tag)
    per_attempt, verdict = judge(results, tag, args.budget_ms, status, service.child.returncode,
                                 git_config.read_text(), route, real)
    record = {'schema': 'ukai.vm.warm-live/2', 'binary': harness.fingerprint(binary),
              'real_client_binary': harness.fingerprint(jail) if jail else None,
              'status': status, 'workspace_cleaned': removed, 'attempts': results,
              'attempt_facts': per_attempt, 'service_exit': service.child.returncode,
              'service_stderr': service.stderr_text().strip()[-2000:], **verdict}
    harness.write_json(out / 'warm-live.json', record)
    print(json.dumps({k: v for k, v in verdict.items() if k not in ('k108_latencies_ms', 'k108_real_client')}))
    return 0 if verdict['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
