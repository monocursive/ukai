#!/usr/bin/env python3
"""Live measurement of the proxied network policy path (J18 §6).

Three `ukai-jail run --vm` attempts sharing ONE data directory and
workspace, so the second and third reuse the warm guest the first booted
(with its NAT adapter, as a proxied policy requires):

  1. agent, allow api.github.com and the D9 probe target: the guest jail
     starts its own qualified Linux proxy; the allowed host answers through
     it, example.com refuses, and the route control's CONNECT to the probe
     target succeeds (the guest itself has a route to it);
  2. agent, allow example.com instead: the proxy re-arms with the new allow
     set on the same boot (example.com now answers, api.github.com refuses);
  3. tool, offline, on the same guest with NAT still attached: the egress
     probe (harness.py, D9) fails with the jail's denial errno after its
     loopback positive control, against the target attempt 1 reached.

"Same boot" is measured, not assumed: every attempt's transport record names
one serve boot id and every guest binding one guest kernel boot id. Each
attempt directory's receipt is bound to its own argv (harness.attempt_dir_bound).

Usage: proxy_measurement.py <home> <workspace> <out> [--ukai-jail PATH]
       (or UKAI_JAIL_BINARY=...)
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


def fetch(name, url):
    return ("python3 -c \"import urllib.request\n"
            "try:\n"
            f" r = urllib.request.urlopen('{url}', timeout=20)\n"
            f" print('{name}_ANSWERED', r.status)\n"
            "except Exception as error:\n"
            f" print('{name}_REFUSED', type(error).__name__)\"")


GITHUB = 'https://api.github.com/zen'
EXAMPLE = 'https://example.com/'


def run_vm(jail, environment, workspace, profile, allow, argv, wall=40):
    command = [str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', profile,
               *harness.vm_wall(wall), '--workspace', str(workspace)]
    for host in allow:
        command += ['--allow-host', host]
    command += ['--', *argv]
    started = time.monotonic()
    try:
        done = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=600)
        result = {'exit': done.returncode, 'stdout': done.stdout, 'stderr': done.stderr[-600:]}
    except subprocess.TimeoutExpired as error:
        result = {'exit': None, 'stdout': str(error.stdout or ''), 'stderr': 'timeout'}
    result['elapsed_s'] = round(time.monotonic() - started, 1)
    return result


def attempt_records(data, argvs=()):
    """Every attempt in run order, with its receipt, transport and binding facts.

    `argvs` are the runs' argvs in run order: each record says whether its
    receipt is bound to that argv.
    """
    records = []
    for index, jail in enumerate(sorted((Path(data) / 'attempts').glob('att_*/jail.json'),
                                        key=lambda p: p.stat().st_mtime)):
        attempt = jail.parent

        def read(name):
            path = attempt / name
            return json.loads(path.read_text()) if path.is_file() else {}
        stored, transport, binding, guest = (read('jail.json'), read('vm-transport.json'),
                                             read('evidence/vm-binding.json'), read('evidence/jail.json'))
        records.append({'attempt_id': attempt.name, 'phase': stored.get('phase'),
                        'exit': (stored.get('outcome') or {}).get('code'),
                        'tree_empty': (stored.get('lifetime') or {}).get('tree_empty'),
                        'policy': (stored.get('policy') or {}).get('name'),
                        'guest_network': ((guest.get('applied') or {}).get('network') or {}),
                        'serve_boot': transport.get('boot_id'),
                        'guest_boot': binding.get('guest_boot_id'),
                        'bound': index < len(argvs) and harness.attempt_dir_bound(attempt, argvs[index])})
    return records


def settled(record):
    return bool(record) and record['phase'] == 'settled' and record['tree_empty'] is True


def judge(runs, records, probe_tag):
    """Every fact is computed whatever was recorded: an absent attempt fails its facts."""
    first, second, offline = runs
    three = len(records) == 3
    serve = {r['serve_boot'] for r in records}
    guest = {r['guest_boot'] for r in records}
    facts = {
        'three_attempts_recorded': three,
        'first_allowed_answers': 'GITHUB_ANSWERED 200' in first['stdout'],
        'first_denied_refused': 'EXAMPLE_REFUSED' in first['stdout'] and 'EXAMPLE_ANSWERED' not in first['stdout'],
        'route_control_reached_the_target': harness.route_verdict(first['stdout'], f'{probe_tag}-route')['reached'],
        'rearmed_allowed_answers': 'EXAMPLE_ANSWERED' in second['stdout'],
        'rearmed_old_host_refused': 'GITHUB_REFUSED' in second['stdout'] and 'GITHUB_ANSWERED' not in second['stdout'],
        'offline_probe_denied': harness.probe_verdict(offline['stdout'], probe_tag)['denied'],
        'agent_attempts_proxy': three and all(r['guest_network'].get('mode') == 'proxy' for r in records[:2]),
        'offline_attempt_none': three and records[2]['guest_network'].get('mode') == 'none',
        'every_attempt_settled': three and all(settled(r) for r in records),
        'every_receipt_bound': three and all(r.get('bound') is True for r in records),
        'same_serve_boot': three and len(serve) == 1 and None not in serve,
        'same_guest_boot': three and len(guest) == 1 and None not in guest,
    }
    return facts, 'PASS' if all(value is True for value in facts.values()) else 'FAIL'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('home', type=Path)
    parser.add_argument('workspace', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--ukai-jail', help='the ukai-jail under test (default: $UKAI_JAIL_BINARY)')
    args = parser.parse_args(argv)
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.ukai_jail)
    home = args.home.resolve(strict=True)
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    harness.clean_workspace(workspace)
    data = Path(tempfile.mkdtemp(prefix='proxy-vm-'))
    config = Path(tempfile.mkdtemp(prefix='proxy-cfg-'))
    os.chmod(config, 0o700)
    environment = harness.vm_client_environment(UKAI_VM_HOME=home, UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    tag = harness.nonce()
    reachability = harness.host_reachability()
    argvs = [['/bin/sh', '-c', fetch('GITHUB', GITHUB) + ' ; ' + fetch('EXAMPLE', EXAMPLE)
              + ' ; ' + harness.route_shell(f'{tag}-route')],
             ['/bin/sh', '-c', fetch('EXAMPLE', EXAMPLE) + ' ; ' + fetch('GITHUB', GITHUB)],
             harness.probe_argv(tag)]
    try:
        runs = [
            run_vm(jail, environment, workspace, 'agent', ['api.github.com', harness.route_rule()], argvs[0]),
            run_vm(jail, environment, workspace, 'agent', ['example.com'], argvs[1]),
            run_vm(jail, environment, workspace, 'tool', [], argvs[2], wall=20),
        ]
    finally:
        stop = subprocess.run([str(home / 'bin' / 'ukai-vm'), 'stop'], env=environment,
                              capture_output=True, text=True, timeout=60)
    records = attempt_records(data, argvs)
    facts, outcome = judge(runs, records, tag)
    facts['probe_target_answers_from_host'] = reachability['answers']
    if not reachability['answers']:
        outcome = 'FAIL'
    refusals = harness.vm_refusals('\n'.join(run['stderr'] for run in runs))
    if refusals:
        outcome = 'REFUSED'  # recorded as what it is, never a pass
    verdict = {'schema': 'ukai.vm.proxy-policy/2', 'binary': harness.fingerprint(jail),
               'runs': [{**run, 'stdout': run['stdout'][-600:]} for run in runs],
               'records': records, 'probe': harness.probe_verdict(runs[2]['stdout'], tag),
               'route_control': harness.route_verdict(runs[0]['stdout'], f'{tag}-route'),
               'reachability': reachability, 'stop_exit': stop.returncode, 'refusals': refusals,
               'facts': facts, 'outcome': outcome}
    harness.write_json(out / 'proxy-policy.json', verdict)
    print(json.dumps({'facts': facts, 'outcome': outcome}))
    return 0 if outcome == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
