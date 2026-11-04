#!/usr/bin/env python3
"""The guest's own record of the D6 attempt stop, on one warm boot.

The fault matrix and capabilities.py judge the stop from the host: the next
attempt runs on the same guest boot, which a failed stop would prevent (the
guest powers off with `attempt_tree_unverified`). They do not keep the
guest's console, where guest.py writes its stop audit (`UKAI_VM` events:
`infrastructure_learned`, `workload_tree_empty` with `strays_killed`), because
the serve removes a cleanly stopped boot's directory. This script runs a few
attempts through the serve, reads that boot's console while the boot is
still live, and only then stops the serve.

Attempts, in order, all `tool` on the live share:
  plain      prints a nonce and exits 0
  detached   leaves two descendants behind (one in a new session) and exits 0
  wall       sleeps past a 3 s wall
  after      prints a nonce and exits 0: the boot is still usable

Usage: UKAI_VM_BINARY=<ukai-vm> stop_audit.py <harness-dir> <home> <workspace> <out>
"""
import json
import sys
import tempfile
from pathlib import Path


def events(console):
    out = []
    for line in console.splitlines():
        line = line.strip('\r')
        if line.startswith('UKAI_VM '):
            try:
                out.append(json.loads(line[len('UKAI_VM '):]))
            except ValueError:
                out.append({'unparsed': line[:300]})
    return out


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    sys.path.insert(0, str(Path(argv[0]).resolve(strict=True)))
    import harness
    home = Path(argv[1]).resolve(strict=True)
    workspace = harness.guarded_workspace(argv[2])
    out = harness.fresh_out_dir(argv[3])
    binary = harness.required_binary('UKAI_VM_BINARY')
    harness.clean_workspace(workspace)
    tag = harness.nonce()
    plan = [
        ('plain', 30, ['/bin/sh', '-c', f'printf "plain-{tag}\\n"']),
        ('detached', 30, ['/bin/sh', '-c',
                          '(setsid sleep 120 >/dev/null 2>&1 &); (sleep 120 >/dev/null 2>&1 &); '
                          f'printf "detached-{tag}\\n"']),
        ('wall', 3, ['/bin/sh', '-c', f'printf "wall-{tag}\\n"; sleep 60; printf "late-{tag}\\n"']),
        ('after', 30, ['/bin/sh', '-c', f'printf "after-{tag}\\n"']),
    ]
    data = tempfile.mkdtemp(prefix='stop-audit-')
    attempts = []
    with harness.Service(binary, home, workspace, data) as service:
        status = service.warm_status
        for name, wall, command in plan:
            record = harness.run_attempt(service.connect, f'stop-{name}-{tag}', command, wall=wall)
            receipt = record.get('receipt') or {}
            attempts.append({'name': name, 'attempt_id': record['attempt_id'], 'wall_seconds': wall,
                             'started_at': record['started_at'], 'exit_code': record.get('exit_code'),
                             'error': record.get('error'), 'stdout': record['stdout'][-400:],
                             'serve_boot': record.get('boot_id'), 'guest_boot': harness.guest_boot(record),
                             'receipt_bound': harness.receipt_bound(record),
                             'outcome': receipt.get('outcome')})
        console_path = service.boot_dir() / 'console.log'
        console = console_path.read_text(errors='replace')
    service_exit = service.child.returncode
    record = {'schema': 'ukai.vm.stop-audit/1', 'binary': harness.fingerprint(binary),
              'harness_sha256': {name: harness.fingerprint(Path(argv[0]) / name)['sha256']
                                 for name in ('harness.py',)},
              'tag': tag, 'status': status, 'attempts': attempts,
              'console_events': events(console), 'service_exit': service_exit,
              'service_stderr': service.stderr_text()[-2000:]}
    (out / 'console.log').write_text(console)
    harness.write_json(out / 'stop-audit.json', record)
    stops = [event for event in record['console_events'] if event.get('event') == 'workload_tree_empty']
    print(json.dumps({'attempts': [(a['name'], a['exit_code'], a['receipt_bound']) for a in attempts],
                      'stops_recorded': len(stops), 'service_exit': service_exit}))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
