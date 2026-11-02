"""K90 direct-client reachability: no launchctl anywhere, against a live run.

For each custodian side, a real jailed run (the product's launcher applies
the profile and strips the bootstrap port) executes the direct launchd
client inside; the same client runs outside as the positive control. A pass
requires the inside client to hold no port and receive no launchd reply,
the outside control to reach launchd both ways, and both custodians to be
alive throughout.
"""
import json
import os
from pathlib import Path
import resource
import shlex
import time

from macos_j16_spike_guest import Trial, command, guard, save, snapshot


def check(root, who):
    t = Trial(root, 'direct-client-' + who)
    result = t.result
    try:
        script = ('echo \'{"ready":true}\'; i=0\n'
                  'while [ ! -f matrix-finish ]; do\n'
                  '  if [ -f "request.sh" ] && [ ! -f inside.done ]; then\n'
                  '    /bin/bash request.sh; : > inside.done\n'
                  '  else /bin/sleep 0.01; fi\ndone')
        t.launch([root / 'src/spike-fixture', 'command', t.ws / 'births.jsonl',
                  '/bin/bash', '-c', script], wall='40s')
        assert t.ready(), 'fixture must start'
        pid = t.proc.pid if who == 'supervisor' else t.guardian
        birth = t.custodian_births[pid]
        result['target'] = {'custodian': who, 'pid': pid, 'birth': birth}
        probe = str(root / 'src/launchd-client')
        payload = (
            f'{shlex.join([probe, "lookup"])} > lookup.out 2>&1; echo $? > lookup.rc\n'
            f'{shlex.join([probe, "pipe"])} > pipe.out 2>&1; echo $? > pipe.rc\n')
        (t.ws / 'request.tmp').write_text(payload)
        (t.ws / 'request.tmp').rename(t.ws / 'request.sh')
        until = time.monotonic() + 10
        while not (t.ws / 'pipe.rc').exists() and time.monotonic() < until:
            time.sleep(0.05)
        result['inside'] = {
            'lookup': {'rc': (t.ws / 'lookup.rc').read_text().strip() if (t.ws / 'lookup.rc').exists() else None,
                       'out': (t.ws / 'lookup.out').read_text(errors='replace') if (t.ws / 'lookup.out').exists() else ''},
            'pipe': {'rc': (t.ws / 'pipe.rc').read_text().strip() if (t.ws / 'pipe.rc').exists() else None,
                     'out': (t.ws / 'pipe.out').read_text(errors='replace') if (t.ws / 'pipe.out').exists() else ''}}
        result['outside'] = {mode: command([probe, mode], timeout=10)
                             for mode in ('lookup', 'pipe')}
        result['custodians_alive_after'] = {
            str(p): snapshot(t.fixture, b)['alive']
            for p, b in t.custodian_births.items()}
        inside = result['inside']
        denied_inside = (
            'port=0' in inside['lookup']['out'] and 'kr=0' not in inside['lookup']['out']
            and inside['lookup']['rc'] not in (None, '0')
            and 'port=0' in inside['pipe']['out'] and 'reply=1' not in inside['pipe']['out'])
        control = (
            result['outside']['lookup']['exit'] == 0 and 'kr=0' in result['outside']['lookup']['stdout']
            and 'reply=1' in result['outside']['pipe']['stdout'])
        alive = all(result['custodians_alive_after'].values())
        result['denied_inside'] = denied_inside
        result['outside_control_reached_launchd'] = control
        result['custodians_alive'] = alive
        result['outcome'] = ('PASS' if denied_inside and control and alive else
                             'BLOCKED' if denied_inside else 'FAIL')
        (t.ws / 'matrix-finish').touch()
        t.finish()
    finally:
        t.cleanup()
    return result


if __name__ == '__main__':
    import sys
    guard()
    resource.setrlimit(resource.RLIMIT_NPROC, (2000, resource.getrlimit(resource.RLIMIT_NPROC)[1]))
    root = Path(sys.argv[1]).resolve()
    results = []
    for who in ('supervisor', 'guardian'):
        results.append(check(root, who))
        save(root / 'results/k90-direct-client.json', results)
        print(json.dumps({'name': results[-1]['name'], 'outcome': results[-1]['outcome']}), flush=True)
