#!/usr/bin/env python3
"""Live measurement of the proxied network policy path (J18 §6).

One cold boot with `ukai-jail run --vm --profile agent --allow-host ...`:
the guest jail starts its own qualified Linux proxy; the workload's
environment carries the bridge; an allowed host answers through it, a
denied host refuses, and a second attempt with a different allow set
re-arms the proxy on the same warm boot. Also verifies the offline tool
profile still has no egress on the same guest (NAT attached throughout).
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

BIN = Path('/Users/monocursive/code/ouroboros/target/release/ukai-jail')
HOME = sys.argv[1]          # UKAI_VM_HOME (the prepared install)
WS = Path(sys.argv[2])      # case-sensitive workspace volume
OUT = Path(sys.argv[3])

ALLOWED = ("python3 -c \"import urllib.request; "
           "r=urllib.request.urlopen('https://api.github.com/zen', timeout=20); "
           "print('ALLOWED', r.status)\"")
DENIED = ("python3 -c \"import urllib.request\n"
          "import socket\n"
          "try:\n"
          " urllib.request.urlopen('https://example.com/', timeout=15)\n"
          " print('DENIED_BUT_ANSWERED')\n"
          "except Exception as error:\n"
          " print('DENIED', type(error).__name__)\"")


def run_vm(profile, allow, script, wall=40):
    data = tempfile.mkdtemp(prefix='proxy-vm-')
    env = dict(os.environ, UKAI_VM_HOME=str(HOME), UKAI_DATA_DIR=data)
    argv = [str(BIN), 'run', '--vm', '--terminal', 'detach',
            '--profile', profile, '--limit', f'wall={wall}s',
            '--workspace', str(WS)]
    for host in allow:
        argv += ['--allow-host', host]
    argv += ['--', '/bin/sh', '-c', script]
    started = time.monotonic()
    done = subprocess.run(argv, env=env, capture_output=True, text=True,
                          timeout=600)
    return {'exit': done.returncode, 'stdout': done.stdout,
            'stderr': done.stderr[-400:], 'elapsed': round(time.monotonic() - started, 1),
            'data': data}


def attempt_records(data):
    root = Path(data) / 'attempts'
    for jail in sorted(root.glob('att_*/jail.json'),
                       key=lambda p: p.stat().st_mtime, reverse=True):
        d = json.loads(jail.read_text())
        transport = jail.parent / 'vm-transport.json'
        return {'phase': d.get('phase'),
                'exit': d.get('outcome', {}).get('code'),
                'tree_empty': d.get('lifetime', {}).get('tree_empty'),
                'network': d.get('applied', {}).get('network'),
                'transport': (json.loads(transport.read_text())
                              if transport.exists() else None)}
    return None


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in WS.iterdir():
        shutil.rmtree(stale) if stale.is_dir() else stale.unlink()

    verdict = {}

    # 1. Allowed host through the proxy; denied host refused.
    script = ALLOWED + ' ; ' + DENIED
    agent = run_vm('agent', ['api.github.com'], script)
    verdict['agent_run'] = {'exit': agent['exit'], 'elapsed': agent['elapsed'],
                            'stdout': agent['stdout'][-300:],
                            'stderr': agent['stderr'],
                            'records': attempt_records(agent['data'])}
    stdout = agent['stdout']
    verdict['agent_run']['allowed_through_proxy'] = 'ALLOWED 200' in stdout
    verdict['agent_run']['denied_refused'] = 'DENIED' in stdout and 'DENIED_BUT_ANSWERED' not in stdout

    # 2. Offline tool on the same (warm) guest: no egress at all.
    offline = run_vm('tool', [],
                     '(echo > /dev/tcp/93.184.216.34/443) 2>/dev/null '
                     '&& echo NET_ALLOWED || echo net_refused', wall=20)
    verdict['tool_offline'] = {
        'exit': offline['exit'],
        'net_refused': 'net_refused' in offline['stdout'],
        'records': attempt_records(offline['data']),
    }

    verdict['outcome'] = 'PASS' if (
        verdict['agent_run']['allowed_through_proxy']
        and verdict['agent_run']['denied_refused']
        and verdict['tool_offline']['net_refused']
        and verdict['agent_run']['records']
        and verdict['agent_run']['records']['phase'] == 'settled'
        and verdict['agent_run']['records']['tree_empty'] is True) else 'FAIL'
    (OUT / 'proxy-policy.json').write_text(json.dumps(verdict, indent=2) + '\n')
    print(json.dumps({k: (v if not isinstance(v, dict) else
                          {k2: v2 for k2, v2 in v.items()
                           if k2 in ('exit', 'elapsed', 'allowed_through_proxy',
                                     'denied_refused', 'net_refused', 'phase')})
                      for k, v in verdict.items()}))
    return 0 if verdict['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
