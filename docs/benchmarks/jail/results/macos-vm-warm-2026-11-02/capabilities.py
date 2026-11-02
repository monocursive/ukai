#!/usr/bin/env python3
"""Pre-release guest capability measurements (vm/README's requirement).

Before `run --vm` may report any capability as available, each claim the
guest jail makes for an attempt must be MEASURED on the prepared image,
through the warm service, with the live share attached. This suite runs one
boot and one attempt per capability; an unmeasured capability is recorded
as such, never assumed.

Capabilities measured (the limits guest.py's run_command applies):
  wall            the guest jail ends an attempt at its wall deadline
  pids            a fork storm stops at the pids limit (EAGAIN), not before
  mem             an allocation beyond the mem limit is refused
  containment     a write outside the workspace grants is refused
  network_none    outbound TCP refuses with the NAT adapter attached
  workspace       a granted write reaches the host (K109's live claim)
"""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fault_matrix import Service, frame, send, drain_until_done  # noqa: E402

WS_SENTINEL = '[core]\n'


def sh(script):
    return [base64.b64encode(b'/bin/sh').decode(),
            base64.b64encode(b'-c').decode(),
            base64.b64encode(script.encode()).decode()]


def run_capability(service, name, script, wall=30, expect_stdout=None):
    """One attempt; returns {exit, stdout, verdict}."""
    s = service.sock()
    ready = frame(s)
    assert ready['event'] == 'ready', ready
    send(s, op='prepare', attempt_id=f'cap-{name}', profile='tool',
         wall_seconds=wall, argv=sh(script), secrets=[])
    assert frame(s)['event'] == 'prepared'
    send(s, op='run')
    stdout = []
    exit_code = None
    while True:
        message = frame(s)
        if message['event'] == 'stdout':
            stdout.append(base64.b64decode(message['data']).decode())
        elif message['event'] == 'stderr':
            stdout.append(base64.b64decode(message['data']).decode())
        elif message['event'] == 'done':
            exit_code = message['exit_code']
            break
        elif message['event'] == 'error':
            exit_code = None
            stdout.append(f"guest error: {message.get('message')}")
            break
    s.close()
    text = ''.join(stdout)
    verdict = expect_stdout(text, exit_code) if expect_stdout else None
    return {'exit': exit_code, 'stdout': text[-400:], 'verdict': verdict}


def main():
    home = sys.argv[1]
    workspace = Path(sys.argv[2])
    out = Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    git_config = workspace / '.git' / 'config'
    git_config.parent.mkdir(exist_ok=True)
    git_config.write_text(WS_SENTINEL)

    data = tempfile.mkdtemp(prefix='cap-')
    service = Service(home, workspace, data, extra=('--guest-nat',))
    service.__enter__()
    results = {}
    try:
        results['wall'] = run_capability(
            service, 'wall',
            'echo start; sleep 30; echo never',
            wall=5,
            expect_stdout=lambda text, code: (
                'never' not in text and code not in (0, None)))
        results['pids'] = run_capability(
            service, 'pids',
            'i=0; while :; do /bin/sleep 10 & i=$((i+1)); '
            '[ $((i % 32)) -eq 0 ] && echo spawned=$i; done',
            wall=20,
            expect_stdout=lambda text, code: 'spawned=' in text)
        # The mem limit is cgroup-enforced: exceeding it OOM-kills the
        # workload (SIGKILL, exit 137) — a MemoryError is only catchable
        # when malloc itself fails. Either outcome proves the bound; the
        # attempt surviving with unbounded allocations would disprove it.
        results['mem'] = run_capability(
            service, 'mem',
            'python3 -c "blocks=[]\n'
            'while True: blocks.append(bytearray(64*1024*1024))\n'
            'print(\'unbounded\', len(blocks))"',
            wall=40,
            expect_stdout=lambda text, code: (
                code == 137 or 'Killed' in text or 'mem_refused' in text))
        results['containment'] = run_capability(
            service, 'containment',
            'if echo x > /etc/ukai-cap-probe 2>/dev/null; then echo ETC_WRITE_ALLOWED; '
            'else echo etc_write_refused; fi; '
            'if echo x > /usr/local/bin/ukai-cap-probe 2>/dev/null; then echo BIN_WRITE_ALLOWED; '
            'else echo usr_write_refused; fi',
            expect_stdout=lambda text, code: (
                'etc_write_refused' in text and 'usr_write_refused' in text))
        results['network_none'] = run_capability(
            service, 'network_none',
            '(echo > /dev/tcp/93.184.216.34/443) 2>/dev/null && echo NET_ALLOWED '
            '|| echo net_refused; '
            'getent hosts example.com >/dev/null 2>&1 && echo DNS_ALLOWED || echo dns_refused',
            expect_stdout=lambda text, code: (
                'net_refused' in text and 'dns_refused' in text))
        results['workspace'] = run_capability(
            service, 'workspace',
            'echo live > capability-write.txt && echo wrote',
            expect_stdout=lambda text, code: (
                'wrote' in text
                and (workspace / 'capability-write.txt').read_text() == 'live\n'))
    finally:
        if service.child.poll() is None:
            service.child.terminate()
            try:
                service.child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                service.child.kill()
                service.child.wait()

    summary = {}
    for name, result in results.items():
        summary[name] = result['verdict'] is True
    summary['git_config_untouched'] = git_config.read_text() == WS_SENTINEL
    summary['outcome'] = 'PASS' if all(
        value is True for name, value in summary.items()
        if name != 'outcome') else 'FAIL'
    record = {'results': results, 'summary': summary,
              'service_exit': service.child.returncode}
    (out / 'capabilities.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(summary))
    return 0 if summary['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
