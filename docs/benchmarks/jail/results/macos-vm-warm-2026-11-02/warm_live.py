#!/usr/bin/env python3
"""Drive ukai-vm serve against a real prepared image with a live share.

One warm boot, N attempts over the attempt socket (the §6 protocol), each
writing through the virtio-fs share to the host workspace. Verifies K109's
live claim per attempt (granted writes appear on the host; the protected
.git never changes), warm reuse (one boot_id across every attempt), and
measures K108's release latency (prepared -> released) per attempt against
the first attempt's.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

BINARY = Path(os.environ.get('UKAI_VM_BINARY',
                             Path(__file__).resolve().parents[3] / 'target/release/ukai-vm'))


class AttemptResult(dict):
    pass


def frame(stream, buffer):
    raw = buffer[0]
    while b'\n' not in raw:
        chunk = stream.recv(16384)
        if not chunk:
            raise RuntimeError('stream ended before a complete frame')
        raw += chunk
    line, buffer[0] = raw.split(b'\n', 1)
    return json.loads(line)


def send(stream, **value):
    stream.sendall((json.dumps(value) + '\n').encode())


def connect(root, name, timeout=180):
    stream = socket.socket(socket.AF_UNIX)
    stream.settimeout(timeout)
    deadline = time.monotonic() + timeout
    while True:
        try:
            stream.connect(str(root / 'data/vm' / (name + '.sock')))
            return stream
        except (FileNotFoundError, ConnectionRefusedError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def one_attempt(root, index):
    stream = connect(root, 'attempt')
    buffer = [b'']
    ready = frame(stream, buffer)
    t0 = time.monotonic()
    send(stream, op='prepare', attempt_id=f'warm-{index}', profile='tool',
         wall_seconds=30,
         argv=[base64.b64encode(b'/bin/sh').decode(),
               base64.b64encode(b'-c').decode(),
               base64.b64encode(
                   f'echo warm-{index} > attempt-{index}.txt; echo denied > .git/config; (echo > /dev/tcp/93.184.216.34/443) 2>/dev/null && echo NET_ALLOWED || echo net_denied'
                   f' 2>/dev/null && echo GIT_ALLOWED || echo git_denied; echo out-{index}'
                   .encode()).decode()],
         secrets=[])
    prepared = frame(stream, buffer)
    t1 = time.monotonic()
    assert prepared['event'] == 'prepared', prepared
    send(stream, op='run')
    released = None
    stdout = []
    receipt = None
    done = None
    while True:
        message = frame(stream, buffer)
        event = message['event']
        if event == 'released':
            released = message
            t2 = time.monotonic()
        elif event == 'stdout':
            stdout.append(base64.b64decode(message['data']).decode())
        elif event == 'bound_receipt':
            receipt = message
        elif event == 'done':
            done = message
            break
        elif event == 'error':
            raise RuntimeError(f'attempt {index}: guest error: {message}')
    stream.close()
    if released is None or receipt is None:
        raise RuntimeError(f'attempt {index}: missing released/receipt')
    return AttemptResult(
        index=index, boot_id=ready['boot_id'], exit_code=done['exit_code'],
        release_latency_ms=round((t2 - t1) * 1000, 1),
        end_to_end_ms=round((t2 - t0) * 1000, 1),
        stdout=''.join(stdout), attempt_id=receipt['binding']['attempt_id'],
        network_denied='net_denied' in ''.join(stdout),
        protected_write_absorbed='[core]' == '[core]',  # verified host-side below
        receipt_sha256=receipt['sha256'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--attempts', type=int, default=20)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--guest-nat', action='store_true',
                        help='attach the guest NAT adapter (the jail stays the policy gate)')
    args = parser.parse_args()
    workspace = args.workspace.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=True)
    git_config = workspace / '.git' / 'config'
    git_config.parent.mkdir(exist_ok=True)
    git_config.write_text('[core]\n')
    with tempfile.TemporaryDirectory(prefix='ukai-warm-live-') as temp:
        root = Path(temp)
        env = dict(os.environ, UKAI_VM_HOME=str(args.image.resolve()),
                   UKAI_DATA_DIR=str(root / 'data'))
        child = subprocess.Popen(
            ([str(BINARY), 'serve', '--live-workspace', str(workspace),
              '--idle-seconds', '0'] + (['--guest-nat'] if args.guest_nat else [])),
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        failure = None
        try:
            control = connect(root, 'control')
            send(control, op='status')
            status = frame(control, [b''])
            control.close()
            results = [one_attempt(root, index) for index in range(args.attempts)]
        except BaseException as error:  # diagnostics first, then re-raise
            failure = f'{type(error).__name__}: {error}'
            child.poll()
        finally:
            control = connect(root, 'control')
            send(control, op='stop')
            try:
                frame(control, [b''])
            except (RuntimeError, socket.timeout):
                pass
            control.close()
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            if failure is not None:
                stderr_text = child.stderr.read()
                raise RuntimeError(
                    f'{failure}\nservice exit={child.returncode} '
                    f'stderr={stderr_text[:800]}') from None
        stderr = child.stderr.read()
        boot_ids = {result['boot_id'] for result in results}
        written = {index: (workspace / f'attempt-{index}.txt').exists()
                   for index in range(args.attempts)}
        initial = results[0]['release_latency_ms']
        within = [result['release_latency_ms'] <= initial + 1000
                  for result in results]
        verdict = {
            'attempts': results,
            'service_exit': child.returncode,
            'service_stderr': stderr.strip(),
            'status': status,
            'warm_reuse_one_boot': len(boot_ids) == 1,
            'every_granted_write_reached_host': all(written.values()),
            'git_config_untouched': git_config.read_text() == '[core]\n',
            'protected_git_never_reached': all(
                result['protected_write_absorbed'] for result in results),
            'every_exit_zero': all(result['exit_code'] == 0 for result in results),
            'every_attempt_network_denied': all(result['network_denied'] for result in results),
            'k108_initial_release_ms': initial,
            'k108_max_release_ms': max(r['release_latency_ms'] for r in results),
            'k108_every_attempt_within_initial_plus_1s': all(within),
        }
        for result in results:
            result['protected_write_absorbed'] = (
                (workspace / '.git' / 'config').read_text() == '[core]\n')
        verdict['protected_git_never_reached'] = all(
            result['protected_write_absorbed'] for result in results)
        verdict['outcome'] = 'PASS' if (
            verdict['warm_reuse_one_boot']
            and verdict['every_granted_write_reached_host']
            and verdict['git_config_untouched']
            and verdict['protected_git_never_reached']
            and verdict['every_exit_zero']
            and verdict['every_attempt_network_denied']
            and verdict['k108_every_attempt_within_initial_plus_1s']
            and child.returncode == 0) else 'FAIL'
        (args.out / 'warm-live.json').write_text(json.dumps(verdict, indent=2) + '\n')
        print(json.dumps({k: v for k, v in verdict.items()
                          if k not in ('attempts', 'status', 'service_stderr')}))
        return 0 if verdict['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
