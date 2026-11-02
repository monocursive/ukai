#!/usr/bin/env python3
"""The secret-transport lifecycle + K110 fault matrix against a live serve.

Secrets: two values (one nested id) cross per attempt; the guest must ack
each with a path inside its tmpfs credentials root, the attempt completes,
and a second attempt runs on the same boot afterwards.

Faults (K110, warm design), each in its own service boot:
  A. killing the host `ukai-vm serve` ends that attempt and the guest with
     it (the custodian's lease backstop), while the workspace survives;
  B. a terminal-style Ctrl-Z (SIGSTOP to the whole foreground process
     group) does NOT end the attempt: resume finishes it and the guest
     serves another attempt afterwards;
  C. an attempt socket EOF mid-run cancels only that attempt: the session
     stays up and a second attempt runs on the same boot.
"""
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BINARY = Path(__file__).resolve().parents[3] / 'target/release/ukai-vm'


class Service:
    def __init__(self, home, workspace, data, extra=()):
        self.data = Path(data)
        env = dict(os.environ, UKAI_VM_HOME=str(home), UKAI_DATA_DIR=str(self.data))
        self.stderr_path = self.data / 'serve.stderr.log'
        self.stderr_file = open(self.stderr_path, 'w')
        self.child = subprocess.Popen(
            [str(BINARY), 'serve', '--live-workspace', str(workspace),
             '--idle-seconds', '0', *extra],
            env=env, stdout=subprocess.DEVNULL, stderr=self.stderr_file, text=True)

    def link_console(self):
        import glob
        for log in glob.glob(str(self.data / 'vm/vm-*/console.log')):
            try:
                os.link(log, '/tmp/fault-console-live')
                return True
            except OSError:
                pass
        return False

    def warm(self):
        self.link_console()
        try:
            s = self.sock('control', timeout=5)
            s.sendall(b'{"op":"status"}\n')
            raw = b''
            while b'\n' not in raw:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk
            s.close()
            return json.loads(raw).get('warm', False)
        except OSError:
            return False

    def __enter__(self):
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if self.warm():
                return self
            if self.child.poll() is not None:
                self.stderr_file.close()
                raise RuntimeError(f'service died: {self.stderr_path.read_text()[:400]}')
            time.sleep(0.2)
        raise RuntimeError('service never became warm')

    def stderr_text(self):
        self.stderr_file.flush()
        return self.stderr_path.read_text()

    def __exit__(self, *exc):
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()

    def sock(self, name='attempt', timeout=120):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(timeout)
        s.connect(str(self.data / 'vm' / (name + '.sock')))
        return s


def frame(s, buf=[b'']):
    while b'\n' not in buf[0]:
        d = s.recv(16384)
        if not d:
            raise RuntimeError('EOF')
        buf[0] += d
    line, buf[0] = buf[0].split(b'\n', 1)
    return json.loads(line)


def send(s, **v):
    s.sendall((json.dumps(v) + '\n').encode())


def attempt_argv(marker, probe_network=False):
    script = f'echo {marker} > {marker}.txt; echo out-{marker}'
    if probe_network:
        script = ('(echo > /dev/tcp/93.184.216.34/443) 2>/dev/null && echo NET_ALLOWED '
                  '|| echo net_denied; ') + script
    return [base64.b64encode(b'/bin/sh').decode(),
            base64.b64encode(b'-c').decode(),
            base64.b64encode(script.encode()).decode()]


def start_attempt(service, marker, secrets=(), probe_network=False, timeout=120,
                  capture=None):
    s = service.sock(timeout=timeout)
    ready = frame(s)
    assert ready['event'] == 'ready', ready
    send(s, op='prepare', attempt_id=f'fault-{marker}', profile='tool',
         wall_seconds=20, argv=attempt_argv(marker, probe_network),
         secrets=[{'id': i, 'data': base64.b64encode(v).decode()}
                  for i, v in secrets])
    prepared = frame(s)
    assert prepared['event'] == 'prepared', prepared
    staged_here = prepared.get('staged_secrets', [])
    send(s, op='run')
    released = frame(s)
    assert released['event'] == 'released', released
    if capture is not None:
        capture.extend(staged_here)
    return s


def drain_until_done(s):
    stdout = []
    while True:
        message = frame(s)
        if message['event'] == 'stdout':
            stdout.append(base64.b64decode(message['data']).decode())
        elif message['event'] == 'done':
            return stdout
        elif message['event'] == 'error':
            raise RuntimeError(f"guest error: {message.get('message')}")


def section_secrets(home, workspace):
    with Service(home, workspace, tempfile.mkdtemp(prefix='fault-secrets-'),
                 extra=('--guest-nat',)) as service:
        staged = []
        s = start_attempt(service, 'secret', secrets=[
            ('api/token', b'secret-value-one'),
            ('nested/id/two', b'secret-value-two'),
        ], probe_network=True, capture=staged)
        while True:
            message = frame(s)
            if message['event'] == 'done':
                break
        s.close()
        second_error = None
        try:
            second = start_attempt(service, 'after-secrets')
            drain_until_done(second)
            second.close()
        except (RuntimeError, OSError, socket.timeout) as error:
            second_error = str(error)
        return {
            'acked': [tuple(entry) for entry in staged],
            'paths_in_tmpfs_root': all(
                entry[1].startswith('/run/ukai-vm/credentials/') for entry in staged),
            'nested_id_staged': any(entry[0] == 'nested/id/two' for entry in staged),
            'second_attempt_same_boot': second_error is None,
            'second_attempt_error': second_error,
            'outcome': 'PASS' if len(staged) == 2 and all(
                entry[1].startswith('/run/ukai-vm/credentials/') for entry in staged
            ) and any(entry[0] == 'nested/id/two' for entry in staged)
            and second_error is None else 'FAIL',
        }


def section_fault_a(home, workspace):
    data = tempfile.mkdtemp(prefix='fault-a-')
    service = Service(home, workspace, data)
    service.__enter__()
    s = start_attempt(service, 'killa')
    time.sleep(0.5)  # the workload is running
    service.child.kill()
    service.child.wait()
    s.close()
    time.sleep(4)
    vz_left = subprocess.run(['pgrep', '-f', 'console.log run'],
                             capture_output=True).stdout.strip()
    # A SIGKILLed service cannot unlink its sockets; the next boot removes
    # them (serve's stale-socket sweep). The fault-relevant fact is that
    # nothing answers on them any more.
    def answered(path):
        try:
            probe = socket.socket(socket.AF_UNIX)
            probe.settimeout(2)
            probe.connect(str(Path(data) / 'vm' / path))
            probe.close()
            return True
        except OSError:
            return False

    result = {
        'attempt_socket_unanswered': not answered('attempt.sock'),
        'no_vz_left': not vz_left,
        'workspace_survived': (workspace / 'killa.txt').exists(),
    }
    result['outcome'] = 'PASS' if all(result.values()) else 'FAIL'
    return result


def section_fault_b(home, workspace):
    with Service(home, workspace, tempfile.mkdtemp(prefix='fault-b-')) as service:
        s = start_attempt(service, 'stopb')
        # A terminal Ctrl-Z stops the foreground process GROUP: the service
        # and its custodian together — and this harness, which is in the
        # same group, so the stopper must live OUTSIDE it (a session of its
        # own) or the SIGCONT could never be sent.
        group = os.getpgid(service.child.pid)
        stopper = subprocess.Popen(
            [sys.executable, '-c',
             'import os, signal, sys, time\n'
             'group = int(sys.argv[1])\n'
             'os.killpg(group, signal.SIGSTOP)\n'
             'time.sleep(2)\n'
             'os.killpg(group, signal.SIGCONT)', str(group)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        stopper.wait(timeout=30)
        try:
            drain_until_done(s)
            completed = True
        except (RuntimeError, OSError, socket.timeout) as error:
            completed = False
            section_fault_b.last_attempt_error = f'{type(error).__name__}: {error}'
        s.close()
        guest_survived = False
        try:
            second = service.sock(timeout=30)
            guest_survived = frame(second)['event'] == 'ready'
            second.close()
        except (RuntimeError, OSError, socket.timeout):
            guest_survived = False
        return {
            'attempt_completed_after_resume': completed,
            'guest_survived_suspend': guest_survived,
            'attempt_error': getattr(section_fault_b, 'last_attempt_error', None),
            'service_exit': service.child.poll(),
            'service_stderr': (service.child.stderr.read()[:300]
                               if service.child.poll() is not None else None),
            'outcome': 'PASS' if completed and guest_survived else 'FAIL',
        }


def section_fault_c(home, workspace):
    with Service(home, workspace, tempfile.mkdtemp(prefix='fault-c-')) as service:
        s = start_attempt(service, 'eofc')
        time.sleep(0.5)
        s.close()  # the lease: end-of-file cancels this attempt only
        time.sleep(3)
        second_error = None
        stage = 'connect'
        try:
            second = service.sock(timeout=60)
            stage = 'ready'
            assert frame(second)['event'] == 'ready'
            stage = 'prepare'
            send(second, op='prepare', attempt_id='fault-after-eof', profile='tool',
                 wall_seconds=15, argv=attempt_argv('after-eof'), secrets=[])
            stage = 'prepared'
            assert frame(second)['event'] == 'prepared'
            stage = 'run'
            send(second, op='run')
            stage = 'drain'
            drain_until_done(second)
            second.close()
        except (RuntimeError, OSError, socket.timeout, AssertionError) as error:
            second_error = f'at {stage}: {type(error).__name__}: {error}'
        return {
            'guest_stayed_warm_and_next_attempt_ran': second_error is None,
            'second_attempt_error': second_error,
            'service_exit': service.child.poll(),
            'service_stderr': service.stderr_text()[-600:],
            'outcome': 'PASS' if second_error is None else 'FAIL',
        }


SECTIONS = {'secrets': section_secrets, 'a': section_fault_a,
            'b': section_fault_b, 'c': section_fault_c}


class SectionTimeout(Exception):
    pass


def _timeout(*_):
    raise SectionTimeout()


def main():
    home, workspace = sys.argv[1], Path(sys.argv[2])
    out = Path(sys.argv[3])
    requested = sys.argv[4].split(',') if len(sys.argv) > 4 else ['secrets', 'a', 'b', 'c']
    out.mkdir(parents=True, exist_ok=True)
    verdict = {}
    signal.signal(signal.SIGALRM, _timeout)
    for name in requested:
        print(f'phase: {name}', flush=True)
        signal.alarm(320)
        try:
            verdict[name] = SECTIONS[name](home, workspace)
        except SectionTimeout:
            verdict[name] = {'outcome': 'TIMEOUT'}
            print(f'phase: {name} timed out', flush=True)
        except Exception as error:  # a section failure is a result, not the end
            verdict[name] = {'outcome': 'ERROR', 'error': f'{type(error).__name__}: {error}'}
        finally:
            signal.alarm(0)
    verdict['outcome'] = 'PASS' if all(
        section.get('outcome') == 'PASS' for section in verdict.values()
        if isinstance(section, dict)) else 'FAIL'
    (out / 'fault-matrix.json').write_text(json.dumps(verdict, indent=2) + '\n')
    print(json.dumps({k: (v.get('outcome') if isinstance(v, dict) else v)
                      for k, v in verdict.items()}))
    return 0 if verdict['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
