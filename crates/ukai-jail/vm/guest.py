#!/usr/bin/env python3
"""Single-attempt guest controller. Installed root-owned outside the jail."""
import base64
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import selectors
import shutil
import socket
import stat
import subprocess
import time

PORT = 1024
LEASE = 2.0
# The transport limits live here because this file is installed alone in the
# guest; run.py imports them, so both ends enforce the same values.
MAX_LINE = 2 * 1024 * 1024
MAX_BYTES = 32 * 1024 * 1024
MAX_FILE = 512 * 1024
MAX_FILES = 5000
WORKSPACE = Path('/home/ukai/workspace')
EVIDENCE = Path('/home/ukai/evidence')
# J18 (jail-macos.md §6): where an attempt's ephemeral credentials stage.
# tmpfs, so a secret is never written to the guest disk; the path is the
# jail's vault source location for the attempt. UKAI_VM_SECRETS relocates it
# for tests, which run where /run is not writable; the value is read per
# call, so a test cannot pin the module's import order.
SECRETS = '/run/ukai-vm/credentials'


def secrets_root():
    return Path(os.environ.get('UKAI_VM_SECRETS', SECRETS))


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def audit(event, **fields):
    with open('/dev/hvc0', 'w') as output:
        output.write('UKAI_VM ' + json.dumps({'event': event, **fields}) + '\n')


def notify():
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect('\0' + address[1:] if address.startswith('@') else address)
            sock.sendall(b'READY=1\nWATCHDOG=1')


def kill_workload():
    """cgroup.kill of the workload boundary, verified empty: the facts the
    audit records stand on their own, so a warm session's cancel can share
    them with the poweroff path."""
    boundary = Path('/sys/fs/cgroup/user.slice')
    with (boundary / 'cgroup.events').open() as events:
        inode = os.fstat(events.fileno()).st_ino
        (boundary / 'cgroup.kill').write_text('1')
        deadline = clock() + 1
        while True:
            events.seek(0)
            state = dict(line.split() for line in events.read().splitlines())
            if state.get('populated') == '0':
                audit('workload_tree_empty', boundary='user.slice', events_inode=inode)
                return
            if clock() >= deadline:
                raise TimeoutError('cgroup did not empty')
            time.sleep(.01)


def stop_attempt_tree():
    """Ends one attempt's tree without ending the session. A boundary that
    cannot be verified empty is recorded and the session carries on: the
    attempt's outcome is already unknown to the host."""
    try:
        kill_workload()
    except (OSError, ValueError, TimeoutError) as error:
        audit('workload_cleanup_unverified', error=type(error).__name__)


def poweroff(reason):
    # VZ may retain its service while the Mac client is SIGSTOP'ed, even after
    # guest poweroff. First kill and verify the Linux workload boundary so
    # payload cleanup does not depend on the host processing a VM callback.
    try:
        kill_workload()
    except (OSError, ValueError, TimeoutError) as error:
        audit('workload_cleanup_unverified', error=type(error).__name__)
    audit('poweroff', reason=reason)
    subprocess.run(['/usr/bin/systemctl', 'poweroff', '--force', '--force'], check=False)
    # A failed shutdown is not a successful cleanup. The host still owns the VM.
    raise RuntimeError('poweroff returned: ' + reason)


def relative(name):
    # Same verdict as run.output_path: PurePosixPath would silently collapse
    # empty components ('a//b', 'a/'), so the raw components are checked.
    parts = PurePosixPath(name).parts
    if not parts or name.startswith('/') or '\0' in name or any(p in ('', '..', '.') for p in name.split('/')):
        raise ValueError('invalid relative path')
    return parts


# ---------------------------------------------------------------------------
# Warm sessions (J18, jail-macos.md §6)
#
# The preview's `run` op stays byte-for-byte what it was: one run per boot,
# poweroff at completion. A warm guest instead runs a session: the host
# resets the attempt directories, stages at most one workspace and a secret
# set, runs the same jail command, and reads the attempt back — without a
# poweroff. The lease on an attempt is the host's connection, not a timer:
# the controller keeps the session until the vsock end closes or the VM
# service ends.
# ---------------------------------------------------------------------------

def reset_attempt(account, workspace=WORKSPACE, evidence=EVIDENCE):
    """Empties both attempt directories for the next attempt, as the host's
    reset op asks. The directories, their modes and their owner come back
    exactly as boot made them."""
    for path in (workspace, evidence):
        shutil.rmtree(path, ignore_errors=True)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(path, account.pw_uid, account.pw_gid)


def stage_secret(secret_id, payload, secrets=None):
    """Writes one ephemeral credential to its tmpfs path, 0600. The value
    crossed the vsock once for this attempt and lives here only until the
    attempt ends."""
    secrets = secrets_root() if secrets is None else Path(secrets)
    parts = relative(secret_id)
    path = secrets.joinpath(*parts)
    secrets.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(payload)
    os.chmod(path, 0o600)
    return path


def clear_secrets(secrets=None):
    """Removes every staged secret; every run2 attempt and every cancel ends
    with this, so no value outlives its attempt."""
    shutil.rmtree(secrets_root() if secrets is None else Path(secrets), ignore_errors=True)


def run_command(profile, argv, wall, workspace=WORKSPACE, evidence=EVIDENCE):
    """The jail command one attempt runs, in either mode. The single-run
    `run` op builds exactly this list, and `run2` shares it, so the warm
    design changes nothing about what the jail is asked to do."""
    command = [b'/usr/local/bin/ukai-jail', b'run', b'--profile', profile.encode(),
               b'--workspace', os.fsencode(workspace), b'--receipt', os.fsencode(Path(evidence) / 'jail.json'),
               b'--limit', f'wall={wall}s'.encode(), b'--limit', b'mem=512MiB',
               b'--limit', b'swap=0', b'--limit', b'pids=64']
    # The build baseline grants only scratch. Explicitly grant
    # this disposable copy, never the Mac's input directory.
    if profile == 'build':
        command += [b'--rw', os.fsencode(workspace)]
    command += [b'--', *argv]
    return command


def attempt_environment(account):
    """The environment one guest jail runs under, in either mode."""
    return {'HOME': account.pw_dir, 'USER': 'ukai', 'LOGNAME': 'ukai',
            'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
            'XDG_RUNTIME_DIR': f'/run/user/{account.pw_uid}'}


def main():
    account = pwd.getpwnam('ukai')
    WORKSPACE.mkdir(mode=0o700, exist_ok=True)
    EVIDENCE.mkdir(mode=0o700, exist_ok=True)
    for path in (WORKSPACE, EVIDENCE):
        os.chown(path, account.pw_uid, account.pw_gid)
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((socket.VMADDR_CID_ANY, PORT))
    server.listen(1)
    server.settimeout(.2)
    # Even a launcher that disappears during boot cannot leave an idle VM.
    idle_deadline = clock() + 90
    audit('ready', kernel=os.uname().release)
    while True:
        notify()
        if clock() > idle_deadline:
            poweroff('no_host')
        try:
            conn, peer = server.accept()
            break
        except socket.timeout:
            pass
    if peer[0] != socket.VMADDR_CID_HOST:
        poweroff('non_host_peer')
    conn.settimeout(.25)

    def send(value):
        conn.sendall(json.dumps(value, separators=(',', ':')).encode() + b'\n')

    send({'event': 'ready', 'kernel': os.uname().release, 'lease_seconds': LEASE})
    selector = selectors.DefaultSelector()
    selector.register(conn, selectors.EVENT_READ, 'control')
    last_ping = clock()
    last_sequence = -1
    uploaded = 0
    files = 0
    buffer = b''
    process = None
    stream_count = 0
    output_bytes = 0
    wall_deadline = None
    # J18: a warm session keeps the VM up across attempts; `lease_expired`
    # no longer applies, because the attempt's lease is this connection's
    # end-of-file, not a timer. The vsock end closing still powers off, as
    # does the outer wall backstop for a live attempt.
    in_session = False

    def discard_attempt():
        """Closes one attempt's streams and counters, after its tree has
        been ended: the next attempt stages from scratch."""
        nonlocal process, stream_count, uploaded, files, output_bytes, wall_deadline
        for key in list(selector.get_map().values()):
            if key.data != 'control':
                selector.unregister(key.fileobj)
                key.fileobj.close()
        if process is not None and process.poll() is None:
            process.wait()
        process = None
        stream_count = 0
        uploaded = files = output_bytes = 0
        wall_deadline = None

    while True:
        notify()
        if not in_session and clock() - last_ping > LEASE:
            poweroff('lease_expired')
        if wall_deadline is not None and clock() > wall_deadline:
            if not in_session:
                poweroff('outer_wall_expired')
            # The backstop ends the attempt, not the warm VM (§6: the guest
            # jail's own wall still ends it first when the jail can act).
            stop_attempt_tree()
            clear_secrets()
            reset_attempt(account)
            discard_attempt()
            send({'event': 'error', 'message': 'outer_wall_expired'})
        for key, _ in selector.select(.1):
            if key.data != 'control':
                data = os.read(key.fd, 16384)
                if data:
                    output_bytes += len(data)
                    if output_bytes > MAX_BYTES:
                        poweroff('output_limit')
                    send({'event': key.data, 'data': base64.b64encode(data).decode()})
                else:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    stream_count -= 1
                continue
            data = conn.recv(65536)
            if not data:
                poweroff('host_eof')
            buffer += data
            if len(buffer) > MAX_LINE:
                poweroff('input_limit')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                request = json.loads(line)
                op = request['op']
                if op == 'ping':
                    sequence = request['sequence']
                    if type(sequence) is not int or sequence != last_sequence + 1:
                        poweroff('invalid_lease_sequence')
                    last_sequence = sequence
                    last_ping = clock()
                    send({'event': 'pong', 'sequence': sequence})
                elif op == 'put' and process is None:
                    parts = relative(request['path'])
                    path = WORKSPACE.joinpath(*parts)
                    payload = base64.b64decode(request['data'], validate=True)
                    uploaded += len(payload)
                    files += 1
                    if uploaded > MAX_BYTES or files > MAX_FILES:
                        poweroff('workspace_limit')
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open('xb') as output:
                        output.write(payload)
                    os.chmod(path, 0o755 if request['executable'] else 0o644)
                    for parent in [path, *path.parents]:
                        if parent == WORKSPACE.parent:
                            break
                        os.chown(parent, account.pw_uid, account.pw_gid)
                    send({'event': 'put', 'path': request['path']})
                elif op == 'run' and process is None:
                    profile = request['profile']
                    wall = request['wall_seconds']
                    if profile not in ('tool', 'build') or type(wall) is not int or not 1 <= wall <= 300:
                        poweroff('invalid_policy')
                    argv = [base64.b64decode(value, validate=True) for value in request['argv']]
                    if not argv or any(b'\0' in value for value in argv):
                        poweroff('invalid_argv')
                    command = run_command(profile, argv, wall)
                    env = attempt_environment(account)
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, cwd=WORKSPACE, env=env,
                                               user=account.pw_uid, group=account.pw_gid, extra_groups=[])
                    for stream, name in [(process.stdout, 'stdout'), (process.stderr, 'stderr')]:
                        selector.register(stream, selectors.EVENT_READ, name)
                    stream_count = 2
                    wall_deadline = clock() + wall + 10
                    audit('running', supervisor_pid=process.pid)
                    send({'event': 'running', 'supervisor_pid': process.pid})
                elif op == 'run2' and process is None and in_session:
                    # J18: the warm session's run — the same jail command,
                    # without the poweroff at completion. The host staged a
                    # fresh workspace (reset op) before the puts.
                    profile = request['profile']
                    wall = request['wall_seconds']
                    if profile not in ('tool', 'build') or type(wall) is not int or not 1 <= wall <= 300:
                        poweroff('invalid_policy')
                    argv = [base64.b64decode(value, validate=True) for value in request['argv']]
                    if not argv or any(b'\0' in value for value in argv):
                        poweroff('invalid_argv')
                    command = run_command(profile, argv, wall)
                    env = attempt_environment(account)
                    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, cwd=WORKSPACE, env=env,
                                               user=account.pw_uid, group=account.pw_gid, extra_groups=[])
                    for stream, name in [(process.stdout, 'stdout'), (process.stderr, 'stderr')]:
                        selector.register(stream, selectors.EVENT_READ, name)
                    stream_count = 2
                    wall_deadline = clock() + wall + 10
                    audit('running', supervisor_pid=process.pid)
                    send({'event': 'running', 'supervisor_pid': process.pid})
                elif op == 'session' and process is None and not in_session:
                    # J18: the warm session's handshake. After this the ping
                    # lease no longer applies: the attempt's lease is this
                    # connection's end-of-file (§6), not a timer.
                    in_session = True
                    audit('session_opened')
                    send({'event': 'session', 'kernel': os.uname().release})
                elif op == 'reset' and process is None and in_session:
                    reset_attempt(account)
                    uploaded = files = output_bytes = 0
                    send({'event': 'reset'})
                elif op == 'secret' and process is None and in_session:
                    secret_id = request['id']
                    if type(secret_id) is not str:
                        poweroff('invalid_operation')
                    stage_secret(secret_id, base64.b64decode(request['data'], validate=True))
                    send({'event': 'secret', 'id': secret_id})
                elif op == 'cancel2' and in_session:
                    # The attempt lease's end-of-file reached the host's
                    # ukai-vm, which passes the cancellation on. The session
                    # and the VM stay up; no timer was involved.
                    stop_attempt_tree()
                    clear_secrets()
                    reset_attempt(account)
                    discard_attempt()
                    audit('attempt_cancelled')
                    send({'event': 'cancelled'})
                elif op == 'cancel':
                    poweroff('cancelled')
                else:
                    poweroff('invalid_operation')
        if process is not None and process.poll() is not None and stream_count == 0:
            # Only regular files are transported. Never dereference guest links.
            count = 0
            total = 0
            for root, label in [(WORKSPACE, 'workspace'), (EVIDENCE, 'evidence')]:
                for directory, dirs, names in os.walk(root, followlinks=False):
                    dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
                    for name in names:
                        path = Path(directory) / name
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, 'rb') as source:
                            info = os.fstat(source.fileno())
                            if not stat.S_ISREG(info.st_mode):
                                raise ValueError('nonregular output')
                            count += 1
                            total += info.st_size
                            if count > MAX_FILES or total > MAX_BYTES or info.st_size > MAX_FILE:
                                raise ValueError('export_limit')
                            payload = source.read(MAX_FILE + 1)
                        send({'event': 'file', 'group': label, 'path': str(path.relative_to(root)),
                              'executable': bool(info.st_mode & 0o111), 'data': base64.b64encode(payload).decode()})
            send({'event': 'done', 'exit_code': process.returncode})
            audit('done', exit_code=process.returncode)
            if not in_session:
                # No new run and no reboot/resume. Host tears down this VM.
                while clock() - last_ping <= LEASE:
                    notify()
                    time.sleep(.1)
                poweroff('completed')
            # J18: the warm session carries on — the ephemeral credentials
            # die with the attempt, the next attempt stages its own
            # workspace, and the VM stays up until the host asks it to stop.
            clear_secrets()
            discard_attempt()


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        poweroff('controller_error:' + type(error).__name__)
