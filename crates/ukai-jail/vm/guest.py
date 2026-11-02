#!/usr/bin/env python3
"""Single-attempt guest controller. Installed root-owned outside the jail."""
import base64
import json
import hashlib
import struct
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


def kill_workload(boundary='/sys/fs/cgroup/user.slice'):
    """cgroup.kill of a workload boundary, verified empty: the facts the
    audit records stand on their own, so a warm session's cancel can share
    them with the poweroff path. The per-attempt boundary is the attempts
    slice below; `user.slice` stays the last-resort boundary at poweroff,
    because it also holds the lingered user manager whose delegation the
    jail needs — killing it mid-session is exactly the warm-reuse bug this
    signature exists to prevent (measured 2026-11-02: the first warm reset
    killed user@1001.service and the next jail refused with
    `limit:pids (cgroup_unavailable)`)."""
    root = Path(boundary)
    with (root / 'cgroup.events').open() as events:
        inode = os.fstat(events.fileno()).st_ino
        (root / 'cgroup.kill').write_text('1')
        deadline = clock() + 1
        while True:
            events.seek(0)
            state = dict(line.split() for line in events.read().splitlines())
            if state.get('populated') == '0':
                audit('workload_tree_empty', boundary=root.name, events_inode=inode)
                return
            if clock() >= deadline:
                raise TimeoutError('cgroup did not empty')
            time.sleep(.01)


# ---------------------------------------------------------------------------
# The per-attempt cgroup: a delegated child of a dedicated attempts slice.
# The jail (as uid 1001) can create its own cgroups beneath it, and the
# attempt's kill never touches user.slice's lingered user manager.
# ---------------------------------------------------------------------------

ATTEMPTS_SLICE = Path('/sys/fs/cgroup/ukai-attempts.slice')
attempt_counter = 0


def prepare_attempt_cgroup(account):
    """Creates this attempt's delegated cgroup and returns its path. The
    controller (root) owns the slice; each attempt's child is chowned to
    the workload user, so the jail's own cgroup setup works as it does on
    any delegated Linux host. The slice enables the controllers the jail's
    limits need (pids, memory) in its subtree_control — a freshly created
    cgroup has none, and the jail measures that as `cgroup_unavailable`
    (measured 2026-11-02)."""
    global attempt_counter
    attempt_counter += 1
    child = ATTEMPTS_SLICE / f'attempt-{attempt_counter}'
    child.mkdir(parents=True, exist_ok=False)
    with (ATTEMPTS_SLICE / 'cgroup.controllers').open() as available:
        present = set(available.read().split())
    enabled = {name for name in ('pids', 'memory', 'cpu') if name in present}
    if enabled:
        with (ATTEMPTS_SLICE / 'cgroup.subtree_control').open('w') as control:
            control.write(' '.join(f'+{name}' for name in sorted(enabled)))
    for path in (child, *(descendant for descendant in child.iterdir())):
        os.chown(path, account.pw_uid, account.pw_gid)
        os.chmod(path, 0o755)
    return child




# The join wrapper runs as the workload user, before the jail execs: a
# failure names the cgroup and errno on stderr (relayed to the host by the
# controller) instead of dying inside preexec_fn where the reason is lost.
# The wrapper waits until its own pid appears in the attempt cgroup's
# cgroup.procs; the controller (root) performs the move, because moving a
# process out of the root-owned service cgroup needs the source-side
# permission only root has (measured: uid 1001 writing cgroup.procs gets
# EIO). Waiting (not writing) keeps the join race-free: the jail execs
# only after the move, and a controller death times out loudly.
_JOIN_CGROUP_WRAPPER = [
    '/bin/sh', '-c',
    'i=0; while ! grep -qx "$$" "$1/cgroup.procs" 2>/dev/null; do '
    'i=$((i+1)); [ "$i" -gt 500 ] && { echo "CGROUP_JOIN_TIMEOUT:$1" >&2; exit 124; }; '
    'sleep 0.02; done; shift; exec "$@"', 'join-cgroup',
]


def _join_attempt_cgroup(child):
    """The argv prefix whose process waits for its move into the attempt's
    delegated cgroup; the controller completes it with
    [`move_into_attempt_cgroup`] before the jail execs."""
    return [*_JOIN_CGROUP_WRAPPER, str(child)]


def move_into_attempt_cgroup(child, pid):
    """Root performs the move the delegated user cannot: one write of the
    spawned pid into the attempt cgroup's cgroup.procs."""
    with (child / 'cgroup.procs').open('w') as procs:
        procs.write(str(pid))
def drop_attempt_cgroup(child):
    """Removes one attempt's cgroup after its verified-empty kill."""
    try:
        child.rmdir()
    except OSError:
        pass  # A leftover is recorded by the next attempt's fresh name.


def stop_attempt_tree(boundary=None):
    """Ends one attempt's tree without ending the session. A boundary that
    cannot be verified empty is recorded and the session carries on: the
    attempt's outcome is already unknown to the host."""
    # A warm reset must never run alongside surviving workload processes.
    # Failure propagates to the controller's poweroff path. The boundary is
    # this attempt's delegated cgroup — never user.slice, whose lingered
    # user manager provides the delegation the next jail needs.
    target = Path(boundary) if boundary is not None \
        else ATTEMPTS_SLICE / f'attempt-{attempt_counter}'
    if not target.exists():
        # A boundary that does not exist holds no processes: empty by
        # construction. This is the normal state after a cancel dropped the
        # attempt's cgroup and before the next attempt creates its own
        # (measured 2026-11-02: the reset after a cancel re-killed the
        # dropped boundary and powered the guest off). An EXPLICIT boundary
        # that vanished mid-attempt is the caller's anomaly to handle.
        audit('workload_tree_empty', boundary=target.name, events_inode=0)
        return
    kill_workload(str(target))


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


# ---------------------------------------------------------------------------
# The live workspace share (J18 §6, K109)
#
# When the host attaches a virtio-fs share of the workspace (tag below), the
# attempt workspace is that live share instead of the staged tmpfs: files are
# the host's files, writes appear on the host, and the guest jail's policy is
# the only write gate. Measured on this transport (2026-11-02 probe): the
# server authorizes every guest uid as the host user, so guest-side DAC is
# advisory inside the share; symlinks resolve client-side (guest VFS) and
# cannot escape; mknod is refused; pre-existing host hardlinks and APFS
# case/normalization folding DO escape policy denials, so the host preflight
# refuses them before boot. Staging (put) and workspace export do not apply
# in live mode.
# ---------------------------------------------------------------------------

SHARE_TAG = 'workspace'
SHARE_MOUNT = Path('/mnt/workspace')


def mount_share():
    """Mounts the live workspace share once at boot. Returns True when the
    share is live; a guest booted without the device keeps the preview's
    staged-tmpfs behavior unchanged."""
    if os.path.ismount(SHARE_MOUNT):
        return True
    try:
        SHARE_MOUNT.mkdir(parents=True, exist_ok=True)
        subprocess.run(['mount', '-t', 'virtiofs', SHARE_TAG, str(SHARE_MOUNT)],
                       check=True, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return os.path.ismount(SHARE_MOUNT)


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

def reset_attempt(account, workspace=None, evidence=None):
    """Empties both attempt directories for the next attempt, as the host's
    reset op asks. The directories, their modes and their owner come back
    exactly as boot made them. The live share is never wiped: it is the
    host's directory, and its contents are the host's business. Paths
    resolve at CALL time so the live-share switch is honored."""
    workspace = WORKSPACE if workspace is None else Path(workspace)
    evidence = EVIDENCE if evidence is None else Path(evidence)
    if workspace == SHARE_MOUNT and os.path.ismount(SHARE_MOUNT):
        workspace = None  # the evidence tree below still resets per attempt
    for path in [Path(p) for p in (workspace, evidence) if p is not None]:
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                info = None
            if info is not None:
                if stat.S_ISDIR(info.st_mode):
                    if not shutil.rmtree.avoids_symlink_attacks:
                        raise RuntimeError('fd-relative safe rmtree is required')
                    shutil.rmtree(path.name, dir_fd=parent)
                else:
                    os.unlink(path.name, dir_fd=parent)
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
            directory = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(directory, 0o700)
                os.fchown(directory, account.pw_uid, account.pw_gid)
            finally:
                os.close(directory)
        finally:
            os.close(parent)


def stage_secret(secret_id, payload, secrets=None):
    """Writes one ephemeral credential to its tmpfs path, 0600. The value
    crossed the vsock once for this attempt and lives here only until the
    attempt ends."""
    secrets = secrets_root() if secrets is None else Path(secrets)
    parts = relative(secret_id)
    path = secrets.joinpath(*parts)
    # The id may nest (api/token): create every level private, not just the
    # root (measured: open('xb') on a nested id raised ENOENT).
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(payload)
    os.chmod(path, 0o600)
    return path


def clear_secrets(secrets=None):
    """Removes every staged secret; every run2 attempt and every cancel ends
    with this, so no value outlives its attempt."""
    shutil.rmtree(secrets_root() if secrets is None else Path(secrets), ignore_errors=True)


def run_command(profile, argv, wall, workspace=None, evidence=None):
    """The jail command one attempt runs, in either mode. The single-run
    `run` op builds exactly this list, and `run2` shares it, so the warm
    design changes nothing about what the jail is asked to do. The paths
    resolve at CALL time: a live share must become the jail's workspace,
    and a definition-time default would still name the staged tmpfs."""
    workspace = WORKSPACE if workspace is None else Path(workspace)
    evidence = EVIDENCE if evidence is None else Path(evidence)
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


def receipt_binding(request, receipt, guest_boot_id):
    """Keep the raw jail receipt unchanged; bind its identity in a separate envelope.

    These are controller reports. The host verifies consistency, not kernel
    attestation. A stale receipt with a different argv/boot/profile is refused.
    """
    argv = [base64.b64decode(value, validate=True) for value in request['argv']]
    preimage = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(argv))
    preimage += b''.join(struct.pack('>Q', len(value)) + value for value in argv)
    digest = 'sha256:' + hashlib.sha256(preimage).hexdigest()
    if receipt['argv_digest'] != digest or receipt['policy']['name'] != request['profile']:
        raise ValueError('receipt argv/profile mismatch')
    if receipt['process']['identity']['value']['boot_id'] != guest_boot_id:
        raise ValueError('receipt boot mismatch')
    return dict(attempt_id=request['attempt_id'], boot_id=request['boot_id'],
                guest_attempt_id=receipt['attempt_id'], guest_boot_id=guest_boot_id,
                profile=request['profile'], argv_digest=digest)


def main():
    global WORKSPACE
    account = pwd.getpwnam('ukai')
    if mount_share():
        # The live share is the workspace (J18 §6): everything downstream —
        # the jail's cwd, the put and export paths — flows from this switch.
        WORKSPACE = SHARE_MOUNT
        audit('live_share_mounted', mount=str(SHARE_MOUNT))
    reset_attempt(account)
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
    run_request = None
    guest_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()

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
                    if WORKSPACE == SHARE_MOUNT:
                        # Live share: staging is the host's side of the mount;
                        # a put would write through to the host workspace.
                        poweroff('live_share_no_staging')
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
                    if profile == 'build' and WORKSPACE == SHARE_MOUNT:
                        # The build profile's disposable-copy grant has no
                        # protected segments; on a live share that would
                        # expose the operator's real .git (measured, run 2
                        # of the 2026-11-02 K109 evidence).
                        poweroff('live_share_requires_protected_profile')
                    argv = [base64.b64decode(value, validate=True) for value in request['argv']]
                    if not argv or any(b'\0' in value for value in argv):
                        poweroff('invalid_argv')
                    command = run_command(profile, argv, wall)
                    env = attempt_environment(account)
                    attempt_cgroup = prepare_attempt_cgroup(account)
                    joined = [os.fsencode(part) for part in _join_attempt_cgroup(attempt_cgroup)]
                    process = subprocess.Popen([*joined, *command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, cwd=WORKSPACE, env=env,
                                               user=account.pw_uid, group=account.pw_gid, extra_groups=[])
                    move_into_attempt_cgroup(attempt_cgroup, process.pid)
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
                    run_request = request
                    if not request.get("attempt_id") or not request.get("boot_id"):
                        poweroff("missing_attempt_binding")
                    profile = request['profile']
                    wall = request['wall_seconds']
                    if profile not in ('tool', 'build') or type(wall) is not int or not 1 <= wall <= 300:
                        poweroff('invalid_policy')
                    argv = [base64.b64decode(value, validate=True) for value in request['argv']]
                    if not argv or any(b'\0' in value for value in argv):
                        poweroff('invalid_argv')
                    command = run_command(profile, argv, wall)
                    env = attempt_environment(account)
                    attempt_cgroup = prepare_attempt_cgroup(account)
                    joined = [os.fsencode(part) for part in _join_attempt_cgroup(attempt_cgroup)]
                    process = subprocess.Popen([*joined, *command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, cwd=WORKSPACE, env=env,
                                               user=account.pw_uid, group=account.pw_gid, extra_groups=[])
                    move_into_attempt_cgroup(attempt_cgroup, process.pid)
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
                    stop_attempt_tree()
                    if attempt_counter:
                        drop_attempt_cgroup(ATTEMPTS_SLICE / f'attempt-{attempt_counter}')
                    reset_attempt(account)
                    uploaded = files = output_bytes = 0
                    send({'event': 'reset'})
                elif op == 'secret' and process is None and in_session:
                    # J18 §6 transport: the value crosses the vsock once and
                    # lands in tmpfs for this attempt only (never the guest
                    # disk). The jail-side vault binding stays refused until
                    # the guest jail's credential staging is wired; the
                    # transport, its privacy and its clearing are what the
                    # warm measurements verify.
                    path = stage_secret(request['id'], base64.b64decode(request['data'], validate=True))
                    send({'event': 'secret', 'id': request['id'], 'path': str(path)})
                elif op == 'cancel2' and in_session:
                    # The attempt lease's end-of-file reached the host's
                    # ukai-vm, which passes the cancellation on. The session
                    # and the VM stay up; no timer was involved.
                    stop_attempt_tree()
                    if attempt_counter:
                        drop_attempt_cgroup(ATTEMPTS_SLICE / f'attempt-{attempt_counter}')
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
            if in_session:
                stop_attempt_tree(attempt_cgroup)
            # Only regular files are transported. Never dereference guest links.
            count = 0
            total = 0
            binding = None
            # The live share's files are already on the host; only the
            # evidence tree travels back.
            groups = ([(EVIDENCE, 'evidence')] if WORKSPACE == SHARE_MOUNT
                      else [(WORKSPACE, 'workspace'), (EVIDENCE, 'evidence')])
            for root, label in groups:
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
                        if in_session and label == 'evidence' and path.name == 'jail.json' and path.parent == EVIDENCE:
                            binding = receipt_binding(run_request, json.loads(payload), guest_boot_id)
                        send({'event': 'file', 'group': label, 'path': str(path.relative_to(root)),
                              'executable': bool(info.st_mode & 0o111), 'data': base64.b64encode(payload).decode()})
            if in_session and binding is None:
                raise ValueError('missing bound jail receipt')
            send({'event': 'done', 'exit_code': process.returncode, **({'binding': binding} if in_session else {})})
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
        # The traceback reaches the console (and so the host's evidence)
        # before the poweroff audit names the class: a warm-session crash
        # on a real guest is otherwise undiagnosable.
        import traceback
        with open('/dev/hvc0', 'w') as console:
            console.write('UKAI_VM_CONTROLLER_TRACEBACK\n')
            traceback.print_exc(file=console)
        poweroff('controller_error:' + type(error).__name__)
