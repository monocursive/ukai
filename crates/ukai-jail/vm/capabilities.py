#!/usr/bin/env python3
"""Pre-release guest capability measurements (vm/README's requirement).

Before `run --vm` may report any capability as available, each claim the
guest jail makes for an attempt must be MEASURED on the prepared image,
through the warm service, with the live share attached. This suite runs one
boot and one attempt per capability; an unmeasured capability is recorded
as such, never assumed.

Every verdict reads facts, not shell exit statuses: the guest jail's own
receipt (limit hits, outcome cause, applied network), a probe's tagged JSON
line printed by python3 inside the attempt, or the host's view of the share.
A receipt backs a verdict only when its digest verified and its binding
names that very attempt, argv, profile and serve boot (harness.receipt_bound).

Each capability is measured alone, by its own attempt, and recorded under
the requirement it backs (`measurements[<requirement>]`: verdict, the
attempt's RFC 3339 start time, the attempt id), so a later entry in the
host's GUEST_MEASUREMENTS table can point at exactly one verdict.

Capabilities measured (the limits guest.py's run_command applies):
  wall            limit:wall. The guest jail ends an attempt at its own wall
                  deadline: the receipt records the wall hit AND the
                  wall_expiry cause, the workload's later output never
                  appears, and released->done ends before wall + 5 s (the
                  guest controller's own backstop fires at wall + 10 s, so a
                  backstop kill cannot pass for the jail's deadline)
  pids            limit:pids. A fork storm stops at the pids limit with EAGAIN, not
                  before (the count of successful forks is within PIDS_SLACK
                  of the limit), the receipt says the jail applied pids=64
                  through pids.max and records the hit (and the cgroup's own
                  pids.max, where the probe can read it, is 64), and the
                  attempt settles without a jail error
  mem             limit:mem. An allocation beyond the mem limit is OOM-killed near the
                  limit: SIGKILL (137), the receipt's mem limit applied at
                  512 MiB with its hit or memory_oom, and the last reported
                  allocation between half the limit and the limit
  containment     filesystem_containment. Writes to /etc, /usr/local/bin and
                  the guest's root refuse with a filesystem errno and leave
                  nothing behind; reads of guest paths outside the grants
                  (/etc/shadow, the controller's /var/lib/ukai-vm, the
                  account home, the /run/ukai-vm credential root, /root)
                  refuse; and, as the probe's positive control, a granted
                  runtime file and a workspace file read
  network_none    network_none. With the NAT adapter attached (control status guest_nat),
                  the egress probe (harness.py, D9) fails with the jail's
                  own denial errno after its loopback positive control
                  connected, DNS does not resolve, the receipt's applied
                  network is `none`; the same target answers from the host
                  AND, on the same guest boot, through the route control (an
                  agent attempt whose proxy, outside the jail's namespace,
                  reached it), so the denial is the jail's, not a guest
                  without a route (harness.network_denial)
  workspace       (K109, no probe requirement) a granted write reaches the
                  host with this run's bytes
  tree_termination
                  tree_termination. A python3 fixture starts six kinds of
                  descendant (a plain child, one ignoring SIGTERM, a setsid
                  child, a double-fork daemon, a SIGSTOPped member, a child
                  in its own process group); the root confirms each kind
                  from /proc (its positive control), and each writes a
                  marker and a heartbeat into the live share. Two end paths,
                  each its own attempt: the root returns 0 after a
                  TREE_HOLD_SECONDS hold (`exit`), and the root sleeps past a
                  5 s wall (`wall`). Facts: the host saw every member's
                  marker (naming the pid the probe reports) and at least two
                  beats of each; while the attempt ran, the host saw each
                  running member's beats GROW through the share (the settle
                  window's positive control); no beat file grows in the
                  TREE_SETTLE_SECONDS window that opens TREE_SHARE_GRACE
                  after `done`; the receipt says tree_empty, integrity
                  verified, boundary pid_namespace, scope attempt_tree, and
                  the end path's own cause (the target's exit 0, or the wall
                  hit with wall_expiry); and the guest controller's own stop
                  (`guest_stop`: outside the jail, after the jail exited)
                  covered the attempt's cgroup yet found no populated
                  boundary and no live workload process before it signalled
                  anything, and killed no stray. The stopped member never
                  beats again, so its survival is the stop's alone to
                  witness. The jail's exit status and receipt errors are
                  recorded in `notes`, not required (a left-behind
                  descendant settles as evidence_lost). A mid-run cancel is
                  NOT measured (NOT_MEASURED says why).
  closed_set_observation
                  closed_set_observation. One fixture, run with one round
                  and with three: per round it execs /usr/bin/true and
                  /bin/sh, makes a granted workspace write (bytes checked on
                  the host), a write /etc refuses and a connect the network
                  namespace refuses. Facts: observer attached (ptrace) with
                  set linux-closed-v1 and no gaps, classes exec, fs.write,
                  fs.deny and net active without gaps and counting at least
                  the fixture's operations (PER_ROUND each round), the
                  forwarded evidence trace (record['files']) holding exactly
                  the audit results the receipt counts, no receipt error and
                  exit 0; and, between the two runs, each class's count
                  grows by exactly the two extra rounds' operations (so the
                  counts follow the workload, not a constant). A third
                  attempt leaves a descendant writing at settlement: the
                  host saw it start and its loss is never silent (each class
                  complete, or degraded with a null count and gaps naming
                  it, and then the receipt names evidence_lost); a complete
                  fs.write counts every beat the host saw, and every
                  complete class matches the trace.
  syscall_filter  syscall_filter. A python3 ctypes probe (aarch64 numbers;
                  it refuses to call anything on another machine) calls
                  rc.5 DENY_EPERM syscalls, clone3, and the argument rules
                  (clone flags, TIOCSTI, a seccomp listener, socket
                  families) with arguments an unfiltered kernel answers
                  with another, known result (EINVAL, EFAULT, EBADF, ESRCH,
                  EOPNOTSUPP, success), and gets the filter's EPERM (ENOSYS,
                  EAFNOSUPPORT); its positive controls are allowed calls
                  shaped the same way, which get the kernel's own answer.
                  The probe also reads /proc/self/status: Seccomp 2,
                  NoNewPrivs 1, and as many filters as the receipt says it
                  expected and observed
  protected_coverage
                  protected_coverage:existing_and_root, for both profiles a
                  plan can require it under. The host seeds protected paths
                  at depth (tool: a nested .git, a nested .ukai, a file-form
                  .git; agent: nested .git/config and .git/hooks) beside the
                  root .git; the probe first reads each (so it saw the very
                  bytes and listings), then tries write, truncate, chmod,
                  replace, rename and unlink (files) or create, mkdir,
                  symlink, chmod and rename (directories), and, under tool,
                  five ways to create the absent root literal .ukai.
                  Positive controls: the same operations succeed on
                  unprotected look-alike files and directories and on root
                  names beside the literal, and ordinary and near-miss names
                  (x.git, .github, .ukai-sibling, agent's writable .git) are
                  created. Host facts: protected bytes, modes, inodes and
                  listings unchanged, nothing moved, the literal still
                  absent, and every control's effect present. The receipt
                  names existing_and_root and a read-only mount for each
                  path.
  network_proxy   network_proxy. An agent attempt allowed exactly the probe
                  target: a CONNECT through the jail's proxy reaches it (up
                  to PROXY_TRIES tries, every one recorded; never reached is
                  a FAIL); CONNECTs to another address, another port and a
                  loopback port are refused 403 host_not_allowed; a direct
                  connect to the same target fails with the jail's denial
                  errno after a loopback control connected; the proxy's own
                  socket refuses the workload (EACCES) after an AF_UNIX
                  control connected; the proxy variables are the bridge's;
                  the receipt applied proxy with exactly that allow set and
                  counted every request in proxy.net

Each of these five also needs every attempt's receipt to name a policy that
requires the measured requirement.

A requirement backed by more than one attempt records all of them
(`measurements[<requirement>].attempt_ids`); its `attempt_id` and
`measured_at` are its first attempt's.

Usage: UKAI_VM_BINARY=<ukai-vm under test> capabilities.py <home> <workspace> <out>
"""
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

PIDS_SLACK = 8
MEM_FLOOR_FRACTION = 0.5
BACKSTOP_MARGIN_SECONDS = 5      # guest.py's controller backstop is wall + 10 s
FS_REFUSALS = {'EROFS', 'EACCES', 'EPERM', 'ENOENT'}
READ_REFUSALS = {'EACCES', 'EPERM', 'ENOENT'}
# The requirement each capability's verdict backs (the receipt's names).
REQUIREMENTS = {'wall': 'limit:wall', 'pids': 'limit:pids', 'mem': 'limit:mem',
                'containment': 'filesystem_containment', 'network_none': 'network_none',
                'tree_termination': 'tree_termination', 'closed_set_observation': 'closed_set_observation',
                'syscall_filter': 'syscall_filter', 'protected_coverage': 'protected_coverage:existing_and_root',
                'network_proxy': 'network_proxy'}
# Every attempt a capability's verdict reads, its own first (whose start
# time the requirement records).
CAPABILITY_ATTEMPTS = {'network_none': ('network_none', 'route_control'),
                       'tree_termination': ('tree_termination', 'tree_wall'),
                       'closed_set_observation': ('closed_set_observation', 'observe_3', 'observe_background'),
                       'protected_coverage': ('protected_coverage', 'protected_agent')}
READ_OUTSIDE = ('/etc/shadow', '/var/lib/ukai-vm', '/home/ukai', '/run/ukai-vm', '/root')

# tree_termination
TREE_KINDS = ('normal', 'sigterm_ignored', 'setsid', 'daemon', 'stopped', 'own_pgid')
TREE_PATHS = {'tree_termination': 'exit', 'tree_wall': 'wall'}
TREE_EXIT_WALL = 30
TREE_WALL = 5
TREE_SETTLE_SECONDS = 3.0
TREE_MIN_BEATS = 2
TREE_HOLD_SECONDS = 2.0     # the exit path's root lives this long after every member beat
TREE_SHARE_GRACE = 1.0      # the share's own delay before the settle window opens
TREE_POLL = 0.1
NOT_MEASURED = {'tree_termination': {
    'cancel': 'harness.run_attempt has no mid-run cancel; the only cancel the harnesses have is the '
              'attempt-socket EOF (fault_matrix eof), which ends the attempt through the guest '
              "controller's own stop (cancel2), never through the guest jail, and returns no receipt "
              'and no done frame, so it cannot back the guest jail\'s tree_termination'}}
GUEST_STOP_LISTS = ('boundaries', 'populated_before_kill', 'live_before_kill', 'strays_killed')
ATTEMPT_CGROUP_PREFIX = 'ukai-attempts.slice/attempt-'

# closed_set_observation
OBSERVE_EXECS = ((['/usr/bin/true'], 0), (['/bin/sh', '-c', 'exit 7'], 7))
OBSERVE_ROUNDS = {'closed_set_observation': ('r1', 1), 'observe_3': ('r3', 3), 'observe_background': ('bg', 1)}
AUDIT_CLASSES = ('exec', 'fs.write', 'fs.deny', 'net')
# What one round adds to each class (rc.5's audit writer): a proc.exec and a
# proc.exit per program (the exec class counts both), the granted write's
# mutating open, the refused write's open (EROFS on a write counts as
# fs.deny) and the refused connect (ENETUNREACH stays net; only EACCES/EPERM
# would move a connect to fs.deny).
PER_ROUND = {'exec': 2 * len(OBSERVE_EXECS), 'fs.write': 1, 'fs.deny': 1, 'net': 1}
DENIED_WRITE_ERRNOS = ('EROFS', 'EACCES', 'EPERM')
# The audit trace's result operations, by the coverage class rc.5 counts
# them under (observer.rs ClosedOperation::coverage_class).
TRACE_CLASSES = {'proc.exec': 'exec', 'proc.exit': 'exec', 'fs.create': 'fs.write', 'fs.write': 'fs.write',
                 'fs.rename': 'fs.write', 'fs.unlink': 'fs.write', 'fs.deny': 'fs.deny', 'net.connect': 'net'}

# syscall_filter: (label, aarch64 number, arguments, the filter's answer,
# the answer of the same call on an unfiltered aarch64 kernel). Each kernel
# answer is decided by an argument check at the top of the syscall, before
# any privilege check, so the filter's EPERM is never the kernel's own.
CLONE_SIGHAND, CLONE_UNTRACED, CLONE_NEWUSER = 0x800, 0x00800000, 0x10000000
SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, SECCOMP_FILTER_FLAG_NEW_LISTENER = 1, 1, 8
NO_PID = 0x3fffffff          # above any pid_max: no such process
NO_FD = 0x7fffffff           # no such descriptor
ALL_FLAGS = 0xffffffff       # every flag bit: invalid for each call below
SYSCALL_DENIED = (
    ('ptrace', 117, (7, NO_PID, 0, 0), 'EPERM', 'ESRCH'),
    ('process_vm_readv', 270, (0, 0, 0, 0, 0, 1), 'EPERM', 'EINVAL'),
    ('process_vm_writev', 271, (0, 0, 0, 0, 0, 1), 'EPERM', 'EINVAL'),
    ('perf_event_open', 241, (0, 0, -1, -1, ALL_FLAGS), 'EPERM', 'EINVAL'),
    ('kcmp', 272, (NO_PID, NO_PID, 0, 0, 0), 'EPERM', 'ESRCH'),
    ('keyctl', 219, (0x7fffffff, 0, 0, 0, 0), 'EPERM', 'EOPNOTSUPP'),
    ('add_key', 217, (0, 0, 0, 0, 0), 'EPERM', 'EFAULT'),
    ('request_key', 218, (0, 0, 0, 0), 'EPERM', 'EFAULT'),
    ('io_uring_enter', 426, (NO_FD, 0, 0, 0, 0, 0), 'EPERM', 'EBADF'),
    ('io_uring_register', 427, (NO_FD, 0, 0, 0), 'EPERM', 'EBADF'),
    ('mount', 40, (0, 0, 0, 0, 0), 'EPERM', 'EFAULT'),
    ('umount2', 39, (0, ALL_FLAGS), 'EPERM', 'EINVAL'),
    ('mount_setattr', 442, (-1, 0, ALL_FLAGS, 0, 0), 'EPERM', 'EINVAL'),
    ('chroot', 51, (0,), 'EPERM', 'EFAULT'),
    ('unshare', 97, (1,), 'EPERM', 'EINVAL'),
    ('setns', 268, (-1, 0), 'EPERM', 'EBADF'),
    ('pidfd_open', 434, (1, ALL_FLAGS), 'EPERM', 'EINVAL'),
    ('pidfd_send_signal', 424, (-1, 0, 0, ALL_FLAGS), 'EPERM', 'EINVAL'),
    ('pidfd_getfd', 438, (-1, 0, 1), 'EPERM', 'EINVAL'),
    ('process_madvise', 440, (-1, 0, 0, 0, 1), 'EPERM', 'EINVAL'),
    ('statmount', 457, (0, 0, 0, ALL_FLAGS), 'EPERM', 'EINVAL'),
    ('listmount', 458, (0, 0, 0, ALL_FLAGS), 'EPERM', 'EINVAL'),
    ('quotactl', 60, (ALL_FLAGS, 0, 0, 0), 'EPERM', 'EINVAL'),
    ('adjtimex', 171, (0,), 'EPERM', 'EFAULT'),
    ('clock_settime', 112, (0, 0), 'EPERM', 'EFAULT'),
    ('clock_adjtime', 266, (0, 0), 'EPERM', 'EFAULT'),
    ('settimeofday', 170, (1, 0), 'EPERM', 'EFAULT'),
    ('name_to_handle_at', 264, (-1, 0, 0, 0, ALL_FLAGS), 'EPERM', 'EINVAL'),
    # clone3 is refused by both the baseline and the observer's narrowing
    # filter: its ENOSYS shows a filter, not which one.
    ('clone3', 435, (0, 0), 'ENOSYS', 'EINVAL'),
    # The argument rules. Each clone shape is invalid (CLONE_SIGHAND without
    # CLONE_VM), so no process is ever created.
    ('clone_untraced', 220, (CLONE_UNTRACED | CLONE_SIGHAND, 0, 0, 0, 0), 'EPERM', 'EINVAL'),
    ('clone_newuser', 220, (CLONE_NEWUSER | CLONE_SIGHAND, 0, 0, 0, 0), 'EPERM', 'EINVAL'),
    ('ioctl_tiocsti', 29, (-1, 0x5412, 0), 'EPERM', 'EBADF'),
    ('seccomp_listener', 277, (SECCOMP_SET_MODE_FILTER,
                               SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER, 0), 'EPERM', 'EINVAL'),
    ('socket_unix', 198, (1, 1, 0), 'EPERM', 'ok'),
    ('socket_vsock', 198, (40, 1, 0), 'EAFNOSUPPORT', 'ok'),
)
# Allowed calls, shaped like the denied ones: the kernel's own answer.
SYSCALL_CONTROLS = (
    ('eventfd2', 19, (0, ALL_FLAGS), 'EINVAL'),
    ('epoll_create1', 20, (ALL_FLAGS,), 'EINVAL'),
    ('uname', 160, (0,), 'EFAULT'),
    ('gettimeofday', 169, (1, 0), 'EFAULT'),
    ('clock_gettime', 113, (0, 0), 'EFAULT'),
    ('fchdir', 50, (-1,), 'EBADF'),
    ('getpgid', 155, (NO_PID,), 'ESRCH'),
    ('clone_sighand', 220, (CLONE_SIGHAND, 0, 0, 0, 0), 'EINVAL'),
    ('ioctl_tiocgwinsz', 29, (-1, 0x5413, 0), 'EBADF'),
    ('seccomp_bad_flag', 277, (SECCOMP_SET_MODE_FILTER, 0x80000000, 0), 'EINVAL'),
    ('socket_inet', 198, (2, 1, 0), 'ok'),
)

# protected_coverage:existing_and_root
SENTINEL_TEXT = '[core]\n'   # harness.protected_sentinel's text, which main() seeds
WORKSPACE_MOUNT = '/mnt/workspace'   # guest.SHARE_MOUNT: where the attempt sees the live share
PROTECT_PROFILES = {'protected_coverage': 'tool', 'protected_agent': 'agent'}
PROTECT_FILE_OPS = ('write', 'truncate', 'chmod', 'replace', 'rename_away', 'unlink')
PROTECT_DIR_OPS = ('create_inside', 'mkdir_inside', 'symlink_inside', 'chmod', 'rename_away')
ABSENT_OPS = ('mkdir', 'create_file', 'symlink', 'rename_onto', 'create_inside')
PROTECT_REFUSALS = ('EROFS', 'EBUSY', 'EXDEV', 'EACCES', 'EPERM')
# A placeholder holds an absent literal's name, so a create there may also
# answer EEXIST; the host's view after the attempt decides.
ABSENT_REFUSALS = PROTECT_REFUSALS + ('EEXIST',)
ABSENT_CONTROL_KINDS = {'mkdir': 'dir', 'create_file': 'file', 'symlink': 'symlink', 'rename_onto': 'dir'}

# network_proxy
PROXY_TRIES = 3
PROXY_WALL = 60
PROXY_SOCKET = '/run/ukai/proxy/proxy.sock'
PROXY_ENVIRONMENT = {'HTTP_PROXY': 'http://127.0.0.1:3128', 'HTTPS_PROXY': 'http://127.0.0.1:3128',
                     'http_proxy': 'http://127.0.0.1:3128', 'https_proxy': 'http://127.0.0.1:3128',
                     'ALL_PROXY': 'socks5h://127.0.0.1:3129', 'all_proxy': 'socks5h://127.0.0.1:3129',
                     'NO_PROXY': '', 'no_proxy': ''}
PROXY_REFUSAL_REASON = 'host_not_allowed'

PIDS_PROBE = r'''
import errno, json, os, signal, sys, time
record = {'tag': sys.argv[1]}
for name in ('pids.max', 'pids.current'):
    try:
        with open('/sys/fs/cgroup/' + name) as source:
            record[name] = source.read().strip()
    except OSError:
        record[name] = None
children, failure = [], None
while len(children) < 4096:
    try:
        pid = os.fork()
    except OSError as error:
        failure = errno.errorcode.get(error.errno, str(error.errno))
        break
    if pid == 0:
        time.sleep(120)
        os._exit(0)
    children.append(pid)
record['forked'] = len(children)
record['fork_error'] = failure
for pid in children:
    os.kill(pid, signal.SIGKILL)
for pid in children:
    os.waitpid(pid, 0)
print('UKAI_PIDS_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''

MEM_PROBE = r'''
import sys
tag, limit = sys.argv[1], int(sys.argv[2])
chunk, blocks = 16 * 1024 * 1024, []
while len(blocks) * 16 < 2 * limit:
    block = bytearray(chunk)
    for offset in range(0, chunk, 4096):
        block[offset] = 1
    blocks.append(block)
    print('UKAI_MEM_PROBE %s %d' % (tag, len(blocks) * 16), flush=True)
print('UKAI_MEM_UNBOUNDED %s %d' % (tag, len(blocks) * 16), flush=True)
'''

FS_PROBE = r'''
import errno, json, os, sys
spec = json.loads(sys.argv[2])
record = {'tag': sys.argv[1], 'paths': {}, 'reads': {}}
def name(error):
    return errno.errorcode.get(error.errno, str(error.errno))
for path in spec.get('write', []):
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        result = 'created'
    except OSError as error:
        result = name(error)
    record['paths'][path] = {'open': result, 'exists_after': os.path.lexists(path)}
for path in spec.get('read', []) + spec.get('control', []):
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            with open(path, 'rb') as source:
                source.read(1)
        record['reads'][path] = 'read'
    except OSError as error:
        record['reads'][path] = name(error)
print('UKAI_FS_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def fs_probe_argv(tag, write=(), read=(), control=()):
    spec = json.dumps({'write': list(write), 'read': list(read), 'control': list(control)})
    return [harness.PYTHON, '-I', '-c', FS_PROBE, tag, spec]


# The tree fixture. Each descendant becomes its kind, writes its marker (its
# own pid) and appends a beat every 0.2 s until killed; the root waits until
# every kind has beaten twice, stops the `stopped` member, reads each
# member's /proc facts (the kinds' positive controls) and prints them. On the
# `exit` path it then holds TREE_HOLD_SECONDS (so the host sees the beats
# grow) and returns 0; on `wall` it sleeps past the wall.
TREE_PROBE = r'''
import json, os, signal, sys, time
tag, path, kinds, need, hold = sys.argv[1], sys.argv[2], sys.argv[3].split(','), int(sys.argv[4]), float(sys.argv[5])
prefix = 'tt-%s-%s-' % (tag, path)
def beat_forever(kind):
    null = os.open('/dev/null', os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(null, fd)
    with open(prefix + kind + '.start', 'w') as marker:
        marker.write('%d\n' % os.getpid())
    while True:
        fd = os.open(prefix + kind + '.beat', os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        try:
            os.write(fd, b'beat\n')
        finally:
            os.close(fd)
        time.sleep(0.2)
def become(kind):
    try:
        if kind == 'sigterm_ignored':
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        elif kind == 'setsid':
            os.setsid()
        elif kind == 'own_pgid':
            os.setpgid(0, 0)
        elif kind == 'daemon':
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
        beat_forever(kind)
    except BaseException:
        pass
    os._exit(0)
def marker(kind):
    try:
        with open(prefix + kind + '.start') as source:
            return int(source.read().strip())
    except (OSError, ValueError):
        return None
def beats(kind):
    try:
        with open(prefix + kind + '.beat', 'rb') as source:
            return source.read().count(b'\n')
    except OSError:
        return 0
def proc(pid):
    try:
        with open('/proc/%d/stat' % pid) as source:
            text = source.read()
        fields = text[text.rindex(')') + 2:].split()
        with open('/proc/%d/status' % pid) as source:
            ignored = [line.split()[1] for line in source if line.startswith('SigIgn:')]
        return {'state': fields[0], 'ppid': int(fields[1]), 'pgrp': int(fields[2]), 'session': int(fields[3]),
                'sigterm_ignored': bool((int(ignored[0], 16) >> (signal.SIGTERM - 1)) & 1)}
    except (OSError, ValueError, IndexError):
        return None
root = {'pid': os.getpid(), 'pgrp': os.getpgrp(), 'session': os.getsid(0)}
forked = {}
for kind in kinds:
    pid = os.fork()
    if pid == 0:
        become(kind)
    forked[kind] = pid
if 'daemon' in forked:
    os.waitpid(forked['daemon'], 0)
deadline = time.monotonic() + 10
while time.monotonic() < deadline and not all(marker(k) and beats(k) >= need for k in kinds):
    time.sleep(0.05)
members = dict((kind, marker(kind)) for kind in kinds)
if members.get('stopped'):
    os.kill(members['stopped'], signal.SIGSTOP)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and (proc(members['stopped']) or {}).get('state') not in ('T', 't'):
        time.sleep(0.05)
record = {'tag': tag, 'path': path, 'root': root, 'members': dict(
    (kind, {'pid': members[kind], 'beats': beats(kind), 'proc': proc(members[kind]) if members[kind] else None})
    for kind in kinds)}
print('UKAI_TREE_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
time.sleep(600 if path == 'wall' else hold)
'''


def tree_argv(tag, path):
    return [harness.PYTHON, '-I', '-c', TREE_PROBE, tag, path, ','.join(TREE_KINDS), str(TREE_MIN_BEATS),
            str(TREE_HOLD_SECONDS)]


def tree_files(tag, path, kind):
    """(marker, heartbeat) names of one tree member, relative to the workspace."""
    prefix = f'tt-{tag}-{path}-{kind}'
    return prefix + '.start', prefix + '.beat'


# The observation fixture: `rounds` rounds of two execs, one granted write,
# one refused write and one refused connect, each result reported; with
# `background`, a descendant left writing at settlement.
OBSERVE_PROBE = r'''
import errno, json, os, socket, subprocess, sys, time
label, rounds, spec = sys.argv[1], int(sys.argv[2]), json.loads(sys.argv[3])
record = {'tag': label, 'rounds': rounds, 'execs': [], 'writes': [], 'denied_writes': [], 'connects': []}
def name(error):
    return errno.errorcode.get(error.errno, 'errno-%s' % error.errno)
for index in range(rounds):
    for argv in spec['execs']:
        try:
            done = subprocess.run(argv, capture_output=True, timeout=20)
            record['execs'].append({'argv': argv, 'returncode': done.returncode})
        except (OSError, subprocess.SubprocessError) as error:
            record['execs'].append({'argv': argv, 'error': type(error).__name__})
    try:
        fd = os.open('obs-%s-%d.txt' % (label, index), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            os.write(fd, ('observed-%s-%d\n' % (label, index)).encode())
        finally:
            os.close(fd)
        record['writes'].append('written')
    except OSError as error:
        record['writes'].append(name(error))
    denied = spec['denied'] % index
    try:
        os.close(os.open(denied, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        result = 'created'
    except OSError as error:
        result = name(error)
    record['denied_writes'].append({'open': result, 'exists_after': os.path.lexists(denied)})
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(float(spec['timeout']))
    try:
        probe.connect(tuple(spec['target']))
        record['connects'].append('connected')
    except socket.timeout:
        record['connects'].append('timeout')
    except OSError as error:
        record['connects'].append(name(error))
    finally:
        probe.close()
if spec['background']:
    marker, beat = 'obs-%s-bg.start' % label, 'obs-%s-bg.beat' % label
    if os.fork() == 0:
        try:
            os.setsid()
            null = os.open('/dev/null', os.O_RDWR)
            for fd in (0, 1, 2):
                os.dup2(null, fd)
            with open(marker, 'w') as output:
                output.write('%d\n' % os.getpid())
            while True:
                fd = os.open(beat, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
                try:
                    os.write(fd, b'beat\n')
                finally:
                    os.close(fd)
                time.sleep(0.1)
        except BaseException:
            pass
        os._exit(0)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not (os.path.exists(marker) and os.path.exists(beat)):
        time.sleep(0.05)
    record['background_started'] = os.path.exists(marker) and os.path.exists(beat)
print('UKAI_OBSERVE_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def observe_label(tag, name):
    return f'{tag}-{OBSERVE_ROUNDS[name][0]}'


def observe_denied(label):
    return f'/etc/ukai-obs-{label}-%d'


def observe_argv(tag, name):
    label, rounds = observe_label(tag, name), OBSERVE_ROUNDS[name][1]
    spec = {'execs': [argv for argv, _ in OBSERVE_EXECS], 'denied': observe_denied(label),
            'target': list(harness.PROBE_TARGET), 'timeout': harness.PROBE_TIMEOUT,
            'background': name == 'observe_background'}
    return [harness.PYTHON, '-I', '-c', OBSERVE_PROBE, label, str(rounds), json.dumps(spec)]


# The syscall probe. It calls nothing unless it runs on Linux aarch64, the
# only machine whose numbers the tables hold.
SYSCALL_PROBE = r'''
import ctypes, errno, json, os, sys
tag, spec = sys.argv[1], json.loads(sys.argv[2])
machine = os.uname().machine
record = {'tag': tag, 'machine': machine, 'platform': sys.platform, 'calls': {}}
status = {}
try:
    with open('/proc/self/status') as source:
        for line in source:
            key, _, value = line.partition(':')
            if key in ('Seccomp', 'Seccomp_filters', 'NoNewPrivs'):
                status[key] = value.strip()
except OSError as error:
    status['error'] = errno.errorcode.get(error.errno, str(error.errno))
record['status'] = status
if sys.platform.startswith('linux') and machine == 'aarch64':
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    for label, number, args in spec['calls']:
        ctypes.set_errno(0)
        ret = libc.syscall(ctypes.c_long(number), *[ctypes.c_long(value) for value in args])
        code = ctypes.get_errno()
        if ret >= 0:
            record['calls'][label] = 'ok'
            if label.startswith('socket_'):
                os.close(ret)
        else:
            record['calls'][label] = errno.errorcode.get(code, 'errno-%d' % code)
else:
    record['skipped'] = 'not linux aarch64'
print('UKAI_SYSCALL_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def syscall_argv(tag):
    calls = [[label, number, list(args)] for label, number, args, *_ in SYSCALL_DENIED + SYSCALL_CONTROLS]
    return [harness.PYTHON, '-I', '-c', SYSCALL_PROBE, tag, json.dumps({'calls': calls})]


# The protected-path probe: every operation's result, never an exit status.
PROTECT_PROBE = r'''
import errno, hashlib, json, os, sys
tag, spec = sys.argv[1], json.loads(sys.argv[2])
record = {'tag': tag, 'cwd': os.getcwd(), 'files': {}, 'dirs': {}, 'absent': {}, 'file_mirrors': {},
          'dir_mirrors': {}, 'absent_controls': {}, 'creates': {}}
counter = [0]
def name(error):
    return errno.errorcode.get(error.errno, 'errno-%s' % error.errno)
def attempt(action):
    try:
        action()
        return 'ok'
    except OSError as error:
        return name(error)
def create(path, text=b'created\n'):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, text)
    finally:
        os.close(fd)
def append(path):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, b'tampered\n')
    finally:
        os.close(fd)
def fresh(kind):
    counter[0] += 1
    return os.path.join(spec['scratch'], '%s-%s-%d' % (kind, tag, counter[0]))
def digest(path):
    try:
        with open(path, 'rb') as source:
            return hashlib.sha256(source.read()).hexdigest()
    except OSError as error:
        return name(error)
def replace(path):
    source = fresh('replace')
    create(source, b'replacement\n')
    try:
        os.rename(source, path)
    finally:
        if os.path.lexists(source):
            os.unlink(source)
def file_ops(path):
    ops = {'read': seen[path]}
    ops['write'] = attempt(lambda: append(path))
    ops['truncate'] = attempt(lambda: os.truncate(path, 0))
    ops['chmod'] = attempt(lambda: os.chmod(path, 0o600))
    ops['replace'] = attempt(lambda: replace(path))
    ops['rename_away'] = attempt(lambda: os.rename(path, path + '.moved'))
    current = path + '.moved' if ops['rename_away'] == 'ok' else path
    ops['unlink'] = attempt(lambda: os.unlink(current))
    return ops
def listing(path):
    try:
        return sorted(os.listdir(path))
    except OSError as error:
        return name(error)
def dir_ops(path):
    ops = {'list': seen[path]}
    ops['create_inside'] = attempt(lambda: create(os.path.join(path, 'new-' + tag)))
    ops['mkdir_inside'] = attempt(lambda: os.mkdir(os.path.join(path, 'newdir-' + tag)))
    ops['symlink_inside'] = attempt(lambda: os.symlink('/tmp', os.path.join(path, 'link-' + tag)))
    ops['chmod'] = attempt(lambda: os.chmod(path, 0o700))
    ops['rename_away'] = attempt(lambda: os.rename(path, path + '-moved'))
    return ops
def onto(path):
    source = fresh('onto')
    os.mkdir(source)
    try:
        os.rename(source, path)
    finally:
        if os.path.lexists(source):
            os.rmdir(source)
def absent_ops(path, apart):
    def at(op):
        return path + '-' + op if apart else path
    ops = {'seen_as': ('dir' if os.path.isdir(path) else 'present') if os.path.lexists(path) else 'absent'}
    ops['mkdir'] = attempt(lambda: os.mkdir(at('mkdir')))
    ops['create_file'] = attempt(lambda: create(at('create_file')))
    ops['symlink'] = attempt(lambda: os.symlink('/tmp', at('symlink')))
    ops['rename_onto'] = attempt(lambda: onto(at('rename_onto')))
    ops['create_inside'] = attempt(lambda: create(os.path.join(at('mkdir'), 'new-' + tag)))
    return ops
def make(path, text):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    create(path, text.encode())
# Every read before any change: no operation below alters what another saw.
seen = dict((path, digest(path)) for path in spec['files'] + spec['file_mirrors'])
seen.update((path, listing(path)) for path in spec['dirs'] + spec['dir_mirrors'])
for path in spec['files']:
    record['files'][path] = file_ops(path)
for path in spec['file_mirrors']:
    record['file_mirrors'][path] = file_ops(path)
for path in spec['dirs']:
    record['dirs'][path] = dir_ops(path)
for path in spec['dir_mirrors']:
    record['dir_mirrors'][path] = dir_ops(path)
for path in spec['absent']:
    record['absent'][path] = absent_ops(path, False)
if spec['absent_control']:
    record['absent_controls'] = absent_ops(spec['absent_control'], True)
for path, text in sorted(spec['creates'].items()):
    record['creates'][path] = attempt(lambda: make(path, text))
print('UKAI_PROTECT_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def protected_layout(tag, profile):
    """What the host seeds, what the probe tries, and what must hold, per profile.

    jail-v1 §9.1 at rc.5: under `tool` every existing `.git` and `.ukai`
    segment beneath a writable root is read-only, and the root-level literals
    are protected even when absent; under `agent` the protected names are
    `.git/config` and `.git/hooks` at any depth, `.git` itself stays
    writable, and nothing is a root literal. Root `.git/config` is main()'s
    sentinel (SENTINEL_TEXT); root `.git/hooks` is seeded here.
    """
    base = f'pc-{tag}-{profile}'
    seeds = {f'{base}/repo/.git/config': f'[core]\n\tbare = false\n# {tag}\n',
             f'{base}/repo/.git/HEAD': 'ref: refs/heads/main\n',
             f'{base}/repo/.git/hooks/pre-commit': '#!/bin/sh\nexit 0\n',
             f'{base}/repo/notgit/HEAD': 'ref: refs/heads/main\n',
             f'{base}/plain/config': f'plain-config-{tag}\n',
             f'{base}/plain/gitlink': f'plain-gitlink-{tag}\n',
             f'{base}/scratch/.keep': ''}
    creates = {f'{base}/ordinary-{tag}.txt': f'ordinary-{tag}\n'}
    if profile == 'tool':
        seeds.update({f'{base}/deep/a/b/.ukai/state': f'state-{tag}\n',
                      f'{base}/deep/a/b/notukai/state': f'state-{tag}\n',
                      f'{base}/wt/.git': 'gitdir: ../repo/.git\n'})
        files = ['.git/config', f'{base}/repo/.git/config', f'{base}/deep/a/b/.ukai/state', f'{base}/wt/.git']
        dirs = ['.git', f'{base}/repo/.git', f'{base}/deep/a/b/.ukai']
        dir_mirrors = [f'{base}/repo/notgit', f'{base}/deep/a/b/notukai']
        mounts = ['.git', '.ukai', f'{base}/repo/.git', f'{base}/deep/a/b/.ukai', f'{base}/wt/.git']
        absent = ['.ukai']
        creates.update({f'.git-sibling-{tag}': f'sibling-{tag}\n', f'.ukai-sibling-{tag}': f'sibling-{tag}\n',
                        f'{base}/repo/x.git/config': f'near-{tag}\n', f'{base}/repo/.github/config': f'near-{tag}\n',
                        f'{base}/deep/a/b/.ukaix/state': f'near-{tag}\n'})
    else:
        seeds['.git/hooks/pre-commit'] = '#!/bin/sh\nexit 0\n'
        files = ['.git/config', '.git/hooks/pre-commit', f'{base}/repo/.git/config',
                 f'{base}/repo/.git/hooks/pre-commit']
        dirs = ['.git/hooks', f'{base}/repo/.git/hooks']
        dir_mirrors = [f'{base}/repo/notgit']
        mounts = ['.git/config', '.git/hooks', f'{base}/repo/.git/config', f'{base}/repo/.git/hooks']
        absent = []
        creates.update({f'.git/agent-control-{tag}': f'writable-{tag}\n',
                        f'{base}/repo/.git/agent-control-{tag}': f'writable-{tag}\n',
                        f'{base}/repo/.git/config-{tag}': f'near-{tag}\n',
                        f'{base}/repo/.git/hooks-{tag}/x': f'near-{tag}\n'})
    return {'profile': profile, 'base': base, 'seeds': seeds, 'files': files, 'dirs': dirs,
            'file_mirrors': [f'{base}/plain/config', f'{base}/plain/gitlink'], 'dir_mirrors': dir_mirrors,
            'mounts': mounts, 'absent': absent, 'absent_control': f'ukai-absent-{tag}' if absent else None,
            'creates': creates, 'scratch': f'{base}/scratch'}


def protect_argv(tag, profile):
    layout = protected_layout(tag, profile)
    spec = {key: layout[key] for key in ('files', 'dirs', 'file_mirrors', 'dir_mirrors', 'absent',
                                         'absent_control', 'creates', 'scratch')}
    return [harness.PYTHON, '-I', '-c', PROTECT_PROBE, f'{tag}-{profile}', json.dumps(spec)]


# The proxy probe: controls first, then the denials, then the tunnels.
PROXY_PROBE = r'''
import errno, json, os, socket, sys, time
tag, spec = sys.argv[1], json.loads(sys.argv[2])
record = {'tag': tag, 'environment': dict((key, os.environ.get(key)) for key in spec['environment'])}
def name(error):
    return errno.errorcode.get(error.errno, 'errno-%s' % error.errno)
def connect(family, address, timeout):
    probe = socket.socket(family, socket.SOCK_STREAM)
    probe.settimeout(timeout)
    try:
        probe.connect(address)
        return 'connected'
    except socket.timeout:
        return 'timeout'
    except OSError as error:
        return name(error)
    finally:
        probe.close()
def listened(family, address):
    listener = socket.socket(family, socket.SOCK_STREAM)
    try:
        listener.bind(address)
        listener.listen(1)
        listener.settimeout(float(spec['connect_timeout']))
        result = {'connect': connect(family, listener.getsockname(), float(spec['connect_timeout']))}
        try:
            listener.accept()[0].close()
            result['accepted'] = True
        except OSError:
            result['accepted'] = False
        return result
    except OSError as error:
        return {'connect': 'listener-' + name(error), 'accepted': False}
    finally:
        listener.close()
def tunnel(host, port):
    result = {'target': [host, port]}
    proxy = os.environ.get('HTTPS_PROXY', '')
    try:
        scheme, _, rest = proxy.partition('://')
        address, _, proxy_port = rest.rstrip('/').rpartition(':')
        if scheme != 'http' or not address or not proxy_port.isdigit():
            raise ValueError('HTTPS_PROXY names no http proxy')
        stream = socket.create_connection((address, int(proxy_port)), timeout=float(spec['tunnel_timeout']))
        try:
            stream.sendall(('CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n' % (host, port, host, port)).encode())
            reply = b''
            while b'\r\n\r\n' not in reply and len(reply) < 8192:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                reply += chunk
        finally:
            stream.close()
        head = reply.split(b'\r\n\r\n', 1)[0].decode('latin-1').split('\r\n')
        result['status_line'] = head[0][:200]
        for line in head[1:]:
            key, _, value = line.partition(':')
            if key.strip().lower() == 'x-ukai-proxy-reason':
                result['reason'] = value.strip()[:100]
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)[:200]
    return result
record['loopback_control'] = listened(socket.AF_INET, ('127.0.0.1', 0))
record['unix_control'] = listened(socket.AF_UNIX, spec['unix_control'])
try:
    os.unlink(spec['unix_control'])
except OSError:
    pass
record['direct'] = connect(socket.AF_INET, tuple(spec['target']), float(spec['connect_timeout']))
record['proxy_socket'] = connect(socket.AF_UNIX, spec['proxy_socket'], float(spec['connect_timeout']))
record['allowed'] = []
for _ in range(int(spec['tries'])):
    reply = tunnel(*spec['target'])
    record['allowed'].append(reply)
    if (reply.get('status_line') or '').split(' ')[1:2] == ['200']:
        break
    time.sleep(1)
record['refused'] = dict((label, tunnel(host, port)) for label, host, port in spec['refused'])
print('UKAI_PROXY_PROBE ' + json.dumps(record, sort_keys=True), flush=True)
'''


def proxy_refused():
    """(label, host, port) the allow set excludes: another address, another
    port of the allowed address, and a loopback port. rc.5's proxy refuses
    each at its first step, the host rule, before any resolution or connect."""
    host, port = harness.PROBE_TARGET
    return [('other_host', '1.0.0.1' if host != '1.0.0.1' else '1.0.0.2', port),
            ('other_port', host, 80 if port != 80 else 8080),
            ('loopback', '127.0.0.1', 22 if (host, port) != ('127.0.0.1', 22) else 23)]


def proxy_argv(tag):
    spec = {'environment': sorted(PROXY_ENVIRONMENT), 'target': list(harness.PROBE_TARGET),
            'unix_control': f'/tmp/ukai-proxy-{tag}.sock', 'proxy_socket': PROXY_SOCKET,
            'connect_timeout': harness.PROBE_TIMEOUT, 'tunnel_timeout': harness.ROUTE_TIMEOUT,
            'tries': PROXY_TRIES, 'refused': [list(entry) for entry in proxy_refused()]}
    return [harness.PYTHON, '-I', '-c', PROXY_PROBE, tag, json.dumps(spec)]


def tagged(stdout, name, tag):
    """The one `name {json}` line whose tag is `tag`, or None (none or several)."""
    found = harness.tagged_records(stdout, name, 'tag', tag)
    return found[0] if len(found) == 1 else None


def outcome(record):
    return ((record.get('receipt') or {}).get('outcome')) or {}


def judge_wall(record, tag, wall):
    limit = harness.receipt_limit(record.get('receipt'), 'wall') or {}
    elapsed = record['timings_ms'].get('released_to_done')
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'later_output_absent': f'never-{tag}' not in record['stdout'] and f'start-{tag}' in record['stdout'],
        'nonzero_exit': record.get('exit_code') not in (0, None),
        'receipt_records_the_wall_hit': limit.get('hit') is True,
        'receipt_cause_is_wall_expiry': outcome(record).get('cause') == 'wall_expiry',
        'ended_by_the_jail_not_the_backstop': elapsed is not None
        and (wall - 1) * 1000 <= elapsed < (wall + BACKSTOP_MARGIN_SECONDS) * 1000,
    }
    return facts


def applied_limit(record, key, value):
    """The receipt applied this limit at exactly `value`, through its cgroup control."""
    entry = harness.receipt_limit(record.get('receipt'), key) or {}
    return (entry.get('requested') == str(value) and entry.get('applied') is True
            and entry.get('mechanism') == {'pids': 'pids.max', 'mem': 'memory.max'}[key])


def judge_pids(record, tag):
    probe = tagged(record['stdout'], 'UKAI_PIDS_PROBE', tag) or {}
    forked = probe.get('forked')
    limit = harness.GUEST_PIDS_LIMIT
    expected_max = probe.get('pids.max')
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'fork_failed_with_eagain': probe.get('fork_error') == 'EAGAIN',
        'stopped_at_the_limit_not_before': isinstance(forked, int) and limit - PIDS_SLACK <= forked < limit,
        # The fork failure is tied to the 64 limit by the receipt (pids=64
        # applied through pids.max, and hit) whether or not the probe can read
        # its cgroup; where it can, the cgroup's own pids.max must be 64.
        'receipt_applied_the_guest_limit': applied_limit(record, 'pids', limit),
        'cgroup_limit_is_the_guest_limit': expected_max in (None, str(limit)),
        'attempt_settled_without_jail_error': (record.get('exit_code') == 0 and not record.get('error')
                                               and not harness.jail_error_lines(record['stdout'] + record['stderr'])
                                               and not (record.get('receipt') or {}).get('errors')),
        'receipt_records_the_pids_hit': (harness.receipt_limit(record.get('receipt'), 'pids') or {}).get('hit') is True,
    }
    if isinstance(forked, int) and probe.get('pids.current') and str(probe.get('pids.current')).isdigit():
        # Where the probe can read its own cgroup, the forks fill it exactly.
        facts['forks_fill_the_cgroup'] = abs(forked + int(probe['pids.current']) - limit) <= 1
    return facts


def judge_mem(record, tag):
    reported = [int(line.split()[2]) for line in record['stdout'].splitlines()
                if line.startswith(f'UKAI_MEM_PROBE {tag} ') and line.split()[2].isdigit()]
    last = reported[-1] if reported else None
    limit = harness.GUEST_MEM_LIMIT_MIB
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'receipt_applied_the_guest_limit': applied_limit(record, 'mem', limit * 1024 * 1024),
        'sigkilled': record.get('exit_code') == 137,
        'never_unbounded': f'UKAI_MEM_UNBOUNDED {tag}' not in record['stdout'],
        'receipt_records_the_oom': ((harness.receipt_limit(record.get('receipt'), 'mem') or {}).get('hit') is True
                                    or outcome(record).get('cause') == 'memory_oom'),
        'killed_near_the_limit': last is not None and limit * MEM_FLOOR_FRACTION <= last < limit,
    }
    return facts


def judge_containment(record, tag, paths, read=(), control=()):
    probe = tagged(record['stdout'], 'UKAI_FS_PROBE', tag) or {}
    results = probe.get('paths') or {}
    reads = probe.get('reads') or {}
    facts = {'receipt_bound_to_this_attempt': harness.receipt_bound(record),
             'every_path_probed': sorted(results) == sorted(paths)
             and sorted(reads) == sorted(set(read) | set(control))}
    for path in paths:
        entry = results.get(path) or {}
        facts[f'write_refused:{path}'] = entry.get('open') in FS_REFUSALS and entry.get('exists_after') is False
    for path in read:
        facts[f'read_refused:{path}'] = reads.get(path) in READ_REFUSALS
    for path in control:
        facts[f'control_read:{path}'] = reads.get(path) == 'read'
    return facts


def judge_network(record, tag, status, reachability, route):
    """network_none: the probe attempt, and the route control attempt on the same boot."""
    probe = harness.probe_verdict(record['stdout'], tag)
    network = (((record.get('receipt') or {}).get('applied') or {}).get('network') or {})
    route = route or {'stdout': ''}
    denial = harness.network_denial(probe, harness.route_verdict(route['stdout'], route_tag(tag)),
                                    (status or {}).get('guest_nat'), harness.guest_boot(record),
                                    harness.guest_boot(route), harness.receipt_bound(route))
    return {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'nat_attached': denial['guest_nat_attached'],
        'probe_denied_after_positive_control': denial['probe_saw_the_jails_denial'],
        'route_control_reached_the_target': denial['route_control_reached_the_target'],
        'route_control_on_the_same_guest_boot': denial['route_control_on_the_same_guest_boot'],
        'route_control_receipt_bound': denial['route_control_receipt_bound'],
        'dns_unresolved': probe.get('dns') not in (None, 'resolved'),
        'receipt_network_none': network.get('mode') == 'none',
        'target_answers_from_host': (reachability or {}).get('answers') is True,
    }


def judge_workspace(record, tag, host_text):
    return {'receipt_bound_to_this_attempt': harness.receipt_bound(record),
            'wrote': f'wrote-{tag}' in record['stdout'],
            'host_has_this_runs_bytes': host_text == f'live-{tag}\n'}


def receipt_of(record):
    return (record or {}).get('receipt') or {}


def policy_requires(record, name):
    """The attempt ran under a policy that requires this capability's requirement."""
    return REQUIREMENTS[name] in ((receipt_of(record).get('policy') or {}).get('requirements') or [])


def settled_clean(record):
    return (record.get('exit_code') == 0 and not record.get('error')
            and not harness.jail_error_lines((record.get('stdout') or '') + (record.get('stderr') or ''))
            and receipt_of(record).get('errors') == [])


def lifetime_details(record):
    return ((receipt_of(record).get('lifetime') or {}).get('native') or {}).get('details') or {}


def marker_pid(text):
    text = (text or '').strip()
    return int(text) if text.isdigit() else None


def kind_confirmed(kind, member, root):
    """What /proc said of one tree member, against what its kind must be."""
    member = member or {}
    facts = member.get('proc') or {}
    pid = member.get('pid')
    if not isinstance(pid, int) or not facts or not root.get('pid'):
        return False
    with_root = facts.get('session') == root.get('session')
    if kind == 'normal':
        return facts.get('ppid') == root['pid'] and facts.get('pgrp') == root.get('pgrp') and with_root
    if kind == 'sigterm_ignored':
        return facts.get('sigterm_ignored') is True and facts.get('ppid') == root['pid']
    if kind == 'setsid':
        return facts.get('session') == pid and facts.get('pgrp') == pid
    if kind == 'daemon':
        # setsid, then a second fork: the member leads neither its session
        # nor its group, and its parent (the first fork) is gone.
        return (facts.get('session') == facts.get('pgrp') and facts.get('session') not in (pid, root.get('session'))
                and facts.get('ppid') != root['pid'])
    if kind == 'stopped':
        return facts.get('state') in ('T', 't')
    if kind == 'own_pgid':
        return facts.get('pgrp') == pid and with_root
    return False


def guest_stop_reported(stop):
    """The guest controller's stop report, well formed (harness record['guest_stop'])."""
    if not isinstance(stop, dict) or not all(isinstance(stop.get(key), list) for key in GUEST_STOP_LISTS):
        return False
    pairs = stop['live_before_kill'] + stop['strays_killed']
    return (all(isinstance(name, str) for name in stop['boundaries'] + stop['populated_before_kill'])
            and all(isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], int) for pair in pairs))


def judge_tree(record, tag, path, watch):
    """tree_termination on one end path: `exit` (the root returns 0 at once)
    or `wall` (the root outlives the wall)."""
    record = record or {}
    watch = watch or {}
    probe = tagged(record.get('stdout'), 'UKAI_TREE_PROBE', tag) or {}
    members = probe.get('members') or {}
    root = probe.get('root') or {}
    lifetime = receipt_of(record).get('lifetime') or {}
    markers = watch.get('markers') or {}
    at_done = watch.get('at_done') or {}
    during = watch.get('during') or []
    settled_from, settled_to = watch.get('settled_from') or {}, watch.get('settled_to') or {}
    stop = record.get('guest_stop')
    stop = stop if isinstance(stop, dict) else {}
    if path == 'exit':
        ended = outcome(record).get('kind') == 'exited' and outcome(record).get('code') == 0
    else:
        ended = ((harness.receipt_limit(record.get('receipt'), 'wall') or {}).get('hit') is True
                 and outcome(record).get('cause') == 'wall_expiry')
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'policy_requires_tree_termination': policy_requires(record, 'tree_termination'),
        'probe_reported_this_path': probe.get('path') == path and sorted(members) == sorted(TREE_KINDS),
        **{f'kind_confirmed:{kind}': kind_confirmed(kind, members.get(kind), root) for kind in TREE_KINDS},
        # The host saw each member's own marker (the pid the probe names).
        'every_marker_seen': all(marker_pid(markers.get(kind)) is not None
                                 and marker_pid(markers.get(kind)) == (members.get(kind) or {}).get('pid')
                                 for kind in TREE_KINDS),
        'every_member_beat': all(isinstance(at_done.get(kind), int) and at_done[kind] >= TREE_MIN_BEATS
                                 for kind in TREE_KINDS),
        # The positive control of the settle window: through the share, the
        # host saw each running member's beats GROW while the attempt ran.
        # (The stopped member stops at its second beat: its survival is the
        # guest stop's to witness.)
        'growth_seen_during_the_attempt': all(
            len({sample.get(kind) for sample in during if isinstance(sample.get(kind), int)}) >= 2
            for kind in TREE_KINDS if kind != 'stopped'),
        'no_beat_after_settlement': (all(isinstance(settled_from.get(kind), int) for kind in TREE_KINDS)
                                     and all(settled_to.get(kind) == settled_from.get(kind) for kind in TREE_KINDS)),
        'receipt_tree_empty': lifetime.get('tree_empty') is True,
        'receipt_integrity_verified': lifetime.get('integrity') == 'verified',
        'receipt_boundary_pid_namespace': lifetime.get('boundary') == 'pid_namespace',
        'receipt_scope_attempt_tree': lifetime.get('verification_scope') == 'attempt_tree',
        f'ended_by_{"target_exit" if path == "exit" else "wall_expiry"}': ended,
        'guest_stop_reported': guest_stop_reported(record.get('guest_stop')),
        # The stop's witness is non-vacuous only if it looked at this
        # attempt's own cgroup.
        'guest_stop_covered_the_attempt_cgroup': isinstance(stop.get('boundaries'), list) and any(
            isinstance(name, str) and name.startswith(ATTEMPT_CGROUP_PREFIX) for name in stop['boundaries']),
        'guest_stop_found_no_populated_boundary': stop.get('populated_before_kill') == [],
        'guest_stop_found_no_live_process': stop.get('live_before_kill') == [],
        'guest_stop_killed_no_stray': stop.get('strays_killed') == [],
    }
    return facts


def tree_notes(record):
    """What tree_termination records but does not require."""
    receipt = receipt_of(record)
    return {'exit_code': record.get('exit_code'), 'error': record.get('error'),
            'receipt_errors': [error.get('code') for error in receipt.get('errors') or [] if isinstance(error, dict)],
            'outcome': outcome(record)}


def judge_tree_paths(results, tag, watches):
    facts = {}
    for name, path in TREE_PATHS.items():
        for key, value in judge_tree(results.get(name), tag, path, watches.get(name)).items():
            facts[f'{path}:{key}'] = value
    return facts


def trace_counts(record):
    """Per audit class, the audit results in the forwarded evidence trace
    (record['files']), or None when there is not exactly one readable trace."""
    traces = [entry for entry in (record or {}).get('files') or []
              if entry.get('group') == 'evidence' and Path(entry.get('path') or '').name == 'trace.ndjson']
    if len(traces) != 1 or not isinstance(traces[0].get('text'), str):
        return None
    counts = dict((name, 0) for name in AUDIT_CLASSES)
    for line in traces[0]['text'].splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            return None
        operation = event.get('operation') if isinstance(event, dict) else None
        if event.get('source') == 'audit' and event.get('stage') == 'result' and operation in TRACE_CLASSES:
            counts[TRACE_CLASSES[operation]] += 1
    return counts


def class_count(record, name):
    entry = (receipt_of(record).get('coverage') or {}).get(name) or {}
    count = entry.get('observed_count')
    return count if entry.get('status') == 'active' and isinstance(count, int) else None


def observer_facts(record):
    observer = receipt_of(record).get('observer') or {}
    return {'observer_attached': observer.get('attached') is True and observer.get('backend') == 'ptrace',
            'observer_set_linux_closed_v1': observer.get('set') == 'linux-closed-v1',
            'observer_without_gaps': observer.get('gaps') == []}


def judge_observe_run(record, tag, name, host):
    """One closed_set_observation fixture run: what it did, and what the
    receipt (and the trace behind it) counted of it."""
    record = record or {}
    label, rounds = observe_label(tag, name), OBSERVE_ROUNDS[name][1]
    probe = tagged(record.get('stdout'), 'UKAI_OBSERVE_PROBE', label) or {}
    coverage = receipt_of(record).get('coverage') or {}
    expected_execs = [{'argv': argv, 'returncode': code} for _ in range(rounds) for argv, code in OBSERVE_EXECS]
    denied = probe.get('denied_writes') or []
    writes = (host or {}).get('writes') or {}
    trace = trace_counts(record)
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'policy_requires_closed_set_observation': policy_requires(record, 'closed_set_observation'),
        **observer_facts(record),
        'fixture_ran_every_round': probe.get('rounds') == rounds and probe.get('execs') == expected_execs,
        'granted_writes_written': probe.get('writes') == ['written'] * rounds,
        'denied_writes_refused': len(denied) == rounds and all(
            entry.get('open') in DENIED_WRITE_ERRNOS and entry.get('exists_after') is False for entry in denied),
        'connects_refused_by_the_namespace': probe.get('connects') == [harness.DENIAL_ERRNOS[0]] * rounds,
        'host_has_the_granted_writes': writes == dict(
            (f'obs-{label}-{index}.txt', f'observed-{label}-{index}\n') for index in range(rounds)),
        'trace_counts_match_the_receipt': trace is not None and all(
            trace[cls] == (coverage.get(cls) or {}).get('observed_count') for cls in AUDIT_CLASSES),
        'settled_without_error': settled_clean(record),
    }
    for cls in AUDIT_CLASSES:
        entry = coverage.get(cls) or {}
        count = entry.get('observed_count')
        facts[f'class_counted:{cls}'] = (entry.get('status') == 'active' and entry.get('gaps') == []
                                         and isinstance(count, int) and count >= rounds * PER_ROUND[cls])
    return facts


def judge_observe_background(record, tag, host):
    """A descendant still writing when the target exits: its loss is named."""
    record = record or {}
    name = 'observe_background'
    label = observe_label(tag, name)
    probe = tagged(record.get('stdout'), 'UKAI_OBSERVE_PROBE', label) or {}
    receipt = receipt_of(record)
    coverage = receipt.get('coverage') or {}
    host = host or {}
    beats = host.get('beats')
    degraded = [cls for cls in AUDIT_CLASSES if (coverage.get(cls) or {}).get('status') == 'degraded']
    error_codes = [error.get('code') for error in receipt.get('errors') or [] if isinstance(error, dict)]
    trace = trace_counts(record)
    write = coverage.get('fs.write') or {}
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'policy_requires_closed_set_observation': policy_requires(record, 'closed_set_observation'),
        **observer_facts(record),
        'descendant_started': (probe.get('background_started') is True
                               and marker_pid(host.get('marker')) is not None and isinstance(beats, int) and beats >= 1),
        'loss_named_in_the_receipt_errors': not degraded or 'evidence_lost' in error_codes,
        # A class that stayed complete must account for every beat the host
        # saw: each was a mutating open (plus the round's write and the marker).
        'fs_write_accounts_for_every_beat': (
            'fs.write' in degraded
            or (isinstance(write.get('observed_count'), int) and isinstance(beats, int)
                and write['observed_count'] >= 2 + beats)),
        'trace_counts_match_every_complete_class': trace is not None and all(
            trace[cls] == class_count(record, cls) for cls in AUDIT_CLASSES if cls not in degraded),
    }
    for cls in AUDIT_CLASSES:
        entry = coverage.get(cls) or {}
        gaps = entry.get('gaps')
        complete = (entry.get('status') == 'active' and isinstance(entry.get('observed_count'), int) and gaps == [])
        named = (entry.get('status') == 'degraded' and entry.get('observed_count') is None and isinstance(gaps, list)
                 and bool(gaps) and all(cls in (gap.get('classes') or []) for gap in gaps))
        facts[f'no_silent_loss:{cls}'] = complete or named
    return facts


def judge_observation(results, tag, hosts):
    facts = {}
    for name in ('closed_set_observation', 'observe_3'):
        short = OBSERVE_ROUNDS[name][0]
        for key, value in judge_observe_run(results.get(name), tag, name, hosts.get(name)).items():
            facts[f'{short}:{key}'] = value
    extra = OBSERVE_ROUNDS['observe_3'][1] - OBSERVE_ROUNDS['closed_set_observation'][1]
    for cls in AUDIT_CLASSES:
        low, high = class_count(results.get('closed_set_observation'), cls), class_count(results.get('observe_3'), cls)
        facts[f'count_growth:{cls}'] = low is not None and high is not None and high - low == extra * PER_ROUND[cls]
    short = OBSERVE_ROUNDS['observe_background'][0]
    for key, value in judge_observe_background(results.get('observe_background'), tag,
                                               hosts.get('observe_background')).items():
        facts[f'{short}:{key}'] = value
    return facts


def judge_syscall(record, tag):
    record = record or {}
    probe = tagged(record.get('stdout'), 'UKAI_SYSCALL_PROBE', tag) or {}
    calls = probe.get('calls') or {}
    status = probe.get('status') or {}
    filters = lifetime_details(record).get('seccomp_filters') or {}
    observed = filters.get('observed')
    labels = [entry[0] for entry in SYSCALL_DENIED + SYSCALL_CONTROLS]
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'policy_requires_syscall_filter': policy_requires(record, 'syscall_filter'),
        'probe_ran_on_linux_aarch64': (probe.get('machine') == 'aarch64'
                                       and str(probe.get('platform') or '').startswith('linux')
                                       and 'skipped' not in probe),
        'every_call_made': sorted(calls) == sorted(labels),
        'seccomp_filter_mode': status.get('Seccomp') == '2',
        'no_new_privs': status.get('NoNewPrivs') == '1',
        # The probe's own filter stack is the one the receipt says it installed.
        'filters_match_the_receipt': (isinstance(observed, int) and observed >= 1 and observed == filters.get('expected')
                                      and status.get('Seccomp_filters') == str(observed)),
        'attempt_settled_without_jail_error': settled_clean(record),
    }
    for label, _, _, answer, _ in SYSCALL_DENIED:
        facts[f'denied:{label}'] = calls.get(label) == answer
    for label, _, _, answer in SYSCALL_CONTROLS:
        facts[f'control:{label}'] = calls.get(label) == answer
    return facts


def host_entry(path):
    """The host's view of one workspace path: kind, mode, inode, and its bytes'
    digest or its listing."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {'kind': 'absent'}
    except OSError as error:
        return {'kind': 'unreadable', 'errno': error.errno}
    entry = {'mode': oct(stat.S_IMODE(info.st_mode)), 'ino': info.st_ino}
    if stat.S_ISLNK(info.st_mode):
        entry.update(kind='symlink', target=os.readlink(path))
    elif stat.S_ISDIR(info.st_mode):
        entry.update(kind='dir', entries=sorted(os.listdir(path)))
    elif stat.S_ISREG(info.st_mode):
        entry.update(kind='file', sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())
    else:
        entry.update(kind='other')
    return entry


def protected_names(layout, probe_tag):
    """Every workspace path a protected_coverage verdict reads on the host."""
    names = set(layout['files'] + layout['file_mirrors'] + layout['dirs'] + layout['dir_mirrors']
                + layout['absent'] + list(layout['creates']))
    names |= {path + '.moved' for path in layout['files'] + layout['file_mirrors']}
    names |= {path + '-moved' for path in layout['dirs'] + layout['dir_mirrors']}
    for path in layout['dirs']:
        names |= {f'{path}/{prefix}-{probe_tag}' for prefix in ('new', 'newdir', 'link')}
    for path in layout['absent']:
        names.add(f'{path}/new-{probe_tag}')
    if layout['absent_control']:
        names |= {f'{layout["absent_control"]}-{op}' for op in ABSENT_CONTROL_KINDS}
        names.add(f'{layout["absent_control"]}-mkdir/new-{probe_tag}')
    return sorted(names)


def protected_snapshot(workspace, layout, probe_tag):
    return dict((name, host_entry(Path(workspace) / name)) for name in protected_names(layout, probe_tag))


def seed_protected(workspace, layout):
    for name, text in layout['seeds'].items():
        path = Path(workspace) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def judge_protected(record, tag, profile, before, after):
    """protected_coverage:existing_and_root under one profile."""
    record = record or {}
    layout = protected_layout(tag, profile)
    probe_tag = f'{tag}-{profile}'
    probe = tagged(record.get('stdout'), 'UKAI_PROTECT_PROBE', probe_tag) or {}
    filesystem = (receipt_of(record).get('applied') or {}).get('filesystem') or {}
    mounts = [(entry.get('path'), entry.get('mode')) for entry in filesystem.get('mounts') or []
              if isinstance(entry, dict)]
    before, after = before or {}, after or {}

    def was(name):
        return before.get(name) or {}

    def now(name):
        return after.get(name) or {}
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'policy_requires_protected_coverage': policy_requires(record, 'protected_coverage'),
        'receipt_names_existing_and_root': filesystem.get('protected_coverage') == 'existing_and_root',
        'probe_ran_in_the_workspace': probe.get('cwd') == WORKSPACE_MOUNT,
    }
    for path in layout['mounts']:
        facts[f'receipt_mounts_read_only:{path}'] = (f'{WORKSPACE_MOUNT}/{path}', 'ro') in mounts
    for path in layout['files']:
        ops = (probe.get('files') or {}).get(path) or {}
        facts[f'saw_the_bytes:{path}'] = was(path).get('kind') == 'file' and ops.get('read') == was(path).get('sha256')
        facts[f'refused:{path}'] = all(ops.get(op) in PROTECT_REFUSALS for op in PROTECT_FILE_OPS)
        facts[f'unchanged_on_host:{path}'] = (was(path).get('kind') == 'file' and now(path) == was(path)
                                               and now(path + '.moved').get('kind') == 'absent')
    for path in layout['dirs']:
        ops = (probe.get('dirs') or {}).get(path) or {}
        made = [f'{path}/{prefix}-{probe_tag}' for prefix in ('new', 'newdir', 'link')]
        facts[f'saw_the_listing:{path}'] = was(path).get('kind') == 'dir' and ops.get('list') == was(path).get('entries')
        facts[f'refused:{path}'] = all(ops.get(op) in PROTECT_REFUSALS for op in PROTECT_DIR_OPS)
        facts[f'unchanged_on_host:{path}'] = (was(path).get('kind') == 'dir' and now(path) == was(path)
                                               and now(path + '-moved').get('kind') == 'absent'
                                               and all(now(name).get('kind') == 'absent' for name in made))
    for path in layout['file_mirrors']:
        ops = (probe.get('file_mirrors') or {}).get(path) or {}
        facts[f'control_saw_the_bytes:{path}'] = (was(path).get('kind') == 'file'
                                                   and ops.get('read') == was(path).get('sha256'))
        facts[f'control_succeeded:{path}'] = all(ops.get(op) == 'ok' for op in PROTECT_FILE_OPS)
        facts[f'control_effect_on_host:{path}'] = (was(path).get('kind') == 'file' and now(path).get('kind') == 'absent'
                                                    and now(path + '.moved').get('kind') == 'absent')
    for path in layout['dir_mirrors']:
        ops = (probe.get('dir_mirrors') or {}).get(path) or {}
        moved = now(path + '-moved')
        made = {f'{prefix}-{probe_tag}' for prefix in ('new', 'newdir', 'link')}
        facts[f'control_saw_the_listing:{path}'] = (was(path).get('kind') == 'dir'
                                                     and ops.get('list') == was(path).get('entries'))
        facts[f'control_succeeded:{path}'] = all(ops.get(op) == 'ok' for op in PROTECT_DIR_OPS)
        facts[f'control_effect_on_host:{path}'] = (was(path).get('kind') == 'dir' and now(path).get('kind') == 'absent'
                                                    and moved.get('kind') == 'dir' and moved.get('mode') == '0o700'
                                                    and made <= set(moved.get('entries') or []))
    for path in layout['absent']:
        ops = (probe.get('absent') or {}).get(path) or {}
        facts[f'absent_refused:{path}'] = all(
            ops.get(op) in (ABSENT_REFUSALS + ('ENOENT',) if op == 'create_inside' else ABSENT_REFUSALS)
            for op in ABSENT_OPS)
        facts[f'still_absent_on_host:{path}'] = (was(path).get('kind') == 'absent' and now(path).get('kind') == 'absent'
                                                  and now(f'{path}/new-{probe_tag}').get('kind') == 'absent')
    control = layout['absent_control']
    if control:
        ops = probe.get('absent_controls') or {}
        facts['absent_control_succeeded'] = all(ops.get(op) == 'ok' for op in ABSENT_OPS)
        facts['absent_control_effect_on_host'] = (
            all(was(f'{control}-{op}').get('kind') == 'absent' and now(f'{control}-{op}').get('kind') == kind
                for op, kind in ABSENT_CONTROL_KINDS.items())
            and now(f'{control}-mkdir/new-{probe_tag}').get('kind') == 'file')
    for path, text in sorted(layout['creates'].items()):
        facts[f'created:{path}'] = ((probe.get('creates') or {}).get(path) == 'ok' and was(path).get('kind') == 'absent'
                                    and now(path).get('kind') == 'file'
                                    and now(path).get('sha256') == hashlib.sha256(text.encode()).hexdigest())
    return facts


def judge_protected_profiles(results, tag, views):
    facts = {}
    for name, profile in PROTECT_PROFILES.items():
        view = views.get(name) or {}
        for key, value in judge_protected(results.get(name), tag, profile, view.get('before'),
                                          view.get('after')).items():
            facts[f'{profile}:{key}'] = value
    return facts


def proxy_reached(reply):
    return (reply.get('target') == list(harness.PROBE_TARGET) and isinstance(reply.get('status_line'), str)
            and bool(harness.ROUTE_REACHED.match(reply['status_line'])))


def judge_proxy(record, tag):
    record = record or {}
    probe = tagged(record.get('stdout'), 'UKAI_PROXY_PROBE', tag) or {}
    network = (receipt_of(record).get('applied') or {}).get('network') or {}
    counted = (receipt_of(record).get('coverage') or {}).get('proxy.net') or {}
    tries = [reply for reply in probe.get('allowed') or [] if isinstance(reply, dict)]
    refused = probe.get('refused') or {}
    facts = {
        'receipt_bound_to_this_attempt': harness.receipt_bound(record),
        'policy_requires_network_proxy': policy_requires(record, 'network_proxy'),
        'receipt_applied_proxy_with_exactly_the_target': (network.get('mode') == 'proxy'
                                                          and network.get('allowed_hosts') == [harness.route_rule()]),
        # Every CONNECT the probe made is one proxy.net result.
        'receipt_counted_every_request': (counted.get('status') == 'active'
                                          and counted.get('observed_count') == len(tries) + len(refused)),
        'environment_is_the_bridges': probe.get('environment') == PROXY_ENVIRONMENT,
        'loopback_control_connected': probe.get('loopback_control') == {'connect': 'connected', 'accepted': True},
        'direct_connect_denied': probe.get('direct') in harness.DENIAL_ERRNOS,
        'unix_control_connected': probe.get('unix_control') == {'connect': 'connected', 'accepted': True},
        'proxy_socket_refused': probe.get('proxy_socket') == 'EACCES',
        'every_try_recorded': (1 <= len(tries) <= PROXY_TRIES and not any(proxy_reached(reply) for reply in tries[:-1])
                               and (proxy_reached(tries[-1]) or len(tries) == PROXY_TRIES)),
        'allowed_target_reached': bool(tries) and proxy_reached(tries[-1]),
        'attempt_settled_without_jail_error': settled_clean(record),
    }
    for label, host, port in proxy_refused():
        reply = refused.get(label) or {}
        facts[f'refused:{label}'] = (reply.get('target') == [host, port]
                                     and str(reply.get('status_line') or '').startswith('HTTP/1.1 403 ')
                                     and reply.get('reason') == PROXY_REFUSAL_REASON)
    return facts


def route_tag(tag):
    return f'{tag}-route'


def read_controls(tag):
    return [harness.PYTHON, f'capability-read-{tag}.txt']


def plan(tag):
    """(name, wall, argv, options) per attempt; argv is plain text, encoded later.

    `route_control` is not a capability: it is network_none's same-boot
    route control (an agent attempt allowed exactly the probe target).
    `tree_wall`, `observe_3`, `observe_background` and `protected_agent` are
    the further attempts of the capability CAPABILITY_ATTEMPTS names.
    """
    fs_paths = [f'/etc/ukai-cap-{tag}', f'/usr/local/bin/ukai-cap-{tag}', f'/ukai-cap-{tag}']
    proxy = {'profile': 'agent', 'allow_hosts': [harness.route_rule()]}
    return fs_paths, [
        ('wall', 5, harness.sh(f'echo start-{tag}; sleep 30; echo never-{tag}'), {}),
        ('pids', 30, [harness.PYTHON, '-I', '-c', PIDS_PROBE, tag], {}),
        ('mem', 60, [harness.PYTHON, '-I', '-c', MEM_PROBE, tag, str(harness.GUEST_MEM_LIMIT_MIB)], {}),
        ('containment', 30, fs_probe_argv(tag, fs_paths, READ_OUTSIDE, read_controls(tag)), {}),
        ('network_none', 30, harness.probe_argv(tag, dns='example.com'), {}),
        ('route_control', 30, harness.route_argv(route_tag(tag)), dict(proxy)),
        ('workspace', 30, harness.sh(f'printf "live-{tag}\\n" > capability-{tag}.txt; echo wrote-{tag}'), {}),
        ('tree_termination', TREE_EXIT_WALL, tree_argv(tag, TREE_PATHS['tree_termination']), {}),
        ('tree_wall', TREE_WALL, tree_argv(tag, TREE_PATHS['tree_wall']), {}),
        ('closed_set_observation', 30, observe_argv(tag, 'closed_set_observation'), {}),
        ('observe_3', 30, observe_argv(tag, 'observe_3'), {}),
        ('observe_background', 30, observe_argv(tag, 'observe_background'), {}),
        ('syscall_filter', 30, syscall_argv(tag), {}),
        ('protected_coverage', 30, protect_argv(tag, PROTECT_PROFILES['protected_coverage']), {}),
        ('protected_agent', 30, protect_argv(tag, PROTECT_PROFILES['protected_agent']), {'profile': 'agent'}),
        ('network_proxy', PROXY_WALL, proxy_argv(tag), dict(proxy)),
    ]


def read_text(path):
    try:
        return Path(path).read_text()
    except (OSError, UnicodeDecodeError):
        return None


def beat_counts(workspace, files):
    """Each member's beats as the host sees them now (None: no beat file)."""
    counts = {}
    for kind, (_, beat) in files.items():
        try:
            counts[kind] = (Path(workspace) / beat).read_bytes().count(b'\n')
        except OSError:
            counts[kind] = None
    return counts


def watch_tree(run, workspace, tag, path, sleep=time.sleep):
    """Run one tree attempt on a worker thread while the host samples the
    members' beats through the share; then the settle window after `done`.

    Returns (record, watch): `during` holds each distinct sample taken while
    the attempt ran, `at_done` the first after it, and `settled_from` /
    `settled_to` open and close the TREE_SETTLE_SECONDS window that starts
    TREE_SHARE_GRACE after `done`.
    """
    files = dict((kind, tree_files(tag, path, kind)) for kind in TREE_KINDS)
    box = {}

    def attempt():
        try:
            box['record'] = run()
        except BaseException as error:  # re-raised on the caller's thread
            box['error'] = error
    worker = threading.Thread(target=attempt, name=f'tree-{path}', daemon=True)
    worker.start()
    during = []
    while worker.is_alive():
        sample = beat_counts(workspace, files)
        if not during or during[-1] != sample:
            during.append(sample)
        worker.join(TREE_POLL)
    if 'error' in box:
        raise box['error']
    at_done = beat_counts(workspace, files)
    sleep(TREE_SHARE_GRACE)
    settled_from = beat_counts(workspace, files)
    sleep(TREE_SETTLE_SECONDS)
    settled_to = beat_counts(workspace, files)
    markers = dict((kind, read_text(Path(workspace) / marker)) for kind, (marker, _) in files.items())
    return box['record'], {'markers': markers, 'during': during, 'at_done': at_done,
                           'settled_from': settled_from, 'settled_to': settled_to}


def observe_view(workspace, tag, name):
    """The host's view of one observation run: its granted writes and, for
    the background case, the descendant's marker and beats."""
    label, rounds = observe_label(tag, name), OBSERVE_ROUNDS[name][1]
    view = {'writes': dict((f'obs-{label}-{index}.txt', read_text(Path(workspace) / f'obs-{label}-{index}.txt'))
                           for index in range(rounds))}
    view['writes'] = dict((key, value) for key, value in view['writes'].items() if value is not None)
    if name == 'observe_background':
        view['marker'] = read_text(Path(workspace) / f'obs-{label}-bg.start')
        beats = read_text(Path(workspace) / f'obs-{label}-bg.beat')
        view['beats'] = beats.count('\n') if beats is not None else None
    return view


def measure(service, workspace, tag, reachability, sleep=time.sleep):
    """Run every capability attempt on one warm boot; nothing judged here."""
    fs_paths, attempts = plan(tag)
    workspace = Path(workspace)
    # The read control's workspace file: the probe must be able to read it.
    (workspace / f'capability-read-{tag}.txt').write_text(f'readable-{tag}\n')
    layouts = dict((name, protected_layout(tag, profile)) for name, profile in PROTECT_PROFILES.items())
    for layout in layouts.values():
        seed_protected(workspace, layout)
    results, watches, protected = {}, {}, {}
    for name, wall, argv, options in attempts:
        def run(name=name, wall=wall, argv=argv, options=options):
            return harness.run_attempt(service.connect, f'cap-{name}-{tag}', argv, wall=wall, **options)
        if name in TREE_PATHS:
            results[name], watches[name] = watch_tree(run, workspace, tag, TREE_PATHS[name], sleep)
        elif name in PROTECT_PROFILES:
            probe_tag = f'{tag}-{PROTECT_PROFILES[name]}'
            before = protected_snapshot(workspace, layouts[name], probe_tag)
            results[name] = run()
            protected[name] = {'before': before, 'after': protected_snapshot(workspace, layouts[name], probe_tag)}
        else:
            results[name] = run()
    host_file = workspace / f'capability-{tag}.txt'
    return {'tag': tag, 'fs_paths': fs_paths, 'results': results,
            'host_workspace_file': host_file.read_text() if host_file.is_file() else None,
            'reachability': reachability, 'tree_watch': watches, 'protected': protected,
            'observe_host': dict((name, observe_view(workspace, tag, name)) for name in OBSERVE_ROUNDS)}


def judge(measured, status, git_config_untouched, service_exit):
    tag, results = measured['tag'], measured['results']
    walls = dict((name, wall) for name, wall, _, _ in plan(tag)[1])
    facts = {
        'wall': judge_wall(results['wall'], tag, walls['wall']),
        'pids': judge_pids(results['pids'], tag),
        'mem': judge_mem(results['mem'], tag),
        'containment': judge_containment(results['containment'], tag, measured['fs_paths'],
                                         READ_OUTSIDE, read_controls(tag)),
        'network_none': judge_network(results['network_none'], tag, status, measured['reachability'],
                                      results.get('route_control')),
        'workspace': judge_workspace(results['workspace'], tag, measured['host_workspace_file']),
        'tree_termination': judge_tree_paths(results, tag, measured.get('tree_watch') or {}),
        'closed_set_observation': judge_observation(results, tag, measured.get('observe_host') or {}),
        'syscall_filter': judge_syscall(results.get('syscall_filter'), tag),
        'protected_coverage': judge_protected_profiles(results, tag, measured.get('protected') or {}),
        'network_proxy': judge_proxy(results.get('network_proxy'), tag),
    }
    summary = {name: all(value is True for value in checks.values()) for name, checks in facts.items()}
    summary['git_config_untouched'] = git_config_untouched is True
    summary['service_stopped_cleanly'] = service_exit == 0
    summary['outcome'] = 'PASS' if all(summary.values()) else 'FAIL'
    return facts, summary


def measurements(measured, summary):
    """{requirement: verdict, time, attempt}: one measured requirement per entry.

    A requirement's verdict also needs the run-wide conditions it was
    measured under (the protected .git untouched, the serve's clean stop).
    Each entry lists every attempt its verdict read (`attempt_ids`, its own
    first); tree_termination's also records what was not measured.
    """
    shared = summary['git_config_untouched'] and summary['service_stopped_cleanly']
    results = measured['results']
    entries = {}
    for name, requirement in REQUIREMENTS.items():
        attempts = [results.get(attempt) or {} for attempt in CAPABILITY_ATTEMPTS.get(name, (name,))]
        entries[requirement] = {'verdict': summary[name] is True and shared,
                                'measured_at': results[name]['started_at'],
                                'attempt_id': results[name]['attempt_id'],
                                'attempt_ids': [attempt.get('attempt_id') for attempt in attempts],
                                'capability': name}
        if name in NOT_MEASURED:
            entries[requirement]['not_measured'] = NOT_MEASURED[name]
    entries['tree_termination']['notes'] = dict(
        (attempt, tree_notes(results.get(attempt) or {})) for attempt in TREE_PATHS)
    route = results.get('route_control')
    entries['network_none']['control_attempt_id'] = route.get('attempt_id') if route else None
    return entries


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    home = Path(argv[0]).resolve(strict=True)
    workspace = harness.guarded_workspace(argv[1])
    binary = harness.required_binary('UKAI_VM_BINARY')
    out = harness.fresh_out_dir(argv[2])
    removed = harness.clean_workspace(workspace)
    git_config = harness.protected_sentinel(workspace)
    tag = harness.nonce()
    reachability = harness.host_reachability()
    data = tempfile.mkdtemp(prefix='cap-')
    with harness.Service(binary, home, workspace, data, extra=('--guest-nat',)) as service:
        status = service.warm_status
        measured = measure(service, workspace, tag, reachability)
    git_untouched = git_config.read_text() == '[core]\n'
    facts, summary = judge(measured, status, git_untouched, service.child.returncode)
    record = {'schema': 'ukai.vm.capabilities/2', 'binary': harness.fingerprint(binary),
              'measured_at': measured['results']['wall']['started_at'],
              'measurements': measurements(measured, summary),
              'status': status, 'workspace_cleaned': removed, 'facts': facts,
              'summary': summary, 'service_exit': service.child.returncode,
              'service_stderr': service.stderr_text()[-2000:], **measured}
    harness.write_json(out / 'capabilities.json', record)
    print(json.dumps(summary))
    return 0 if summary['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
