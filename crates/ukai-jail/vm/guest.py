#!/usr/bin/env python3
"""Single-attempt guest controller. Installed root-owned outside the jail."""
import base64
import collections
import json
import hashlib
import struct
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import selectors
import shutil
import signal
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
CONFIG_DIR = Path(os.environ.get('UKAI_VM_CONFIG_DIR', '/var/lib/ukai-vm/config'))
WORKSPACE = Path('/home/ukai/workspace')
EVIDENCE = Path('/home/ukai/evidence')
# J18 (jail-macos.md §6): where an attempt's ephemeral credentials stage.
# tmpfs, so a secret is never written to the guest disk; the path is the
# jail's vault source location for the attempt. UKAI_VM_SECRETS relocates it
# for tests, which run where /run is not writable; the value is read per
# call, so a test cannot pin the module's import order.
SECRETS = '/run/ukai-vm/credentials'
# The kernel interfaces the controller reads and writes. Module values, so
# the test harness can point them at a fake tree; the guest never changes
# them.
CGROUP_ROOT = Path('/sys/fs/cgroup')
PROC_ROOT = Path('/proc')
VIRTIO_DEVICES = Path('/sys/bus/virtio/devices')
# Linux names these; the fallbacks are the kernel's own values, so the
# module imports on a test host whose socket module lacks AF_VSOCK.
VMADDR_CID_ANY = getattr(socket, 'VMADDR_CID_ANY', 0xFFFFFFFF)
VMADDR_CID_HOST = getattr(socket, 'VMADDR_CID_HOST', 2)
GUEST_PROFILES = ('tool', 'agent', 'build')


class Refusal(Exception):
    """A request the controller refuses; `reason` is the poweroff reason the
    console audit names."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class AttemptTreeUnverified(RuntimeError):
    """The attempt's processes could not be shown gone within the budget."""


class InfrastructureUnknown(RuntimeError):
    """The user manager's own processes could not be established from
    systemd's state at session open."""


def secrets_root():
    return Path(os.environ.get('UKAI_VM_SECRETS', SECRETS))


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def audit(event, **fields):
    with open('/dev/hvc0', 'w') as output:
        output.write('UKAI_VM ' + json.dumps({'event': event, **fields}) + '\n')


def notify():
    """READY=1 and a watchdog refresh. ukai-vm.service has WatchdogSec=4 and
    FailureAction=poweroff-force, so every wait the controller makes calls
    this at least once a second: a starved watchdog ends the warm guest."""
    address = os.environ.get('NOTIFY_SOCKET')
    if address:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect('\0' + address[1:] if address.startswith('@') else address)
            sock.sendall(b'READY=1\nWATCHDOG=1')


# ---------------------------------------------------------------------------
# Cgroup hooks: the only places the controller acts on cgroupfs. The test
# harness replaces them with a model of the kernel; everything that decides
# (what to kill, what counts as empty, what a stray is) stays this file's.
# ---------------------------------------------------------------------------

def make_cgroup(path):
    os.mkdir(path, 0o755)


def cgroup_kill(path):
    with open(Path(path) / 'cgroup.kill', 'w') as control:
        control.write('1')


def remove_cgroup(path):
    os.rmdir(path)


def cgroup_populated(path):
    """The `populated` line of `cgroup.events`: True or False, or None when
    the cgroup no longer exists (the kernel removes a cgroup only once it
    is empty, so a vanished boundary holds no process). A directory without
    a readable population is never taken for an empty one."""
    path = Path(path)
    try:
        text = (path / 'cgroup.events').read_text()
    except FileNotFoundError:
        if path.exists():
            raise
        return None
    for line in text.splitlines():
        key, _, value = line.partition(' ')
        if key == 'populated' and value.strip() in ('0', '1'):
            return value.strip() == '1'
    raise ValueError('unreadable cgroup population: ' + str(path))


def kill_workload(boundary='/sys/fs/cgroup/user.slice'):
    """cgroup.kill of a workload boundary, verified empty, at poweroff: the
    last-resort boundary is `user.slice`, which also holds the lingered user
    manager — the right thing when the guest ends, and exactly what an
    attempt's stop must never do (measured 2026-11-02: a warm reset that
    killed user@1001.service made the next jail refuse with
    `limit:pids (cgroup_unavailable)`). Per-attempt stops use
    [`stop_attempt`]."""
    root = Path(boundary)
    with (root / 'cgroup.events').open() as events:
        inode = os.fstat(events.fileno()).st_ino
        cgroup_kill(root)
        deadline = clock() + 1
        while True:
            notify()
            events.seek(0)
            state = dict(line.split() for line in events.read().splitlines())
            if state.get('populated') == '0':
                audit('workload_tree_empty', boundary=root.name, events_inode=inode)
                return
            if clock() >= deadline:
                raise TimeoutError('cgroup did not empty')
            time.sleep(.01)


# ---------------------------------------------------------------------------
# The per-attempt cgroup, and every cgroup an attempt can occupy
#
# The waiting wrapper joins `ukai-attempts.slice/attempt-N`, a delegated
# child the controller creates. The guest's Linux jail then does what it
# does on any lingering host (jail-v1 §9.3, platform/linux/scope.rs): its
# supervisor asks the user manager for a transient scope and moves itself
# into `user@<uid>.service/app.slice/ukai-jail-<pid>-<hex>.scope`, and it
# creates the execution leaf directly under `user@<uid>.service`
# (`ukai-<attempt>.leaf`; the K111/K113 guest receipts record both). So
# the attempt cgroup alone is empty within the first second, and killing it
# alone kills nothing (review 2026-11-03 H1).
#
# The stop therefore kills every attempt cgroup and every cgroup under the
# user manager except the manager's own infrastructure units, and then
# requires that no process of the workload account survives anywhere in
# the guest except the infrastructure's own processes, killing each other
# one by pid. The jail's scope logic is shared with Linux hosts and is not
# changed here.
#
# The infrastructure is what the next attempt's jail needs to get its
# scope, and nothing else. prepare.py's image leaves exactly three
# processes of the account running (measured on systemd 259, review
# 2026-11-03 cgroup-exp baseline; re-measured on ouro-dev the same day):
#
# * the user manager, `systemd --user` in `user@<uid>.service/init.scope`
#   (`loginctl enable-linger ukai` keeps it up): the system manager's
#   MainPID for `user@<uid>.service`;
# * its `(sd-pam)` helper, in the same scope: forked by the manager's
#   executor before it became `systemd --user`, so its parent is that
#   MainPID (measured: PPid = MainPID);
# * the session bus `dbus-user-session` installs (dbus-daemon, the jail's
#   `busctl --user` talks to it): the user manager's MainPID for
#   `dbus.service`, in that unit's ControlGroup as the manager reports it
#   (`session.slice/dbus.service` on the image; no spelling is assumed).
#
# They are learned once, at session open (`learn_infrastructure`): before
# any attempt of this boot has run, so no workload process exists yet to
# answer for systemd or to stand in for one of them. Each is pinned by pid
# AND start time, so a reused pid is not mistaken for it. Nothing a
# process says about itself (exe, comm, cmdline, the cgroup it sits in)
# makes it infrastructure.
#
# What this covers: a process of the account placed INSIDE init.scope or
# dbus.service (by a direct `cgroup.procs` write, the route the review
# measured), or into a sub-cgroup of either, or anywhere outside the user
# manager, is killed and shown gone, or the stop fails. A bus that died
# and was socket-activated again during an attempt is not the learned one:
# the stop kills it too, and the next attempt's `busctl` activates it
# again. Today's jail gives the workload no cgroupfs (`--unshare-cgroup`,
# no /sys) and no user bus, so this is the defence behind the jail's own.
# ---------------------------------------------------------------------------

Infrastructure = collections.namedtuple('Infrastructure', 'pids units')
Infrastructure.__doc__ = """The user manager's own processes and units, learned at session open:
`pids` maps each pid to its start time; `units` are cgroup paths relative
to `user@<uid>.service`."""

ProcessFacts = collections.namedtuple('ProcessFacts', 'uids ppid starttime live cgroup')
# The stop's whole budget for kill and verification, and the separate bound
# on reaping the jail supervisor afterwards. Both waits feed the watchdog.
STOP_BUDGET = 2.5
REAP_BUDGET = 1.0
# One systemctl call at session open; the watchdog is fed on either side.
SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMCTL_TIMEOUT = 2.0
attempt_counter = 0
# The vaulted launch profile's TOML for the attempt in flight (staged by
# the launch_toml op; consumed when the run writes it under its config
# directory). One per attempt: the reset/cancel paths clear it.
launch_toml = None


def attempts_slice():
    return CGROUP_ROOT / 'ukai-attempts.slice'


def delegated_root(uid):
    return CGROUP_ROOT / 'user.slice' / f'user-{uid}.slice' / f'user@{uid}.service'


def cgroup_name(path):
    """A cgroupfs directory as /proc/<pid>/cgroup and systemd spell it."""
    return '/' + Path(path).relative_to(CGROUP_ROOT).as_posix()


def child_cgroups(path):
    """A cgroup's child cgroups (its subdirectories; control files are not)."""
    try:
        with os.scandir(path) as entries:
            return sorted(Path(path) / entry.name for entry in entries
                          if entry.is_dir(follow_symlinks=False))
    except FileNotFoundError:
        return []


def systemctl(*args, account=None):
    """One bounded systemctl call and its standard output. With `account`,
    `systemctl --user` as that account, through its manager's private
    socket: root's own systemctl refuses that socket (its peer is not root;
    measured on systemd 259), and `-M <user>@` would go through a transient
    system unit and the session bus. Raises InfrastructureUnknown."""
    argv = [SYSTEMCTL, *(('--user',) if account is not None else ()), *args]
    options = {}
    if account is not None:
        options = dict(user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                       env={'XDG_RUNTIME_DIR': f'/run/user/{account.pw_uid}', 'LANG': 'C.UTF-8',
                            'PATH': '/usr/bin:/bin'})
    notify()
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd='/',
                                timeout=SYSTEMCTL_TIMEOUT, check=False, **options)
    except (OSError, subprocess.SubprocessError) as error:
        raise InfrastructureUnknown(f'{" ".join(argv[1:])}: {type(error).__name__}') from None
    finally:
        notify()
    if result.returncode != 0:
        raise InfrastructureUnknown(f'{" ".join(argv[1:])} exited {result.returncode}')
    return result.stdout


def unit_properties(text):
    """`systemctl show -p` output (KEY=VALUE lines) as a dict."""
    properties = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if separator:
            properties[key] = value
    return properties


def _stat_fields(text):
    # Fields after the parenthesized comm (which may hold spaces and
    # parentheses): index 0 is field 3 (state), 1 is ppid, 19 is starttime.
    return text.rpartition(')')[2].split()


def process_facts(pid):
    """One process as /proc shows it, or None once it is gone. `live` is
    whether any of its threads still runs: a thread-group leader that
    exited while a sibling thread lives reads as a zombie but is not one."""
    directory = PROC_ROOT / str(pid)
    try:
        status = (directory / 'status').read_text()
        fields = _stat_fields((directory / 'stat').read_text())
        membership = (directory / 'cgroup').read_text()
        tids = os.listdir(directory / 'task')
    except (FileNotFoundError, ProcessLookupError):
        return None  # it ended while it was read
    states = []
    for tid in tids:
        try:
            states.append(_stat_fields((directory / 'task' / tid / 'stat').read_text())[0])
        except (FileNotFoundError, ProcessLookupError):
            continue  # that thread ended while it was read
    uids = next((line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')), [])
    cgroup = next((line[3:] for line in membership.splitlines() if line.startswith('0::')), None)
    return ProcessFacts(uids=uids, ppid=int(fields[1]), starttime=int(fields[19]),
                        live=any(state not in ('Z', 'X') for state in states), cgroup=cgroup)


def account_processes(uid):
    """(pid, facts) of every process of `uid` (any of its real, effective,
    saved or filesystem ids)."""
    found = []
    for name in sorted(os.listdir(PROC_ROOT)):
        if not name.isdigit():
            continue
        facts = process_facts(int(name))
        if facts is not None and str(uid) in facts.uids:
            found.append((int(name), facts))
    return found


def learn_infrastructure(account):
    """The user manager's own processes and units, from systemd's state, at
    session open (see the section comment): the manager is the system
    manager's MainPID for user@<uid>.service, its helper the one process
    that manager forked into init.scope, the bus the user manager's MainPID
    for dbus.service (started first, as the jail's first `busctl` would
    socket-activate it) in that unit's ControlGroup. Every fact is checked
    against /proc. Raises InfrastructureUnknown."""
    uid = account.pw_uid
    root = cgroup_name(delegated_root(uid))
    manager_scope = root + '/init.scope'

    def require(condition, why):
        if not condition:
            raise InfrastructureUnknown(why)

    def main_pid(properties):
        value = properties.get('MainPID', '')
        return int(value) if value.isdigit() else 0

    manager = main_pid(unit_properties(systemctl('show', f'user@{uid}.service', '-p', 'MainPID')))
    require(manager > 0, f'user@{uid}.service has no main process')
    systemctl('start', 'dbus.service', account=account)
    unit = unit_properties(systemctl('show', 'dbus.service', '-p', 'MainPID', '-p', 'ControlGroup',
                                     account=account))
    bus, bus_cgroup = main_pid(unit), unit.get('ControlGroup', '')
    require(bus > 0, 'dbus.service has no main process')
    require(bus_cgroup.startswith(root + '/') and not within_cgroup(bus_cgroup, manager_scope),
            f'dbus.service is not a unit of the user manager: {bus_cgroup!r}')
    pids = {}
    for pid, cgroup, what in ((manager, manager_scope, 'user manager'), (bus, bus_cgroup, 'session bus')):
        facts = process_facts(pid)
        require(facts is not None and facts.live and facts.uids and all(value == str(uid) for value in facts.uids)
                and facts.cgroup == cgroup, f'the {what} (pid {pid}) is not a live process of {uid} in {cgroup}')
        pids[pid] = facts.starttime
    helpers = [(pid, facts) for pid, facts in account_processes(uid)
               if facts.live and facts.ppid == manager and facts.cgroup == manager_scope]
    require(len(helpers) <= 1, f'{len(helpers)} processes beside the user manager in init.scope')
    for pid, facts in helpers:
        pids[pid] = facts.starttime
    units = ('init.scope', bus_cgroup[len(root) + 1:])
    audit('infrastructure_learned', manager=manager, helper=[pid for pid, _ in helpers], bus=bus,
          bus_unit=units[1])
    return Infrastructure(pids=pids, units=units)


def within_cgroup(member, boundary):
    return member == boundary or member.startswith(boundary + '/')


def attempt_boundaries(uid, units):
    """Every cgroup the attempt can occupy, each killed whole: each attempt
    cgroup, and every cgroup under the user manager that neither is one of
    the infrastructure `units` nor holds one. Those are walked into
    instead: a unit's own sub-cgroups and a slice's other units are
    boundaries."""
    root = delegated_root(uid)
    targets = child_cgroups(attempts_slice())
    pending = child_cgroups(root)
    while pending:
        cgroup = pending.pop()
        name = cgroup.relative_to(root).as_posix()
        if any(within_cgroup(unit, name) for unit in units):
            pending += child_cgroups(cgroup)
        else:
            targets.append(cgroup)
    return sorted(targets)


def stray_processes(uid, infrastructure_pids):
    """The live processes of `uid` that are not the infrastructure's own
    (pid and start time), wherever they sit, as (pid, starttime, cgroup).

    A zombie runs nothing and is not a stray. A zombie thread-group leader
    whose sibling thread still runs IS live: cgroup.kill does not end such a
    group, and its cgroup reads `populated 1` for as long as it lives
    (measured 2026-11-03: past 9.5 s in the review's experiment, past 5 s
    on 7.2.12), while a SIGKILL to the process ends it (measured: within
    0.25 s, by kill or pidfd), so the stop kills it here."""
    strays = []
    for pid, facts in account_processes(uid):
        if facts.live and infrastructure_pids.get(pid) != facts.starttime:
            strays.append((pid, facts.starttime, facts.cgroup))
    return strays


def kill_process(pid, starttime):
    """SIGKILL to one process through a pidfd, sent only if the pid still
    names the process the scan saw (its start time, read after the pidfd
    pins it): a pid reused since the scan is never signalled."""
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        facts = process_facts(pid)
        if facts is not None and facts.starttime == starttime:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


def boundary_members(boundaries):
    """For the failure audit: the processes /proc places in each populated
    boundary (any account), as [pid, uid, thread states]. A boundary still
    populated with no member of the workload account names a root-owned
    survivor or a kernel that has not yet emptied the cgroup."""
    names = {cgroup_name(boundary): [] for boundary in boundaries}
    for entry in sorted(os.listdir(PROC_ROOT)):
        if not entry.isdigit():
            continue
        facts = process_facts(int(entry))
        if facts is None or facts.cgroup is None:
            continue
        for name, members in names.items():
            if within_cgroup(facts.cgroup, name) and len(members) < 16:
                members.append([int(entry), (facts.uids or ['?'])[0], 'live' if facts.live else 'zombie'])
    return names


def stop_attempt(account, infrastructure, budget=STOP_BUDGET):
    """Ends one attempt's tree without ending the session: kill every
    boundary the attempt can occupy and every stray process of the account,
    then verify each boundary empty and no stray left, re-killing until
    both hold or the budget is spent. Re-enumerating each round catches a
    unit the manager started while the first kill landed. Raises
    [`AttemptTreeUnverified`] past the budget: a warm reset must never run
    alongside surviving workload processes, and the caller powers the guest
    off."""
    if infrastructure is None:
        raise AttemptTreeUnverified('no infrastructure was learned for this session')
    uid = account.pw_uid
    deadline = clock() + budget
    killed = {}
    while True:
        notify()
        targets = attempt_boundaries(uid, infrastructure.units)
        for target in targets:
            try:
                cgroup_kill(target)
            except FileNotFoundError:
                pass  # removed since it was listed: empty by construction
        strays = stray_processes(uid, infrastructure.pids)
        for pid, starttime, cgroup in strays:
            kill_process(pid, starttime)
            killed.setdefault(pid, cgroup)
        populated = [target for target in targets if cgroup_populated(target)]
        if not populated and not strays:
            audit('workload_tree_empty', boundaries=[str(target.relative_to(CGROUP_ROOT)) for target in targets],
                  strays_killed=sorted([pid, cgroup] for pid, cgroup in killed.items()))
            return targets
        if clock() >= deadline:
            detail = {'populated': [str(target) for target in populated],
                      'strays': [[pid, cgroup] for pid, _, cgroup in strays],
                      'members': boundary_members(populated)}
            audit('attempt_tree_unverified', **detail)
            raise AttemptTreeUnverified(json.dumps(detail))
        time.sleep(.02)


def drop_attempt_cgroups(uid):
    """Removes the attempt cgroups and the jail's leftover execution leaves
    after a verified-empty stop. Units' cgroups are the user manager's to
    collect (the jail's scope is CollectMode=inactive-or-failed). Best
    effort: a leftover is empty and the next stop lists it again."""
    leaves = [child for child in child_cgroups(delegated_root(uid))
              if child.name.startswith('ukai-') and child.name.endswith('.leaf')]
    for target in child_cgroups(attempts_slice()) + leaves:
        for directory in sorted((Path(d) for d, _, _ in os.walk(target)), key=lambda p: -len(p.parts)):
            try:
                remove_cgroup(directory)
            except OSError:
                pass


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
    slice_dir = attempts_slice()
    if not slice_dir.exists():
        make_cgroup(slice_dir)
    child = slice_dir / f'attempt-{attempt_counter}'
    make_cgroup(child)
    with (slice_dir / 'cgroup.controllers').open() as available:
        present = set(available.read().split())
    enabled = {name for name in ('pids', 'memory', 'cpu') if name in present}
    if enabled:
        with (slice_dir / 'cgroup.subtree_control').open('w') as control:
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


def reap(process, budget=REAP_BUDGET):
    """Waits, bounded, for the jail supervisor the controller spawned. It
    is killed by then; one that outlives the bound was not."""
    if process is None:
        return
    deadline = clock() + budget
    while process.poll() is None:
        notify()
        if clock() >= deadline:
            raise AttemptTreeUnverified('the jail supervisor did not exit after its kill')
        time.sleep(.01)


def poweroff(reason):
    # VZ may retain its service while the Mac client is SIGSTOP'ed, even after
    # guest poweroff. First kill and verify the Linux workload boundary so
    # payload cleanup does not depend on the host processing a VM callback.
    try:
        kill_workload()
    except (OSError, ValueError, TimeoutError) as error:
        audit('workload_cleanup_unverified', error=type(error).__name__)
    # The per-attempt files go too: the staged values are on tmpfs, but the
    # launch profile is on the (per-boot) guest disk, which a failed boot's
    # retained evidence keeps.
    try:
        clear_attempt_files()
    except OSError as error:
        audit('attempt_files_not_cleared', error=type(error).__name__)
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
# case folding DO escape policy denials, so the host preflight refuses them
# before boot. Staging (put) and workspace export do not apply in live mode.
# ---------------------------------------------------------------------------

SHARE_TAG = 'workspace'
SHARE_MOUNT = Path('/mnt/workspace')
# nosuid and nodev: a file the host (or a guest write through the share)
# marks setuid, or a device node in the host directory, must not become a
# privilege inside the guest. Not noexec: the live share is the operator's
# real workspace, whose scripts and build outputs the workload runs exactly
# as it runs the staged copy's (whose files keep their executable bits);
# the guest jail's policy, not the mount, decides what executes.
SHARE_OPTIONS = 'nosuid,nodev'
# The virtio device id of a virtio-fs device (VIRTIO_ID_FS, 26). The VZ
# client attaches exactly one, the workspace share, and only when the serve
# was given --live-workspace.
VIRTIO_ID_FS = 26


def share_attached():
    """Whether the host attached a virtio-fs device, read from the virtio
    bus (independent of whether the virtiofs module has bound it yet)."""
    try:
        devices = sorted(VIRTIO_DEVICES.iterdir())
    except FileNotFoundError:
        return False
    for device in devices:
        try:
            if int((device / 'device').read_text().strip(), 16) == VIRTIO_ID_FS:
                return True
        except (OSError, ValueError):
            continue
    return False


def share_mounted():
    return os.path.ismount(SHARE_MOUNT)


def mount_share():
    """Mounts the live workspace share once at boot. Returns True when the
    share is live; a guest booted without the device keeps the preview's
    staged-tmpfs behavior unchanged. D7: a guest booted WITH the device
    whose mount fails powers off with a named reason — it never falls back
    to the staged workspace, because the host believes the workload writes
    its real directory. The session and ready replies state `live_share`
    and the host compares it with what it attached, which also covers a
    device this check cannot see."""
    if share_mounted():
        return True
    attached = share_attached()
    error = None
    try:
        SHARE_MOUNT.mkdir(parents=True, exist_ok=True)
        # A local virtio-fs mount completes at once; the bound stays inside
        # the 4 s watchdog, which this boot-time call cannot feed.
        subprocess.run(['mount', '-t', 'virtiofs', '-o', SHARE_OPTIONS, SHARE_TAG, str(SHARE_MOUNT)],
                       check=True, capture_output=True, timeout=3)
    except (OSError, subprocess.SubprocessError) as failure:
        error = failure
    if share_mounted():
        return True
    if attached:
        audit('live_share_mount_failed', error=type(error).__name__ if error else 'not_mounted')
        poweroff('live_share_mount_failed')
    return False


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
# The preview's `run` op stays what it was: one run per boot, poweroff at
# completion. A warm guest instead runs a session: the host resets the
# attempt directories, stages at most one workspace and a secret set, runs
# the same jail command, and reads the attempt back — without a poweroff.
# The lease on an attempt is the host's connection, not a timer: the
# controller keeps the session until the vsock end closes or the VM service
# ends.
# ---------------------------------------------------------------------------

LAUNCH_NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}')


def valid_launch_name(name):
    """The guest jail's own `--launch` name grammar (launch_profile.rs)."""
    return type(name) is str and LAUNCH_NAME.fullmatch(name) is not None


def launch_directory():
    return CONFIG_DIR / 'launch'


def _stage_launch_profile(name, account):
    """Writes the staged launch TOML as `<config>/launch/<name>.toml`: the
    exact shape the guest jail's loader accepts (launch_profile.rs `load`):
    every directory owned by root or the operator and not writable by
    others, the file a regular file the operator (the jail's effective uid,
    the workload account) owns, mode 0600, one link. No credential value is
    inside — the transport staged those under /run (tmpfs). Removed by
    [`clear_launch_profile`] at the end of every attempt."""
    text = globals()['launch_toml']
    if text is None:
        raise Refusal('launch_without_toml')
    if not valid_launch_name(name):
        raise Refusal('invalid_launch')
    directory = launch_directory()
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # O_EXCL also refuses a planted name (a symlink included); a stale
        # file from an earlier attempt was removed when that attempt ended.
        fd = os.open(name + '.toml', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, 'w') as output:
        output.write(text)
        output.flush()
        os.fchmod(fd, 0o600)
        os.fchown(fd, account.pw_uid, account.pw_gid)
    globals()['launch_toml'] = None


def clear_launch_profile():
    """Removes every staged launch profile. Only the controller writes the
    launch directory, so whatever it holds is a previous attempt's."""
    try:
        parent = os.open(launch_directory(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    try:
        for name in os.listdir(parent):
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
        if os.listdir(parent):
            raise OSError('the launch profile directory did not empty')
    finally:
        os.close(parent)


def reset_attempt(account, workspace=None, evidence=None):
    """Empties both attempt directories for the next attempt, as the host's
    reset op asks. The directories, their modes and their owner come back
    exactly as boot made them. The live share is never wiped: it is the
    host's directory, and its contents are the host's business. Paths
    resolve at CALL time so the live-share switch is honored."""
    workspace = WORKSPACE if workspace is None else Path(workspace)
    evidence = EVIDENCE if evidence is None else Path(evidence)
    if workspace == SHARE_MOUNT and share_mounted():
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


def _workload_ids(account):
    if account is not None:
        return account.pw_uid, account.pw_gid
    # The workload account exists on the guest; unit-test hosts without one
    # fall back to the current ids (the fchown is then a no-op).
    try:
        found = pwd.getpwnam('ukai')
        return found.pw_uid, found.pw_gid
    except KeyError:
        return os.getuid(), os.getgid()


def _private_level(parent, name, owner, gid):
    """Creates (or enters) one staging directory below `parent` without
    following a link, owned by the controller with the workload group,
    mode 0710: the jail (the workload account) can traverse it, and only
    the controller can change it. A level that exists already must be the
    controller's own directory."""
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner:
            raise ValueError('a staging level is not the controller\'s own directory')
        os.fchown(fd, owner, gid)
        os.fchmod(fd, 0o710)
    except BaseException:
        os.close(fd)
        raise
    return fd


def stage_secret(secret_id, payload, secrets=None, account=None):
    """Writes one ephemeral credential to its tmpfs path. The value crossed
    the vsock once for this attempt and lives here only until the attempt
    ends.

    The guest jail reads it as the workload account through its vault
    source walk (credentials.rs `open_source`): every directory from `/`
    owned by root or the operator and not writable by others, the file a
    regular file owned by root or the operator, no group or other bits, one
    link. So every level is the controller's own (root on the guest, group
    the workload's, mode 0710: traversable by the jail, writable only by
    root), created and entered with mkdirat/openat and O_NOFOLLOW — nothing
    the workload owns is ever followed — and the file is created O_EXCL,
    then fchmod 0600 and fchown'd to the workload account, the one owner
    the jail running as that account can read."""
    secrets = secrets_root() if secrets is None else Path(secrets)
    parts = relative(secret_id)
    uid, gid = _workload_ids(account)
    owner = os.geteuid()
    # /run/ukai-vm (or a test's directory) is created by the controller
    # under the root-owned /run: nothing on that path is the workload's.
    secrets.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    current = os.open(secrets.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in (secrets.name, *parts[:-1]):
            level = _private_level(current, name, owner, gid)
            os.close(current)
            current = level
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                     dir_fd=current)
    finally:
        os.close(current)
    with os.fdopen(fd, 'wb') as output:
        output.write(payload)
        output.flush()
        os.fchmod(fd, 0o600)
        os.fchown(fd, uid, gid)
    return secrets.joinpath(*parts)


def clear_secrets(secrets=None):
    """Removes every staged secret; every attempt's end and every reset
    calls this, so no value outlives its attempt. A tree that is still
    there afterwards is an error, never a silent leftover."""
    root = secrets_root() if secrets is None else Path(secrets)
    try:
        shutil.rmtree(root)
    except FileNotFoundError:
        pass
    if os.path.lexists(root):
        raise OSError('the staged credentials were not removed')


def clear_attempt_files():
    """Everything one attempt staged outside its directories."""
    clear_secrets()
    clear_launch_profile()


def run_command(profile, argv, wall, workspace=None, evidence=None, allow_hosts=(), launch=None):
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
    # The agent profile's proxied policy (J18 §6): the guest jail starts
    # its own qualified Linux proxy and enforces each host rule; an
    # invalid spelling refuses inside the guest before any workload runs.
    for rule in allow_hosts:
        command += [b'--allow-host', os.fsencode(rule)]
    # The vaulted launch profile (J18 §6): the controller wrote its TOML
    # (credential sources at the tmpfs staging root) under the attempt's
    # config directory; the jail resolves `--launch` from there and its
    # vault proxy injects the staged values into admitted requests.
    if launch is not None:
        command += [b'--launch', os.fsencode(launch)]
    command += [b'--', *argv]
    return command


def validate_run(request, live_share):
    """One verdict for the `run` and `run2` requests (review 2026-11-03 M2:
    the warm op lacked the build-on-live-share refusal). Returns the
    profile, wall, argv bytes, allow-host rules and launch name; raises
    [`Refusal`] naming the poweroff reason."""
    profile = request.get('profile')
    wall = request.get('wall_seconds')
    if type(profile) is not str or profile not in GUEST_PROFILES or type(wall) is not int or not 1 <= wall <= 300:
        raise Refusal('invalid_policy')
    launch = request.get('launch')
    if launch is not None and (not valid_launch_name(launch) or profile != 'agent'):
        raise Refusal('invalid_launch')
    allow_hosts = request.get('allow_hosts') or []
    if type(allow_hosts) is not list or (allow_hosts and profile != 'agent') or any(
            type(rule) is not str or not rule or '\0' in rule or ' ' in rule for rule in allow_hosts):
        raise Refusal('invalid_proxy_policy')
    if profile == 'build' and live_share:
        # The build profile's disposable-copy grant has no protected
        # segments; on a live share that would expose the operator's real
        # .git (measured, run 2 of the 2026-11-02 K109 evidence).
        raise Refusal('live_share_requires_protected_profile')
    encoded = request.get('argv')
    try:
        if type(encoded) is not list or any(type(value) is not str for value in encoded):
            raise ValueError
        argv = [base64.b64decode(value, validate=True) for value in encoded]
    except ValueError:
        raise Refusal('invalid_argv') from None
    if not argv or not argv[0] or any(b'\0' in value for value in argv):
        raise Refusal('invalid_argv')
    return profile, wall, argv, allow_hosts, launch


def attempt_environment(account):
    """The environment one guest jail runs under, in either mode."""
    return {'HOME': account.pw_dir, 'USER': 'ukai', 'LOGNAME': 'ukai',
            'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
            'XDG_RUNTIME_DIR': f'/run/user/{account.pw_uid}',
            # The controller stages the vaulted launch profile (if any) under
            # this directory; the jail resolves `--launch` from it.
            'UKAI_CONFIG_DIR': str(CONFIG_DIR)}


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


def vsock_listener():
    server = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    server.bind((VMADDR_CID_ANY, PORT))
    server.listen(1)
    server.settimeout(.2)
    return server


def main():
    global WORKSPACE
    account = pwd.getpwnam('ukai')
    if mount_share():
        # The live share is the workspace (J18 §6): everything downstream —
        # the jail's cwd, the put and export paths — flows from this switch.
        WORKSPACE = SHARE_MOUNT
        audit('live_share_mounted', mount=str(SHARE_MOUNT), options=SHARE_OPTIONS)
    live_share = WORKSPACE == SHARE_MOUNT
    reset_attempt(account)
    server = vsock_listener()
    # Even a launcher that disappears during boot cannot leave an idle VM.
    idle_deadline = clock() + 90
    audit('ready', kernel=os.uname().release, live_share=live_share)
    while True:
        notify()
        if clock() > idle_deadline:
            poweroff('no_host')
        try:
            conn, peer = server.accept()
            break
        except socket.timeout:
            pass
    if peer[0] != VMADDR_CID_HOST:
        poweroff('non_host_peer')
    conn.settimeout(.25)

    def send(value):
        conn.sendall(json.dumps(value, separators=(',', ':')).encode() + b'\n')

    send({'event': 'ready', 'kernel': os.uname().release, 'lease_seconds': LEASE, 'live_share': live_share})
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
    # The user manager's own processes, learned at session open (D6, F1):
    # the stop spares these and nothing else of the account.
    infrastructure = None
    run_request = None
    guest_boot_id = (PROC_ROOT / 'sys/kernel/random/boot_id').read_text().strip()

    def end_attempt():
        """D6: the one stop every warm path takes (done, cancel2, reset, the
        outer-wall backstop). Kill and verify every boundary the attempt can
        occupy, reap the supervisor, remove the attempt's staged files —
        each bounded, each failure a named poweroff rather than a starved
        watchdog."""
        try:
            stop_attempt(account, infrastructure)
            drop_attempt_cgroups(account.pw_uid)
            reap(process)
        except (AttemptTreeUnverified, OSError, ValueError) as error:
            audit('attempt_stop_failed', error=type(error).__name__)
            poweroff('attempt_tree_unverified')
        try:
            clear_attempt_files()
        except OSError as error:
            audit('attempt_files_not_cleared', error=type(error).__name__)
            poweroff('attempt_files_not_cleared')

    def discard_attempt():
        """Closes one attempt's streams and counters, after its tree has
        been ended: the next attempt stages from scratch."""
        nonlocal process, stream_count, uploaded, files, output_bytes, wall_deadline
        for key in list(selector.get_map().values()):
            if key.data != 'control':
                selector.unregister(key.fileobj)
                key.fileobj.close()
        process = None
        stream_count = 0
        uploaded = files = output_bytes = 0
        wall_deadline = None

    def start(request):
        """Starts the jail for a validated `run` or `run2` request."""
        nonlocal process, stream_count, wall_deadline
        profile, wall, argv, allow_hosts, launch = validate_run(request, WORKSPACE == SHARE_MOUNT)
        command = run_command(profile, argv, wall, allow_hosts=allow_hosts, launch=launch)
        env = attempt_environment(account)
        if launch is not None:
            try:
                _stage_launch_profile(launch, account)
            except OSError:
                # A name already present (a symlink included) or an
                # unwritable directory: never written through.
                raise Refusal('launch_profile_unstageable') from None
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

    while True:
        notify()
        if not in_session and clock() - last_ping > LEASE:
            poweroff('lease_expired')
        if wall_deadline is not None and clock() > wall_deadline:
            if not in_session:
                poweroff('outer_wall_expired')
            # The backstop ends the attempt, not the warm VM (§6: the guest
            # jail's own wall still ends it first when the jail can act).
            end_attempt()
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
                try:
                    if op == 'ping':
                        sequence = request['sequence']
                        if type(sequence) is not int or sequence != last_sequence + 1:
                            poweroff('invalid_lease_sequence')
                        last_sequence = sequence
                        last_ping = clock()
                        send({'event': 'pong', 'sequence': sequence})
                    elif op == 'launch_toml' and process is None and in_session:
                        # The vaulted launch profile's TOML: it carries no
                        # value (sources point at /run/ukai-vm/credentials),
                        # so writing it under the config dir keeps the guest
                        # disk value-free. The run writes it workload-owned,
                        # 0600, single-link (the loader's shape), and the
                        # attempt's end removes it.
                        text = request['toml']
                        if type(text) is not str or not text or '\0' in text or len(text) > 65536:
                            poweroff('invalid_launch_toml')
                        globals()['launch_toml'] = text
                        send({'event': 'launch_toml'})
                    elif op == 'put' and process is None:
                        if WORKSPACE == SHARE_MOUNT:
                            # Live share: staging is the host's side of the
                            # mount; a put would write through to the host
                            # workspace.
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
                        start(request)
                    elif op == 'run2' and process is None and in_session:
                        # J18: the warm session's run — the same jail command
                        # and the same validation, without the poweroff at
                        # completion. The host staged a fresh workspace
                        # (reset op) before the puts.
                        if not request.get('attempt_id') or not request.get('boot_id'):
                            poweroff('missing_attempt_binding')
                        run_request = request
                        start(request)
                    elif op == 'session' and process is None and not in_session:
                        # J18: the warm session's handshake. After this the
                        # ping lease no longer applies: the attempt's lease
                        # is this connection's end-of-file (§6), not a timer.
                        # `live_share` is what the serve compares with what it
                        # attached (D7). No attempt has run yet, so this is
                        # when the user manager's own processes are learned.
                        in_session = True
                        try:
                            infrastructure = learn_infrastructure(account)
                        except InfrastructureUnknown as error:
                            audit('infrastructure_unknown', error=str(error))
                            poweroff('infrastructure_unknown')
                        audit('session_opened', live_share=live_share)
                        send({'event': 'session', 'kernel': os.uname().release, 'live_share': live_share})
                    elif op == 'reset' and process is None and in_session:
                        globals()['launch_toml'] = None
                        end_attempt()
                        reset_attempt(account)
                        uploaded = files = output_bytes = 0
                        send({'event': 'reset'})
                    elif op == 'secret' and process is None and in_session:
                        # J18 §6 transport: the value crosses the vsock once
                        # and lands in tmpfs for this attempt only (never the
                        # guest disk); a vaulted launch profile's sources
                        # name these paths, and the attempt's end removes
                        # them. A refused id is the attempt's error (the
                        # serve cancels it), never a controller crash.
                        secret_id, data = request.get('id'), request.get('data')
                        try:
                            if type(secret_id) is not str or type(data) is not str:
                                raise ValueError('ill-typed secret frame')
                            path = stage_secret(secret_id, base64.b64decode(data, validate=True),
                                                account=account)
                        except (ValueError, OSError) as error:
                            send({'event': 'error', 'message': 'secret_refused:' + type(error).__name__})
                            continue
                        send({'event': 'secret', 'id': secret_id, 'path': str(path)})
                    elif op == 'cancel2' and in_session:
                        # The attempt lease's end-of-file reached the host's
                        # ukai-vm, which passes the cancellation on. The
                        # session and the VM stay up; no timer was involved.
                        end_attempt()
                        reset_attempt(account)
                        discard_attempt()
                        audit('attempt_cancelled')
                        send({'event': 'cancelled'})
                    elif op == 'cancel':
                        poweroff('cancelled')
                    else:
                        poweroff('invalid_operation')
                except Refusal as refusal:
                    poweroff(refusal.reason)
        if process is not None and process.poll() is not None and stream_count == 0:
            if in_session:
                # The tree goes before anything is read back, and the staged
                # values with it: nothing the attempt left runs on, and no
                # value outlives the attempt that `done` reports.
                end_attempt()
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
            # J18: the warm session carries on — the next attempt stages its
            # own workspace, and the VM stays up until the host asks it to
            # stop.
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
