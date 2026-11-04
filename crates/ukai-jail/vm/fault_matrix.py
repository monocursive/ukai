#!/usr/bin/env python3
"""K110 for the warm design, plus the secret-transport lifecycle, live.

K110.1 (docs/specs/jail-v1/acceptance-map.toml), sentence by sentence:

  "The preview's fault matrix, rerun for the warm design."
      Every case below runs on its own boot of the serve under test.
  "Killing the host `ukai-jail` ends that attempt through its lease"
      client-kill: the client is SIGKILLed while its long-running workload
      (a leader and two descendants beating into the live share) runs; it
      dies of that SIGKILL (its wait status, within KILL_EXIT_SECONDS — far
      inside any cleanup's safety kill), the beats stop, the service stays
      warm, the next attempt runs on the same serve boot AND the same guest
      kernel boot.
  "and `Ctrl-Z` of it does not."
      client-ctrl-z: SIGTSTP to the client's process group (a terminal
      Ctrl-Z of exactly that client) for SUSPEND_SECONDS while the workload
      runs; the beats continue while it is stopped, and after SIGCONT the
      attempt completes with exit 0 on the same boot.
  "Killing the custodian, the VZ client or `ukai-vm` ends the VM service
   and every attempt."
      custodian-kill, vz-kill, serve-kill: SIGKILL of that one process while
      one attempt runs and a second is queued on the attempt socket; both
      attempts were still open at the kill and end after it without `done`,
      the beats stop, and the serve, custodian,
      VZ client and the Virtualization XPC service holding this boot's disk
      are all gone; the workspace's files survive.
  "With every host controller suspended, the guest's wall deadline ends the
   attempt."
      all-suspended: SIGSTOP of the client and of the serve's process group
      (serve, custodian, VZ client; the XPC service is the VM, not a
      controller) after release; while they are all stopped, the beats must
      continue past the stop and then end at the guest wall deadline.
  "All are checked before any test cleanup."
      Every case takes its observations, computes its verdict from them, and
      only then resumes, stops, kills or deletes anything; the record keeps
      both times (`checked_at` <= `cleanup_started_at`).

The host client is, by default, a Python attempt client in its own process
(harness.ClientProcess), recorded as `client: python-stand-in`. With
--ukai-jail, client-kill and client-ctrl-z also run against the real
`ukai-jail run --vm` (sharing this run's data directory, so it reuses the
warm serve); a refusal is recorded as that client's result, not hidden.

Every completed attempt a verdict counts (the follow-up, the secrets
attempt, a resumed Ctrl-Z or serve-group-stop attempt) must carry a receipt
whose digest verified and whose binding names that attempt
(harness.receipt_bound).

Also measured:
  secrets           two values (one nested id) cross per attempt, acked under
                    the guest tmpfs root; the attempt's egress probe sees the
                    jail's denial with the NAT attached and a same-boot route
                    control reaching the target (harness.network_denial); a
                    duplicate id refuses before `prepared`; the next attempt
                    runs on the same boot
  eof               an attempt-socket EOF mid-run cancels only that attempt
                    (beats stop; the next attempt runs on the same boot)
  serve-group-stop  the serve's process group (serve, custodian, VZ client)
                    SIGSTOPped for SUSPEND_SECONDS across a running workload,
                    past the custodian's 3 s lease window (which restarts
                    after a wake gap); the attempt completes after resume and
                    the serve and guest boot ids are the same before and after

Usage: UKAI_VM_BINARY=<ukai-vm> fault_matrix.py <home> <workspace> <out>
           [case,case,...] [--ukai-jail PATH]
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

SUSPEND_SECONDS = 5.0      # longer than the custodian's 3 s lease and the 1.5 s ack budget
QUIET_SECONDS = 2.0        # ten missed beats at 0.2 s
END_BOUND_SECONDS = 15.0   # how long a kill may take to stop every beat
KILL_EXIT_SECONDS = 2.0    # our SIGKILL's death, well inside ClientProcess.finish's 10 s safety kill
SUSPENDED_WALL = 10        # the all-suspended case's guest wall
CASES = ('secrets', 'client-kill', 'client-ctrl-z', 'serve-kill', 'custodian-kill', 'vz-kill',
         'all-suspended', 'eof', 'serve-group-stop')


# ---------------------------------------------------------------------------
# Verdicts: pure functions of a case's observations
# ---------------------------------------------------------------------------

def _same_boot(obs):
    return {
        'next_attempt_exit_zero': obs.get('next_exit') == 0,
        'next_attempt_receipt_bound': obs.get('next_receipt_bound') is True,
        'next_attempt_same_serve_boot': bool(obs.get('serve_boot')) and obs.get('next_serve_boot') == obs.get('serve_boot'),
        'next_attempt_same_guest_boot': bool(obs.get('guest_boot')) and obs.get('next_guest_boot') == obs.get('guest_boot'),
    }


def _stopped_after(obs, moment_key, bound=END_BOUND_SECONDS):
    last, moment = obs.get('last_beat_at'), obs.get(moment_key)
    return (obs.get('beats_quiet') is True and last is not None and moment is not None
            and last - moment <= bound)


def _open_until_the_kill(obs, label):
    """Attempt `label` was still open at the kill, and its stream ended after it."""
    ended, killed = obs.get(f'{label}_ended_at'), obs.get('killed_at')
    return (obs.get(f'{label}_open_at_kill') is True and ended is not None and killed is not None
            and ended > killed)


def verdict_client_kill(obs):
    return {'released': obs.get('released') is True,
            'workload_beating_before_kill': obs.get('beating') is True,
            'workload_stopped_after_kill': _stopped_after(obs, 'killed_at'),
            'client_alive_at_the_kill': obs.get('client_alive_at_kill') is True,
            # Our SIGKILL, not a later safety kill: the wait status is SIGKILL
            # and it arrived within KILL_EXIT_SECONDS of the kill.
            'client_died_of_our_sigkill': obs.get('client_exit') == -signal.SIGKILL
            and obs.get('client_exit_seconds') is not None
            and obs['client_exit_seconds'] <= KILL_EXIT_SECONDS,
            'service_still_warm': obs.get('status_after', {}).get('warm') is True,
            **_same_boot(obs)}


def verdict_client_ctrl_z(obs):
    return {'released': obs.get('released') is True,
            'workload_beating_before_stop': obs.get('beating') is True,
            'client_was_stopped': obs.get('client_state_while_stopped', '').startswith('T'),
            'workload_continued_while_client_stopped': obs.get('beats_during_stop') is True,
            'attempt_completed_after_resume': obs.get('done_exit') == 0 and obs.get('workload_finished') is True,
            'resumed_attempt_receipt_bound': obs.get('receipt_bound') is True,
            **_same_boot(obs)}


def verdict_controller_kill(obs):
    gone = obs.get('gone_seconds') or {}
    return {'released': obs.get('released') is True,
            'workload_beating_before_kill': obs.get('beating') is True,
            'one_custodian_vz_and_vm_identified': obs.get('identified') is True,
            'running_attempt_ended_without_done': obs.get('a_done') is False and obs.get('a_ended') is True,
            'running_attempt_open_until_the_kill': _open_until_the_kill(obs, 'a'),
            'queued_attempt_ended_without_done': obs.get('b_done') is False and obs.get('b_ended') is True,
            'queued_attempt_open_until_the_kill': _open_until_the_kill(obs, 'b'),
            'workload_stopped_after_kill': _stopped_after(obs, 'killed_at'),
            'serve_gone': gone.get('serve') is not None,
            'custodian_gone': gone.get('custodian') is not None,
            'vz_gone': gone.get('vz') is not None,
            'vm_service_gone': gone.get('vm') is not None,
            'sockets_unanswered': obs.get('sockets_unanswered') is True,
            'workspace_survived': obs.get('workspace_survived') is True}


def verdict_all_suspended(obs):
    wall = obs.get('wall')
    last, released, stopped = obs.get('last_beat_at'), obs.get('released_at'), obs.get('stopped_at')
    deadline_ok = (last is not None and released is not None and wall is not None
                   and released + wall - 1.5 <= last <= released + wall + 3.0)
    guest_span = obs.get('guest_beat_span_s')
    return {'released': obs.get('released') is True,
            'workload_beating_before_stop': obs.get('beating') is True,
            'every_controller_stopped': obs.get('every_controller_stopped') is True,
            'workload_ran_on_after_the_stop': bool(stopped) and bool(last) and last - stopped >= 1.0,
            'beats_ended_while_suspended': obs.get('beats_quiet') is True and obs.get('quiet_before_resume') is True,
            'ended_at_the_guest_wall_deadline': deadline_ok,
            'guest_clock_agrees': guest_span is not None and guest_span <= wall + 1.5}


def verdict_secrets(obs):
    staged = obs.get('staged') or []
    return {'two_values_acked': len(staged) == 2,
            'paths_in_tmpfs_root': bool(staged) and all(
                path.startswith('/run/ukai-vm/credentials/') for _, path in staged),
            'nested_id_staged': any(key == 'nested/id/two' for key, _ in staged),
            'first_attempt_exit_zero': obs.get('first_exit') == 0,
            'first_attempt_receipt_bound': obs.get('first_receipt_bound') is True,
            'network_denied_with_nat': bool(obs.get('network_denial')) and all(
                value is True for value in obs['network_denial'].values()),
            'duplicate_id_refused_before_prepared': obs.get('duplicate_prepared') is False
            and bool(obs.get('duplicate_error')),
            **_same_boot(obs)}


def verdict_eof(obs):
    return {'released': obs.get('released') is True,
            'workload_beating_before_eof': obs.get('beating') is True,
            'workload_stopped_after_eof': _stopped_after(obs, 'eof_at'),
            'service_still_warm': obs.get('status_after', {}).get('warm') is True,
            **_same_boot(obs)}


def verdict_serve_group_stop(obs):
    return {'released': obs.get('released') is True,
            'workload_beating_before_stop': obs.get('beating') is True,
            'serve_boot_unchanged_after_resume': bool(obs.get('serve_boot'))
            and obs.get('status_boot_after') == obs.get('serve_boot'),
            'workload_spanned_the_stop': obs.get('beats_during_stop') is True,
            'attempt_completed_after_resume': obs.get('done_exit') == 0 and obs.get('workload_finished') is True,
            'resumed_attempt_receipt_bound': obs.get('receipt_bound') is True,
            **_same_boot(obs)}


VERDICTS = {'client-kill': verdict_client_kill, 'client-ctrl-z': verdict_client_ctrl_z,
            'serve-kill': verdict_controller_kill, 'custodian-kill': verdict_controller_kill,
            'vz-kill': verdict_controller_kill, 'all-suspended': verdict_all_suspended,
            'secrets': verdict_secrets, 'eof': verdict_eof, 'serve-group-stop': verdict_serve_group_stop}


def judge(case, obs):
    facts = VERDICTS[case](obs)
    failed = [name for name, value in facts.items() if value is not True]
    return {'facts': facts, 'failed': failed, 'outcome': 'PASS' if not failed else 'FAIL'}


def matrix_outcome(results, requested):
    """PASS only when every case of CASES was requested, ran, passed, and was
    judged before its cleanup."""
    outcomes = [result.get('outcome') for result in results.values()]
    complete = not (set(CASES) - set(requested))
    judged_first = all(result.get('checked_before_cleanup') is True for result in results.values())
    return 'PASS' if outcomes and all(o == 'PASS' for o in outcomes) and complete and judged_first else 'FAIL'


# ---------------------------------------------------------------------------
# Live mechanics
# ---------------------------------------------------------------------------

class Run:
    """One case: its own data dir and boot; cleanup only after the verdict."""

    def __init__(self, context, case):
        self.context = context
        self.case = case
        self.data = Path(tempfile.mkdtemp(prefix=f'fault-{case}-'))
        self.service = None
        self.clients = []
        self.processes = []
        self.stopped_groups = []
        self.identities = {}
        self.cleanup = {}

    def boot(self, nat=False):
        harness.clean_workspace(self.context['workspace'])
        self.service = harness.Service(self.context['binary'], self.context['home'],
                                       self.context['workspace'], self.data,
                                       extra=('--guest-nat',) if nat else ())
        status = self.service.wait_warm()
        self.identities['serve'] = (self.service.pid, harness.identity(self.service.pid))
        return status

    def client(self, marker, wall, beats=None):
        script = harness.heartbeat_script(marker, beats=beats)
        client = harness.ClientProcess(self.service.socket_path('attempt'), f'fault-{marker}',
                                       harness.sh(script), wall)
        self.clients.append(client)
        return client

    def controllers(self):
        """(pid, identity) for the custodian, VZ client and the VM service of this boot."""
        boot = self.service.boot_dir()
        found = harness.boot_processes(boot)
        vm = harness.vm_services_holding(boot / 'image' / 'base.raw')
        picked = {}
        for name, pids in (('custodian', found['custodian']), ('vz', found['vz']), ('vm', vm)):
            if len(pids) == 1:
                picked[name] = (pids[0], harness.identity(pids[0]))
        self.identities.update(picked)
        return picked, len(picked) == 3

    def follow_up(self, obs):
        """The next attempt on this boot: does it run, and on the same boots?"""
        record = harness.run_attempt(self.service.connect, f'fault-next-{harness.nonce()}',
                                     harness.sh('cat /proc/sys/kernel/random/boot_id'), wall=20)
        obs['next_exit'] = record.get('exit_code')
        obs['next_error'] = record.get('error')
        obs['next_receipt_bound'] = harness.receipt_bound(record)
        obs['next_serve_boot'] = record.get('boot_id')
        obs['next_guest_boot'] = harness.guest_boot(record)
        obs['next_stdout_boot'] = record['stdout'].strip() or None

    def stop_group(self, pgid, sig=signal.SIGSTOP):
        os.killpg(pgid, sig)
        self.stopped_groups.append(pgid)

    def tear_down(self):
        """After the verdict: resume, stop, and kill only what this run identified."""
        log = self.cleanup
        log['started_at'] = time.monotonic()
        for pgid in self.stopped_groups:
            try:
                os.killpg(pgid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        for client in self.clients:
            if client.process.poll() is None:
                client.process.kill()
            client.finish()
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        if self.service is not None:
            log['service_exit'] = self.service.stop()
            log['service_stderr'] = self.service.stderr_text()[-1500:]
        killed = []
        for name, (pid, ident) in self.identities.items():
            if name != 'serve' and ident and harness.identity(pid) == ident:
                try:
                    os.kill(pid, signal.SIGKILL)
                    killed.append(name)
                except ProcessLookupError:
                    pass
        log['emergency_killed'] = killed


def beats_while_stopped(watch, stopped_at, seconds, settle=0.5, clock=time.monotonic, sleep=time.sleep):
    """Poll the share until `stopped_at + seconds`; whether any beat changed
    more than `settle` after the stop (a beat in flight at the stop is not one)."""
    while clock() < stopped_at + seconds:
        watch.poll()
        sleep(0.05)
    return bool(watch.changed_since(stopped_at + settle))


def newest_attempt_bound(data, argv):
    """harness.attempt_dir_bound() on a real client's newest attempt directory."""
    attempts = sorted((Path(data) / 'attempts').glob('att_*'), key=lambda path: path.stat().st_mtime)
    return bool(attempts) and harness.attempt_dir_bound(attempts[-1], argv)


def process_state(pid):
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'stat='], capture_output=True, text=True)
    return result.stdout.strip()


def wait_status(service, predicate, timeout=15.0):
    deadline = time.monotonic() + timeout
    status = {}
    while time.monotonic() < deadline:
        try:
            status = service.status()
            if predicate(status):
                return status
        except (OSError, harness.StreamEnded, ValueError):
            status = {}
        time.sleep(0.2)
    return status


def started(run, obs, client, watch, timeout=180):
    """Released, then every beating process seen; the guest boot from the share."""
    obs['released'] = client.wait_event('released', timeout) is not None
    obs['released_at'] = time.monotonic()
    obs['beating'] = watch.wait_beating(30)
    obs['guest_boot'] = watch.guest_boot_id()
    client.capture_identity()


class Refused(harness.HarnessError):
    """The real client refused before its workload ran (a recorded outcome)."""

    def __init__(self, message, refusals):
        super().__init__(message)
        self.refusals = refusals


def real_started(watch, process, timeout=180):
    """The real client released its workload (every beat seen), or it refused."""
    beating = watch.wait_beating(timeout, give_up=lambda: process.poll() is not None)
    if not beating and process.poll() is not None:
        _, stderr = process.communicate(timeout=10)
        raise Refused(f'ukai-jail run --vm exited {process.returncode} before its workload ran: '
                      f'{(stderr or "")[-600:]}', harness.vm_refusals(stderr))
    return beating


def case_client_kill(run, obs, real=None):
    status = run.boot()
    obs['serve_boot'] = status.get('boot_id')
    marker = 'ck' + harness.nonce()
    watch = harness.BeatWatch(run.context['workspace'], marker)
    if real is None:
        obs['client'] = 'python-stand-in'
        client = run.client(marker, wall=120)
        started(run, obs, client, watch)
        pid, ident = client.process.pid, client.identity
    else:
        obs['client'] = 'ukai-jail run --vm'
        process = real(run, marker, harness.heartbeat_script(marker), 120)
        obs['released'] = real_started(watch, process)
        obs['beating'] = obs['released']
        obs['guest_boot'] = watch.guest_boot_id()
        pid, ident = process.pid, harness.identity(process.pid)
        run.real_process = process
    target = client.process if real is None else run.real_process
    obs['client_alive_at_kill'] = target.poll() is None
    obs['killed_at'] = time.monotonic()
    harness.signal_checked(pid, ident, signal.SIGKILL)
    # The wait status within KILL_EXIT_SECONDS, never after a safety kill:
    # a client still alive then is recorded as such (cleanup kills it later).
    try:
        obs['client_exit'] = target.wait(timeout=KILL_EXIT_SECONDS)
        obs['client_exit_seconds'] = round(time.monotonic() - obs['killed_at'], 3)
    except subprocess.TimeoutExpired:
        obs['client_exit'], obs['client_exit_seconds'] = None, None
    if real is None and obs['client_exit'] is not None:
        client.finish()
    obs['beats_quiet'], obs['last_beat_at'] = watch.wait_quiet(QUIET_SECONDS, END_BOUND_SECONDS + QUIET_SECONDS)
    obs['status_after'] = wait_status(run.service, lambda s: s.get('attempt_live') is False)
    run.follow_up(obs)
    if real is not None:
        obs['client_stderr'] = run.real_process.stderr.read()[-800:] if run.real_process.stderr else None


def case_client_ctrl_z(run, obs, real=None):
    status = run.boot()
    obs['serve_boot'] = status.get('boot_id')
    marker = 'cz' + harness.nonce()
    watch = harness.BeatWatch(run.context['workspace'], marker)
    beats = int((SUSPEND_SECONDS + 6) / 0.2)
    if real is None:
        obs['client'] = 'python-stand-in'
        client = run.client(marker, wall=90, beats=beats)
        started(run, obs, client, watch)
        process = client.process
    else:
        obs['client'] = 'ukai-jail run --vm'
        script = harness.heartbeat_script(marker, beats=beats)
        process = real(run, marker, script, 90)
        obs['released'] = real_started(watch, process)
        obs['beating'] = obs['released']
        obs['guest_boot'] = watch.guest_boot_id()
    group = os.getpgid(process.pid)
    obs['stopped_at'] = time.monotonic()
    run.stop_group(group, signal.SIGTSTP)
    time.sleep(0.5)
    obs['client_state_while_stopped'] = process_state(process.pid)
    obs['beats_during_stop'] = beats_while_stopped(watch, obs['stopped_at'], SUSPEND_SECONDS)
    os.killpg(group, signal.SIGCONT)
    run.stopped_groups.remove(group)
    if real is None:
        done = client.wait_event('done', 90)
        client.finish(timeout=30)
        obs['done_exit'] = done.get('exit_code') if done else None
        obs['receipt_bound'] = client.receipt_bound()
        text = ''.join(event.get('text', '') for event in client.seen('stdout'))
    else:
        try:
            out, err = process.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            out, err = '', 'timeout'
        obs['done_exit'] = process.returncode
        obs['client_stderr'] = (err or '')[-800:]
        obs['receipt_bound'] = newest_attempt_bound(run.data, harness.sh(script))
        text = out or ''
    obs['workload_finished'] = f'hb-{marker}-done' in text
    run.follow_up(obs)


def case_controller_kill(run, obs, target):
    status = run.boot()
    obs['serve_boot'] = status.get('boot_id')
    marker = 'kk' + harness.nonce()
    watch = harness.BeatWatch(run.context['workspace'], marker)
    first = run.client(marker, wall=120)
    started(run, obs, first, watch)
    controllers, obs['identified'] = run.controllers()
    queued = run.client('q' + marker, wall=20, beats=1)
    time.sleep(1.0)  # queued: connected into the backlog, waiting for its `ready`
    victim = run.identities['serve'] if target == 'serve' else controllers.get(target)
    if victim is None:
        raise harness.HarnessError(f'no unique {target} process for this boot')
    for label, client in (('a', first), ('b', queued)):
        obs[f'{label}_open_at_kill'] = client.process.poll() is None and client.ended_at() is None
    obs['killed_at'] = time.monotonic()
    harness.signal_checked(victim[0], victim[1], signal.SIGKILL)
    obs['beats_quiet'], obs['last_beat_at'] = watch.wait_quiet(QUIET_SECONDS, END_BOUND_SECONDS + QUIET_SECONDS)

    def serve_gone():
        deadline = time.monotonic() + END_BOUND_SECONDS
        while time.monotonic() < deadline:
            if run.service.child.poll() is not None:
                return round(time.monotonic() - obs['killed_at'], 2)
            time.sleep(0.1)
        return None

    gone = {'serve': serve_gone()}
    for name in ('custodian', 'vz', 'vm'):
        gone[name] = harness.wait_gone([controllers[name]], END_BOUND_SECONDS) if name in controllers else None
    obs['gone_seconds'] = gone
    for label, client in (('a', first), ('b', queued)):
        client.finish(timeout=END_BOUND_SECONDS)
        obs[f'{label}_done'] = bool(client.seen('done'))
        obs[f'{label}_ended'] = client.ended_by_itself()
        obs[f'{label}_ended_at'] = client.ended_at()
        obs[f'{label}_events'] = [event.get('event') for event in client.events]
    obs['sockets_unanswered'] = not any(harness.answers(run.service.socket_path(name))
                                        for name in ('attempt', 'control'))
    obs['workspace_survived'] = watch.boot_file.exists() and all(path.exists() for path in watch.files)


def case_all_suspended(run, obs):
    status = run.boot()
    obs['serve_boot'] = status.get('boot_id')
    obs['wall'] = SUSPENDED_WALL
    marker = 'as' + harness.nonce()
    watch = harness.BeatWatch(run.context['workspace'], marker)
    client = run.client(marker, wall=SUSPENDED_WALL)
    started(run, obs, client, watch)
    controllers, obs['identified'] = run.controllers()
    first_guest = watch.guest_times()
    obs['stopped_at'] = time.monotonic()
    run.stop_group(os.getpgid(run.service.pid))
    run.stop_group(os.getpgid(client.process.pid))
    time.sleep(0.3)
    states = {name: process_state(pid) for name, (pid, _) in
              {**controllers, 'serve': run.identities['serve']}.items() if name != 'vm'}
    states['client'] = process_state(client.process.pid)
    obs['controller_states'] = states
    obs['every_controller_stopped'] = (obs['identified'] and
                                       all(state.startswith('T') for state in states.values()))
    remaining = obs['released_at'] + SUSPENDED_WALL + 3.0 + QUIET_SECONDS - time.monotonic()
    obs['beats_quiet'], obs['last_beat_at'] = watch.wait_quiet(QUIET_SECONDS, max(remaining, QUIET_SECONDS))
    obs['quiet_before_resume'] = all(process_state(pid).startswith('T') for pid in
                                     [run.identities['serve'][0], client.process.pid])
    last_guest = watch.guest_times()
    spans = [last_guest[name] - first_guest[name] for name in last_guest
             if last_guest.get(name) and first_guest.get(name)]
    obs['guest_beat_span_s'] = round(max(spans) / 1e9, 2) if spans else None
    # Recovery is recorded apart from the verdict: it happens after the
    # suspended-state checks above, and the custodian's lease may end the VM.
    obs['recovery'] = 'recorded in cleanup'


def case_secrets(run, obs):
    status = run.boot(nat=True)
    obs['serve_boot'] = status.get('boot_id')
    obs['guest_nat'] = status.get('guest_nat')
    tag = harness.nonce()
    first = harness.run_attempt(run.service.connect, f'fault-secret-{tag}',
                                harness.sh(harness.probe_shell(tag) + '\ncat /proc/sys/kernel/random/boot_id'),
                                secrets=[('api/token', b'secret-value-one'),
                                         ('nested/id/two', b'secret-value-two')])
    obs['first_exit'] = first.get('exit_code')
    obs['first_error'] = first.get('error')
    obs['staged'] = [tuple(entry) for entry in first.get('staged_secrets', [])]
    obs['first_receipt_bound'] = harness.receipt_bound(first)
    obs['probe'] = harness.probe_verdict(first['stdout'], tag)
    obs['guest_boot'] = harness.guest_boot(first)
    route = harness.run_attempt(run.service.connect, f'fault-route-{tag}', harness.route_argv(f'{tag}-route'),
                                profile='agent', allow_hosts=[harness.route_rule()])
    obs['route'] = harness.route_verdict(route['stdout'], f'{tag}-route')
    obs['network_denial'] = harness.network_denial(obs['probe'], obs['route'], status.get('guest_nat'),
                                                   obs['guest_boot'], harness.guest_boot(route),
                                                   harness.receipt_bound(route))
    duplicate = harness.run_attempt(run.service.connect, f'fault-dup-{tag}', harness.sh('true'),
                                    secrets=[('same', b'one'), ('same', b'two')])
    obs['duplicate_prepared'] = 'prepared' in duplicate.get('events', [])
    obs['duplicate_error'] = duplicate.get('error')
    run.follow_up(obs)


def case_eof(run, obs):
    status = run.boot()
    obs['serve_boot'] = status.get('boot_id')
    marker = 'eo' + harness.nonce()
    watch = harness.BeatWatch(run.context['workspace'], marker)
    channel = run.service.connect()
    ready = channel.frame()
    channel.send(op='prepare', attempt_id=f'fault-{marker}', profile='tool', wall_seconds=120,
                 argv=[harness.b64(word) for word in harness.sh(harness.heartbeat_script(marker))], secrets=[])
    prepared = channel.frame()
    channel.send(op='run')
    released = channel.frame()
    obs['released'] = (ready.get('event'), prepared.get('event'), released.get('event')) == (
        'ready', 'prepared', 'released')
    obs['beating'] = watch.wait_beating(30)
    obs['guest_boot'] = watch.guest_boot_id()
    obs['eof_at'] = time.monotonic()
    channel.close()
    obs['beats_quiet'], obs['last_beat_at'] = watch.wait_quiet(QUIET_SECONDS, END_BOUND_SECONDS + QUIET_SECONDS)
    obs['status_after'] = wait_status(run.service, lambda s: s.get('attempt_live') is False)
    run.follow_up(obs)


def case_serve_group_stop(run, obs):
    status = run.boot()
    obs['serve_boot'] = status.get('boot_id')
    marker = 'gs' + harness.nonce()
    watch = harness.BeatWatch(run.context['workspace'], marker)
    client = run.client(marker, wall=90, beats=int((SUSPEND_SECONDS + 6) / 0.2))
    started(run, obs, client, watch)
    group = os.getpgid(run.service.pid)
    obs['stopped_at'] = time.monotonic()
    obs['stopped_seconds'] = SUSPEND_SECONDS
    run.stop_group(group)
    obs['beats_during_stop'] = beats_while_stopped(watch, obs['stopped_at'], SUSPEND_SECONDS)
    os.killpg(group, signal.SIGCONT)
    run.stopped_groups.remove(group)
    done = client.wait_event('done', 60)
    client.finish(timeout=30)
    obs['done_exit'] = done.get('exit_code') if done else None
    obs['receipt_bound'] = client.receipt_bound()
    obs['workload_finished'] = f'hb-{marker}-done' in ''.join(e.get('text', '') for e in client.seen('stdout'))
    obs['status_boot_after'] = wait_status(run.service, lambda s: s.get('attempt_live') is False).get('boot_id')
    run.follow_up(obs)


def real_client(jail):
    """A launcher for the real `ukai-jail run --vm` against this run's warm serve."""
    def launch(run, marker, script, wall):
        config = Path(tempfile.mkdtemp(prefix='fault-cfg-'))
        os.chmod(config, 0o700)
        environment = harness.vm_client_environment(UKAI_VM_HOME=run.context['home'],
                                                    UKAI_DATA_DIR=run.data, UKAI_CONFIG_DIR=config)
        process = subprocess.Popen([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                                    *harness.vm_wall(wall), '--workspace', str(run.context['workspace']),
                                    '--', '/bin/sh', '-c', script],
                                   env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   process_group=0)  # a job of this session: Ctrl-Z stops it
        run.processes.append(process)
        return process
    return launch


def run_case(context, case, variant=None):
    run = Run(context, case)
    obs = {'case': case}
    result = {'case': case}
    try:
        if case == 'client-kill':
            case_client_kill(run, obs, variant)
        elif case == 'client-ctrl-z':
            case_client_ctrl_z(run, obs, variant)
        elif case in ('serve-kill', 'custodian-kill', 'vz-kill'):
            case_controller_kill(run, obs, case.split('-')[0])
        elif case == 'all-suspended':
            case_all_suspended(run, obs)
        elif case == 'secrets':
            case_secrets(run, obs)
        elif case == 'eof':
            case_eof(run, obs)
        elif case == 'serve-group-stop':
            case_serve_group_stop(run, obs)
        else:
            raise harness.HarnessError(f'unknown case {case}')
        result.update(judge(case, obs))
    except Refused as refusal:  # vm:not-measured until the live phase: recorded, never a pass
        result.update({'outcome': 'REFUSED', 'refusals': refusal.refusals, 'error': str(refusal)})
    except Exception as error:  # a case failure is a result, not the end of the matrix
        result.update({'outcome': 'ERROR', 'error': f'{type(error).__name__}: {error}'})
    result['checked_at'] = time.monotonic()
    result['observations'] = obs
    try:
        run.tear_down()
    finally:
        result['cleanup'] = run.cleanup
        if case == 'all-suspended':
            result['recovery_after_resume'] = {
                'service_exit': run.cleanup.get('service_exit'),
                'note': 'after the suspended-state verdict; never counted as proof'}
    result['checked_before_cleanup'] = result['checked_at'] <= run.cleanup.get('started_at', float('inf'))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('home', type=Path)
    parser.add_argument('workspace', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('cases', nargs='?', default=','.join(CASES))
    parser.add_argument('--ukai-jail', help='also run the client cases with this real ukai-jail')
    args = parser.parse_args(argv)
    requested = [case for case in args.cases.split(',') if case]
    unknown = sorted(set(requested) - set(CASES))
    if unknown:
        parser.error(f'unknown cases: {", ".join(unknown)}')
    context = {'home': args.home.resolve(strict=True),
               'workspace': harness.guarded_workspace(args.workspace),
               'binary': harness.required_binary('UKAI_VM_BINARY')}
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.ukai_jail) if args.ukai_jail else None
    out = harness.fresh_out_dir(args.out)
    verdict = {'schema': 'ukai.vm.fault-matrix/2', 'binary': harness.fingerprint(context['binary']),
               'real_client': harness.fingerprint(jail) if jail else None, 'cases': {}}
    for case in requested:
        print(f'case: {case}', flush=True)
        verdict['cases'][case] = run_case(context, case)
        if jail is not None and case in ('client-kill', 'client-ctrl-z'):
            verdict['cases'][case + ':ukai-jail'] = run_case(context, case, real_client(jail))
    verdict['not_run'] = {case: 'not requested' for case in CASES if case not in requested}
    if jail is None:
        verdict['not_run'].update({f'{case}:ukai-jail': 'no --ukai-jail given; the python stand-in ran'
                                   for case in ('client-kill', 'client-ctrl-z') if case in requested})
    verdict['outcome'] = matrix_outcome(verdict['cases'], requested)
    harness.write_json(out / 'fault-matrix.json', verdict)
    print(json.dumps({name: result.get('outcome') for name, result in verdict['cases'].items()}))
    return 0 if verdict['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
