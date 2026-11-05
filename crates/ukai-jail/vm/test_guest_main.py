"""guest.py's `main()` driven over a socketpair (guest_harness.py): every op
handler, the attempt stop (D6), the per-attempt files (H2, H5), the shared
run validation (M2) and the live-share switch (D7).

The harness models the kernel from the measured receipts; what it cannot
show is the live phase's to measure on a booted guest:

* that the real Linux jail's scope and leaf land where the K111/K113
  receipts say (the model plays exactly that);
* that cgroup.kill of the jail's user scope and leaf ends the real tree,
  that the user manager collects the killed scope, and that the next
  attempt's jail still gets its scope (the manager and the bus survive);
* that `learn_infrastructure` finds exactly the manager, its (sd-pam)
  helper and the bus on the image, through the real systemctl calls (the
  model answers for systemd), and that killing processes beside them in
  init.scope or dbus.service leaves the manager and the bus working;
* that a real cancel of a running workload finishes inside WatchdogSec=4
  with no watchdog poweroff;
* that the guest kernel (7.0) behaves as the model's two measured facts
  say (measured on 7.2.12): cgroup.kill leaves a zombie-leader thread
  group, and a pidfd SIGKILL ends it (test_guest_warm.RealProcTests runs
  the second on any Linux host);
* the virtio-fs detection and the mount options on the real kernel;
* the staged files' real owners (root levels, workload-owned file) as the
  guest jail's loaders read them.
"""
import base64
import os
from pathlib import Path
import stat
import unittest

from guest_harness import GuestHarness, complete, hold, within


def b64(data):
    return base64.b64encode(data).decode()


LAUNCH = '[credentials.api]\nsource = "/run/ukai-vm/credentials/api/token"\n'


class BootTests(unittest.TestCase):
    def test_the_staged_mode_states_no_live_share(self):
        guest = GuestHarness(self)
        ready, session = guest.session()
        self.assertIs(ready['live_share'], False)
        self.assertIs(session['live_share'], False)
        self.assertEqual(session['kernel'], os.uname().release)

    def test_a_mounted_share_is_live_stated_and_nosuid_nodev(self):
        guest = GuestHarness(self, share='mounts')
        ready, session = guest.session()
        self.assertIs(ready['live_share'], True)
        self.assertIs(session['live_share'], True)
        mount = next(argv for argv, _ in guest.subprocess.runs if argv[0] == 'mount')
        options = mount[mount.index('-o') + 1].split(',')
        self.assertEqual(sorted(options), ['nodev', 'nosuid'])
        self.assertEqual(guest.guest.WORKSPACE, guest.guest.SHARE_MOUNT)

    def test_an_attached_share_that_fails_to_mount_powers_off_named(self):
        # D7: never the staged fallback once the host attached a share.
        guest = GuestHarness(self, share='fails')
        self.assertEqual(guest.ended(), 'live_share_mount_failed')
        self.assertNotEqual(guest.guest.WORKSPACE, guest.guest.SHARE_MOUNT)

    def test_no_device_and_no_mount_is_the_staged_mode(self):
        guest = GuestHarness(self)
        guest.session()
        self.assertNotEqual(guest.guest.WORKSPACE, guest.guest.SHARE_MOUNT)

    def test_a_non_host_peer_powers_off(self):
        guest = GuestHarness(self, peer_cid=3)
        self.assertEqual(guest.ended(), 'non_host_peer')

    def test_host_eof_powers_off(self):
        guest = GuestHarness(self)
        guest.session()
        guest.host.shutdown(2)
        self.assertEqual(guest.ended(), 'host_eof')


class PreviewOpTests(unittest.TestCase):
    """The single-run ops keep their meaning."""

    def test_ping_acknowledges_in_order_and_refuses_a_skip(self):
        guest = GuestHarness(self)
        guest.expect('ready')
        guest.send(op='ping', sequence=0)
        self.assertEqual(guest.expect('pong')['sequence'], 0)
        guest.send(op='ping', sequence=2)
        self.assertEqual(guest.ended(), 'invalid_lease_sequence')

    def test_the_ping_lease_expires_outside_a_session(self):
        guest = GuestHarness(self)
        guest.expect('ready')
        # No ping: the loop's own turn (0.1 s at most) judges the lease. A
        # ping sent now could be handled first and renew it.
        guest.clock.advance(3)
        self.assertEqual(guest.ended(), 'lease_expired')

    def test_put_then_run_exports_both_groups_and_powers_off_completed(self):
        guest = GuestHarness(self, scenarios=[complete(code=3, workspace_file='out.txt')])
        guest.expect('ready')
        guest.send(op='put', path='dir/input.sh', executable=True, data=b64(b'#!/bin/sh\n'))
        self.assertEqual(guest.expect('put')['path'], 'dir/input.sh')
        staged = guest.guest.WORKSPACE / 'dir/input.sh'
        self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o755)
        guest.send(op='run', profile='tool', wall_seconds=30, argv=[b64(b'/bin/true')])
        guest.expect('running')
        done = guest.expect('done')
        self.assertEqual(done['exit_code'], 3)
        self.assertNotIn('binding', done)
        self.assertNotIn('stop', done, 'the single-run preview has no warm stop to report')
        exported = {(f['group'], f['path']) for f in done['_seen'] if f['event'] == 'file'}
        self.assertIn(('workspace', 'out.txt'), exported)
        self.assertIn(('workspace', 'dir/input.sh'), exported)
        self.assertIn(('evidence', 'jail.json'), exported)
        self.assertEqual(guest.ended(), 'completed')

    def test_cancel_and_unknown_ops_power_off(self):
        for op, reason in [('cancel', 'cancelled'), ('reboot', 'invalid_operation'),
                           ('run2', 'invalid_operation'), ('reset', 'invalid_operation')]:
            with self.subTest(op=op):
                guest = GuestHarness(self)
                guest.expect('ready')
                guest.send(op=op)
                self.assertEqual(guest.ended(), reason)


class RunValidationTests(unittest.TestCase):
    """M2: `run` and `run2` share one validator; each refusal is named."""

    CASES = [
        (dict(profile='none'), 'invalid_policy'),
        (dict(wall_seconds=301), 'invalid_policy'),
        (dict(wall_seconds=True), 'invalid_policy'),
        (dict(allow_hosts=['api.example.com:443']), 'invalid_proxy_policy'),
        (dict(profile='agent', allow_hosts=['bad host']), 'invalid_proxy_policy'),
        (dict(profile='agent', allow_hosts='api.example.com'), 'invalid_proxy_policy'),
        (dict(launch='claude'), 'invalid_launch'),
        (dict(profile='agent', launch='Claude'), 'invalid_launch'),
        (dict(profile='agent', launch='a/b'), 'invalid_launch'),
        (dict(profile='agent', launch='x' * 65), 'invalid_launch'),
        (dict(argv=[]), 'invalid_argv'),
        (dict(argv=[b64(b'')]), 'invalid_argv'),
        (dict(argv=[b64(b'a\0b')]), 'invalid_argv'),
        (dict(argv=['%%%']), 'invalid_argv'),
    ]

    def request(self, **overrides):
        request = dict(op='run2', attempt_id='a', boot_id='b', profile='tool', wall_seconds=30,
                       argv=[b64(b'/bin/true')])
        request.update(overrides)
        return request

    def test_every_refusal_is_named_and_nothing_starts(self):
        for overrides, reason in self.CASES:
            with self.subTest(overrides=overrides):
                guest = GuestHarness(self)
                guest.session()
                guest.send(**self.request(**overrides))
                self.assertEqual(guest.ended(), reason)
                self.assertEqual(guest.subprocess.jails, [])

    def test_build_on_a_live_share_refuses_in_both_ops(self):
        for op in ('run', 'run2'):
            with self.subTest(op=op):
                guest = GuestHarness(self, share='mounts')
                if op == 'run2':
                    guest.session()
                else:
                    guest.expect('ready')
                guest.send(**self.request(op=op, profile='build'))
                self.assertEqual(guest.ended(), 'live_share_requires_protected_profile')
                self.assertEqual(guest.subprocess.jails, [])

    def test_run2_needs_its_attempt_binding(self):
        guest = GuestHarness(self)
        guest.session()
        guest.send(**self.request(attempt_id=''))
        self.assertEqual(guest.ended(), 'missing_attempt_binding')

    def test_the_agent_policy_reaches_the_jail_command(self):
        guest = GuestHarness(self)
        guest.session()
        guest.send(op='reset')
        guest.expect('reset')
        guest.send(op='launch_toml', toml=LAUNCH)
        guest.expect('launch_toml')
        guest.run2(profile='agent', allow_hosts=['api.anthropic.com', 'api.example.com:443'], launch='claude')
        guest.expect('done')
        command = guest.subprocess.jails[0].command()
        # A portless (TLS-only) rule crosses as the host spelled it.
        self.assertEqual([command[i + 1] for i, part in enumerate(command) if part == b'--allow-host'],
                         [b'api.anthropic.com', b'api.example.com:443'])
        self.assertEqual(command[command.index(b'--launch') + 1], b'claude')
        self.assertLess(command.index(b'--launch'), command.index(b'--'))


class AttemptStopTests(unittest.TestCase):
    """D6: the stop kills every cgroup the attempt can occupy, keeps the
    user manager and its bus, and is bounded."""

    def assert_infrastructure_alive(self, guest):
        kernel = guest.kernel
        for process in (kernel.manager, kernel.sd_pam, kernel.bus):
            self.assertTrue(process.alive, f'{process.exe} in {process.cgroup} was killed')

    def test_cancel_kills_the_jail_in_its_user_scope_and_leaf(self):
        guest = GuestHarness(self, scenarios=[hold()])
        guest.session()
        guest.run2()
        guest.expect('running')
        jail = guest.started_jail()
        # The move the wrapper waits for happened, to the attempt cgroup.
        self.assertIn(str(jail.pid), (jail.attempt_cgroup() / 'cgroup.procs').read_text().split())
        self.assertTrue(jail.process.cgroup.endswith('.scope'), jail.process.cgroup)
        self.assertTrue(jail.children[0].alive)
        guest.send(op='cancel2')
        guest.expect('cancelled')
        self.assertFalse(jail.process.alive, 'the supervisor in its user scope survived the cancel')
        self.assertFalse(jail.children[0].alive, 'the workload in its leaf survived the cancel')
        # Both died by a cgroup.kill of a boundary that holds them.
        for member in (jail.process, jail.children[0]):
            self.assertTrue(any(within(member.cgroup, kill) for kill in guest.kernel.kills), member.cgroup)
        self.assert_infrastructure_alive(guest)
        # The leaf and the attempt cgroups are gone; the session goes on.
        self.assertEqual(list(guest.kernel.cgroups.glob(f'{guest.kernel.delegated}/ukai-*.leaf')), [])
        self.assertEqual([p for p in (guest.kernel.cgroups / 'ukai-attempts.slice').iterdir() if p.is_dir()], [])
        guest.send(op='reset')
        guest.expect('reset')

    def test_an_unkillable_tree_powers_off_named_bounded_and_feeding_the_watchdog(self):
        guest = GuestHarness(self, scenarios=[hold(unkillable=True)])
        guest.session()
        guest.run2()
        guest.expect('running')
        guest.notifies.clear()
        started = guest.clock.now
        guest.send(op='cancel2')
        self.assertEqual(guest.ended(), 'attempt_tree_unverified')
        spent = guest.clock.now - started
        budget = guest.guest.STOP_BUDGET + guest.guest.REAP_BUDGET
        self.assertLessEqual(spent, budget + .5)
        gaps = [b - a for a, b in zip([started, *guest.notifies], [*guest.notifies, guest.clock.now])]
        self.assertLess(max(gaps), 1.0, 'a wait in the stop starved the 4 s watchdog')
        self.assert_infrastructure_alive(guest)

    def test_completion_kills_what_the_attempt_left_before_done(self):
        guest = GuestHarness(self, scenarios=[complete(leftover='app.slice/run-u7.service')])
        guest.session()
        guest.run2()
        done = guest.expect('done')
        leftovers = guest.kernel.alive_in(f'{guest.kernel.delegated}/app.slice/run-u7.service')
        self.assertEqual(leftovers, [], 'an escaped daemon outlived the attempt that reported done')
        self.assert_infrastructure_alive(guest)
        # `done` tells the host the guest jail left it: the host refuses
        # the jail's own tree_empty on that report.
        unit = f'{guest.kernel.delegated}/app.slice/run-u7.service'
        populated = done['stop']['populated_before_kill']
        self.assertTrue(any(unit == b or unit.startswith(b + '/') for b in populated), populated)
        self.assertEqual([cgroup for _, cgroup in done['stop']['live_before_kill']], ['/' + unit])

    def test_a_clean_completion_carries_an_empty_stop_witness_with_done(self):
        guest = GuestHarness(self, scenarios=[complete()])
        guest.session()
        guest.run2()
        stop = guest.expect('done')['stop']
        self.assertEqual(sorted(stop), ['boundaries', 'live_before_kill', 'populated_before_kill', 'strays_killed'])
        self.assertEqual((stop['populated_before_kill'], stop['live_before_kill'], stop['strays_killed']),
                         ([], [], []))

    def test_reset_kills_a_stray_under_the_user_manager(self):
        guest = GuestHarness(self)
        guest.session()
        stray = guest.kernel.spawn(guest.uid, f'{guest.kernel.delegated}/app.slice/run-u9.service', '/bin/sh')
        guest.send(op='reset')
        guest.expect('reset')
        self.assertFalse(stray.alive)
        self.assert_infrastructure_alive(guest)

    def test_a_stray_outside_the_user_manager_is_killed_by_pid(self):
        guest = GuestHarness(self)
        guest.session()
        session_scope = f'user.slice/user-{guest.uid}.slice/session-1.scope'
        stray = guest.kernel.spawn(guest.uid, session_scope, '/bin/sh')
        guest.send(op='reset')
        guest.expect('reset')
        self.assertFalse(stray.alive)
        self.assert_infrastructure_alive(guest)

    def test_an_unkillable_stray_outside_the_user_manager_refuses_the_reset(self):
        guest = GuestHarness(self)
        guest.session()
        session_scope = f'user.slice/user-{guest.uid}.slice/session-1.scope'
        guest.kernel.spawn(guest.uid, session_scope, '/bin/sh', unkillable=True)
        guest.send(op='reset')
        self.assertEqual(guest.ended(), 'attempt_tree_unverified')

    def test_intruders_in_init_scope_and_the_bus_unit_die_and_the_infrastructure_lives(self):
        # F1, as the review measured it on systemd 259: workload-uid
        # processes written into the manager's and the bus's own units.
        guest = GuestHarness(self, scenarios=[hold(), complete()])
        guest.session()
        guest.run2()
        guest.expect('running')
        delegated = guest.kernel.delegated
        intruders = [guest.kernel.spawn(guest.uid, f'{delegated}/{unit}', '/usr/bin/python3')
                     for unit in ('init.scope', 'session.slice/dbus.service', 'init.scope/x')]
        guest.send(op='cancel2')
        guest.expect('cancelled')
        for intruder in intruders:
            self.assertFalse(intruder.alive, f'an intruder in {intruder.cgroup} outlived the stop')
        self.assert_infrastructure_alive(guest)
        # The next attempt still runs: nothing it needs was killed.
        guest.send(op='reset')
        guest.expect('reset')
        guest.run2()
        guest.expect('done')

    def test_a_zombie_leader_workload_is_ended_and_the_session_goes_on(self):
        # F2: a workload whose thread-group leader exited while a thread
        # runs on keeps its leaf populated through cgroup.kill (measured);
        # the stop kills it by pid instead of exhausting its budget.
        def scenario(jail):
            jail.children.append(jail.kernel.spawn(jail.process.uid, f'{jail.kernel.delegated}/ukai-att_{jail.pid}.leaf',
                                                   '/usr/bin/python3', zombie_leader=True))
        guest = GuestHarness(self, scenarios=[scenario])
        guest.session()
        guest.run2()
        guest.expect('running')
        jail = guest.started_jail()
        guest.send(op='cancel2')
        guest.expect('cancelled')
        self.assertFalse(jail.children[0].alive)
        self.assertIn(jail.children[0].pid, guest.kernel.signals)

    def test_the_session_learns_the_infrastructure_before_any_attempt(self):
        guest = GuestHarness(self)
        guest.session()
        learned = [fields for event, fields in guest.audits if event == 'infrastructure_learned']
        kernel = guest.kernel
        self.assertEqual(learned, [{'manager': kernel.manager.pid, 'helper': [kernel.sd_pam.pid],
                                    'bus': kernel.bus.pid, 'bus_unit': 'session.slice/dbus.service'}])
        self.assertEqual(guest.subprocess.jails, [], 'an attempt ran before the infrastructure was learned')

    def test_an_unlearnable_infrastructure_powers_off_before_the_session(self):
        guest = GuestHarness(self, start=False)
        guest.kernel.reported['manager'] = 0
        guest.thread.start()
        guest.expect('ready')
        guest.send(op='session')
        self.assertEqual(guest.ended(), 'infrastructure_unknown')
        self.assertNotIn('session_opened', [event for event, _ in guest.audits])

    def test_the_outer_wall_ends_the_attempt_not_the_session(self):
        guest = GuestHarness(self, scenarios=[hold(), complete()])
        guest.session()
        guest.run2()
        guest.expect('running')
        jail = guest.started_jail()
        guest.clock.advance(41)  # the loop's next turn (0.1 s at most) sees it
        error = guest.expect('error')
        self.assertEqual(error['message'], 'outer_wall_expired')
        self.assertFalse(jail.process.alive)
        self.assertFalse(jail.children[0].alive)
        self.assert_infrastructure_alive(guest)


class AttemptFileTests(unittest.TestCase):
    """H2 and H5: the launch profile and the staged values exist only while
    their attempt runs, on every way the attempt ends."""

    def observe(self, seen):
        """A jail that records what it finds staged while it runs."""
        def scenario(jail):
            launch = jail.kernel.root.parent / 'config/launch/claude.toml'
            token = jail.kernel.root.parent / 'run/ukai-vm/credentials/api/token'
            seen.append({'launch': launch.exists() and stat.S_IMODE(launch.stat().st_mode),
                         'token': token.exists() and token.read_bytes()})
            complete()(jail)
        return scenario

    def vaulted_attempt(self, guest, value):
        guest.send(op='reset')
        guest.expect('reset')
        guest.send(op='launch_toml', toml=LAUNCH)
        guest.expect('launch_toml')
        guest.send(op='secret', id='api/token', data=b64(value))
        self.assertEqual(guest.expect('secret')['id'], 'api/token')
        guest.run2(profile='agent', launch='claude')

    def test_two_vaulted_attempts_on_one_boot(self):
        seen = []
        guest = GuestHarness(self, scenarios=[self.observe(seen), self.observe(seen)])
        guest.session()
        launch = guest.guest.CONFIG_DIR / 'launch/claude.toml'
        for value in (b'first-value', b'second-value'):
            self.vaulted_attempt(guest, value)
            guest.expect('done')
            self.assertFalse(launch.exists(), 'the launch profile outlived its attempt')
            self.assertFalse(guest.secrets.exists(), 'a staged value outlived its attempt')
        self.assertEqual(seen, [{'launch': 0o600, 'token': b'first-value'},
                                {'launch': 0o600, 'token': b'second-value'}])

    def test_cancel_removes_the_launch_profile_and_the_values(self):
        guest = GuestHarness(self, scenarios=[hold()])
        guest.session()
        self.vaulted_attempt(guest, b'value')
        guest.expect('running')
        self.assertTrue((guest.guest.CONFIG_DIR / 'launch/claude.toml').exists())
        guest.send(op='cancel2')
        guest.expect('cancelled')
        self.assertFalse((guest.guest.CONFIG_DIR / 'launch/claude.toml').exists())
        self.assertFalse(guest.secrets.exists())

    def test_reset_forgets_an_unconsumed_launch_toml(self):
        guest = GuestHarness(self)
        guest.session()
        guest.send(op='launch_toml', toml=LAUNCH)
        guest.expect('launch_toml')
        guest.send(op='reset')
        guest.expect('reset')
        guest.run2(profile='agent', launch='claude')
        self.assertEqual(guest.ended(), 'launch_without_toml')

    def test_reset_removes_leftover_staged_files(self):
        guest = GuestHarness(self)
        guest.session()
        directory = guest.guest.CONFIG_DIR / 'launch'
        directory.mkdir(parents=True)
        (directory / 'stale.toml').write_text('x')
        guest.send(op='secret', id='leftover', data=b64(b'v'))
        guest.expect('secret')
        guest.send(op='reset')
        guest.expect('reset')
        self.assertEqual(list(directory.iterdir()), [])
        self.assertFalse(guest.secrets.exists())

    def test_a_planted_launch_name_is_refused_and_not_written_through(self):
        guest = GuestHarness(self)
        guest.session()
        guest.send(op='reset')
        guest.expect('reset')
        outside = guest.root / 'outside.toml'
        outside.write_text('untouched')
        directory = guest.guest.CONFIG_DIR / 'launch'
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'claude.toml').symlink_to(outside)
        guest.send(op='launch_toml', toml=LAUNCH)
        guest.expect('launch_toml')
        guest.run2(profile='agent', launch='claude')
        self.assertEqual(guest.ended(), 'launch_profile_unstageable')
        self.assertEqual(outside.read_text(), 'untouched')

    def test_invalid_launch_toml_powers_off(self):
        for toml in ('', 'a\0b', 7, 'x' * 65537):
            with self.subTest(toml=str(toml)[:10]):
                guest = GuestHarness(self)
                guest.session()
                guest.send(op='launch_toml', toml=toml)
                self.assertEqual(guest.ended(), 'invalid_launch_toml')

    def test_a_refused_secret_is_the_attempts_error_not_a_crash(self):
        for first, second in [('a', 'a/b'), ('a/b', 'a'), ('x', '../escape'), ('y', 7)]:
            with self.subTest(ids=(first, second)):
                guest = GuestHarness(self)
                guest.session()
                guest.send(op='secret', id=first, data=b64(b'1'))
                guest.expect('secret')
                guest.send(op='secret', id=second, data=b64(b'2'))
                error = guest.expect('error')
                self.assertTrue(error['message'].startswith('secret_refused:'), error)
                self.assertNotIn('2', error['message'].split(':', 1)[1])
                guest.send(op='cancel2')
                guest.expect('cancelled')
                self.assertFalse(guest.secrets.exists())


class LiveShareTests(unittest.TestCase):
    def test_put_on_a_live_share_powers_off_and_writes_nothing(self):
        guest = GuestHarness(self, share='mounts')
        guest.session()
        guest.send(op='put', path='planted.txt', executable=False, data=b64(b'x'))
        self.assertEqual(guest.ended(), 'live_share_no_staging')
        self.assertFalse((guest.guest.SHARE_MOUNT / 'planted.txt').exists())

    def test_a_live_attempt_exports_only_its_evidence(self):
        guest = GuestHarness(self, share='mounts', scenarios=[complete(workspace_file='result.txt')])
        guest.session()
        guest.run2()
        done = guest.expect('done')
        groups = {f['group'] for f in done['_seen'] if f['event'] == 'file'}
        self.assertEqual(groups, {'evidence'})
        # The workload's write is on the share (the host's directory) itself.
        self.assertTrue((guest.guest.SHARE_MOUNT / 'result.txt').exists())
        self.assertEqual(done['binding']['attempt_id'], 'host-attempt')

    def test_reset_never_wipes_the_live_share(self):
        guest = GuestHarness(self, share='mounts')
        guest.session()
        (guest.guest.SHARE_MOUNT / 'precious.txt').write_text('keep')
        guest.send(op='reset')
        guest.expect('reset')
        self.assertEqual((guest.guest.SHARE_MOUNT / 'precious.txt').read_text(), 'keep')


class CompletionTests(unittest.TestCase):
    def test_a_warm_attempt_binds_its_receipt_and_the_session_goes_on(self):
        guest = GuestHarness(self, scenarios=[complete(code=0), complete(code=4)])
        guest.session()
        for expected in (0, 4):
            guest.send(op='reset')
            guest.expect('reset')
            guest.send(op='put', path='input.txt', executable=False, data=b64(b'hello\n'))
            guest.expect('put')
            guest.run2(argv=(b'/bin/cat', b'input.txt'))
            guest.expect('running')
            done = guest.expect('done')
            self.assertEqual(done['exit_code'], expected)
            self.assertEqual(done['binding']['attempt_id'], 'host-attempt')
            self.assertEqual(done['binding']['boot_id'], 'vm-boot')
            self.assertEqual(done['binding']['guest_boot_id'], 'guest-boot-0001')
            stdout = [base64.b64decode(f['data']) for f in done['_seen'] if f['event'] == 'stdout']
            self.assertEqual(b''.join(stdout), b'guest stdout\n')

    def test_a_receipt_for_another_profile_is_not_bound(self):
        def wrong_profile(jail):
            jail.write_receipt(profile='agent')
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[wrong_profile])
        guest.session()
        guest.run2()
        self.assertEqual(guest.ended(), 'receipt_unbound')
        self.assertIsNone(guest.error, 'a named poweroff, not a controller crash')

    def test_an_attempt_without_a_receipt_powers_off_named(self):
        def no_receipt(jail):
            jail.workload()
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[no_receipt])
        guest.session()
        guest.run2()
        self.assertEqual(guest.ended(), 'receipt_missing')
        self.assertIsNone(guest.error)

    def test_an_oversized_evidence_file_powers_off_named_and_sends_no_done(self):
        def oversized(jail):
            jail.workload()
            jail.write_receipt()
            receipt = Path(os.fsdecode(jail.option(b'--receipt')))
            (receipt.parent / 'big.bin').write_bytes(b'x' * (guest.guest.MAX_FILE + 1))
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[oversized])
        guest.session()
        guest.run2()
        frames = []
        while (frame := guest.frame()) is not None:
            frames.append(frame['event'])
        self.assertNotIn('done', frames)
        self.assertEqual(guest.ended(), 'export_limit')
        self.assertIsNone(guest.error)

    def test_a_link_in_the_staged_workspace_powers_off_named(self):
        def linked(jail):
            jail.workload()
            os.symlink('/etc/passwd', Path(jail.kwargs['cwd']) / 'link')
            jail.write_receipt()
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[linked])
        guest.expect('ready')
        guest.send(op='run', profile='tool', wall_seconds=30, argv=[b64(b'/bin/true')])
        guest.expect('running')
        self.assertEqual(guest.ended(), 'export_nonregular')
        self.assertIsNone(guest.error)

    def test_a_directory_link_in_the_staged_workspace_powers_off_named(self):
        # Review 2026-11-05 F3: a link to a directory used to be dropped from
        # the walk, so the export went out without it and the guest said
        # `completed`.
        def linked(jail):
            jail.workload()
            workspace = Path(jail.kwargs['cwd'])
            (workspace / 'real').mkdir()
            (workspace / 'real' / 'f.txt').write_text('kept')
            os.symlink('real', workspace / 'dirlink')
            jail.write_receipt()
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[linked])
        guest.expect('ready')
        guest.send(op='run', profile='tool', wall_seconds=30, argv=[b64(b'/bin/true')])
        guest.expect('running')
        self.assertEqual(guest.ended(), 'export_nonregular')
        self.assertIsNone(guest.error)

    @unittest.skipIf(os.geteuid() == 0, 'root lists a mode-000 directory')
    def test_a_directory_the_walk_cannot_list_powers_off_named(self):
        closed = []

        def unlistable(jail):
            jail.workload()
            directory = Path(jail.kwargs['cwd']) / 'closed'
            directory.mkdir()
            (directory / 'f.txt').write_text('hidden')
            directory.chmod(0)
            closed.append(directory)
            jail.write_receipt()
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[unlistable])
        self.addCleanup(lambda: [path.chmod(0o700) for path in closed])
        guest.expect('ready')
        guest.send(op='run', profile='tool', wall_seconds=30, argv=[b64(b'/bin/true')])
        guest.expect('running')
        self.assertEqual(guest.ended(), 'export_unreadable')
        self.assertIsNone(guest.error)

    def test_a_fifo_in_the_staged_workspace_powers_off_named(self):
        # O_NONBLOCK opens a FIFO for reading at once; only the S_ISREG check
        # keeps it from being exported as an empty file.
        def fifo(jail):
            jail.workload()
            os.mkfifo(Path(jail.kwargs['cwd']) / 'pipe')
            jail.write_receipt()
            jail.exit(0)
        guest = GuestHarness(self, scenarios=[fifo])
        guest.expect('ready')
        guest.send(op='run', profile='tool', wall_seconds=30, argv=[b64(b'/bin/true')])
        guest.expect('running')
        self.assertEqual(guest.ended(), 'export_nonregular')
        self.assertIsNone(guest.error)

    def test_the_file_count_and_total_limits_power_off_named(self):
        # Each file stays under MAX_FILE: only the count or the total trips.
        for limit, value in [('MAX_FILES', 2), ('MAX_BYTES', 64)]:
            with self.subTest(limit=limit):
                def many(jail):
                    jail.workload()
                    jail.write_receipt()
                    receipt = Path(os.fsdecode(jail.option(b'--receipt')))
                    for index in range(3):
                        (receipt.parent / f'extra-{index}.txt').write_bytes(b'x' * 40)
                    jail.exit(0)
                guest = GuestHarness(self, scenarios=[many])
                setattr(guest.guest, limit, value)
                guest.session()
                guest.run2()
                frames = []
                while (frame := guest.frame()) is not None:
                    frames.append(frame['event'])
                self.assertNotIn('done', frames)
                self.assertEqual(guest.ended(), 'export_limit')
                self.assertIsNone(guest.error)


if __name__ == '__main__':
    unittest.main()
