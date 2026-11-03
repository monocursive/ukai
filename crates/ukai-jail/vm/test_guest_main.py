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
* that INFRASTRUCTURE_UNITS is the image's real set (dbus.service's slice);
* that a real cancel of a running workload finishes inside WatchdogSec=4
  with no watchdog poweroff;
* the virtio-fs detection and the mount options on the real kernel;
* the staged files' real owners (root levels, workload-owned file) as the
  guest jail's loaders read them.
"""
import base64
import os
from pathlib import Path
import stat
import unittest

from guest_harness import GuestHarness, complete, hold


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
        guest.run2(profile='agent', allow_hosts=['api.example.com:443'], launch='claude')
        guest.expect('done')
        command = guest.subprocess.jails[0].command()
        self.assertEqual(command[command.index(b'--allow-host') + 1], b'api.example.com:443')
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
        self.assertTrue(any(k.endswith('.scope') and 'ukai-jail-' in k for k in guest.kernel.kills))
        self.assertTrue(any(k.endswith('.leaf') for k in guest.kernel.kills))
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
        guest.expect('done')
        leftovers = guest.kernel.alive_in(f'{guest.kernel.delegated}/app.slice/run-u7.service')
        self.assertEqual(leftovers, [], 'an escaped daemon outlived the attempt that reported done')
        self.assert_infrastructure_alive(guest)

    def test_reset_kills_a_stray_under_the_user_manager(self):
        guest = GuestHarness(self)
        guest.session()
        stray = guest.kernel.spawn(guest.uid, f'{guest.kernel.delegated}/app.slice/run-u9.service', '/bin/sh')
        guest.send(op='reset')
        guest.expect('reset')
        self.assertFalse(stray.alive)
        self.assert_infrastructure_alive(guest)

    def test_a_stray_outside_the_user_manager_refuses_the_reset(self):
        guest = GuestHarness(self)
        guest.session()
        session_scope = f'user.slice/user-{guest.uid}.slice/session-1.scope'
        guest.kernel.spawn(guest.uid, session_scope, '/bin/sh')
        guest.send(op='reset')
        self.assertEqual(guest.ended(), 'attempt_tree_unverified')

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
        self.assertIsNone(guest.ended(raise_error=False))
        self.assertIsInstance(guest.error, ValueError)


if __name__ == '__main__':
    unittest.main()
