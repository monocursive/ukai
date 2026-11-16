"""The warm session's pieces (J18, jail-macos.md §6), without a VM.

`guest.py` runs alone in the guest, so its session semantics are tested at
the seams a test can reach on any host: the command the jail is given, the
reset of the attempt directories, the ephemeral credential and launch
profile staging, the attempt stop against a model of the kernel, and the
shared shapes the host's ukai-vm depends on. test_guest_main.py drives the
whole controller loop; the live behavior — a second attempt released inside
a running guest, the lease by end-of-file, the suspend cases — needs the
preview VM and is the fault matrix's (K110), not this file's.
"""
import base64
import os
import stat
import tempfile
import shutil
import sys
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import guest
from guest_harness import Clock, Kernel, install_kernel, load_guest


def account(uid=None, gid=None, home='/home/ukai'):
    return types.SimpleNamespace(pw_name='ukai', pw_uid=os.getuid() if uid is None else uid,
                                 pw_gid=os.getgid() if gid is None else gid, pw_dir=home)


class RecordedFchown:
    """os.fchown, recorded by the inode it reached and never performed, so
    a test can name owners an unprivileged test host cannot set."""

    def __init__(self):
        self.calls = {}

    def __call__(self, fd, uid, gid):
        self.calls[os.fstat(fd).st_ino] = (uid, gid)

    def owner_of(self, path):
        return self.calls.get(os.lstat(path).st_ino)


class RunCommandTests(unittest.TestCase):
    """`run2` must hand the jail exactly what the single-run `run` op does:
    the warm design changes the lifetime around the attempt, never the
    command."""

    def test_tool_run_is_the_preview_command(self):
        argv = [b'/bin/sh', b'-c', b'cat input.txt']
        self.assertEqual(
            guest.run_command('tool', argv, 30),
            [b'/usr/local/bin/ukai-jail', b'run', b'--profile', b'tool',
             b'--workspace', b'/home/ukai/workspace',
             b'--receipt', b'/home/ukai/evidence/jail.json',
             b'--limit', b'wall=30s', b'--limit', b'mem=512MiB',
             b'--limit', b'swap=0', b'--limit', b'pids=64',
             b'--', *argv],
        )

    def test_build_adds_only_the_disposable_workspace_grant(self):
        command = guest.run_command('build', [b'/bin/true'], 300)
        self.assertIn(b'--rw', command)
        self.assertIn(b'/home/ukai/workspace', command)
        # The grant names the guest copy; no host path can appear in it.
        self.assertNotIn(b'/tmp', b''.join(command))

    def test_the_agent_policy_and_launch_reach_the_jail_before_the_argv(self):
        command = guest.run_command('agent', [b'claude', b'-p', b'--launch'], 60,
                                    allow_hosts=['api.anthropic.com:443', '*.example.com'],
                                    launch='claude')
        separator = command.index(b'--')
        options = command[:separator]
        self.assertEqual([options[i + 1] for i, part in enumerate(options) if part == b'--allow-host'],
                         [b'api.anthropic.com:443', b'*.example.com'])
        self.assertEqual(options[options.index(b'--launch') + 1], b'claude')
        self.assertEqual(command[separator + 1:], [b'claude', b'-p', b'--launch'])

    def test_the_environment_is_exactly_launch_shaped(self):
        env = guest.attempt_environment(account(uid=1001, home='/home/ukai'))
        # Exact: an added variable (a secret's path, a token) is a leak.
        self.assertEqual(env, {'HOME': '/home/ukai', 'USER': 'ukai', 'LOGNAME': 'ukai',
                               'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
                               'XDG_RUNTIME_DIR': '/run/user/1001',
                               'UKAI_CONFIG_DIR': str(guest.CONFIG_DIR)})
        self.assertFalse(any(guest.SECRETS in value for value in env.values()))


class ValidateRunTests(unittest.TestCase):
    def request(self, **overrides):
        request = dict(profile='tool', wall_seconds=30, argv=[base64.b64encode(b'/bin/true').decode()])
        request.update(overrides)
        return request

    def test_a_valid_agent_request_returns_its_parts(self):
        profile, wall, argv, hosts, launch = guest.validate_run(
            self.request(profile='agent', allow_hosts=['api.example.com:443'], launch='my-tool_2'), False)
        self.assertEqual((profile, wall, argv, hosts, launch),
                         ('agent', 30, [b'/bin/true'], ['api.example.com:443'], 'my-tool_2'))

    def test_a_portless_tls_only_rule_passes_verbatim(self):
        # The host sends a TLS-only grant without its port (the snapshot's
        # tls_only shape); the guest jail's `--allow-host HOST[:PORT]` reads
        # the omitted port as TLS-only, so the controller must not add one.
        rules = ['api.anthropic.com', '*.example.com', 'example.org:8443']
        hosts = guest.validate_run(self.request(profile='agent', allow_hosts=rules), False)[3]
        self.assertEqual(hosts, rules)
        command = guest.run_command('agent', [b'/bin/true'], 30, allow_hosts=hosts)
        self.assertEqual([command[i + 1] for i, part in enumerate(command) if part == b'--allow-host'],
                         [b'api.anthropic.com', b'*.example.com', b'example.org:8443'])

    def test_the_launch_name_grammar_is_the_jails(self):
        for name in ('claude', 'a', 'a' * 64, 'x1-_'):
            self.assertTrue(guest.valid_launch_name(name), name)
        for name in ('', 'Claude', '1abc', '-a', 'a' * 65, 'a.b', 'a/b', 'a b', None, 7):
            self.assertFalse(guest.valid_launch_name(name), name)

    def test_refusals(self):
        for overrides, live, reason in [
                (dict(allow_hosts=['h:443']), False, 'invalid_proxy_policy'),
                (dict(launch='claude'), False, 'invalid_launch'),
                (dict(profile='build'), True, 'live_share_requires_protected_profile'),
                (dict(profile='agent', launch='../x'), False, 'invalid_launch'),
                (dict(wall_seconds=0), False, 'invalid_policy')]:
            with self.subTest(overrides=overrides), self.assertRaises(guest.Refusal) as refused:
                guest.validate_run(self.request(**overrides), live)
            self.assertEqual(refused.exception.reason, reason)
        # Build stays allowed on the staged (disposable) workspace.
        self.assertEqual(guest.validate_run(self.request(profile='build'), False)[0], 'build')


class ResetAttemptTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.account = account()

    def test_reset_empties_and_recreates_both_directories(self):
        workspace = self.root / 'workspace'
        evidence = self.root / 'evidence'
        guest.reset_attempt(self.account, workspace, evidence)
        (workspace / 'leftover.txt').write_text('last attempt')
        (evidence / 'jail.json').write_text('{}')
        (workspace / 'nested').mkdir()
        guest.reset_attempt(self.account, workspace, evidence)
        for path in (workspace, evidence):
            self.assertEqual(list(path.iterdir()), [], f'{path} is empty for the next attempt')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_reset_recreates_missing_directories(self):
        workspace = self.root / 'gone'
        guest.reset_attempt(self.account, workspace, self.root / 'evidence')
        self.assertTrue(workspace.is_dir())

    def test_reset_hands_both_directories_to_the_workload_by_descriptor(self):
        recorded = RecordedFchown()
        with mock.patch.object(guest.os, 'fchown', recorded):
            guest.reset_attempt(account(uid=4242, gid=4343), self.root / 'workspace', self.root / 'evidence')
        for name in ('workspace', 'evidence'):
            self.assertEqual(recorded.owner_of(self.root / name), (4242, 4343), name)


class SecretStagingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.credentials = self.root / 'credentials'

    def test_a_secret_stages_private_and_ephemeral(self):
        path = guest.stage_secret('token', b's3cret', self.credentials)
        self.assertEqual(path.read_bytes(), b's3cret')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.credentials.stat().st_mode), 0o710)
        guest.clear_secrets(self.credentials)
        self.assertFalse(self.credentials.exists())

    def test_levels_are_the_controllers_and_the_file_the_workloads(self):
        # H5: the levels are never the workload's (it could plant links in
        # them); the file is, because the jail reads it as that account.
        recorded = RecordedFchown()
        with mock.patch.object(guest.os, 'fchown', recorded):
            path = guest.stage_secret('api/v1/token', b'v', self.credentials, account=account(4242, 4343))
        controller = os.geteuid()
        for level in (self.credentials, self.credentials / 'api', self.credentials / 'api/v1'):
            self.assertEqual(recorded.owner_of(level), (controller, 4343), level)
            self.assertEqual(stat.S_IMODE(level.stat().st_mode), 0o710, level)
        self.assertEqual(recorded.owner_of(path), (4242, 4343))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_a_planted_link_at_any_level_is_never_followed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        guest.stage_secret('first', b'v1', self.credentials)
        os.symlink(outside, self.credentials / 'api')
        with self.assertRaises(OSError):
            guest.stage_secret('api/token', b'SECRET', self.credentials)
        os.symlink(outside / 'target', self.credentials / 'leaf')
        with self.assertRaises(OSError):
            guest.stage_secret('leaf', b'SECRET', self.credentials)
        self.assertEqual(list(outside.iterdir()), [])
        # The root itself, swapped for a link.
        guest.clear_secrets(self.credentials)
        os.symlink(outside, self.credentials)
        with self.assertRaises(OSError):
            guest.stage_secret('token', b'SECRET', self.credentials)
        self.assertEqual(list(outside.iterdir()), [])

    def test_a_level_someone_else_owns_is_refused(self):
        self.credentials.mkdir()
        with mock.patch.object(guest.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError):
                guest.stage_secret('token', b'v', self.credentials)

    def test_prefix_colliding_ids_refuse_without_overwriting(self):
        guest.stage_secret('a', b'1', self.credentials)
        with self.assertRaises(OSError):
            guest.stage_secret('a/b', b'2', self.credentials)
        guest.stage_secret('c/d', b'3', self.credentials)
        with self.assertRaises(OSError):
            guest.stage_secret('c', b'4', self.credentials)
        self.assertEqual((self.credentials / 'a').read_bytes(), b'1')

    def test_a_secret_id_cannot_climb_out_of_the_staging_root(self):
        for secret_id in ('../escape', '/absolute', 'a/../../b'):
            with self.subTest(secret_id=secret_id), self.assertRaises(ValueError):
                guest.stage_secret(secret_id, b'x', self.credentials)

    def test_the_default_root_is_tmpfs_and_env_relocates_it(self):
        with mock.patch.dict(os.environ, {'UKAI_VM_SECRETS': str(self.root / 'elsewhere')}):
            self.assertEqual(guest.secrets_root(), self.root / 'elsewhere')
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('UKAI_VM_SECRETS', None)
            self.assertEqual(guest.secrets_root(), Path(guest.SECRETS))

    def test_a_second_secret_with_one_id_refuses(self):
        guest.stage_secret('token', b'one', self.credentials)
        with self.assertRaises(FileExistsError):
            guest.stage_secret('token', b'two', self.credentials)
        self.assertEqual((self.credentials / 'token').read_bytes(), b'one')

    def test_a_clear_that_leaves_the_tree_is_an_error(self):
        guest.stage_secret('token', b'v', self.credentials)
        with mock.patch.object(guest.shutil, 'rmtree'):
            with self.assertRaises(OSError):
                guest.clear_secrets(self.credentials)


class LaunchProfileStagingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.guest = load_guest()
        self.guest.CONFIG_DIR = self.root / 'config'

    def stage(self, name='claude', who=None):
        self.guest.launch_toml = '[credentials.api]\nsource = "/run/ukai-vm/credentials/api"\n'
        self.guest._stage_launch_profile(name, who or account())

    def test_the_file_has_the_loaders_shape_and_the_toml_is_consumed(self):
        recorded = RecordedFchown()
        with mock.patch.object(self.guest.os, 'fchown', recorded):
            self.stage(who=account(4242, 4343))
        path = self.root / 'config/launch/claude.toml'
        info = path.lstat()
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(recorded.owner_of(path), (4242, 4343))
        self.assertIsNone(self.guest.launch_toml)
        self.assertFalse(stat.S_IMODE((self.root / 'config/launch').stat().st_mode) & 0o022)

    def test_a_present_name_is_refused_never_written_through(self):
        outside = self.root / 'outside'
        outside.write_text('untouched')
        directory = self.root / 'config/launch'
        directory.mkdir(parents=True)
        (directory / 'claude.toml').symlink_to(outside)
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertEqual(outside.read_text(), 'untouched')

    def test_a_second_stage_after_clear_succeeds(self):
        self.stage()
        self.guest.clear_launch_profile()
        self.assertEqual(list((self.root / 'config/launch').iterdir()), [])
        self.stage()

    def test_without_staged_toml_or_with_a_bad_name_it_refuses(self):
        with self.assertRaises(self.guest.Refusal) as refused:
            self.guest._stage_launch_profile('claude', account())
        self.assertEqual(refused.exception.reason, 'launch_without_toml')
        self.guest.launch_toml = 'x'
        with self.assertRaises(self.guest.Refusal) as refused:
            self.guest._stage_launch_profile('../escape', account())
        self.assertEqual(refused.exception.reason, 'invalid_launch')

    def test_clearing_an_absent_directory_is_quiet(self):
        self.guest.clear_launch_profile()


class StopModelTests(unittest.TestCase):
    """D6 against the kernel model directly (test_guest_main.py drives the
    same stop through the controller loop)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.kernel = Kernel(self.root, 1001)
        self.clock = Clock()
        g = self.guest = load_guest()
        install_kernel(g, self.kernel)
        g.clock = self.clock.clock
        g.time = types.SimpleNamespace(sleep=self.clock.sleep)
        self.audits = []
        self.fields = {}
        g.audit = lambda event, **fields: (self.audits.append(event), self.fields.__setitem__(event, fields))
        self.notifies = []
        g.notify = lambda: self.notifies.append(self.clock.now)
        self.account = account(uid=1001, gid=1001)
        self.delegated = self.kernel.delegated

    def learned(self):
        return self.guest.learn_infrastructure(self.account)

    def assert_infrastructure_alive(self):
        for process in (self.kernel.manager, self.kernel.sd_pam, self.kernel.bus):
            self.assertTrue(process.alive, f'{process.exe} in {process.cgroup} was killed')

    def stop(self):
        return self.guest.stop_attempt(self.account, self.learned())

    # -- learning the infrastructure (F1) ------------------------------------

    def test_the_infrastructure_is_systemds_manager_its_helper_and_the_bus(self):
        infrastructure = self.learned()
        kernel = self.kernel
        self.assertEqual(infrastructure.pids, {kernel.manager.pid: kernel.manager.starttime,
                                               kernel.sd_pam.pid: kernel.sd_pam.starttime,
                                               kernel.bus.pid: kernel.bus.starttime})
        self.assertEqual(infrastructure.units, ('init.scope', 'session.slice/dbus.service'))
        # The bus is started (as the jail's first busctl would activate it)
        # before it is read; both --user calls are the account's.
        self.assertEqual(kernel.systemctl_calls, [
            (('show', 'user@1001.service', '-p', 'MainPID'), False),
            (('start', 'dbus.service'), True),
            (('show', 'dbus.service', '-p', 'MainPID', '-p', 'ControlGroup'), True)])

    def test_a_bus_not_yet_running_is_started_then_learned(self):
        self.kernel.exit(self.kernel.bus)
        infrastructure = self.learned()
        self.assertTrue(self.kernel.bus.alive)
        self.assertIn(self.kernel.bus.pid, infrastructure.pids)

    def test_the_bus_unit_is_where_systemd_says_not_a_fixed_spelling(self):
        self.kernel.move(self.kernel.bus, f'{self.delegated}/app.slice/dbus.service')
        self.assertEqual(self.learned().units, ('init.scope', 'app.slice/dbus.service'))

    def test_disagreements_with_proc_refuse_the_session(self):
        kernel = self.kernel
        bystander = kernel.spawn(1001, f'{self.delegated}/app.slice/run-u1.service', 'sh')
        cases = {
            'no manager': dict(manager=0),
            'manager outside init.scope': dict(manager=bystander.pid),
            'bus pid elsewhere': dict(bus=bystander.pid),
            'bus unit outside the manager': dict(bus_cgroup=f'/system.slice/dbus.service'),
            'bus unit is init.scope': dict(bus_cgroup=f'/{self.delegated}/init.scope'),
            'bus unit spelled differently from /proc': dict(bus_cgroup=f'/{self.delegated}/app.slice/dbus.service'),
            'no bus': dict(bus=0),
        }
        for name, reported in cases.items():
            with self.subTest(name):
                kernel.reported = {'manager': None, 'bus': None, 'bus_cgroup': None, **reported}
                with self.assertRaises(self.guest.InfrastructureUnknown):
                    self.learned()
        kernel.reported = {'manager': None, 'bus': None, 'bus_cgroup': None}
        root_bus = kernel.spawn(0, f'{self.delegated}/session.slice/dbus.service', 'dbus-daemon')
        kernel.reported['bus'] = root_bus.pid
        with self.assertRaises(self.guest.InfrastructureUnknown):
            self.learned()

    def test_a_bus_that_systemd_and_proc_agree_is_misplaced_refuses_the_session(self):
        # Agreement is not enough: the bus must be a unit of the user
        # manager, and not inside the manager's own scope.
        for cgroup in ('system.slice/dbus.service', f'{self.delegated}/init.scope/x'):
            with self.subTest(cgroup):
                self.kernel.move(self.kernel.bus, cgroup)
                with self.assertRaises(self.guest.InfrastructureUnknown):
                    self.learned()

    def test_a_failed_systemctl_refuses_the_session(self):
        for verb in ('show', 'start'):
            with self.subTest(verb):
                self.kernel.systemctl_failures = {verb}
                with self.assertRaises(self.guest.InfrastructureUnknown):
                    self.learned()

    def test_a_second_manager_child_in_init_scope_refuses_the_session(self):
        self.kernel.spawn(1001, f'{self.delegated}/init.scope', 'sh', ppid=self.kernel.manager.pid)
        with self.assertRaises(self.guest.InfrastructureUnknown):
            self.learned()

    def test_only_the_managers_own_child_is_its_helper(self):
        # A process of the account in init.scope that the manager did not
        # fork is not infrastructure, whatever it is called.
        impostor = self.kernel.spawn(1001, f'{self.delegated}/init.scope', '(sd-pam)')
        self.assertNotIn(impostor.pid, self.learned().pids)

    # -- the stop -------------------------------------------------------------

    def test_the_boundaries_are_the_attempt_and_everything_but_the_infrastructure(self):
        g = self.guest
        g.attempt_counter = 0
        self.kernel.ensure('ukai-attempts.slice/attempt-3')
        for cgroup in ('app.slice/ukai-jail-9-abc.scope', 'app.slice/run-u1.service', 'ukai-att_x.leaf',
                       'background.slice/thing.service', 'session.slice/other.service',
                       'init.scope/x', 'session.slice/dbus.service/y/z'):
            self.kernel.ensure(f'{self.delegated}/{cgroup}')
        units = ('init.scope', 'session.slice/dbus.service')
        names = sorted(self.kernel.relative(path) for path in g.attempt_boundaries(1001, units))
        self.assertEqual(names, sorted([
            'ukai-attempts.slice/attempt-3',
            f'{self.delegated}/app.slice',
            f'{self.delegated}/ukai-att_x.leaf',
            f'{self.delegated}/background.slice',
            f'{self.delegated}/session.slice/other.service',
            f'{self.delegated}/init.scope/x',
            f'{self.delegated}/session.slice/dbus.service/y']))
        # The same tree with the bus where a unit without Slice= lands.
        self.kernel.ensure(f'{self.delegated}/app.slice/dbus.service')
        names = sorted(self.kernel.relative(path)
                       for path in g.attempt_boundaries(1001, ('init.scope', 'app.slice/dbus.service')))
        self.assertIn(f'{self.delegated}/app.slice/ukai-jail-9-abc.scope', names)
        self.assertIn(f'{self.delegated}/session.slice', names)
        self.assertNotIn(f'{self.delegated}/app.slice', names)
        self.assertNotIn(f'{self.delegated}/app.slice/dbus.service', names)

    def test_the_stop_kills_the_scope_and_leaf_and_spares_the_manager_and_bus(self):
        supervisor = self.kernel.spawn(1001, f'{self.delegated}/app.slice/ukai-jail-9-abc.scope', 'ukai-jail')
        workload = self.kernel.spawn(1001, f'{self.delegated}/ukai-att_9.leaf', 'sleep')
        self.stop()
        self.guest.drop_attempt_cgroups(1001)
        self.assertFalse(supervisor.alive)
        self.assertFalse(workload.alive)
        self.assert_infrastructure_alive()
        self.assertFalse((self.kernel.cgroups / self.delegated / 'ukai-att_9.leaf').exists())
        self.assertIn('workload_tree_empty', self.audits)

    def test_the_report_names_what_the_stop_found_before_it_killed_anything(self):
        # The witness the host checks: cgroup.kill ends the leaf's process
        # without the stop recording it among strays_killed, so only the
        # pre-kill snapshot says the guest jail left it behind.
        leaf = f'{self.delegated}/ukai-att_9.leaf'
        workload = self.kernel.spawn(1001, leaf, 'sleep')
        report = self.stop()
        self.assertFalse(workload.alive)
        self.assertEqual(report['populated_before_kill'], [leaf])
        self.assertEqual(report['live_before_kill'], [[workload.pid, '/' + leaf]])
        self.assertIn(leaf, report['boundaries'])
        self.assertEqual(self.fields['workload_tree_empty'], report)

    def test_a_stray_elsewhere_is_in_the_witness_and_among_the_killed(self):
        stray = self.kernel.spawn(1001, 'user.slice/user-1001.slice/session-1.scope', 'sh')
        report = self.stop()
        self.assertEqual(report['populated_before_kill'], [])
        self.assertEqual(report['live_before_kill'], [[stray.pid, '/user.slice/user-1001.slice/session-1.scope']])
        self.assertEqual(report['strays_killed'], [[stray.pid, '/user.slice/user-1001.slice/session-1.scope']])

    def test_a_stop_after_a_clean_exit_reports_an_empty_witness(self):
        report = self.stop()
        self.assertEqual(sorted(report), ['boundaries', 'live_before_kill', 'populated_before_kill', 'strays_killed'])
        self.assertEqual((report['populated_before_kill'], report['live_before_kill'], report['strays_killed']),
                         ([], [], []))
        self.assert_infrastructure_alive()

    def test_the_infrastructure_is_never_in_the_witness(self):
        # The manager, its helper and the bus are live account processes;
        # they are the session's, not survivors of the guest jail.
        report = self.stop()
        pids = {pid for pid, _ in report['live_before_kill']}
        self.assertFalse(pids & {self.kernel.manager.pid, self.kernel.sd_pam.pid, self.kernel.bus.pid})

    def test_intruders_inside_the_infrastructure_units_are_killed_and_it_survives(self):
        # The review's measured route (cgroup-exp): a direct cgroup.procs
        # write into init.scope or the bus's unit, or a sub-cgroup of one.
        infrastructure = self.learned()
        intruders = [self.kernel.spawn(1001, f'{self.delegated}/{cgroup}', 'python3')
                     for cgroup in ('init.scope', 'session.slice/dbus.service', 'init.scope/x',
                                    'app.slice/dbus.service')]
        self.guest.stop_attempt(self.account, infrastructure)
        for intruder in intruders:
            self.assertFalse(intruder.alive, f'an intruder in {intruder.cgroup} survived the stop')
        self.assert_infrastructure_alive()
        killed = {pid for pid, _ in self.fields['workload_tree_empty']['strays_killed']}
        self.assertTrue({intruders[0].pid, intruders[1].pid} <= killed)

    def test_an_intruder_that_cannot_be_killed_fails_the_stop(self):
        infrastructure = self.learned()
        self.kernel.spawn(1001, f'{self.delegated}/init.scope', 'python3', unkillable=True)
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.guest.stop_attempt(self.account, infrastructure)
        self.assert_infrastructure_alive()

    def test_a_reused_infrastructure_pid_is_not_infrastructure(self):
        infrastructure = self.learned()
        bus = self.kernel.bus
        self.kernel.exit(bus)
        impostor = self.kernel.spawn(1001, bus.cgroup, '/usr/bin/dbus-daemon', pid=bus.pid, ppid=bus.ppid)
        self.guest.stop_attempt(self.account, infrastructure)
        self.assertFalse(impostor.alive, 'a process on the learned bus pid passed for the bus')
        self.assertTrue(self.kernel.manager.alive and self.kernel.sd_pam.alive)

    def test_a_restarted_bus_is_killed_and_the_manager_survives(self):
        infrastructure = self.learned()
        self.kernel.exit(self.kernel.bus)
        restarted = self.kernel.spawn(1001, f'{self.delegated}/session.slice/dbus.service', 'dbus-daemon',
                                      ppid=self.kernel.manager.pid)
        self.guest.stop_attempt(self.account, infrastructure)
        self.assertFalse(restarted.alive)
        self.assertTrue(self.kernel.manager.alive and self.kernel.sd_pam.alive)

    def test_a_zombie_leader_with_a_live_thread_is_killed_by_pid(self):
        # F2: cgroup.kill leaves such a group and its leaf stays populated
        # (measured); the stray scan sees its live thread and kills it.
        group = self.kernel.spawn(1001, f'{self.delegated}/ukai-att_9.leaf', 'python3', zombie_leader=True)
        self.stop()
        self.assertFalse(group.alive)
        self.assertIn(group.pid, self.kernel.signals)
        self.assertIn('workload_tree_empty', self.audits)

    def test_a_populated_boundary_without_a_workload_uid_still_fails_the_stop(self):
        # An unkillable root-owned process in the jail's scope: no uid stray,
        # but the boundary never empties — the populated check decides, and
        # the audit names what holds it.
        helper = self.kernel.spawn(0, f'{self.delegated}/app.slice/ukai-jail-9-abc.scope', 'helper',
                                   unkillable=True)
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.stop()
        self.assertLessEqual(max(b - a for a, b in zip(self.notifies, self.notifies[1:])), .1)
        detail = self.fields['attempt_tree_unverified']
        self.assertEqual(detail['strays'], [])
        self.assertEqual(detail['members'], {f'/{self.delegated}/app.slice': [[helper.pid, '0', 'live']]})

    def test_a_stray_anywhere_else_is_killed(self):
        stray = self.kernel.spawn(1001, 'user.slice/user-1001.slice/session-1.scope', 'sh')
        self.stop()
        self.assertFalse(stray.alive)
        self.assertEqual(self.fields['workload_tree_empty']['strays_killed'],
                         [[stray.pid, '/user.slice/user-1001.slice/session-1.scope']])

    def test_an_unkillable_stray_anywhere_else_fails_the_stop_after_the_budget(self):
        stray = self.kernel.spawn(1001, 'user.slice/user-1001.slice/session-1.scope', 'sh', unkillable=True)
        infrastructure = self.learned()
        start = self.clock.now
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.guest.stop_attempt(self.account, infrastructure)
        self.assertGreaterEqual(self.clock.now - start, self.guest.STOP_BUDGET)
        self.assertLess(self.clock.now - start, self.guest.STOP_BUDGET + .1)
        self.assertIn('attempt_tree_unverified', self.audits)
        self.assertEqual(self.fields['attempt_tree_unverified']['strays'],
                         [[stray.pid, '/user.slice/user-1001.slice/session-1.scope']])

    def test_a_stop_without_learned_infrastructure_fails(self):
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.guest.stop_attempt(self.account, None)

    def test_other_accounts_and_zombies_are_not_strays(self):
        self.kernel.spawn(0, 'system.slice/cron.service', 'cron')
        zombie = self.kernel.spawn(1001, 'system.slice/ukai-vm.service', 'sh')
        infrastructure = self.learned()
        self.kernel.set_state(zombie, 'Z')
        self.assertEqual(self.guest.stray_processes(1001, infrastructure.pids), [])
        self.kernel.set_state(zombie, 'R')
        self.assertEqual(self.guest.stray_processes(1001, infrastructure.pids),
                         [(zombie.pid, zombie.starttime, '/system.slice/ukai-vm.service')])

    def test_process_facts_read_past_a_hostile_comm(self):
        # The comm field may hold spaces and parentheses; the fields after
        # its last ')' are the kernel's.
        process = self.kernel.spawn(1001, f'{self.delegated}/ukai-att_9.leaf', 'evil) S 1 (x')
        facts = self.guest.process_facts(process.pid)
        self.assertEqual((facts.ppid, facts.starttime, facts.live), (1, process.starttime, True))
        self.assertIsNone(self.guest.process_facts(999999))

    def test_a_vanished_cgroup_is_empty_and_an_unreadable_one_is_not(self):
        g = self.guest
        self.assertIsNone(g.cgroup_populated(self.root / 'nowhere'))
        directory = self.root / 'odd'
        directory.mkdir()
        with self.assertRaises(FileNotFoundError):
            g.cgroup_populated(directory)
        (directory / 'cgroup.events').write_text('frozen 0\n')
        with self.assertRaises(ValueError):
            g.cgroup_populated(directory)
        (directory / 'cgroup.events').write_text('populated 1\nfrozen 0\n')
        self.assertTrue(g.cgroup_populated(directory))

    def test_the_reap_is_bounded(self):
        class Stuck:
            def poll(self):
                return None
        start = self.clock.now
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.guest.reap(Stuck())
        self.assertLess(self.clock.now - start, self.guest.REAP_BUDGET + .1)
        self.assertTrue(self.notifies)

    def test_the_poweroff_kill_feeds_the_watchdog_while_it_waits(self):
        g = self.guest
        boundary = self.kernel.cgroups / 'user.slice'
        self.kernel.spawn(1001, 'user.slice/stuck', 'sh', unkillable=True)
        with self.assertRaises(TimeoutError):
            g.kill_workload(str(boundary))
        self.assertGreater(len(self.notifies), 10)


class SystemctlTests(unittest.TestCase):
    """The one systemctl call `learn_infrastructure` makes, as it reaches
    subprocess (the harness answers for systemd above this seam)."""

    def setUp(self):
        g = self.guest = load_guest()
        self.calls = []
        self.answer = guest.subprocess.CompletedProcess([], 0, stdout='MainPID=7\n', stderr='')
        self.notifies = []
        g.notify = lambda: self.notifies.append(len(self.calls))

        def run(argv, **options):
            self.calls.append((argv, options))
            if isinstance(self.answer, BaseException):
                raise self.answer
            return self.answer
        g.subprocess = types.SimpleNamespace(run=run, DEVNULL=guest.subprocess.DEVNULL,
                                             SubprocessError=guest.subprocess.SubprocessError)

    def test_the_system_call_is_roots_and_the_user_call_is_the_accounts(self):
        g = self.guest
        self.assertEqual(g.systemctl('show', 'user@1001.service', '-p', 'MainPID'), 'MainPID=7\n')
        g.systemctl('show', 'dbus.service', account=account(uid=1001, gid=1001))
        (system, system_options), (user, user_options) = self.calls
        self.assertEqual(system, ['/usr/bin/systemctl', 'show', 'user@1001.service', '-p', 'MainPID'])
        self.assertNotIn('user', system_options)
        self.assertEqual(user, ['/usr/bin/systemctl', '--user', 'show', 'dbus.service'])
        self.assertEqual((user_options['user'], user_options['group'], user_options['extra_groups']),
                         (1001, 1001, []))
        self.assertEqual(user_options['env']['XDG_RUNTIME_DIR'], '/run/user/1001')
        for options in (system_options, user_options):
            self.assertLessEqual(options['timeout'], 2.0)
            self.assertIs(options['stdin'], guest.subprocess.DEVNULL)
        self.assertEqual(self.notifies, [0, 1, 1, 2], 'the watchdog is fed on both sides of each call')

    def test_a_failed_or_hung_call_is_infrastructure_unknown(self):
        g = self.guest
        self.answer = guest.subprocess.CompletedProcess([], 1, stdout='', stderr='')
        with self.assertRaises(g.InfrastructureUnknown):
            g.systemctl('show', 'x')
        self.answer = guest.subprocess.TimeoutExpired(['systemctl'], 2.0)
        with self.assertRaises(g.InfrastructureUnknown):
            g.systemctl('show', 'x')
        self.answer = FileNotFoundError('systemctl')
        with self.assertRaises(g.InfrastructureUnknown):
            g.systemctl('show', 'x')

    def test_unit_properties_parse_systemds_order(self):
        self.assertEqual(self.guest.unit_properties('ControlGroup=/a/b=c\nMainPID=12\nnoise\n'),
                         {'ControlGroup': '/a/b=c', 'MainPID': '12'})


ZOMBIE_LEADER = r'''
import ctypes, os, sys, threading, time
if os.fork():
    os._exit(0)
thread = threading.Thread(target=lambda: time.sleep(30), daemon=False)
thread.start()
print(os.getpid(), flush=True)
ctypes.CDLL(None).syscall(93 if os.uname().machine == 'aarch64' else 60, 0)
'''


@unittest.skipUnless(hasattr(os, 'pidfd_open') and Path('/proc/self/task').is_dir(),
                     'pidfd and /proc are Linux')
class RealProcTests(unittest.TestCase):
    """The stray scan's /proc reading and its pidfd kill on the running
    kernel: the two facts F2 rests on (measured 2026-11-03 on 7.2.12)."""

    def setUp(self):
        self.guest = load_guest()

    def test_a_zombie_leader_with_a_live_thread_reads_live_and_its_pidfd_kill_ends_it(self):
        g = self.guest
        spawner = guest.subprocess.Popen([sys.executable, '-c', ZOMBIE_LEADER], stdout=guest.subprocess.PIPE,
                                         text=True)
        pid = int(spawner.stdout.readline())  # the group keeps the pipe open
        spawner.stdout.close()
        spawner.wait(timeout=5)
        self.addCleanup(lambda: os.path.exists(f'/proc/{pid}') and os.kill(pid, 9))
        deadline = time.monotonic() + 5
        while 'Z' not in (Path(f'/proc/{pid}/status').read_text().split('State:')[1].split()[0]):
            self.assertLess(time.monotonic(), deadline, 'the leader never exited')
            time.sleep(.02)
        facts = g.process_facts(pid)
        self.assertTrue(facts.live, 'a zombie leader whose thread runs read as dead')
        self.assertIn(pid, [found for found, _, _ in g.stray_processes(os.getuid(), {})])
        g.kill_process(pid, facts.starttime)
        deadline = time.monotonic() + 5
        while (facts := g.process_facts(pid)) is not None and facts.live:
            self.assertLess(time.monotonic(), deadline, 'the pidfd SIGKILL did not end the group')
            time.sleep(.02)

    def test_a_stale_start_time_is_never_signalled(self):
        g = self.guest
        sleeper = guest.subprocess.Popen(['sleep', '30'])
        self.addCleanup(sleeper.wait)
        self.addCleanup(sleeper.kill)
        starttime = g.process_facts(sleeper.pid).starttime
        g.kill_process(sleeper.pid, starttime + 1)
        time.sleep(.2)
        self.assertIsNone(sleeper.poll(), 'a pid whose start time differs was signalled')
        g.kill_process(sleeper.pid, starttime)
        self.assertEqual(sleeper.wait(timeout=5), -9)
        g.kill_process(sleeper.pid, starttime)  # gone: quiet


class ShareMountTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        g = self.guest = load_guest()
        g.VIRTIO_DEVICES = self.root / 'virtio'
        g.SHARE_MOUNT = self.root / 'mnt/workspace'
        self.runs = []
        g.subprocess = types.SimpleNamespace(
            run=lambda argv, **kw: self.runs.append(argv) or (_ for _ in ()).throw(
                guest.subprocess.CalledProcessError(32, argv)),
            SubprocessError=guest.subprocess.SubprocessError)
        g.share_mounted = lambda: False
        g.audit = lambda *a, **k: None
        self.reasons = []

        def poweroff(reason):
            self.reasons.append(reason)
            raise RuntimeError(reason)
        g.poweroff = poweroff

    def device(self, name, value):
        (self.root / 'virtio' / name).mkdir(parents=True)
        (self.root / 'virtio' / name / 'device').write_text(value + '\n')

    def test_only_a_virtio_fs_device_counts_as_attached(self):
        self.assertFalse(self.guest.share_attached())
        self.device('virtio0', '0x0001')
        self.device('virtio2', 'garbage')
        self.assertFalse(self.guest.share_attached())
        self.device('virtio1', '0x001a')
        self.assertTrue(self.guest.share_attached())

    def test_a_failed_mount_without_a_device_is_the_staged_mode(self):
        self.assertFalse(self.guest.mount_share())
        self.assertEqual(self.reasons, [])
        self.assertIn('nosuid,nodev', self.runs[0])
        self.assertNotIn('noexec', ','.join(self.runs[0]))

    def test_a_failed_mount_with_a_device_powers_off_named(self):
        self.device('virtio1', '0x001a')
        with self.assertRaises(RuntimeError):
            self.guest.mount_share()
        self.assertEqual(self.reasons, ['live_share_mount_failed'])


class SessionAgreementTests(unittest.TestCase):
    """ukai-vm drives `session`/`reset`/`secret`/`run2`/`cancel2`; the shapes
    here are what it must send and expect back."""

    OPS = ('session', 'reset', 'secret', 'run2', 'cancel2', 'launch_toml')

    def test_the_session_ops_are_named_and_the_single_run_op_is_untouched(self):
        source = Path(guest.__file__).read_text()
        for op in self.OPS:
            with self.subTest(op=op):
                self.assertIn(f"op == '{op}'", source)
        self.assertIn("op == 'run' and process is None:", source,
                      'the single-run op keeps its own gate')

    def test_the_session_reply_names_its_kernel_and_share_like_the_ready_frame(self):
        # ukai-vm reads `kernel` and `live_share` from the session reply.
        source = Path(guest.__file__).read_text()
        self.assertIn("'event': 'session', 'kernel': os.uname().release, 'live_share': live_share", source)


class GuestSafetyRegressionTests(unittest.TestCase):
    def test_reset_replaces_workload_symlink_without_touching_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / 'outside'
            outside.mkdir()
            outside.chmod(0o755)  # explicit: no dependence on the process umask
            (outside / 'keep').write_text('untouched')
            (root / 'workspace').symlink_to(outside)
            guest.reset_attempt(account(), root / 'workspace', root / 'evidence')
            self.assertFalse((root / 'workspace').is_symlink())
            self.assertEqual((outside / 'keep').read_text(), 'untouched')
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)

    def test_reset_never_chowns_by_path_after_workload(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(guest.os, 'chown', side_effect=AssertionError('path chown')):
            guest.reset_attempt(account(), Path(temp) / 'workspace', Path(temp) / 'evidence')

    def test_receipt_binding_uses_canonical_argv_and_rejects_wrong_boot_or_profile(self):
        import hashlib
        import struct
        argv = [b'/bin/true', b'']
        preimage = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(argv))
        preimage += b''.join(struct.pack('>Q', len(a)) + a for a in argv)
        digest = 'sha256:' + hashlib.sha256(preimage).hexdigest()
        request = dict(attempt_id='host', boot_id='boot', profile='tool', argv=[base64.b64encode(a).decode() for a in argv])
        receipt = dict(attempt_id='guest', argv_digest=digest, policy=dict(name='tool'), process=dict(identity=dict(value=dict(boot_id='linux'))))
        binding = guest.receipt_binding(request, receipt, 'linux')
        self.assertEqual(binding['attempt_id'], 'host')
        self.assertEqual(binding['argv_digest'], digest)
        with self.assertRaises(ValueError):
            guest.receipt_binding(request, receipt, 'other-boot')
        with self.assertRaises(ValueError):
            guest.receipt_binding(dict(request, profile='agent'), receipt, 'linux')
        with self.assertRaises(ValueError):
            guest.receipt_binding(dict(request, argv=[base64.b64encode(b'/bin/false').decode()]), receipt, 'linux')


if __name__ == '__main__':
    unittest.main()
