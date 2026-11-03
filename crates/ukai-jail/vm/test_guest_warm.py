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
import types
import unittest
from pathlib import Path
from unittest import mock

import guest
from guest_harness import Clock, Kernel, load_guest


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
        g.CGROUP_ROOT, g.PROC_ROOT = self.kernel.cgroups, self.kernel.proc
        g.make_cgroup, g.cgroup_kill, g.remove_cgroup = self.kernel.make_cgroup, self.kernel.kill, self.kernel.remove
        g.clock = self.clock.clock
        g.time = types.SimpleNamespace(sleep=self.clock.sleep)
        self.audits = []
        g.audit = lambda event, **fields: self.audits.append(event)
        self.notifies = []
        g.notify = lambda: self.notifies.append(self.clock.now)
        self.account = account(uid=1001, gid=1001)
        self.delegated = self.kernel.delegated

    def test_the_boundaries_are_the_attempt_and_everything_but_the_infrastructure(self):
        g = self.guest
        g.attempt_counter = 0
        self.kernel.ensure('ukai-attempts.slice/attempt-3')
        for cgroup in ('app.slice/ukai-jail-9-abc.scope', 'app.slice/run-u1.service', 'ukai-att_x.leaf',
                       'background.slice/thing.service', 'session.slice/other.service'):
            self.kernel.ensure(f'{self.delegated}/{cgroup}')
        names = sorted(self.kernel.relative(path) for path in g.attempt_boundaries(1001))
        self.assertEqual(names, sorted([
            'ukai-attempts.slice/attempt-3',
            f'{self.delegated}/app.slice/ukai-jail-9-abc.scope',
            f'{self.delegated}/app.slice/run-u1.service',
            f'{self.delegated}/ukai-att_x.leaf',
            f'{self.delegated}/background.slice/thing.service',
            f'{self.delegated}/session.slice/other.service']))

    def test_the_stop_kills_the_scope_and_leaf_and_spares_the_manager_and_bus(self):
        supervisor = self.kernel.spawn(1001, f'{self.delegated}/app.slice/ukai-jail-9-abc.scope', 'ukai-jail')
        workload = self.kernel.spawn(1001, f'{self.delegated}/ukai-att_9.leaf', 'sleep')
        self.guest.stop_attempt(self.account)
        self.guest.drop_attempt_cgroups(1001)
        self.assertFalse(supervisor.alive)
        self.assertFalse(workload.alive)
        for process in (self.kernel.manager, self.kernel.sd_pam, self.kernel.bus):
            self.assertTrue(process.alive, process.cgroup)
        self.assertFalse((self.kernel.cgroups / self.delegated / 'ukai-att_9.leaf').exists())
        self.assertIn('workload_tree_empty', self.audits)

    def test_a_populated_boundary_without_a_workload_uid_still_fails_the_stop(self):
        # An unkillable root-owned process in the jail's scope: no uid stray,
        # but the boundary never empties — the populated check decides.
        self.kernel.spawn(0, f'{self.delegated}/app.slice/ukai-jail-9-abc.scope', 'helper', unkillable=True)
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.guest.stop_attempt(self.account)
        self.assertLessEqual(max(b - a for a, b in zip(self.notifies, self.notifies[1:])), .1)

    def test_a_stray_anywhere_else_fails_the_stop_after_the_budget(self):
        self.kernel.spawn(1001, 'user.slice/user-1001.slice/session-1.scope', 'sh')
        start = self.clock.now
        with self.assertRaises(self.guest.AttemptTreeUnverified):
            self.guest.stop_attempt(self.account)
        self.assertGreaterEqual(self.clock.now - start, self.guest.STOP_BUDGET)
        self.assertLess(self.clock.now - start, self.guest.STOP_BUDGET + .1)
        self.assertIn('attempt_tree_unverified', self.audits)

    def test_other_accounts_and_zombies_are_not_strays(self):
        self.kernel.spawn(0, 'system.slice/cron.service', 'cron')
        zombie = self.kernel.spawn(1001, 'system.slice/ukai-vm.service', 'sh')
        status = self.kernel.proc / str(zombie.pid) / 'status'
        status.write_text(status.read_text().replace('S (sleeping)', 'Z (zombie)'))
        self.assertEqual(self.guest.stray_processes(1001), [])
        status.write_text(status.read_text().replace('Z (zombie)', 'R (running)'))
        self.assertEqual(self.guest.stray_processes(1001), [(zombie.pid, '/system.slice/ukai-vm.service')])

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
