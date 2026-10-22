"""The warm session's pieces (J18, jail-macos.md §6), without a VM.

`guest.py` runs alone in the guest, so its session semantics are tested at
the seams a test can reach on any host: the command the jail is given, the
reset of the attempt directories, the ephemeral credential staging, and the
shared shapes the host's ukai-vm depends on. The live behavior — a second
attempt released inside a running guest, the lease by end-of-file, the
suspend cases — needs the preview VM and is the fault matrix's (K110), not
this file's; the README records what stays untested here.
"""
import base64
import os
import pwd
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import guest


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

    def test_the_environment_is_launch_shaped(self):
        account = mock.Mock(pw_dir='/home/ukai', pw_uid=1001, pw_gid=1001)
        env = guest.attempt_environment(account)
        self.assertEqual(env['HOME'], '/home/ukai')
        self.assertEqual(env['XDG_RUNTIME_DIR'], '/run/user/1001')
        self.assertNotIn('UKAI_VAULT_TOKEN', env, 'secrets cross as staged sources, never as variables')


class ResetAttemptTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.account = mock.Mock(pw_uid=os.getuid(), pw_gid=os.getgid())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

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


class SecretStagingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def test_a_secret_stages_private_and_ephemeral(self):
        path = guest.stage_secret('token', b's3cret', self.root / 'credentials')
        self.assertEqual(path.read_bytes(), b's3cret')
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / 'credentials').stat().st_mode), 0o700)
        guest.clear_secrets(self.root / 'credentials')
        self.assertFalse((self.root / 'credentials').exists())

    def test_a_secret_id_cannot_climb_out_of_the_staging_root(self):
        for secret_id in ('../escape', '/absolute', 'a/../../b'):
            with self.subTest(secret_id=secret_id), self.assertRaises(ValueError):
                guest.stage_secret(secret_id, b'x', self.root / 'credentials')

    def test_the_default_root_is_tmpfs_and_env_relocates_it(self):
        with mock.patch.dict(os.environ, {'UKAI_VM_SECRETS': str(self.root / 'elsewhere')}):
            self.assertEqual(guest.secrets_root(), self.root / 'elsewhere')
        self.assertEqual(guest.secrets_root(), Path(guest.SECRETS))

    def test_a_second_secret_with_one_id_refuses(self):
        guest.stage_secret('token', b'one', self.root / 'credentials')
        with self.assertRaises(FileExistsError):
            guest.stage_secret('token', b'two', self.root / 'credentials')


class SessionAgreementTests(unittest.TestCase):
    """ukai-vm drives `session`/`reset`/`secret`/`run2`/`cancel2`; the shapes
    here are what it must send and expect back."""

    OPS = ('session', 'reset', 'secret', 'run2', 'cancel2')

    def test_the_session_ops_are_named_and_the_single_run_op_is_untouched(self):
        source = Path(guest.__file__).read_text()
        for op in self.OPS:
            with self.subTest(op=op):
                self.assertIn(f"op == '{op}'", source)
        self.assertIn("op == 'run' and process is None:", source,
                      'the single-run op keeps its own gate')

    def test_the_session_reply_names_its_kernel_like_the_ready_frame(self):
        # ukai-vm reads `kernel` from both; one shape, one meaning.
        self.assertIn("'event': 'session', 'kernel':", Path(guest.__file__).read_text())


if __name__ == '__main__':
    unittest.main()
