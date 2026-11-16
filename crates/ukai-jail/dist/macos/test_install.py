import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import install
import native
from test_native import fixture


class Crash(BaseException):
    pass


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.home = self.root / 'home'
        self.home.mkdir()
        self.package = self.root / 'first'
        self.first = fixture(self.package)
        self.second_path = self.root / 'second'
        self.second = fixture(self.second_path, '0.1.0-native.2', b'two')
        self.installation = install.Installation(self.home)

    def assert_installed(self, report):
        self.assertEqual(native.bundle_files(self.installation.app), report['files'])
        self.assertEqual(self.installation.record(), report)
        self.assertEqual(os.readlink(self.installation.link), self.installation.target)
        self.assertFalse(self.installation.journal.exists())

    def test_unsigned_requires_explicit_opt_in(self):
        with self.assertRaisesRegex(native.Refused, 'allow-unsigned'):
            self.installation.install(self.package)
        self.assertFalse(self.installation.app.exists())

    def test_install_upgrade_remove_preserves_operator_state(self):
        data = self.home / '.config/ukai/credentials'
        data.parent.mkdir(parents=True)
        data.write_text('operator-state')
        self.installation.install(self.package, True)
        self.assert_installed(self.first)
        self.installation.install(self.second_path, True)
        self.assert_installed(self.second)
        self.installation.remove()
        self.assertFalse(self.installation.app.exists())
        self.assertFalse(install.exists(self.installation.link))
        self.assertFalse(self.installation.state.exists())
        self.assertEqual(data.read_text(), 'operator-state')
        self.assertTrue((self.installation.apps / install.LOCK).is_file())

    def test_unmanaged_app_is_preserved(self):
        self.installation.app.mkdir(parents=True)
        (self.installation.app / 'mine').write_text('unrelated')
        with self.assertRaises(native.Refused):
            self.installation.install(self.package, True)
        self.assertEqual((self.installation.app / 'mine').read_text(), 'unrelated')

    def test_symlinked_installation_directories_refused(self):
        for name in ('Applications', '.local'):
            with self.subTest(name=name):
                home = self.root / ('home-' + name)
                home.mkdir()
                (home / name).symlink_to(self.home, target_is_directory=True)
                with self.assertRaises(native.Refused):
                    install.Installation(home).install(self.package, True)

    def test_symlinked_app_or_record_refused(self):
        self.installation.apps.mkdir()
        self.installation.app.symlink_to(self.package / native.APP, target_is_directory=True)
        with self.assertRaises(native.Refused):
            self.installation.install(self.package, True)
        self.installation.app.unlink()
        self.installation.state.symlink_to(self.package / 'package.json')
        with self.assertRaises(OSError):
            self.installation.install(self.package, True)

    def test_command_conflict_preserved(self):
        self.installation.bin.mkdir(parents=True)
        self.installation.link.write_text('unrelated')
        with self.assertRaisesRegex(native.Refused, 'unrelated'):
            self.installation.install(self.package, True)
        self.assertEqual(self.installation.link.read_text(), 'unrelated')

    def test_remove_preserves_replacement_command(self):
        self.installation.install(self.package, True)
        self.installation.link.unlink()
        self.installation.link.symlink_to('/bin/echo')
        self.installation.remove()
        self.assertFalse(self.installation.app.exists())
        self.assertEqual(os.readlink(self.installation.link), '/bin/echo')

    def test_tampered_app_is_not_deleted(self):
        self.installation.install(self.package, True)
        executable = self.installation.app / native.EXECUTABLE
        executable.write_bytes(b'modified')
        with self.assertRaises(native.Refused):
            self.installation.remove()
        self.assertEqual(executable.read_bytes(), b'modified')

    def test_lock_symlink_and_hardlink_refused(self):
        self.installation.apps.mkdir()
        lock = self.installation.apps / install.LOCK
        target = self.root / 'other'
        target.write_bytes(b'unchanged')
        target.chmod(0o600)
        lock.symlink_to(target)
        with self.assertRaises(OSError):
            self.installation.install(self.package, True)
        lock.unlink()
        os.link(target, lock)
        with self.assertRaisesRegex(native.Refused, 'lock'):
            self.installation.install(self.package, True)
        self.assertEqual(target.read_bytes(), b'unchanged')

    def test_new_install_failure_rolls_back_all_activation(self):
        def fail(step):
            if step == 'activated':
                raise RuntimeError('failure')
        self.installation.hook = fail
        with self.assertRaises(RuntimeError):
            self.installation.install(self.package, True)
        self.assertFalse(self.installation.app.exists())
        self.assertFalse(install.exists(self.installation.link))
        self.assertFalse(self.installation.state.exists())
        self.assertFalse(self.installation.journal.exists())

    def test_upgrade_failure_restores_previous_and_identical_versions(self):
        self.installation.install(self.package, True)
        def fail(step):
            if step == 'published':
                raise RuntimeError('failure')
        self.installation.hook = fail
        for package in (self.second_path, self.package):
            with self.assertRaises(RuntimeError):
                self.installation.install(package, True)
            self.assert_installed(self.first)

    def test_remove_failure_restores_previous(self):
        self.installation.install(self.package, True)
        def fail(step):
            if step == 'activated':
                raise RuntimeError('failure')
        self.installation.hook = fail
        with self.assertRaises(RuntimeError):
            self.installation.remove()
        self.assert_installed(self.first)

    def test_committed_cleanup_crash_can_finish(self):
        def crash(work):
            shutil.rmtree(work)
            raise Crash()
        with patch.object(self.installation, 'cleanup', side_effect=crash):
            with self.assertRaises(Crash):
                self.installation.install(self.package, True)
        self.assertEqual(json.loads(self.installation.journal.read_text())['phase'], 'committed')
        self.installation.recover()
        self.assert_installed(self.first)

    def test_rollback_cleanup_crash_can_finish(self):
        self.installation.install(self.package, True)
        def fail(step):
            if step == 'published':
                raise RuntimeError('failure')
        def crash(work):
            shutil.rmtree(work)
            raise Crash()
        self.installation.hook = fail
        with patch.object(self.installation, 'cleanup', side_effect=crash):
            with self.assertRaises(Crash):
                self.installation.install(self.second_path, True)
        self.assertEqual(json.loads(self.installation.journal.read_text())['phase'], 'rolled-back')
        self.installation.recover()
        self.assert_installed(self.first)

    def test_cleanup_interrupted_halfway_accepts_only_unchanged_remaining_files(self):
        self.installation.install(self.package, True)
        def crash(work):
            (work / 'previous.app' / native.EXECUTABLE).unlink()
            raise Crash()
        with patch.object(self.installation, 'cleanup', side_effect=crash):
            with self.assertRaises(Crash):
                self.installation.install(self.second_path, True)
        self.installation.recover()
        self.assert_installed(self.second)

    def test_cleanup_does_not_delete_changed_remaining_files(self):
        self.installation.install(self.package, True)
        def crash(work):
            (work / 'previous.app' / native.EXECUTABLE).write_bytes(b'unrelated replacement')
            raise Crash()
        with patch.object(self.installation, 'cleanup', side_effect=crash):
            with self.assertRaises(Crash):
                self.installation.install(self.second_path, True)
        with self.assertRaisesRegex(native.Refused, 'changed'):
            self.installation.recover()
        self.assertTrue(self.installation.journal.exists())

    def child(self, body, *args):
        return subprocess.Popen([sys.executable, '-c', body, *map(str, args)],
                                cwd=Path(__file__).parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_process_death_after_publish_recovers_previous(self):
        self.installation.install(self.package, True)
        body = '''import os, sys
from pathlib import Path
from install import Installation
def hook(step):
    if step == 'published': os._exit(17)
Installation(Path(sys.argv[1]), hook).install(Path(sys.argv[2]), True)
'''
        child = self.child(body, self.home, self.second_path)
        child.communicate(timeout=10)
        self.assertEqual(child.returncode, 17)
        with self.assertRaisesRegex(native.Refused, 'recover'):
            self.installation.install(self.package, True)
        self.installation.recover()
        self.assert_installed(self.first)

    def test_recovery_refuses_modified_app_without_deleting_it(self):
        self.installation.install(self.package, True)
        with patch.object(self.installation, 'recover_locked', side_effect=Crash()):
            self.installation.hook = lambda step: (_ for _ in ()).throw(RuntimeError('fail')) if step == 'published' else None
            with self.assertRaises(Crash):
                self.installation.install(self.second_path, True)
        executable = self.installation.app / native.EXECUTABLE
        executable.write_bytes(b'user modification')
        with self.assertRaisesRegex(native.Refused, 'changed'):
            self.installation.recover()
        self.assertEqual(executable.read_bytes(), b'user modification')
        self.assertTrue(self.installation.journal.exists())

    def test_simultaneous_installers_preserve_winner(self):
        body = '''import sys, time
from pathlib import Path
from install import Installation
home, package, gate, ready, release = map(Path, sys.argv[1:])
deadline = time.monotonic() + 10
while not gate.exists():
    if time.monotonic() > deadline: raise RuntimeError('gate timeout')
    time.sleep(.01)
def hook(step):
    if step == 'validated':
        ready.touch()
        while not release.exists():
            if time.monotonic() > deadline: raise RuntimeError('release timeout')
            time.sleep(.01)
Installation(home, hook).install(package, True)
'''
        gate, release = self.root / 'gate', self.root / 'release'
        ready = [self.root / 'ready0', self.root / 'ready1']
        children = [self.child(body, self.home, self.package, gate, ready[i], release) for i in range(2)]
        try:
            gate.touch()
            deadline = time.monotonic() + 5
            while not (any(p.exists() for p in ready) and any(c.poll() is not None for c in children)):
                self.assertLess(time.monotonic(), deadline, 'contender did not refuse promptly')
                time.sleep(.01)
            self.assertTrue(self.installation.bin.is_dir())
            release.touch()
            outputs = [child.communicate(timeout=5) for child in children]
            self.assertEqual(sorted(child.returncode for child in children), [0, 1])
            self.assertTrue(any(b'Another install/remove/recover' in stderr for _, stderr in outputs))
            self.assert_installed(self.first)
        finally:
            release.touch()
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    def test_signed_install_even_with_unsigned_flag_requires_apple_validation(self):
        report = dict(self.first, signing='developer-id')
        with patch.object(native, 'load_package', return_value=report), patch.object(
                native, 'verify_signature', side_effect=native.Refused('Apple rejected')) as verify:
            with self.assertRaisesRegex(native.Refused, 'Apple rejected'):
                self.installation.install(self.package, True)
            self.assertTrue(verify.call_args.kwargs['distribution'])
        self.assertFalse(self.installation.app.exists())


if __name__ == '__main__':
    unittest.main()
