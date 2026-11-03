"""The live-workspace share preflight (J18 §6, K109). The refusals encode
the measured 2026-11-02 probe escapes; a clean workspace passes with its
facts recorded."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unicodedata
import unittest
import uuid

spec = importlib.util.spec_from_file_location('run', Path(__file__).parent / 'run.py')
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


class SharePreflightTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.workspace = Path(self.root.name) / 'ws'
        self.outside = Path(self.root.name) / 'outside'
        self.workspace.mkdir()
        self.outside.write_text('outside\n')

    def tearDown(self):
        self.root.cleanup()

    @unittest.skipUnless(sys.platform == 'darwin', 'hdiutil and APFS are macOS-only')
    def test_a_clean_workspace_passes_with_facts(self):
        """On a case-sensitive volume the preflight passes and records its
        facts; the probe creates a small one because the Mac's default
        volume folds names (which the sibling test asserts)."""
        import subprocess
        # A unique volume name: concurrent runs (two checkouts, CI shards)
        # must never attach at one mount point.
        name = 'UKAI-CASE-' + uuid.uuid4().hex[:12].upper()
        image = Path(self.root.name) / 'ukai-case-sensitive-test.dmg'
        volume = '/Volumes/' + name
        subprocess.run(['hdiutil', 'create', '-size', '16m', '-fs', 'Case-sensitive APFS',
                        '-volname', name, str(image)],
                       check=True, capture_output=True)
        try:
            subprocess.run(['hdiutil', 'attach', '-nobrowse', '-mountpoint', volume, str(image)],
                           check=True, capture_output=True)
            try:
                workspace = Path(volume) / 'ws'
                workspace.mkdir()
                (workspace / 'file.txt').write_text('x')
                sub = workspace / 'sub'
                sub.mkdir()
                (sub / 'nested.txt').write_text('y')
                facts = run.share_preflight(workspace)
                self.assertFalse(facts['case_fold'])
                # Normalization folding is disclosed, not refused: APFS folds
                # it even case-sensitively (measured 2026-11-03 with distinct
                # NFD/NFC probe names), and the protected segments are pure
                # ASCII, so no denial can be bypassed.
                self.assertIs(facts['normalization_fold'], True)
                self.assertEqual((facts['symlinks'], facts['multi_link_files']), (0, 0))
                self.assertEqual(sorted(p.name for p in workspace.iterdir()),
                                 ['file.txt', 'sub'])
            finally:
                subprocess.run(['hdiutil', 'detach', volume], check=True, capture_output=True)
        finally:
            image.unlink(missing_ok=True)

    def test_the_normalization_probe_names_differ_only_by_normalization(self):
        _, _, nfd, nfc = run.fold_probe_names('.m')
        self.assertNotEqual(nfd, nfc)
        self.assertEqual(unicodedata.normalize('NFC', nfd), nfc)
        self.assertEqual(unicodedata.normalize('NFD', nfc), nfd)

    @unittest.skipIf(sys.platform == 'darwin', 'the Mac volumes fold normalization')
    def test_a_non_folding_volume_reports_no_folds(self):
        self.assertEqual(run.fold_probes(self.workspace), (False, False))
        self.assertEqual(list(self.workspace.iterdir()), [])

    @unittest.skipUnless(sys.platform == 'darwin', "the Mac's default volume is the folding one")
    def test_a_folding_volume_refuses_with_the_remedy(self):
        """The Mac's default volume folds case: the preflight must refuse
        and name the remedy, whatever else is in the workspace."""
        (self.workspace / 'file.txt').write_text('x')
        with self.assertRaises(ValueError) as refused:
            run.share_preflight(self.workspace)
        message = str(refused.exception)
        self.assertIn('folds case', message)
        self.assertIn('case-sensitive', message)

    def test_a_symlink_is_refused_before_any_boot(self):
        os.symlink('../outside', self.workspace / 'link')
        with self.assertRaises(ValueError) as refused:
            run.share_preflight(self.workspace)
        self.assertIn('symlinks', str(refused.exception))

    def test_a_multi_link_file_is_refused_before_any_boot(self):
        target = self.workspace / 'shared.txt'
        target.write_text('x')
        os.link(target, self.workspace / 'second-name.txt')
        with self.assertRaises(ValueError) as refused:
            run.share_preflight(self.workspace)
        # The refusal names the offending file.
        self.assertIn('second-name.txt', str(refused.exception)
                      or 'shared.txt', str(refused.exception))

    def test_a_link_into_the_workspace_from_outside_is_caught(self):
        inside = self.workspace / 'inside.txt'
        inside.write_text('x')
        # A host process hard-linked the workspace file from outside it:
        # the inode now has two names, one of them beyond the share.
        os.link(inside, self.outside.parent / 'climb.txt')
        with self.assertRaises(ValueError):
            run.share_preflight(self.workspace)



    def test_the_live_share_refuses_the_build_profile(self):
        """Directly through execute's guard: the same refusal the CLI gives
        before any VM boots (the guest enforces it again at the run op)."""
        import types
        args = types.SimpleNamespace(
            profile='build', live_workspace=True,
            image=Path('/nonexistent'), workspace=Path('/nonexistent'),
            out=Path('/nonexistent'))
        with self.assertRaises(ValueError) as refused:
            run.execute(args)
        self.assertIn('disposable copy', str(refused.exception))


class GuestShareModeTests(unittest.TestCase):
    """The guest controller's live-share switch, on the host: the device
    and the mount are faked (test_guest_warm.ShareMountTests and
    test_guest_main.py drive the switch itself)."""

    def setUp(self):
        guest_spec = importlib.util.spec_from_file_location('guest_share_mode', Path(__file__).parent / 'guest.py')
        self.guest = importlib.util.module_from_spec(guest_spec)
        guest_spec.loader.exec_module(self.guest)
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.guest.VIRTIO_DEVICES = Path(self.root.name) / 'no-virtio-bus'
        self.guest.SHARE_MOUNT = Path(self.root.name) / 'mnt/workspace'

    def test_without_a_device_the_share_is_not_live(self):
        self.guest.subprocess = types.SimpleNamespace(
            run=self.fail_mount, SubprocessError=__import__('subprocess').SubprocessError)
        self.guest.share_mounted = lambda: False
        self.assertFalse(self.guest.mount_share())
        self.assertNotEqual(self.guest.WORKSPACE, self.guest.SHARE_MOUNT)

    @staticmethod
    def fail_mount(argv, **kwargs):
        import subprocess
        raise subprocess.CalledProcessError(32, argv)

    def test_reset_never_wipes_a_live_share(self):
        import pwd
        account = pwd.getpwuid(os.getuid())
        live = Path(self.root.name) / 'live'
        live.mkdir()
        (live / 'precious.txt').write_text('keep')
        self.guest.SHARE_MOUNT = live
        self.guest.share_mounted = lambda: True
        self.guest.reset_attempt(account, workspace=live, evidence=Path(self.root.name) / 'evidence')
        # The host's live workspace survived; the evidence tree reset.
        self.assertEqual((live / 'precious.txt').read_text(), 'keep')
        self.assertTrue((Path(self.root.name) / 'evidence').is_dir())


class PinnedManifestTests(unittest.TestCase):
    """The image manifest's pinned-version parsing, from console text."""

    def test_markers_parse_sorted_and_digest_stably(self):
        console = ('boot noise\n'
                   'UKAI_PINNED bubblewrap=0.11.0-1\n'
                   'UKAI_PINNED dbus-user-session=1.16.2-1\n'
                   'UKAI_PINNED\n'  # malformed: no row, ignored
                   'UKAI_BOOTSTRAP_DONE\n')
        prepare = importlib.util.spec_from_file_location(
            'prepare', Path(__file__).parent / 'prepare.py')
        module = importlib.util.module_from_spec(prepare)
        prepare.loader.exec_module(module)
        rows = module.pinned_from_console(console)
        self.assertEqual(rows, ['bubblewrap=0.11.0-1', 'dbus-user-session=1.16.2-1'])
        digest = module.pinned_digest(rows)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, module.pinned_digest(list(reversed(rows))))


if __name__ == '__main__':
    unittest.main()
