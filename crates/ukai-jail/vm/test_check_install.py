import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import check_install

HERE = Path(__file__).resolve().parent
ENVIRONMENT = {key: value for key, value in os.environ.items() if key != 'PYTHONOPTIMIZE'}


def exits(code, text):
    return [sys.executable, '-c', f'import sys; print({text!r}, file=sys.stderr); sys.exit({code})']


def passed_case(name):
    return {'case': name, 'exit_code': 0, 'passed': True, 'failed_checks': []}


class CaseRecordingTests(unittest.TestCase):
    def test_failed_postcondition_is_recorded_before_the_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            leftover = root / 'payload-tamper-prefix'
            leftover.mkdir()
            results = [passed_case(name) for name in check_install.CASES[:-1]]
            with self.assertRaises(check_install.CaseFailed):
                check_install.run_case(results, root, 'payload-tamper', exits(1, 'Package checksum mismatch.'),
                                       ENVIRONMENT, 1, 'Package checksum mismatch',
                                       [('nothing-installed', lambda: not os.path.lexists(leftover))])
            self.assertEqual(results[-1], {'case': 'payload-tamper', 'exit_code': 1, 'passed': False,
                                           'failed_checks': ['nothing-installed']})
            self.assertFalse(check_install.summary(results)['passed'])

    def test_postcondition_error_is_a_failed_check(self):
        def unreadable():
            raise FileNotFoundError('marker removed')

        with tempfile.TemporaryDirectory() as temporary:
            results = []
            with self.assertRaises(check_install.CaseFailed):
                check_install.run_case(results, Path(temporary), 'unrelated-refused', exits(2, 'unrelated command:'),
                                       ENVIRONMENT, 2, 'unrelated command:', [('preserved', unreadable)])
            self.assertEqual(results[0]['failed_checks'], ['preserved'])

    def test_exit_code_and_message_are_both_required(self):
        for argv in (exits(0, 'Package checksum mismatch.'), exits(1, 'something else')):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as temporary:
                results = []
                with self.assertRaises(check_install.CaseFailed):
                    check_install.run_case(results, Path(temporary), 'payload-tamper', argv, ENVIRONMENT, 1,
                                           'Package checksum mismatch')
                self.assertFalse(results[0]['passed'])

    def test_case_passes_only_when_every_check_holds(self):
        with tempfile.TemporaryDirectory() as temporary:
            results = []
            check_install.run_case(results, Path(temporary), 'install', exits(0, 'Installed x'), ENVIRONMENT, 0,
                                   'Installed ', [('runs', lambda: True)])
            self.assertEqual(results, [passed_case('install')])

    def test_summary_requires_every_case_in_order(self):
        complete = [passed_case(name) for name in check_install.CASES]
        artifact = {'manifest_sha256': 'a' * 64, 'installer_sha256': 'b' * 64}
        self.assertTrue(check_install.summary(complete, artifact)['passed'])
        for results in (complete[:-1], complete + [passed_case('install')], list(reversed(complete)),
                        complete[:-1] + [dict(complete[-1], passed=False)]):
            with self.subTest(results=[r['case'] for r in results]):
                self.assertFalse(check_install.summary(results, artifact)['passed'])

    def test_summary_binds_the_artifact_it_judged(self):
        complete = [passed_case(name) for name in check_install.CASES]
        self.assertFalse(check_install.summary(complete)['passed'])
        self.assertFalse(check_install.summary(complete, {})['passed'])
        with tempfile.TemporaryDirectory() as temporary:
            volume = Path(temporary)
            (volume / 'SHA256SUMS').write_text('x\n')
            (volume / 'install.sh').write_text("version='1.2.3'\n")
            dmg = volume / 'u.dmg'
            dmg.write_bytes(b'dmg')
            identity = check_install.artifact_identity(volume, dmg)
        self.assertEqual(identity['manifest_sha256'], hashlib.sha256(b'x\n').hexdigest())
        self.assertEqual(identity['version'], '1.2.3')
        self.assertEqual(identity['dmg_sha256'], hashlib.sha256(b'dmg').hexdigest())


class InstalledTreeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.volume = Path(temporary.name) / 'volume'
        self.installed = Path(temporary.name) / 'installed'
        files = {'bin/ukai-vm': b'service', 'image/vz': b'helper', 'image/image.json': b'{}'}
        for name, data in files.items():
            for root in (self.volume / 'payload', self.installed):
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
        write_manifest(self.volume)

    def test_the_installed_tree_is_the_manifest(self):
        self.assertTrue(check_install.installed_tree_matches(self.volume, self.installed))

    def test_an_extra_changed_missing_or_linked_file_fails(self):
        for name, change in [('extra', lambda: (self.installed / 'bin' / 'extra').write_bytes(b'x')),
                             ('changed', lambda: (self.installed / 'image' / 'vz').write_bytes(b'other')),
                             ('missing', lambda: (self.installed / 'image' / 'vz').unlink()),
                             ('symlink', lambda: (self.installed / 'bin' / 'alias').symlink_to('ukai-vm'))]:
            with self.subTest(name):
                change()
                self.assertFalse(check_install.installed_tree_matches(self.volume, self.installed))
                self.setUp()

    def test_a_link_that_hashes_nothing_still_fails(self):
        # Reviewer CI4: a dangling link, or one to a directory, adds no file
        # to the hashed tree; the link itself must still fail the check.
        for name, make in [('dangling', lambda: (self.installed / 'bin' / 'gone').symlink_to('/nonexistent/ukai')),
                           ('to a directory', lambda: (self.installed / 'bin' / 'up').symlink_to('..'))]:
            with self.subTest(name):
                make()
                self.assertFalse(check_install.installed_tree_matches(self.volume, self.installed))
                self.setUp()

    def normalize(self):
        for path in [self.installed, *self.installed.rglob('*')]:
            path.chmod(0o755 if path.is_dir() or path.name == 'ukai-vm' else 0o644)
        for path in (self.volume / 'payload').rglob('*'):
            if path.is_file():
                path.chmod(0o755 if path.name == 'ukai-vm' else 0o644)

    def test_installed_modes_are_the_normalized_ones(self):
        # Reviewer F-11: modes are not in the manifest; install.sh sets them.
        self.normalize()
        self.assertTrue(check_install.installed_modes_normal(self.volume, self.installed))
        for name, change in [('world-writable file', lambda: (self.installed / 'image' / 'vz').chmod(0o666)),
                             ('setuid service', lambda: (self.installed / 'bin' / 'ukai-vm').chmod(0o4755)),
                             ('group-writable directory', lambda: (self.installed / 'bin').chmod(0o775)),
                             ('private directory', lambda: (self.installed / 'image').chmod(0o700)),
                             ('executable bit the volume never had', lambda: (self.installed / 'image' / 'vz').chmod(0o755)),
                             ('a link', lambda: (self.installed / 'bin' / 'alias').symlink_to('ukai-vm')),
                             ('the service replaced by a link', lambda: ((self.installed / 'bin' / 'ukai-vm').unlink(),
                                                                         (self.installed / 'bin' / 'ukai-vm').symlink_to('/bin/sh')))]:
            with self.subTest(name):
                change()
                self.assertFalse(check_install.installed_modes_normal(self.volume, self.installed))
                self.setUp()
                self.normalize()
        empty = self.installed.parent / 'empty'
        empty.mkdir(mode=0o755)
        empty.chmod(0o755)
        self.assertFalse(check_install.installed_modes_normal(self.volume, empty))

    def test_the_expanded_disk_is_checked_against_image_json(self):
        import gzip
        (self.volume / 'payload' / 'image' / 'base.raw.gz').write_bytes(gzip.compress(b'disk'))
        image = json.dumps({'disk_sha256': hashlib.sha256(b'disk').hexdigest()}).encode()
        for root in (self.volume / 'payload', self.installed):
            (root / 'image' / 'image.json').write_bytes(image)
        write_manifest(self.volume)
        (self.installed / 'image' / 'base.raw').write_bytes(b'disk')
        self.assertTrue(check_install.installed_tree_matches(self.volume, self.installed))
        (self.installed / 'image' / 'base.raw').write_bytes(b'other disk')
        self.assertFalse(check_install.installed_tree_matches(self.volume, self.installed))


def write_manifest(volume):
    files = sorted(path for path in volume.rglob('*') if path.is_file() and path.name not in ('SHA256SUMS', 'install.sh'))
    (volume / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(volume)}\n' for path in files))

    def test_refuses_optimized_python(self):
        script = str(HERE / 'check_install.py')
        normal = subprocess.run([sys.executable, script, '--help'], env=ENVIRONMENT, capture_output=True, text=True)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        optimized = subprocess.run([sys.executable, '-O', script, '--help'], env=ENVIRONMENT,
                                   capture_output=True, text=True)
        self.assertNotEqual(optimized.returncode, 0)
        self.assertIn('must not run with python -O', optimized.stderr)


FAKE_INSTALLER = r'''#!/bin/bash
set -eu
version='0.0.0-test'
prefix="$2"
here="$(cd -- "$(dirname -- "$0")" && pwd -P)"
destination="$prefix/share/ukai-vm/test"
link="$prefix/bin/ukai-vm"
[[ ! -e "$destination" ]] || { echo "Already installed: $destination" >&2; exit 2; }
[[ ! -e "$link" ]] || { @UNRELATED@ echo "Refusing to replace an existing unrelated command: $link" >&2; exit 2; }
if grep -q tampered "$here/SHA256SUMS"; then echo 'Package manifest checksum mismatch.' >&2; exit 1; fi
if grep -q tampered "$here/payload/image/vz"; then @PAYLOAD@ echo 'Package checksum mismatch.' >&2; exit 1; fi
if [[ -e "$here/payload/bin/unlisted" ]]; then @EXTRA@ echo 'Package payload holds files the manifest does not list.' >&2; exit 1; fi
mkdir -p "$destination" "$prefix/bin"
cp -R "$here/payload/." "$destination/"
@INSTALLED@
ln -s "$destination/bin/ukai-vm" "$link"
printf '\nInstalled %s\n' "$link"
'''


class InstallerTextTests(unittest.TestCase):
    def test_the_source_payload_is_read_once_before_every_check(self):
        # Reviewer I6: what is checked is what installs. The volume's payload
        # is copied once into the work directory; nothing after that reads
        # the source volume's payload again.
        text = (HERE / 'install.sh.in').read_text()
        lines = [line.strip() for line in text.splitlines() if '$source_dir' in line]
        self.assertEqual(lines, ['cp "$source_dir/SHA256SUMS" "$work/SHA256SUMS"',
                                 'ditto "$source_dir/payload" "$work/payload"',
                                 "( cd \"$source_dir\" && printf '%s\\n' \"$rest\" | shasum -a 256 --check --status ) || {"])
        copy, check = text.index('ditto "$source_dir/payload"'), text.index('shasum -a 256 --check')
        self.assertLess(copy, check)
        self.assertEqual(text.count('stage="$work/payload"'), 1)
        self.assertEqual([line for line in text.splitlines() if 'ditto' in line or 'cp ' in line],
                         ['cp "$source_dir/SHA256SUMS" "$work/SHA256SUMS"', 'ditto "$source_dir/payload" "$work/payload"'])


@unittest.skipUnless(sys.platform == 'darwin', 'the installer check clones volumes with macOS cp -c')
class InstallerCheckTests(unittest.TestCase):
    def check(self, unrelated=':;', payload=':;', extra=':;', installed=':', reported='0.0.0-test'):
        with tempfile.TemporaryDirectory() as temporary:
            volume = Path(temporary) / 'volume'
            (volume / 'payload' / 'image').mkdir(parents=True)
            (volume / 'payload' / 'bin').mkdir()
            (volume / 'payload' / 'image' / 'vz').write_text('helper\n')
            (volume / 'payload' / 'bin' / 'ukai-vm').write_text(
                '#!/bin/sh\necho \'{"component":"ukai-vm","version":"@REPORTED@"}\'\n'.replace('@REPORTED@', reported))
            (volume / 'payload' / 'bin' / 'ukai-vm').chmod(0o755)
            write_manifest(volume)
            (volume / 'install.sh').write_text(FAKE_INSTALLER.replace('@UNRELATED@', unrelated)
                                               .replace('@PAYLOAD@', payload).replace('@EXTRA@', extra)
                                               .replace('@INSTALLED@', installed))
            out = Path(temporary) / 'out'
            result = subprocess.run([sys.executable, str(HERE / 'check_install.py'), '--volume', str(volume),
                                     '--out', str(out)], env=ENVIRONMENT, capture_output=True, text=True)
            return result.returncode, json.loads((out / 'summary.json').read_text())

    def test_honest_installer_passes(self):
        code, summary = self.check()
        self.assertEqual(code, 0)
        self.assertTrue(summary['passed'])
        self.assertEqual([r['case'] for r in summary['results']], list(check_install.CASES))

    def test_install_after_refused_tamper_fails_the_summary(self):
        code, summary = self.check(payload='mkdir -p "$prefix";')
        self.assertNotEqual(code, 0)
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['results'][-1]['failed_checks'], ['nothing-installed'])

    def test_overwritten_unrelated_command_fails_the_summary(self):
        code, summary = self.check(unrelated='echo replaced > "$link";')
        self.assertNotEqual(code, 0)
        self.assertFalse(summary['passed'])
        self.assertEqual(summary['results'][-1]['failed_checks'], ['unrelated-command-preserved'])

    def test_an_installed_unlisted_file_fails_the_install_case(self):
        code, summary = self.check(installed='echo stray > "$destination/bin/stray"')
        self.assertNotEqual(code, 0)
        self.assertEqual(summary['results'][0]['failed_checks'], ['installed-tree-is-the-manifest'])

    def test_an_installer_that_leaves_a_writable_file_fails_the_install_case(self):
        # Reviewer F-11 (mutation R48): the mode check is one of the install case's checks.
        code, summary = self.check(installed='chmod 0666 "$destination/image/vz"')
        self.assertNotEqual(code, 0)
        self.assertEqual(summary['results'][0]['failed_checks'], ['installed-modes-normalized'])

    def test_an_installer_that_installs_an_unlisted_payload_file_fails(self):
        code, summary = self.check(extra='mkdir -p "$prefix";')
        self.assertNotEqual(code, 0)
        self.assertEqual(summary['results'][-1]['case'], 'payload-extra')
        self.assertEqual(summary['results'][-1]['failed_checks'], ['nothing-installed'])

    def test_a_dev_or_other_version_fails_the_install_case(self):
        for reported in ('0.0.0-test-dev', '0.1.0', ''):
            with self.subTest(reported=reported):
                code, summary = self.check(reported=reported)
                self.assertNotEqual(code, 0)
                self.assertEqual(summary['results'][0]['failed_checks'], ['installed-command-runs'])

    def test_the_summary_names_the_volume_it_judged(self):
        code, summary = self.check()
        self.assertEqual(code, 0)
        self.assertRegex(summary['artifact']['manifest_sha256'], '^[0-9a-f]{64}$')
        self.assertRegex(summary['artifact']['installer_sha256'], '^[0-9a-f]{64}$')
        self.assertEqual(summary['artifact']['version'], '0.0.0-test')


def macos_27_arm64():
    import platform
    try:
        return sys.platform == 'darwin' and platform.machine() == 'arm64' and int(platform.mac_ver()[0].split('.')[0]) >= 27
    except ValueError:
        return False


STUB_HELPER = """#!/bin/sh
here=$(cd "$(dirname "$0")/.." && pwd -P)
[ "$1" = expand-image ] && /usr/bin/gunzip -c "$here/image/base.raw.gz" > "$here/image/base.raw"
exit 0
"""
STUB_SERVICE = """#!/bin/sh
echo '{"component":"ukai-vm","version":"0.0.0-test"}'
"""


@unittest.skipUnless(macos_27_arm64(), 'the real installer runs only on Apple Silicon macOS 27+')
class RealInstallerTests(unittest.TestCase):
    """install.sh.in itself (rendered as package.py does) on a stub payload."""

    def volume(self, root):
        import gzip
        volume = root / 'volume'
        (volume / 'payload' / 'bin').mkdir(parents=True)
        (volume / 'payload' / 'image').mkdir()
        for name, text in (('ukai-vm-install', STUB_HELPER), ('ukai-vm', STUB_SERVICE)):
            (volume / 'payload' / 'bin' / name).write_text(text)
            (volume / 'payload' / 'bin' / name).chmod(0o755)
        (volume / 'payload' / 'image' / 'vz').write_text('helper\n')
        (volume / 'payload' / 'image' / 'base.raw.gz').write_bytes(gzip.compress(b'guest disk'))
        (volume / 'payload' / 'image' / 'image.json').write_text(
            json.dumps({'disk_sha256': hashlib.sha256(b'guest disk').hexdigest()}))
        (volume / 'READ-ME.txt').write_text('read me\n')
        write_manifest(volume)
        manifest = hashlib.sha256((volume / 'SHA256SUMS').read_bytes()).hexdigest()
        script = (HERE / 'install.sh.in').read_text().replace('@VERSION@', '0.0.0-test').replace('@MANIFEST_SHA256@', manifest)
        (volume / 'install.sh').write_text(script)
        (volume / 'install.sh').chmod(0o755)
        return volume

    def test_every_case_of_the_real_installer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            volume = self.volume(root)
            result = subprocess.run([sys.executable, str(HERE / 'check_install.py'), '--volume', str(volume),
                                     '--out', str(root / 'out')], env=ENVIRONMENT, capture_output=True, text=True)
            summary = json.loads((root / 'out' / 'summary.json').read_text())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(summary['passed'], summary)
            self.assertEqual([r['case'] for r in summary['results']], list(check_install.CASES))

    def test_an_unlisted_payload_file_is_refused_not_installed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            volume = self.volume(root)
            (volume / 'payload' / 'bin' / 'extra').write_text('#!/bin/sh\necho planted\n')
            prefix = root / 'prefix'
            result = subprocess.run(['/bin/bash', str(volume / 'install.sh'), '--prefix', str(prefix)],
                                    env=ENVIRONMENT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('manifest does not list', result.stderr)
            self.assertFalse(prefix.exists(), 'a refused install must leave the prefix as it found it')

    def test_volume_modes_never_install(self):
        # Reviewer F-11 (fx_install): a world-writable helper and a setuid,
        # world-writable service on the volume install as 0644 and 0755.
        import stat
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            volume = self.volume(root)
            os.chmod(volume / 'payload' / 'image' / 'vz', 0o666)
            os.chmod(volume / 'payload' / 'bin' / 'ukai-vm', 0o4777)
            os.chmod(volume / 'payload' / 'image', 0o777)
            prefix = root / 'prefix'
            result = subprocess.run(['/bin/bash', str(volume / 'install.sh'), '--prefix', str(prefix)],
                                    env=ENVIRONMENT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = prefix / 'share/ukai-vm/0.0.0-test'
            modes = {str(path.relative_to(installed)): stat.S_IMODE(path.lstat().st_mode)
                     for path in [installed, *installed.rglob('*')]}
            self.assertEqual(modes, {'.': 0o755, 'bin': 0o755, 'image': 0o755, 'bin/ukai-vm': 0o755,
                                     'bin/ukai-vm-install': 0o755, 'image/vz': 0o644, 'image/base.raw': 0o644,
                                     'image/image.json': 0o644})
            self.assertTrue(check_install.installed_modes_normal(volume, installed))

    def test_a_changed_file_outside_the_payload_is_refused(self):
        # Reviewer I7: the volume files that are not installed are still verified.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            volume = self.volume(root)
            (volume / 'READ-ME.txt').write_text('read me, edited\n')
            prefix = root / 'prefix'
            result = subprocess.run(['/bin/bash', str(volume / 'install.sh'), '--prefix', str(prefix)],
                                    env=ENVIRONMENT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('Package checksum mismatch', result.stderr)
            self.assertFalse(prefix.exists(), 'a refused install must leave the prefix as it found it')

    def test_a_symlink_in_the_payload_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            volume = self.volume(root)
            (volume / 'payload' / 'bin' / 'alias').symlink_to('ukai-vm')
            result = subprocess.run(['/bin/bash', str(volume / 'install.sh'), '--prefix', str(root / 'prefix')],
                                    env=ENVIRONMENT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('non-regular file', result.stderr)


if __name__ == '__main__':
    unittest.main()
