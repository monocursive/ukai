import copy
import datetime
import json
import os
from pathlib import Path
import plistlib
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native
import notarize


def fixture(root, release='0.1.0-native.1', payload=b'one'):
    root.mkdir()
    app = root / native.APP
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/Resources').mkdir()
    revision = 'a' * 40
    build = {'component': 'ukai-jail', 'version': '0.1.0', 'build': {
        'revision': revision, 'dirty': False, 'target': 'aarch64-apple-darwin',
        'opt_level': '3', 'debug_assertions': False, 'inputs': 'sha256:' + 'b' * 64,
        'rustc': 'rustc 1.98.1 (fixture)'}}
    provenance = {'source_revision': revision, 'build': build, 'toolchain': '1.98.1',
                  'release': release, 'build_number': 1, 'native_execution': 'disabled-by-default'}
    (app / native.EXECUTABLE).write_bytes(struct.pack('<II', 0xfeedfacf, 0x0100000c) + payload)
    (app / native.EXECUTABLE).chmod(0o755)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(native.info_plist(release, 1)))
    (app / 'Contents/Resources/LICENSES.txt').write_bytes(b'license')
    native.write_json(app / native.PROVENANCE, provenance)
    report = {'schema': native.SCHEMA, 'provenance': provenance, 'signing': 'unsigned',
              'notarization': 'not-submitted', 'qualified': False, 'published': False,
              'files': native.bundle_files(app)}
    native.write_json(root / 'package.json', report)
    return report


def profile():
    return {'TeamIdentifier': ['TEAMID1234'], 'ProvisionsAllDevices': True,
            'ExpirationDate': datetime.datetime(2099, 1, 1), 'Entitlements': {
                native.ENTITLEMENT: True,
                'com.apple.application-identifier': 'TEAMID1234.' + native.BUNDLE_ID,
                'com.apple.developer.team-identifier': 'TEAMID1234'}}


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.package = self.root / 'package'
        self.report = fixture(self.package)

    def test_layout_and_unqualified_flags(self):
        self.assertEqual(native.load_package(self.package), self.report)
        info = plistlib.loads((self.package / native.APP / 'Contents/Info.plist').read_bytes())
        self.assertEqual(info['LSMinimumSystemVersion'], '27.0')
        self.assertEqual(info['CFBundleIdentifier'], native.BUNDLE_ID)
        self.assertFalse(self.report['qualified'])

    def test_bundle_tamper_and_symlink_refused(self):
        executable = self.package / native.APP / native.EXECUTABLE
        executable.write_bytes(b'tampered')
        with self.assertRaises(native.Refused):
            native.load_package(self.package)
        executable.unlink()
        executable.symlink_to('/bin/sh')
        with self.assertRaises(OSError):
            native.load_package(self.package)

    def test_directory_symlink_and_mode_refused(self):
        app = self.package / native.APP
        (app / 'Contents/alias').symlink_to(app / 'Contents/Resources', target_is_directory=True)
        with self.assertRaises(native.Refused):
            native.load_package(self.package)
        (app / 'Contents/alias').unlink()
        (app / 'Contents').chmod(0o777)
        with self.assertRaises(native.Refused):
            native.load_package(self.package)

    def test_manifest_cannot_make_dirty_build_clean(self):
        self.report['provenance']['build']['build']['dirty'] = True
        native.write_json(self.package / native.APP / native.PROVENANCE, self.report['provenance'])
        self.report['files'] = native.bundle_files(self.package / native.APP)
        native.write_json(self.package / 'package.json', self.report)
        with self.assertRaisesRegex(native.Refused, 'clean optimized'):
            native.load_package(self.package)

    def test_bad_build_variants(self):
        for key, value in [('revision', 'c' * 40), ('dirty', True), ('target', 'x86_64-apple-darwin'),
                           ('opt_level', '0'), ('debug_assertions', True), ('inputs', 'bad'),
                           ('rustc', 'rustc 1.97.0 (old)')]:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report['provenance']['build'])
                report['build'][key] = value
                with self.assertRaises(native.Refused):
                    native.check_build(report, 'a' * 40, 'sha256:' + 'b' * 64, '1.98.1')

    def test_stage_dirty_source_refused_before_execution(self):
        def git(_repo, *args):
            return b'a' * 40 if args[0] == 'rev-parse' else b'?? dirty'
        with patch.object(native, 'git', side_effect=git), patch.object(native, 'version') as version:
            with self.assertRaisesRegex(native.Refused, 'not clean'):
                native.stage(Path('/missing'), self.root, self.root / 'out', '0.1.0', 1)
            version.assert_not_called()

    def test_stage_index_flags_refused(self):
        with patch.object(native, 'git', side_effect=[b'a' * 40, b'', b'h hidden']):
            with self.assertRaisesRegex(native.Refused, 'index'):
                native.stage(Path('/missing'), self.root, self.root / 'out', '0.1.0', 1)

    def test_stage_non_native_binary_refused_before_execution(self):
        binary = self.root / 'fake'
        binary.write_bytes(b'#!/bin/sh\nexit 0\n')
        with patch.object(native, 'git', side_effect=[b'a' * 40, b'', b'H file']), patch.object(native, 'version') as version:
            with self.assertRaisesRegex(native.Refused, 'Mach-O'):
                native.stage(binary, self.root, self.root / 'out', '0.1.0', 1)
            version.assert_not_called()

    def test_stage_independently_checks_git_blob_digest_and_pinned_toolchain(self):
        repo = self.root / 'source'
        repo.mkdir()
        inputs = ['rust-toolchain.toml', 'Cargo.lock', 'crates/ukai-jail/profiles/inputs.rs']
        files = {'rust-toolchain.toml': '[toolchain]\nchannel = "1.98.1"\n',
                 'Cargo.lock': 'fixture dependency bytes', 'LICENSE': 'license',
                 'crates/ukai-jail/dist/WEBPKI_ROOTS_LICENSE': 'CA data license',
                 'crates/ukai-jail/profiles/inputs.rs': repr(inputs),
                 'crates/ukai-jail/src/main.rs': 'fn main() {}'}
        for name, data in files.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        native.git(repo, 'init', '-q')
        native.git(repo, 'add', '.')
        native.git(repo, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                   '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
        revision = native.git(repo, 'rev-parse', 'HEAD').decode().strip()
        report = copy.deepcopy(self.report['provenance']['build'])
        report['build'].update(revision=revision, inputs=native.commit_inputs(repo, revision))
        binary = self.package / native.APP / native.EXECUTABLE
        with patch.object(native, 'version', return_value=report):
            result = native.stage(binary, repo, self.root / 'stage', '0.1.0-native.1', 1)
        self.assertEqual(result['provenance']['source_revision'], revision)
        native.load_package(self.root / 'stage')
        report['build']['inputs'] = 'sha256:' + '0' * 64
        with patch.object(native, 'version', return_value=report):
            with self.assertRaisesRegex(native.Refused, 'named source inputs'):
                native.stage(binary, repo, self.root / 'bad-stage', '0.1.0-native.1', 1)

    def test_copy_rejects_changed_source_and_traversal(self):
        (self.package / native.APP / native.EXECUTABLE).write_bytes(b'changed')
        with self.assertRaisesRegex(native.Refused, 'changed during copy'):
            native.copy_bundle(self.package / native.APP, self.root / 'copy', self.report['files'])
        with self.assertRaisesRegex(native.Refused, 'manifest path'):
            native.copy_bundle(self.package / native.APP, self.root / 'other', {'../escape': {}})

    def test_profile_metadata_rejects_wrong_authority(self):
        for mutate in [lambda p: p.update(ProvisionsAllDevices=False),
                       lambda p: p.update(ExpirationDate=datetime.datetime(2000, 1, 1)),
                       lambda p: p['Entitlements'].update({native.ENTITLEMENT: False}),
                       lambda p: p['Entitlements'].update({'com.apple.application-identifier': 'TEAMID1234.*'}),
                       lambda p: p['Entitlements'].update({'com.apple.security.get-task-allow': True})]:
            value = profile()
            mutate(value)
            with self.assertRaises(native.Refused):
                native.profile_entitlements(value)

    def test_unsigned_never_passes_signature_validation(self):
        with patch.object(native, 'execute') as run:
            with self.assertRaises(native.Refused):
                native.verify_signature(self.package / native.APP, self.report, run, distribution=True)
            run.assert_not_called()

    def fake_signature(self, failure=None):
        report = copy.deepcopy(self.report)
        report.update(signing='developer-id', team='TEAMID1234')
        calls = []
        def run(argv, **kwargs):
            args = [str(arg) for arg in argv]
            calls.append((args, kwargs))
            if failure and failure(args):
                raise subprocess.CalledProcessError(1, args)
            if args[0] == '/usr/bin/csrutil':
                return SimpleNamespace(stdout=b'System Integrity Protection status: enabled.\n')
            if '--entitlements' in args:
                return SimpleNamespace(stdout=plistlib.dumps(profile()['Entitlements']))
            if '/usr/bin/security' in args:
                return SimpleNamespace(stdout=plistlib.dumps(profile()))
            if '--verbose=4' in args:
                return SimpleNamespace(stderr=b'flags=0x10000(runtime)')
            if 'version' in args:
                return SimpleNamespace(stdout=json.dumps(report['provenance']['build']).encode())
            return SimpleNamespace(stdout=b'', stderr=b'')
        return report, calls, run

    def test_forged_profile_metadata_cannot_bypass_apple_signature(self):
        report, calls, run = self.fake_signature(lambda a: '--verify' in a)
        with self.assertRaises(subprocess.CalledProcessError):
            native.verify_signature(self.package / native.APP, report, run)
        self.assertEqual(len(calls), 2)
        self.assertIn('anchor apple generic', calls[-1][0][-2])

    def test_disabled_custom_or_unknown_sip_cannot_authorize_profile(self):
        for output in (b'System Integrity Protection status: disabled.',
                       b'System Integrity Protection status: enabled (Custom Configuration).', b'unknown'):
            report, _, _ = self.fake_signature()
            calls = []
            def run(argv, **kwargs):
                calls.append(argv)
                return SimpleNamespace(stdout=output)
            with self.assertRaisesRegex(native.Refused, 'enabled SIP'):
                native.verify_signature(self.package / native.APP, report, run)
            self.assertEqual(calls, [['/usr/bin/csrutil', 'status']])

    def test_sign_refuses_unprotected_host_before_mutation(self):
        path = self.root / 'profile'
        path.write_bytes(b'fabricated')
        calls = []
        def run(argv, **_):
            calls.append(argv)
            if argv[0] == '/usr/bin/security':
                return SimpleNamespace(stdout=plistlib.dumps(profile()))
            return SimpleNamespace(stdout=b'System Integrity Protection status: disabled.')
        out = self.root / 'signed'
        with self.assertRaisesRegex(native.Refused, 'enabled SIP'):
            native.sign(self.package, out, path, 'Developer ID Application: Example (TEAMID1234)', run)
        self.assertFalse(out.exists())
        self.assertFalse(any('--sign' in call for call in calls))

    def test_profile_decode_is_not_enough_os_launch_must_pass(self):
        report, calls, run = self.fake_signature(lambda a: 'version' in a)
        with self.assertRaises(subprocess.CalledProcessError):
            native.verify_signature(self.package / native.APP, report, run)
        self.assertEqual(calls[-1][0][-2:], ['version', '--json'])
        self.assertNotIn('UKAI_JAIL_MACOS_NATIVE', calls[-1][1]['env'])

    def test_distribution_requires_both_apple_checks_without_mutation(self):
        report, calls, run = self.fake_signature()
        native.verify_signature(self.package / native.APP, report, run, distribution=True)
        commands = [args for args, _ in calls]
        self.assertTrue(any('stapler' in a and 'validate' in a for a in commands))
        self.assertTrue(any('/usr/bin/syspolicy_check' in a and 'distribution' in a for a in commands))
        self.assertFalse(any('staple' in a or 'submit' in a or '--sign' in a for a in commands))

    def test_distribution_failure_is_fatal(self):
        for failing in ('stapler', '/usr/bin/syspolicy_check'):
            report, _, run = self.fake_signature(lambda a: failing in a)
            with self.assertRaises(subprocess.CalledProcessError):
                native.verify_signature(self.package / native.APP, report, run, distribution=True)

    def test_sign_failure_cannot_leave_usable_package(self):
        path = self.root / 'profile'
        path.write_bytes(b'fabricated')
        def run(argv, **_):
            if '/usr/bin/security' in argv:
                return SimpleNamespace(stdout=plistlib.dumps(profile()))
            raise subprocess.CalledProcessError(1, argv)
        out = self.root / 'signed'
        with self.assertRaises(subprocess.CalledProcessError):
            native.sign(self.package, out, path, 'Developer ID Application: Example (TEAMID1234)', run)
        self.assertFalse((out / 'package.json').exists())

    def test_execute_allows_explicit_timeout(self):
        result = native.execute([sys.executable, '-c', 'print("ok")'], timeout=5)
        self.assertEqual(result.stdout, b'ok\n')

    def test_unsigned_notarization_refused_without_external_calls(self):
        with patch.object(native, 'verify_signature', side_effect=native.Refused('unsigned')) as verify:
            with self.assertRaises(native.Refused):
                notarize.submit(self.package, self.root / 'submission', 'keychain', lambda *a, **k: self.fail())
            verify.assert_called_once()

    def test_staple_receipt_cannot_name_other_package(self):
        receipt = self.root / 'receipt.json'
        native.write_json(receipt, {'schema': 'ukai.macos.notary/1', 'status': 'Accepted', 'package_sha256': 'wrong'})
        with self.assertRaisesRegex(native.Refused, 'does not name'):
            notarize.staple(self.package, receipt, self.root / 'stapled', lambda *a, **k: self.fail())


if __name__ == '__main__':
    unittest.main()
