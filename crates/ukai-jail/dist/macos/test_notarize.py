import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import install
import native
import notarize
from test_native import fixture


class NotarizeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.package = self.root / 'signed'
        self.report = fixture(self.package)
        app = self.package / native.APP
        (app / 'Contents/_CodeSignature').mkdir()
        (app / 'Contents/_CodeSignature/CodeResources').write_bytes(b'synthetic signature resources')
        (app / 'Contents/embedded.provisionprofile').write_bytes(b'synthetic profile')
        self.report.update(signing='developer-id', team='TEAMID1234', files=native.bundle_files(app))
        native.write_json(self.package / 'package.json', self.report)
        self.receipt = self.root / 'receipt.json'
        native.write_json(self.receipt, {'schema': 'ukai.macos.notary/1', 'status': 'Accepted', 'id': 'fixture-id',
                                        'package_sha256': native.digest((self.package / 'package.json').read_bytes())})

    def run_stapler(self, argv, **_):
        self.assertEqual(argv[:3], ['/usr/bin/xcrun', 'stapler', 'staple'])
        (Path(argv[-1]) / 'Contents/CodeResources').write_bytes(b'synthetic stapled ticket')
        return SimpleNamespace(stdout=b'')

    def test_stapled_ticket_survives_validation_and_install_copy(self):
        output = self.root / 'stapled'
        with patch.object(native, 'verify_signature') as verify:
            report = notarize.staple(self.package, self.receipt, output, self.run_stapler)
            self.assertEqual(verify.call_count, 2)
            self.assertTrue(verify.call_args.kwargs['distribution'])
            native.load_package(output)
            home = self.root / 'home'
            home.mkdir()
            installation = install.Installation(home)
            installation.install(output)
        self.assertEqual((installation.app / 'Contents/CodeResources').read_bytes(), b'synthetic stapled ticket')
        self.assertEqual(report['notarization'], 'stapled')
        self.assertFalse(report['qualified'])
        self.assertFalse((self.package / native.APP / 'Contents/CodeResources').exists())

    def test_unstapled_manifest_cannot_include_ticket(self):
        (self.package / native.APP / 'Contents/CodeResources').write_bytes(b'forged ticket')
        self.report['files'] = native.bundle_files(self.package / native.APP)
        native.write_json(self.package / 'package.json', self.report)
        with self.assertRaisesRegex(native.Refused, 'Unexpected bundle contents'):
            native.load_package(self.package)

    def test_stapler_failure_does_not_create_installable_candidate(self):
        output = self.root / 'failed'
        def fail(argv, **_):
            raise subprocess.CalledProcessError(1, argv)
        with patch.object(native, 'verify_signature'):
            with self.assertRaises(subprocess.CalledProcessError):
                notarize.staple(self.package, self.receipt, output, fail)
        self.assertFalse((output / 'package.json').exists())

    def test_final_distribution_failure_does_not_create_installable_candidate(self):
        output = self.root / 'failed'
        with patch.object(native, 'verify_signature', side_effect=[None, native.Refused('Apple rejected')]):
            with self.assertRaisesRegex(native.Refused, 'Apple rejected'):
                notarize.staple(self.package, self.receipt, output, self.run_stapler)
        self.assertFalse((output / 'package.json').exists())

    def submission(self, status='Accepted', error=None):
        calls = []
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0] == '/usr/bin/ditto':
                Path(argv[-1]).write_bytes(b'synthetic archive')
                return SimpleNamespace(stdout=b'')
            if error:
                raise error
            return SimpleNamespace(stdout=json.dumps({'id': 'fixture-id', 'status': status}).encode())
        return calls, run

    def test_submission_binds_package_and_archive_and_keeps_input_unchanged(self):
        original = (self.package / 'package.json').read_bytes()
        calls, run = self.submission()
        with patch.object(native, 'verify_signature'):
            receipt = notarize.submit(self.package, self.root / 'submission', 'fixture-profile', run)
        self.assertEqual(receipt['package_sha256'], native.digest(original))
        self.assertEqual(receipt['archive_sha256'], native.digest(b'synthetic archive'))
        self.assertEqual(calls[-1][1]['timeout'], 1500)
        self.assertIn('--keychain-profile', calls[-1][0])
        self.assertEqual((self.package / 'package.json').read_bytes(), original)

    def test_rejected_submission_retains_response_without_acceptance(self):
        _, run = self.submission('Invalid')
        out = self.root / 'submission'
        with patch.object(native, 'verify_signature'):
            with self.assertRaisesRegex(native.Refused, 'did not accept'):
                notarize.submit(self.package, out, 'fixture-profile', run)
        self.assertEqual(json.loads((out / 'receipt.json').read_text())['status'], 'Invalid')
        self.assertTrue((out / 'notarytool.json').is_file())

    def test_failed_submission_retains_diagnostics_without_receipt(self):
        error = subprocess.CalledProcessError(1, ['synthetic'], output=b'partial response', stderr=b'rejected')
        _, run = self.submission(error=error)
        out = self.root / 'submission'
        with patch.object(native, 'verify_signature'):
            with self.assertRaises(subprocess.CalledProcessError):
                notarize.submit(self.package, out, 'fixture-profile', run)
        self.assertFalse((out / 'receipt.json').exists())
        self.assertEqual((out / 'notarytool.stderr').read_bytes(), b'rejected')


if __name__ == '__main__':
    unittest.main()
