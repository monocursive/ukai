"""notarize.py: the credential-gated step records only what Apple answered.

subprocess.run is faked, never command(): every recorded argv goes through
notarize's own scrub, so a test fails if a credential value reaches the
record. No network, no Apple credentials, no keychain.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import notarize

SUBMISSION = 'deadbeef-0000-0000-0000-000000000000'


class FakeApple:
    """subprocess.run for xcrun/spctl: scripted answers, every argv kept."""

    def __init__(self, status='Accepted', submit_exit=0, submit_timeout=False, staple_changes_dmg=True,
                 validate_ok=True, dmg=None):
        self.calls = []
        self.status, self.submit_exit, self.submit_timeout = status, submit_exit, submit_timeout
        self.staple_changes_dmg, self.validate_ok, self.dmg = staple_changes_dmg, validate_ok, dmg

    def __call__(self, argv, capture_output=True, text=True, timeout=None):
        self.calls.append(list(argv))
        if argv[:3] == ['xcrun', 'notarytool', 'submit']:
            if self.submit_timeout:
                raise subprocess.TimeoutExpired(argv, timeout, output=f'Submission ID received\n  id: {SUBMISSION}\n')
            return subprocess.CompletedProcess(argv, self.submit_exit,
                                               f'Submission ID received\n  id: {SUBMISSION}\n'
                                               f'Processing complete\n  id: {SUBMISSION}\n  status: {self.status}\n', '')
        if argv[:3] == ['xcrun', 'notarytool', 'log']:
            return subprocess.CompletedProcess(argv, 0, '{"status": "%s", "issues": []}\n' % self.status, '')
        if argv[:3] == ['xcrun', 'stapler', 'staple']:
            if self.staple_changes_dmg:
                with open(self.dmg, 'ab') as output:
                    output.write(b'stapled ticket')
            return subprocess.CompletedProcess(argv, 0, 'The staple and validate action worked!\n', '')
        if argv[:3] == ['xcrun', 'stapler', 'validate']:
            return subprocess.CompletedProcess(argv, 0 if self.validate_ok else 65,
                                               'The validate action worked!\n' if self.validate_ok else 'invalid\n', '')
        return subprocess.CompletedProcess(argv, 0, 'accepted\n', '')

    def steps(self):
        return [' '.join(call[:3]) for call in self.calls]


class PackageFixture:
    def __init__(self, notarization='pending', key_name='my-signing-material.txt'):
        self.root = Path(tempfile.mkdtemp(prefix='notarize-test-'))
        self.dmg = self.root / 'ukai-vm.dmg'
        self.dmg.write_bytes(b'the disk image bytes\n')
        self.report = {'schema': 'ukai.vm.package/1', 'dmg': 'ukai-vm.dmg', 'notarization': notarization,
                       'dmg_sha256_before_notarization': hashlib.sha256(self.dmg.read_bytes()).hexdigest(),
                       'published': False}
        (self.root / 'package.json').write_text(json.dumps(self.report, indent=2) + '\n')
        # The scrub is by value: a key file NOT named *.p8 must not leak either.
        self.key = self.root / key_name
        self.key.write_bytes(b'private key bytes')

    def run(self, apple):
        apple.dmg = self.dmg
        argv = ['notarize.py', '--package', str(self.root), '--key', str(self.key),
                '--key-id', 'KEYID-SECRET-1', '--issuer', 'ISSUER-SECRET-2']
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(notarize.subprocess, 'run', apple), \
                mock.patch('builtins.print'):
            return notarize.main()

    def record(self, name='notarization.json'):
        return json.loads((self.root / name).read_text())


class NotarizationTests(unittest.TestCase):
    def test_a_full_pass_records_every_step_and_the_new_digest(self):
        package = PackageFixture()
        apple = FakeApple()
        self.assertEqual(package.run(apple), 0)
        record = package.record()
        self.assertEqual(record['outcome'], 'notarized')
        self.assertEqual(record['submission_id'], SUBMISSION)
        self.assertEqual(record['status'], 'Accepted')
        self.assertEqual([step['step'] for step in record['steps']],
                         ['submit', 'log', 'staple', 'stapler-validate', 'spctl-assess'])
        self.assertIn('"issues": []', record['steps'][1]['stdout'])
        updated = json.loads((package.root / 'package.json').read_text())
        self.assertEqual(updated['notarization'], SUBMISSION)
        self.assertEqual(updated['dmg_sha256_notarized'], record['dmg_sha256_after_stapling'])
        self.assertNotEqual(record['dmg_sha256_after_stapling'], record['dmg_sha256_before'])

    def test_no_credential_value_appears_in_the_record(self):
        package = PackageFixture()
        apple = FakeApple()
        package.run(apple)
        text = (package.root / 'notarization.json').read_text()
        for secret in (str(package.key), package.key.name, 'KEYID-SECRET-1', 'ISSUER-SECRET-2'):
            self.assertNotIn(secret, text)
        # The fake really received them: the scrub, not the fake, keeps them out.
        self.assertIn(str(package.key), ' '.join(apple.calls[0]))
        self.assertIn('<redacted>', text)

    def test_the_scrub_redacts_every_credential_flag_and_spelling(self):
        argv = ['xcrun', 'notarytool', 'submit', 'x.dmg', '--key', '/k/AuthKey.p8', '--key-id=ABC',
                '--issuer', 'ISS', '--keychain-profile', 'prof', '--wait']
        cleaned = notarize.scrub(argv, secrets=['/k/AuthKey.p8'])
        self.assertEqual(cleaned, ['xcrun', 'notarytool', 'submit', 'x.dmg', '--key', '<redacted>',
                                   '--key-id=<redacted>', '--issuer', '<redacted>', '--keychain-profile',
                                   '<redacted>', '--wait'])
        self.assertEqual(notarize.scrub_text('error reading /k/AuthKey.p8', ['/k/AuthKey.p8']),
                         'error reading <redacted>')

    def test_a_rejected_submission_records_its_log_and_changes_nothing(self):
        package = PackageFixture()
        apple = FakeApple(status='Invalid')
        self.assertEqual(package.run(apple), 1)
        record = package.record()
        self.assertEqual(record['outcome'], 'not-accepted: Invalid')
        self.assertEqual([step['step'] for step in record['steps']], ['submit', 'log'])
        self.assertIn('Invalid', record['steps'][1]['stdout'])
        self.assertEqual(json.loads((package.root / 'package.json').read_text())['notarization'], 'pending')

    def test_a_failed_submit_keeps_pending(self):
        package = PackageFixture()
        self.assertEqual(package.run(FakeApple(submit_exit=69)), 1)
        self.assertEqual(package.record()['outcome'], 'submit-failed')
        self.assertEqual(json.loads((package.root / 'package.json').read_text())['notarization'], 'pending')

    def test_a_timeout_is_recorded_with_the_submission_it_left_running(self):
        package = PackageFixture()
        self.assertEqual(package.run(FakeApple(submit_timeout=True)), 1)
        record = package.record()
        self.assertEqual(record['outcome'], 'submit-timeout')
        self.assertTrue(record['steps'][0]['timed_out'])
        self.assertEqual(record['submission_id'], SUBMISSION)
        self.assertNotIn('status', record)
        self.assertEqual(record['steps'][1]['step'], 'log')

    def test_a_rerun_never_replaces_an_earlier_record(self):
        package = PackageFixture()
        package.run(FakeApple(submit_exit=69))
        first = (package.root / 'notarization.json').read_text()
        self.assertEqual(package.run(FakeApple()), 0)
        self.assertEqual((package.root / 'notarization.json').read_text(), first)
        self.assertEqual(package.record('notarization.2.json')['outcome'], 'notarized')
        self.assertEqual(json.loads((package.root / 'package.json').read_text())['notarization_record'],
                         'notarization.2.json')

    def test_a_stapled_dmg_is_never_resubmitted(self):
        package = PackageFixture()
        self.assertEqual(package.run(FakeApple(validate_ok=False)), 1)
        self.assertTrue(package.record()['outcome'].startswith('incomplete'))
        self.assertTrue(package.record()['dmg_changed'])
        apple = FakeApple()
        with self.assertRaises(SystemExit) as caught, mock.patch('sys.stderr'):
            package.run(apple)
        self.assertEqual(caught.exception.code, 2)
        self.assertEqual(apple.calls, [])

    def test_a_dmg_that_is_not_the_packaged_one_is_refused(self):
        package = PackageFixture()
        package.dmg.write_bytes(b'another image\n')
        apple = FakeApple()
        with self.assertRaises(SystemExit), mock.patch('sys.stderr'):
            package.run(apple)
        self.assertEqual(apple.calls, [])
        self.assertFalse((package.root / 'notarization.json').exists())

    def test_the_step_is_not_idempotent(self):
        package = PackageFixture(notarization='abcd-1234')
        apple = FakeApple()
        with mock.patch('sys.stderr') as quiet, self.assertRaises(SystemExit) as caught:
            package.run(apple)
        self.assertEqual(apple.calls, [])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('not idempotent', ''.join(call.args[0] for call in quiet.write.call_args_list))


if __name__ == '__main__':
    unittest.main()
