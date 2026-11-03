"""notarize.py: the credential-gated step records only what Apple answered.

The xcrun/spctl calls are mocked: these tests pin the evidence contract
(submission id, per-step output, stapled-digest bookkeeping, the .p8 path
never appearing in the record) without any network or Apple credentials.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import notarize


def accepted_submission(submission='deadbeef-0000-0000-0000-000000000000'):
    return {'exit': 0, 'argv': [],
            'stdout': f'  id: {submission}\n  status: Accepted\n',
            'stderr': ''}


def step_ok(stdout=''):
    return {'exit': 0, 'argv': [], 'stdout': stdout, 'stderr': ''}


def routed_calls(submission='deadbeef-0000-0000-0000-000000000000'):
    """A command() stand-in: notarytool accepts, every check passes."""
    def routed(*call, timeout=None):
        text = ' '.join(str(part) for part in call)
        if 'notarytool' in text:
            return accepted_submission(submission)
        return step_ok('The validate action worked!')
    return routed


class PackageFixture:
    def __init__(self, notarization='pending'):
        self.root = Path(tempfile.mkdtemp(prefix='notarize-test-'))
        (self.root / 'ukai-vm.dmg').write_bytes(b'the disk image bytes\n')
        self.report = {'schema': 'ukai.vm.package/1', 'dmg': 'ukai-vm.dmg',
                       'notarization': notarization, 'published': False}
        (self.root / 'package.json').write_text(json.dumps(self.report, indent=2) + '\n')
        (self.root / 'AuthKey_TEST.p8').write_bytes(b'private key bytes')

    def run(self):
        argv = ['notarize.py', '--package', str(self.root),
                '--key', str(self.root / 'AuthKey_TEST.p8'),
                '--key-id', 'TESTKEY', '--issuer', 'ISSUER-1']
        with mock.patch.object(sys, 'argv', argv):
            return notarize.main()


class NotarizationTests(unittest.TestCase):
    def test_a_full_pass_records_every_step_and_the_new_digest(self):
        package = PackageFixture()
        with mock.patch.object(notarize, 'command',
                               side_effect=routed_calls('abcd-1234')):
            self.assertEqual(package.run(), 0)
        record = json.loads((package.root / 'notarization.json').read_text())
        self.assertEqual(record['outcome'], 'notarized')
        self.assertEqual(record['submission_id'], 'abcd-1234')
        self.assertEqual(record['status'], 'Accepted')
        self.assertTrue(all(record[k] for k in
                            ('stapled', 'staple_valid', 'gatekeeper_assesses')))
        self.assertEqual([step['step'] for step in record['steps']],
                         ['submit', 'staple', 'stapler-validate', 'spctl-assess'])
        updated = json.loads((package.root / 'package.json').read_text())
        self.assertEqual(updated['notarization'], 'abcd-1234')
        self.assertEqual(updated['dmg_sha256_notarized'],
                         record['dmg_sha256_after_stapling'])

    def test_the_key_path_never_appears_in_the_record(self):
        package = PackageFixture()
        with mock.patch.object(notarize, 'command',
                               side_effect=routed_calls('abcd-1234')):
            package.run()
        record = json.loads((package.root / 'notarization.json').read_text())
        for step in record['steps']:
            self.assertNotIn('AuthKey_TEST.p8', json.dumps(step['argv']))

    def test_a_rejected_submission_records_verbatim_and_changes_nothing(self):
        package = PackageFixture()
        rejected = {'exit': 0, 'argv': [], 'stdout': '  id: ff-ee\n  status: Invalid\n',
                    'stderr': ''}
        with mock.patch.object(notarize, 'command', return_value=rejected):
            self.assertEqual(package.run(), 1)
        record = json.loads((package.root / 'notarization.json').read_text())
        self.assertEqual(record['outcome'], 'not-accepted: Invalid')
        unchanged = json.loads((package.root / 'package.json').read_text())
        self.assertEqual(unchanged['notarization'], 'pending')

    def test_a_failed_submit_keeps_pending(self):
        package = PackageFixture()
        failure = {'exit': 69, 'argv': [], 'stdout': '', 'stderr': 'Error: HTTP 401'}
        with mock.patch.object(notarize, 'command', return_value=failure):
            self.assertEqual(package.run(), 1)
        record = json.loads((package.root / 'notarization.json').read_text())
        self.assertEqual(record['outcome'], 'submit-failed')
        unchanged = json.loads((package.root / 'package.json').read_text())
        self.assertEqual(unchanged['notarization'], 'pending')

    def test_the_step_is_not_idempotent(self):
        package = PackageFixture(notarization='abcd-1234')
        with mock.patch.object(notarize, 'command') as fake, \
                mock.patch('sys.stderr') as quiet:
            with self.assertRaises(SystemExit) as caught:
                package.run()
        fake.assert_not_called()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('not idempotent', ''.join(call.args[0] for call
                                                in quiet.write.call_args_list))


if __name__ == '__main__':
    unittest.main()
