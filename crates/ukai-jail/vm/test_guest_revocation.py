"""Selected staged-source revocation, independent of the host transport watcher."""
import base64
import os
from pathlib import Path
import tempfile
import unittest

import guest
from guest_harness import GuestHarness, complete, hold


class RevocationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'credentials'
        self.staged = {}
        self.revoked = set()
        for key in ('api/token', 'second'):
            guest.stage_secret(key, b'synthetic-value', secrets=self.root)
            self.staged[key] = guest.staged_secret_identity(key, self.root)

    def test_unlinks_only_exact_selected_entries_and_refuses_duplicate_revocation(self):
        guest.revoke_secrets(['api/token'], self.staged, self.revoked, self.root)
        self.assertFalse((self.root / 'api/token').exists())
        self.assertEqual((self.root / 'second').read_bytes(), b'synthetic-value')
        self.assertEqual(self.revoked, {'api/token'})
        with self.assertRaises(guest.Refusal):
            guest.revoke_secrets(['api/token'], self.staged, self.revoked, self.root)

    def test_invalid_ids_are_rejected_before_any_unlink(self):
        for ids in ([], ['unknown'], ['api/token', 'api/token'], ['second', 'api/token'], ['../token'], 'api/token', [1]):
            with self.subTest(ids=ids), self.assertRaises(guest.Refusal):
                guest.revoke_secrets(ids, self.staged, self.revoked, self.root)
            self.assertTrue((self.root / 'api/token').exists())
            self.assertTrue((self.root / 'second').exists())

    def test_replacement_or_link_is_not_unlinked_or_acknowledged(self):
        original = self.root / 'api/token'
        original.rename(self.root / 'original')
        original.write_bytes(b'replacement')
        with self.assertRaises(guest.Refusal):
            guest.revoke_secrets(['api/token'], self.staged, self.revoked, self.root)
        self.assertEqual(original.read_bytes(), b'replacement')
        original.unlink()
        original.symlink_to(self.root / 'original')
        with self.assertRaises(guest.Refusal):
            guest.revoke_secrets(['api/token'], self.staged, self.revoked, self.root)
        self.assertTrue(original.is_symlink())
        self.assertEqual(self.revoked, set())

    def test_parent_symlink_cannot_redirect_the_unlink(self):
        parent = self.root / 'api'
        parent.rename(self.root / 'original-parent')
        parent.symlink_to(self.root / 'original-parent', target_is_directory=True)
        with self.assertRaises(guest.Refusal):
            guest.revoke_secrets(['api/token'], self.staged, self.revoked, self.root)
        self.assertEqual((self.root / 'original-parent/token').read_bytes(), b'synthetic-value')


class LiveHandlerTests(unittest.TestCase):
    def test_live_ack_names_removed_ids_and_reset_starts_a_fresh_generation(self):
        harness = GuestHarness(self, scenarios=[hold(), hold()])
        harness.session()
        for _ in range(2):
            harness.send(op='reset'); harness.expect('reset')
            harness.send(op='secret', id='api/token', data=base64.b64encode(b'synthetic-value').decode())
            harness.expect('secret')
            harness.run2(); harness.expect('running')
            harness.send(op='revoke_secrets', ids=['api/token'])
            frame = harness.expect('secrets_revoked')
            self.assertEqual(frame['ids'], ['api/token'])
            self.assertFalse((harness.secrets / 'api/token').exists())
            harness.send(op='cancel2'); harness.expect('cancelled')

    def test_unknown_live_id_powers_off_without_acknowledgment(self):
        harness = GuestHarness(self, scenarios=[hold()])
        harness.session(); harness.run2(); harness.expect('running')
        harness.send(op='revoke_secrets', ids=['unknown'])
        self.assertEqual(harness.ended(), 'invalid_secret_revocation')

    def test_partial_failure_never_acknowledges_the_requested_set(self):
        harness = GuestHarness(self, scenarios=[hold()])
        harness.session()
        for key in ('a', 'b'):
            harness.send(op='secret', id=key, data=base64.b64encode(b'synthetic').decode())
            harness.expect('secret')
        harness.run2(); harness.expect('running')
        (harness.secrets / 'b').unlink()
        harness.send(op='revoke_secrets', ids=['a', 'b'])
        seen = []
        while (frame := harness.frame()) is not None:
            seen.append(frame['event'])
        self.assertNotIn('secrets_revoked', seen)
        self.assertEqual(harness.ended(), 'secret_revocation_failed')

    def test_no_secret_can_be_restaged_after_a_completed_run_without_reset(self):
        harness = GuestHarness(self, scenarios=[complete()])
        harness.session(); harness.run2(); harness.expect('done')
        harness.send(op='secret', id='replacement', data=base64.b64encode(b'synthetic').decode())
        self.assertEqual(harness.ended(), 'invalid_operation')


if __name__ == '__main__':
    unittest.main()
