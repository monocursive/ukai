"""Bounded guest evidence export; no private-state or credential tree export."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import guest


ATTEMPT = 'att_00000000-0000-4000-8000-000000000001'


class JournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.data = self.root / 'data'
        self.attempt = self.data / 'attempts' / ATTEMPT
        self.attempt.mkdir(parents=True)
        self.receipt = json.dumps({'attempt_id': ATTEMPT}).encode()

    def exported(self):
        files = dict(guest.journal_export(self.receipt, self.data))
        manifest = json.loads(files.pop('guest-journal/manifest.json'))
        return manifest, files

    def test_multiple_parts_reassemble_exactly_and_export_no_private_state(self):
        content = b'event\n' * (guest.MAX_FILE // 6 + 2)
        (self.attempt / 'trace.ndjson').write_bytes(content)
        (self.attempt / 'private-secret').write_text('secret-must-not-export')
        manifest, files = self.exported()
        self.assertEqual(sorted(files), ['guest-journal/0000.part', 'guest-journal/0001.part'])
        self.assertEqual(b''.join(files.values()), content)
        self.assertTrue(all(len(part) <= guest.MAX_FILE for part in files.values()))
        self.assertEqual(manifest['state'], 'exported')
        self.assertEqual(manifest['guest_attempt_id'], ATTEMPT)
        self.assertEqual(manifest['guest_receipt_sha256'], hashlib.sha256(self.receipt).hexdigest())
        self.assertEqual(manifest['sha256'], hashlib.sha256(content).hexdigest())
        self.assertNotIn(b'secret-must-not-export', b''.join(files.values()))

    def test_absent_and_over_cap_are_metadata_only_never_truncated(self):
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'absent')
        self.assertEqual(files, {})
        with (self.attempt / 'trace.ndjson').open('wb') as stream:
            stream.truncate(guest.MAX_JOURNAL + 1)
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'not_scanned')
        self.assertEqual(manifest['bytes'], guest.MAX_JOURNAL + 1)
        self.assertEqual(files, {})

    def test_symlinked_journal_and_parent_cannot_export_external_bytes(self):
        outside = self.root / 'outside'
        outside.write_text('secret-must-not-export')
        link = self.attempt / 'trace.ndjson'
        link.symlink_to(outside)
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'unreadable')
        self.assertEqual(files, {})
        link.unlink()
        self.attempt.rename(self.root / 'real-attempt')
        self.attempt.symlink_to(self.root / 'real-attempt', target_is_directory=True)
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'unreadable')
        self.assertEqual(files, {})

    def test_nonregular_and_hardlinked_journals_are_unreadable(self):
        journal = self.attempt / 'trace.ndjson'
        os.mkfifo(journal)
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'unreadable')
        self.assertEqual(files, {})
        journal.unlink()
        journal.write_bytes(b'not private\n')
        os.link(journal, self.root / 'alias')
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'unreadable')
        self.assertEqual(files, {})

    def test_receipt_cannot_select_an_arbitrary_state_path_or_previous_attempt(self):
        for attempt in ('../secret', '/etc/passwd', 'att_bad', ATTEMPT.upper()):
            with self.subTest(attempt=attempt), self.assertRaises(guest.Refusal):
                guest.journal_export(json.dumps({'attempt_id': attempt}).encode(), self.data)
        (self.attempt / 'trace.ndjson').write_bytes(b'first attempt\n')
        self.receipt = json.dumps({'attempt_id': ATTEMPT[:-1] + '2'}).encode()
        manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'absent')
        self.assertEqual(files, {})

    def test_read_failure_after_open_exports_no_partial_bytes(self):
        (self.attempt / 'trace.ndjson').write_bytes(b'partial data\n')
        real_fstat = guest.os.fstat
        calls = 0
        def fail_second(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('read failed')
            return real_fstat(fd)
        with mock.patch.object(guest.os, 'fstat', side_effect=fail_second):
            manifest, files = self.exported()
        self.assertEqual(manifest['state'], 'unreadable')
        self.assertEqual(files, {})


if __name__ == '__main__':
    unittest.main()
