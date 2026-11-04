"""The public derivative must never widen an install excerpt into a transcript."""
from pathlib import Path
import unittest
from unittest.mock import patch
from export_reader_results import install_excerpt


class InstallExcerptTests(unittest.TestCase):
    def excerpt(self, command, success=True):
        request, result = {'line': 3}, {'line': 4}
        score = {'operation': {'matched_install_results': [
            {'request': request, 'result': result, 'reported_success': True}]}}
        call = {'request_ref': request, 'result_ref': result, 'success': success,
                'tool': 'Bash', 'input': {'command': command, 'private': 'do not publish'},
                'output': 'do not publish', 'thinking': 'do not publish'}
        with patch('export_reader_results.normalize', return_value={'calls': [call], 'messages': ['do not publish']}), \
                patch('export_reader_results.sha', return_value='a' * 64):
            return install_excerpt(Path('/unused'), score)

    def test_exact_install_keeps_only_allowlisted_fields(self):
        result = self.excerpt('npm ci --offline --no-audit --no-fund --foreground-scripts')
        self.assertNotIn('do not publish', str(result))
        self.assertEqual(len(result['calls']), 1)

    def test_extra_command_or_secret_is_rejected(self):
        with self.assertRaises(ValueError):
            self.excerpt('npm ci --offline --no-audit --no-fund --foreground-scripts; echo private-token')

    def test_conflicting_result_is_rejected(self):
        with self.assertRaises(ValueError):
            self.excerpt('npm ci --offline --no-audit --no-fund --foreground-scripts', False)


class ArchiveDateTests(unittest.TestCase):
    """Archive entries carry the export's own date, never a fixed 26 October stamp."""

    def build(self, root, results):
        import json
        out = root / 'export'
        (out / 'runs').mkdir(parents=True)
        (out / 'results.json').write_text(json.dumps(results))
        (out / 'runs' / 'record.json').write_text('{}')
        return out

    def test_entries_use_the_record_date(self):
        import tempfile, zipfile
        from export_containment import archive
        cases = {'november': ({'date': '2026-11-01'}, (2026, 11, 1, 0, 0, 0)),
                 'october': ({'as_of_utc': '2026-10-26'}, (2026, 10, 26, 0, 0, 0)),
                 'timestamp': ({'as_of_utc': '2026-11-03T08:00:00+00:00'}, (2026, 11, 3, 0, 0, 0))}
        for name, (results, expected) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                out = self.build(Path(tmp), results)
                digest = archive(out, Path(tmp) / 'evidence.zip')
                entries = zipfile.ZipFile(Path(tmp) / 'evidence.zip').infolist()
                self.assertEqual({entry.date_time for entry in entries}, {expected})
                self.assertIn(digest, (Path(tmp) / 'evidence.zip.sha256').read_text())

    def test_missing_or_impossible_date_refuses_before_writing(self):
        import tempfile
        from export_containment import archive
        for results in ({}, {'date': 'unknown'}, {'date': '2026-13-01'}):
            with self.subTest(results=results), tempfile.TemporaryDirectory() as tmp:
                out = self.build(Path(tmp), results)
                with self.assertRaises(ValueError):
                    archive(out, Path(tmp) / 'evidence.zip')
                self.assertFalse((Path(tmp) / 'evidence.zip').exists())


if __name__ == '__main__':
    unittest.main()
