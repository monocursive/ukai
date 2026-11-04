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


if __name__ == '__main__':
    unittest.main()
