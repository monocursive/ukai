"""A valid heartbeat can extend a tool's duration but cannot prove its result."""
import json
from pathlib import Path
import tempfile
import unittest
from m1.adapters import normalize


class ClaudeProgressTests(unittest.TestCase):
    def setUp(self):
        self.request = {'type': 'assistant', 'message': {'content': [
            {'type': 'tool_use', 'id': 'a', 'name': 'Bash', 'input': {'command': 'npm ci'}}]}}
        self.progress = {'type': 'tool_progress', 'tool_use_id': 'a', 'tool_name': 'Bash',
                         'parent_tool_use_id': '', 'elapsed_time_seconds': 30,
                         'heartbeat': True, 'session_id': 'session', 'uuid': 'event'}
        self.result = {'type': 'user', 'message': {'content': [
            {'type': 'tool_result', 'tool_use_id': 'a', 'content': 'done'}]}}
        self.terminal = {'type': 'result', 'usage': {}, 'is_error': False}

    def parse(self, rows):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'stream.ndjson'
            p.write_text(''.join(json.dumps(r) + '\n' for r in rows))
            return normalize(p, 'claude')

    def test_known_active_heartbeat_has_no_evidentiary_content(self):
        r = self.parse([self.request, self.progress, self.result, self.terminal])
        self.assertEqual(r['gaps'], [])
        self.assertEqual(len(r['calls']), 1)
        self.assertEqual(r['messages'], [])
        self.assertEqual(r['adapter'], 'claude/2')

    def test_heartbeat_cannot_complete_tool_or_session(self):
        r = self.parse([self.request, self.progress])
        self.assertIn('missing_terminal', r['gaps'])
        self.assertIn('incomplete_call:a', r['gaps'])
        self.assertFalse(r['calls'][0]['success'])

    def test_parent_correlated_heartbeat_does_not_create_a_child_call(self):
        heartbeat = self.progress | {'tool_use_id': 'heartbeat-id', 'parent_tool_use_id': 'a'}
        r = self.parse([self.request, heartbeat, self.result, self.terminal])
        self.assertEqual(r['gaps'], [])
        self.assertEqual([c['id'] for c in r['calls']], ['a'])

    def test_unknown_malformed_or_late_progress_stays_a_gap(self):
        for change in ({'tool_use_id': 'other'}, {'tool_name': 'Read'}, {'elapsed_time_seconds': -1},
                       {'elapsed_time_seconds': True}, {'elapsed_time_seconds': float('inf')},
                       {'heartbeat': False}, {'content': 'must not be interpreted'}):
            with self.subTest(change=change):
                r = self.parse([self.request, self.progress | change, self.result, self.terminal])
                self.assertTrue(any(g.startswith('invalid_tool_progress:') for g in r['gaps']))
        for rows in ([self.progress, self.request, self.result, self.terminal],
                     [self.request, self.result, self.progress, self.terminal],
                     [self.request, self.result, self.terminal, self.progress]):
            self.assertTrue(any(g.startswith('invalid_tool_progress:') for g in self.parse(rows)['gaps']))


if __name__ == '__main__':
    unittest.main()
