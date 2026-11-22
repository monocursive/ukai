"""Failure evidence survives the disposable guest, without borrowing a prior run."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import onboarding_guest


class WorkflowEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out, self.data = self.root / 'out', self.root / 'data'
        self.out.mkdir()
        self.binary = self.root / 'fake-jail'
        self.result = {'rows': []}
        self.env = {**os.environ, 'UKAI_DATA_DIR': str(self.data)}
        self.workflow = onboarding_guest.Workflow(
            self.binary, self.out, self.env, self.result,
            lambda: (self.out / 'result.json').write_text(json.dumps(self.result)))
        previous = self.data / 'attempts' / 'previous-true'
        previous.mkdir(parents=True)
        (previous / 'jail.json').write_text('{"attempt_id":"previous-true"}')
        # The old heuristic selected this unrelated successful invocation.
        os.utime(previous, ns=(2_000_000_000_000_000_000,) * 2)

    def test_installed_bytes_must_match_the_packaged_candidate(self):
        self.binary.write_bytes(b'candidate')
        digest = onboarding_guest.installed_digest(self.binary, None)
        self.assertEqual(onboarding_guest.installed_digest(self.binary, digest), digest)
        self.binary.write_bytes(b'different candidate')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            onboarding_guest.installed_digest(self.binary, digest)

    def command(self, behavior):
        script = '''import json, os, pathlib, sys, time
data = pathlib.Path(os.environ['UKAI_DATA_DIR'])
counter = data / 'counter'
n = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(n))
mode = sys.argv[2]
if mode == 'early':
    print('ukai-jail: error invalid_config', file=sys.stderr)
    raise SystemExit(2)
attempt = data / 'attempts' / ('current-' + str(n))
attempt.mkdir()
code = 0 if mode == 'retry-success' and n == 2 else 1
receipt = {'attempt_id': attempt.name, 'phase': 'settled', 'containment': 'enforced',
           'exec_observed': True, 'lifetime': {'tree_empty': True, 'integrity': 'verified'},
           'outcome': {'kind': 'exited', 'code': code}, 'state_cleanup': 'complete'}
(attempt / 'jail.json').write_text(json.dumps(receipt))
(attempt / 'trace.ndjson').write_text('trace-' + str(n))
(attempt / 'policy.json').write_text('policy-' + str(n))
log = data / 'state' / 'opencode' / 'key' / 'vendor' / 'data' / 'opencode' / 'log' / 'server.log'
log.parent.mkdir(parents=True, exist_ok=True)
log.write_text('diagnostic-' + str(n))
print('partial stdout-' + str(n), flush=True)
print('Bad Request: fixture' if mode.startswith('retry') else 'UnknownError: err_fixture', file=sys.stderr, flush=True)
if mode == 'timeout': time.sleep(10)
raise SystemExit(code)
'''
        self.binary.write_text(f'#!{sys.executable}\n' + script)
        self.binary.chmod(0o755)
        return [self.binary, 'run', behavior]

    def test_unknown_failure_retains_its_receipt_trace_policy_and_logs(self):
        with self.assertRaisesRegex(RuntimeError, 'exit 1'):
            self.workflow.vendor('opencode', self.command('unknown'), [])
        receipt = json.loads((self.out / 'opencode-jail.json').read_text())
        self.assertEqual(receipt['attempt_id'], 'current-1')
        self.assertEqual((self.out / 'opencode-trace.ndjson').read_text(), 'trace-1')
        self.assertEqual((self.out / 'opencode-policy.json').read_text(), 'policy-1')
        self.assertEqual(self.result['rows'][0]['attempt_ids'], ['current-1'])
        logs = list((self.out / 'opencode-vendor-logs').rglob('server.log'))
        self.assertEqual([path.read_text() for path in logs], ['diagnostic-1'])
        self.assertNotIn('provider_retries', self.result)

    def test_pre_attempt_refusal_never_borrows_the_previous_true_receipt(self):
        with self.assertRaisesRegex(RuntimeError, 'exit 2'):
            self.workflow.vendor('opencode', self.command('early'), [])
        self.assertEqual(self.result['rows'][0]['attempt_ids'], [])
        self.assertFalse((self.out / 'opencode-jail.json').exists())
        self.assertIn('invalid_config', (self.out / 'opencode.stderr').read_text())

    def test_bad_request_retry_retains_separate_attempts_before_success(self):
        self.workflow.vendor('opencode', self.command('retry-success'), [])
        first = json.loads((self.out / 'opencode-provider-failure-jail.json').read_text())
        second = self.workflow.receipt('opencode')
        self.assertEqual((first['attempt_id'], second['attempt_id']), ('current-1', 'current-2'))
        self.assertEqual(self.result['provider_retries'], ['opencode-provider-failure'])
        self.assertEqual([row['attempt_ids'] for row in self.result['rows']], [['current-1'], ['current-2']])
        for label, diagnostic in [('opencode-provider-failure', 'diagnostic-1'), ('opencode', 'diagnostic-2')]:
            logs = list((self.out / f'{label}-vendor-logs').rglob('server.log'))
            self.assertEqual([path.read_text() for path in logs], [diagnostic])

    def test_second_bad_request_is_preserved_but_never_retried_again(self):
        with self.assertRaisesRegex(RuntimeError, 'exit 1'):
            self.workflow.vendor('opencode', self.command('retry-failure'), [])
        self.assertEqual(len(self.result['rows']), 2)
        self.assertEqual(json.loads((self.out / 'opencode-jail.json').read_text())['attempt_id'], 'current-2')
        self.assertTrue((self.out / 'opencode-provider-failure-trace.ndjson').is_file())

    def test_one_attempt_preserves_bad_request_without_second_vendor_launch(self):
        self.workflow.vendor_attempts = 1
        with self.assertRaisesRegex(RuntimeError, 'exit 1'):
            self.workflow.vendor('opencode', self.command('retry-success'), [])
        self.assertEqual(len(self.result['rows']), 1)
        self.assertEqual(self.result['rows'][0]['vendor_attempt_limit'], 1)
        self.assertEqual(self.result['rows'][0]['vendor_attempt'], 1)
        self.assertEqual(self.result['rows'][0]['attempt_ids'], ['current-1'])
        self.assertNotIn('provider_retries', self.result)
        self.assertFalse((self.out / 'opencode-provider-failure-jail.json').exists())
        self.assertEqual((self.data / 'counter').read_text(), '1')

    def test_invalid_attempt_limits_are_refused(self):
        for value in (0, 3, True, 1.0, '1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                onboarding_guest.Workflow(self.binary, self.out, self.env, self.result,
                                         lambda: None, vendor_attempts=value)

    def test_timeout_keeps_partial_streams_and_the_new_attempt(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            self.workflow.run('opencode', self.command('timeout'), timeout=0.3)
        self.assertEqual(json.loads((self.out / 'opencode-jail.json').read_text())['attempt_id'], 'current-1')
        self.assertIn('partial stdout-1', (self.out / 'opencode.stdout').read_text())
        self.assertIn('UnknownError', (self.out / 'opencode.stderr').read_text())
        self.assertIn('execution_error', self.result['rows'][0])


class CredentialStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'provider.key'
        self.path.write_bytes(b'synthetic-key')
        self.path.chmod(0o600)

    def test_success_and_timeout_remove_only_the_owned_copy(self):
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out):
                self.path.write_bytes(b'synthetic-key')
                self.path.chmod(0o600)
                def invoke(argv, **kwargs):
                    self.assertEqual(kwargs['stdin'].read(), b'synthetic-key')
                    self.assertEqual(kwargs['timeout'], 60)
                    if timed_out:
                        raise subprocess.TimeoutExpired(argv, 60, output=b'partial')
                    return subprocess.CompletedProcess(argv, 0, b'', b'')
                with mock.patch.object(onboarding_guest.subprocess, 'run', side_effect=invoke):
                    if timed_out:
                        with self.assertRaises(subprocess.TimeoutExpired):
                            onboarding_guest.store_credential('jail', self.path, {})
                    else:
                        self.assertEqual(onboarding_guest.store_credential('jail', self.path, {}).returncode, 0)
                self.assertFalse(self.path.exists())

    def test_substituted_path_is_retained_and_primary_timeout_remains_chained(self):
        original = self.path.with_name('original')
        def invoke(argv, **kwargs):
            self.path.rename(original)
            self.path.write_bytes(b'unrelated replacement')
            self.path.chmod(0o600)
            raise subprocess.TimeoutExpired(argv, 60)
        with mock.patch.object(onboarding_guest.subprocess, 'run', side_effect=invoke):
            with self.assertRaisesRegex(RuntimeError, 'substituted path retained') as caught:
                onboarding_guest.store_credential('jail', self.path, {})
        self.assertIsInstance(caught.exception.__context__, subprocess.TimeoutExpired)
        self.assertEqual(self.path.read_bytes(), b'unrelated replacement')
        self.assertEqual(original.read_bytes(), b'synthetic-key')

    def test_symlink_is_never_opened_or_unlinked(self):
        original = self.path.with_name('original')
        self.path.rename(original)
        self.path.symlink_to(original)
        with mock.patch.object(onboarding_guest.subprocess, 'run') as run:
            with self.assertRaises(OSError):
                onboarding_guest.store_credential('jail', self.path, {})
        run.assert_not_called()
        self.assertTrue(self.path.is_symlink())
        self.assertEqual(original.read_bytes(), b'synthetic-key')


if __name__ == '__main__':
    unittest.main()
