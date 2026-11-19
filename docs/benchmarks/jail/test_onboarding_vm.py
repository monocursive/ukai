"""Owned synthetic files and mocked VM/SSH failures; no VM or provider calls."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import onboarding_vm as vm


class OnboardingLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.out = self.root / 'out'
        self.out.mkdir()
        self.key = self.root / 'source.key'
        self.key.write_bytes(b'synthetic-private-value')
        self.key.chmod(0o600)
        self.held = vm.read_credential(self.key)
        self.metadata = {'status': 'passed'}

    def save(self):
        (self.out / 'vm.json').write_text(json.dumps(self.metadata))

    def finish(self, **kwargs):
        if kwargs.get('temporary') is not None:
            self.metadata.setdefault('temporary_identity', vm.directory_identity(kwargs['temporary']))
        vm.finalize(self.metadata, self.out, kwargs.get('process'), kwargs.get('temporary'),
                    self.key, self.held, kwargs.get('save', self.save))

    def test_same_held_bytes_are_scanned_when_source_is_deleted_or_replaced(self):
        for replaced in (False, True):
            with self.subTest(replaced=replaced):
                self.metadata = {'status': 'passed'}
                if self.key.exists():
                    self.key.unlink()
                if replaced:
                    self.key.write_bytes(b'different-key')
                    self.key.chmod(0o600)
                (self.out / 'guest.stderr').write_bytes(self.held[0])
                self.finish()
                recorded = json.loads((self.out / 'vm.json').read_text())
                self.assertEqual(recorded['status'], 'blocked')
                self.assertFalse(recorded['credential_source_unchanged'])
                self.assertEqual(recorded['credential_exposure']['files_with_key'], ['guest.stderr'])
                self.assertNotIn(self.held[0], (self.out / 'vm.json').read_bytes())

    def test_vm_teardown_failure_preserves_temporary_but_still_scans_and_saves(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired('owned-qemu', 15)
        temporary = self.root / 'owned-vm'
        temporary.mkdir()
        (temporary / 'disk').write_bytes(b'owned')
        (self.out / 'captured').write_bytes(self.held[0])
        self.metadata.update(status='blocked', primary_failure={'stage': 'workflow', 'type': 'TimeoutExpired'})
        self.finish(process=process, temporary=temporary)
        self.assertTrue(temporary.exists())
        self.assertFalse(self.metadata['vm_destroyed'])
        self.assertEqual(self.metadata['primary_failure']['type'], 'TimeoutExpired')
        self.assertEqual(self.metadata['credential_exposure']['files_with_key'], ['captured'])
        self.assertTrue((self.out / 'vm.json').is_file())
        process.kill.assert_called_once()

    def test_temporary_cleanup_and_scan_failures_do_not_skip_final_record(self):
        temporary = self.root / 'owned-vm'
        temporary.mkdir()
        with mock.patch.object(vm.shutil, 'rmtree', side_effect=OSError('synthetic')), \
                mock.patch.object(vm, 'exposure_scan', side_effect=OSError('synthetic')):
            self.finish(temporary=temporary)
        recorded = json.loads((self.out / 'vm.json').read_text())
        self.assertEqual(recorded['status'], 'blocked')
        self.assertEqual([row['stage'] for row in recorded['cleanup_errors']],
                         ['temporary_cleanup', 'credential_exposure'])
        self.assertFalse(recorded['credential_exposure']['complete'])
        self.assertTrue(temporary.exists())

    def test_final_write_failure_is_explicit_after_all_other_stages(self):
        with mock.patch.object(vm, 'exposure_scan', return_value={'complete': True, 'files_with_key': []}) as scan:
            self.finish(save=mock.Mock(side_effect=OSError('synthetic')))
        scan.assert_called_once()
        self.assertEqual(self.metadata['status'], 'blocked')
        self.assertEqual(self.metadata['finalization_failure']['stage'], 'final_record')

    def test_substituted_temporary_directory_is_not_deleted(self):
        temporary = self.root / 'owned-vm'
        temporary.mkdir()
        self.metadata['temporary_identity'] = vm.directory_identity(temporary)
        temporary.rename(self.root / 'original-vm')
        temporary.mkdir()
        (temporary / 'unrelated').write_text('preserve')
        self.finish(temporary=temporary)
        self.assertEqual((temporary / 'unrelated').read_text(), 'preserve')
        self.assertEqual(self.metadata['status'], 'blocked')
        self.assertFalse(self.metadata['temporary_removed'])

    def test_successful_teardown_then_temporary_cleanup_records_truth(self):
        process = mock.Mock()
        process.poll.side_effect = [None, 0]
        temporary = self.root / 'owned-vm'
        temporary.mkdir()
        self.finish(process=process, temporary=temporary)
        self.assertEqual(self.metadata['status'], 'passed')
        self.assertTrue(self.metadata['vm_destroyed'])
        self.assertTrue(self.metadata['temporary_removed'])
        self.assertFalse(temporary.exists())

    def test_timeout_retrieves_both_diagnostics_without_masking_primary_exception(self):
        execute = mock.Mock(side_effect=[subprocess.TimeoutExpired('scp', 90), subprocess.CalledProcessError(1, 'ssh')])
        original = subprocess.TimeoutExpired('workflow-ssh', 1800)
        with mock.patch.object(vm.subprocess, 'run', side_effect=original):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                vm.run_guest_workflow(execute, ['ssh'], [], 1234, self.out, 'guest', self.metadata)
        self.assertIs(caught.exception, original)
        self.assertEqual(execute.call_count, 2)
        self.assertEqual([row['stage'] for row in self.metadata['retention_errors']],
                         ['guest_evidence', 'bootstrap_evidence'])
        self.assertEqual(execute.call_args_list[0].kwargs['timeout'], 90)
        self.assertEqual(execute.call_args_list[1].kwargs['timeout'], 15)

    def test_held_read_refuses_symlinks_oversize_and_insecure_mode(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.key)
        with self.assertRaises(OSError):
            vm.read_credential(alias)
        self.key.chmod(0o644)
        with self.assertRaises(RuntimeError):
            vm.read_credential(self.key)
        self.key.chmod(0o600)
        self.key.write_bytes(b'x' * 8193)
        with self.assertRaises(RuntimeError):
            vm.read_credential(self.key)

    def test_stream_scan_detects_chunk_boundary_and_redacts_secret_filename(self):
        (self.out / 'boundary').write_bytes(b'x' * (1024 * 1024 - 3) + self.held[0])
        (self.out / self.held[0].decode()).write_bytes(b'public')
        result = vm.exposure_scan(self.out, self.held[0])
        self.assertEqual(result['files_with_key'], ['<redacted filename>', 'boundary'])
        self.assertNotIn(self.held[0], json.dumps(result).encode())
        with mock.patch.object(vm, 'SCAN_MAX_BYTES', 5), self.assertRaises(RuntimeError):
            vm.exposure_scan(self.out, self.held[0])

    def test_scan_refuses_unscanned_symlink(self):
        (self.out / 'link').symlink_to(self.key)
        with self.assertRaises(RuntimeError):
            vm.exposure_scan(self.out, self.held[0])

    def test_attempt_limit_is_forwarded_without_key_value(self):
        args = argparse.Namespace(revision='a' * 40, inputs='b' * 64, model='anthropic/test',
                                  vendor_attempts=1, credential_file=self.key)
        args.target = 'aarch64-unknown-linux-gnu'
        args.only = 'learning'
        argv = vm.guest_arguments(args, 'public')
        self.assertEqual(argv[argv.index('--target') + 1], args.target)
        self.assertEqual(argv[argv.index('--only') + 1], 'learning')
        self.assertEqual(argv[argv.index('--vendor-attempts') + 1], '1')
        self.assertEqual(argv[argv.index('--credential-file') + 1], 'provider.key')
        self.assertNotIn(self.held[0].decode(), ' '.join(argv))

    def test_actual_staging_program_is_exclusive_private_and_silent(self):
        target = self.root / 'remote-home'
        target.mkdir()
        result = subprocess.run([sys.executable, '-I', '-c', vm.RECEIVE_KEY], input=self.held[0],
                                capture_output=True, cwd=target, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))
        path = target / 'provider.key'
        self.assertEqual(path.read_bytes(), self.held[0])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        again = subprocess.run([sys.executable, '-I', '-c', vm.RECEIVE_KEY], input=b'replacement',
                               capture_output=True, cwd=target, timeout=5)
        self.assertNotEqual(again.returncode, 0)
        self.assertEqual(path.read_bytes(), self.held[0])
        path.unlink()
        path.symlink_to(self.key)
        refused = subprocess.run([sys.executable, '-I', '-c', vm.RECEIVE_KEY], input=b'replacement',
                                 capture_output=True, cwd=target, timeout=5)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self.key.read_bytes(), self.held[0])


if __name__ == '__main__':
    unittest.main()
