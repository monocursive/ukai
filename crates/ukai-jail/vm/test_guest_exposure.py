"""Synthetic proc fixtures; live canary control only on Linux, no provider token."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import types
import unittest
from unittest import mock
import guest_exposure as exposure

CANARY = b'public-sampler-canary-not-a-secret-0123456789'
BOOT = '01234567-89ab-4cde-8012-3456789abcde'


def stat_bytes(pid, parent, start):
    fields = [b'S', str(parent).encode()] + [b'0'] * 17 + [str(start).encode()]
    return str(pid).encode() + b' (misleading ) name) ' + b' '.join(fields) + b'\n'


def receipt(pid=10, start=100):
    return json.dumps({'attempt_id': 'att_example', 'process': {'identity': {
        'kind': 'linux_boot_start', 'value': {'boot_id': BOOT, 'pid': pid, 'start_time_ticks': start}}}}).encode()


def binding():
    return dict(host_attempt_id='att_host', service_boot_id='vm_service', guest_attempt_id='att_example',
                guest_boot_id=BOOT, catalog_sha256='c'*64, executable_sha256='e'*64,
                sampler_sha256=exposure.source_sha256())


class SamplerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.proc = self.root / 'proc'; self.proc.mkdir()
        (self.proc/'sys/kernel/random').mkdir(parents=True)
        (self.proc/'sys/kernel/random/boot_id').write_text(BOOT+'\n')
        self.exe = self.root / 'program'; self.exe.write_bytes(b'public executable')
        self.other = self.root / 'other'; self.other.write_bytes(b'other executable')
        self.process(10, 1, 100, 1000, self.other)
        self.process(11, 10, 101, 1000, self.exe)
        self.samplers = []
        self.addCleanup(lambda: [s.close() for s in self.samplers])

    def process(self, pid, parent, start, uid, exe, env=b'LANG=C\0', argv=b'program\0'):
        path = self.proc / str(pid); path.mkdir(exist_ok=True)
        (path/'stat').write_bytes(stat_bytes(pid, parent, start))
        (path/'status').write_bytes(f'Name:\tignored\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n'.encode())
        (path/'environ').write_bytes(env); (path/'cmdline').write_bytes(argv)
        if (path/'exe').is_symlink(): (path/'exe').unlink()
        (path/'exe').symlink_to(exe)
        return path

    def sampler(self, **kwargs):
        args = dict(proc_root=self.proc, boot_id=BOOT, supervisor_pid=10, supervisor_starttime=100,
                    workload_uid=1000, infrastructure_identities=[],
                    catalog_executable_identity=(self.exe.stat().st_dev, self.exe.stat().st_ino),
                    protected_values=[CANARY])
        args.update(kwargs)
        sampler = exposure.Sampler(**args); self.samplers.append(sampler)
        return sampler

    def finish(self, sampler):
        return sampler.finish(receipt(), binding())

    def test_zero_tick_kernel_threads_are_valid_unselected_inventory(self):
        path=self.process(2,0,0,0,self.other)
        # Kernel threads expose no user environment/executable; they are not
        # the nonroot workload or descendants of our pinned supervisor.
        for name in ('exe','environ','cmdline'): (path/name).unlink()
        self.assertEqual(exposure._stat((path/'stat').read_bytes(),2),(0,0))
        sampler=self.sampler();sampler.sample(1);report=self.finish(sampler)
        self.assertEqual(report['scan_errors'],{})
        self.assertFalse(report['observation_incomplete'])
        self.assertNotIn(2,[row['pid'] for row in report['processes']])
        with self.assertRaises(ValueError): self.sampler(supervisor_pid=2,supervisor_starttime=0)
        sampler=self.sampler();sampler.sample(1)
        with self.assertRaises(ValueError): sampler.finish(receipt(start=0),binding())

    def test_clean_positive_vendor_identity_and_detached_json(self):
        sampler = self.sampler(); sampler.sample(100_000_000)
        report = self.finish(sampler)
        self.assertTrue(report['verified_program_observed'])
        self.assertFalse(report['observation_incomplete'])
        self.assertEqual(report['verified_program_reads']['environment']['readable'], 1)
        self.assertEqual(report['processes'][1]['roles'], ['catalog_program', 'descendant', 'workload_uid'])
        self.assertEqual(report['hits'], [])
        self.assertFalse(report['continuous_coverage_claimed'])
        self.assertNotIn(str(self.root), json.dumps(report))
        with self.assertRaises(ValueError): sampler.sample(200_000_000)
        with self.assertRaises(ValueError): sampler.finish(receipt(), binding())

    def test_same_scanner_positive_control_both_channels_no_values_exported(self):
        self.process(11, 10, 101, 1000, self.exe, b'TOKEN='+CANARY+b'\0', b'program\0'+CANARY+b'\0')
        sampler=self.sampler(); sampler.sample(1)
        report=self.finish(sampler)
        self.assertEqual({h['channel'] for h in report['hits']}, {'environment', 'argv'})
        self.assertNotIn(CANARY, json.dumps(report).encode())
        self.assertTrue(all(h['identity_stable'] for h in report['hits']))
        self.assertTrue(report['verified_program_observed'])

    def test_encoded_canary_detected_without_retaining_encoding(self):
        self.process(11, 10, 101, 1000, self.exe, base64.b64encode(CANARY), CANARY.hex().encode())
        sampler=self.sampler(); sampler.sample(1)
        report=self.finish(sampler)
        self.assertIn('base64', {h['representation'] for h in report['hits']})
        self.assertIn('hex', {h['representation'] for h in report['hits']})
        self.assertNotIn(base64.b64encode(CANARY), json.dumps(report).encode())

    def test_uid_sweep_survives_reparenting_and_cgroup_migration(self):
        self.process(11, 1, 101, 1000, self.exe)
        (self.proc/'11/cgroup').write_bytes(b'0::/moved/elsewhere\n')
        sampler=self.sampler(); sampler.sample(1)
        report=self.finish(sampler)
        self.assertTrue(report['verified_program_observed'])
        self.assertEqual(report['processes'][1]['roles'], ['catalog_program', 'workload_uid'])

    def test_descendant_uid_change_still_sampled(self):
        self.process(11, 10, 101, 2000, self.exe)
        sampler=self.sampler(); sampler.sample(1)
        self.assertTrue(self.finish(sampler)['verified_program_observed'])

    def test_only_exact_infrastructure_birth_is_excluded(self):
        sampler=self.sampler(infrastructure_identities=[(11,101)]); sampler.sample(1)
        self.assertFalse(self.finish(sampler)['verified_program_observed'])
        sampler=self.sampler(infrastructure_identities=[(11,100)]); sampler.sample(1)
        self.assertTrue(self.finish(sampler)['verified_program_observed'])

    def test_comm_and_path_spelling_do_not_substitute_for_executable_identity(self):
        self.process(11, 10, 101, 1000, self.other)
        (self.proc/'11/cmdline').write_bytes(str(self.exe).encode()+b'\0')
        sampler=self.sampler(); sampler.sample(1)
        report=self.finish(sampler)
        self.assertFalse(report['verified_program_observed'])
        self.assertTrue(report['observation_incomplete'])

    def test_later_unreadable_vendor_sample_is_not_hidden(self):
        sampler=self.sampler(); sampler.sample(1)
        real_read=sampler._read
        def unreadable(fd,name,limit):
            if name=='environ': raise PermissionError('must not appear in output')
            return real_read(fd,name,limit)
        with mock.patch.object(sampler, '_read', side_effect=unreadable): sampler.sample(100_000_001)
        report=self.finish(sampler)
        self.assertTrue(report['verified_program_observed'])
        self.assertGreater(report['verified_program_reads']['environment']['unreadable'],0)
        self.assertTrue(report['observation_incomplete'])
        self.assertNotIn('must not', json.dumps(report))

    def test_pid_birth_change_during_read_discards_positive_credit_but_keeps_hit(self):
        sampler=self.sampler(); real_read=sampler._read
        def reuse(fd,name,limit):
            value=real_read(fd,name,limit)
            if name=='environ' and value==b'TOKEN='+CANARY:
                (self.proc/'11/stat').write_bytes(stat_bytes(11,10,999))
            return value
        (self.proc/'11/environ').write_bytes(b'TOKEN='+CANARY)
        with mock.patch.object(sampler,'_read',side_effect=reuse): sampler.sample(1)
        report=self.finish(sampler)
        self.assertFalse(report['verified_program_observed'])
        self.assertGreater(report['scan_errors']['identity_changed'],0)
        self.assertTrue(report['hits'])
        self.assertFalse(report['hits'][0]['identity_stable'])

    def test_pid_directory_replacement_rejected_even_with_same_stat(self):
        sampler=self.sampler(); real_read=sampler._read; changed=False
        def replace(fd,name,limit):
            nonlocal changed
            value=real_read(fd,name,limit)
            if name=='environ' and value==b'replace' and not changed:
                changed=True
                (self.proc/'11').rename(self.root/'old-pid')
                self.process(11,10,101,1000,self.exe)
            return value
        (self.proc/'11/environ').write_bytes(b'replace')
        with mock.patch.object(sampler,'_read',side_effect=replace): sampler.sample(1)
        report=self.finish(sampler)
        self.assertFalse(report['verified_program_observed'])
        self.assertGreater(report['scan_errors']['identity_changed'],0)

    def test_executable_switch_during_read_has_no_program_credit(self):
        sampler=self.sampler(); real_read=sampler._read
        def change(fd,name,limit):
            value=real_read(fd,name,limit)
            if name=='environ' and value==b'switch':
                (self.proc/'11/exe').unlink(); (self.proc/'11/exe').symlink_to(self.other)
            return value
        (self.proc/'11/environ').write_bytes(b'switch')
        with mock.patch.object(sampler,'_read',side_effect=change): sampler.sample(1)
        self.assertFalse(self.finish(sampler)['verified_program_observed'])

    def test_root_and_pid_links_refuse(self):
        link=self.root/'proc-link'; link.symlink_to(self.proc)
        with self.assertRaises(OSError): self.sampler(proc_root=link)
        shutil.rmtree(self.proc/'11'); (self.proc/'11').symlink_to(self.root)
        sampler=self.sampler(); sampler.sample(1)
        report=self.finish(sampler)
        self.assertTrue(report['observation_incomplete'])
        self.assertGreater(report['scan_errors']['inventory_unreadable'],0)

    def test_proc_root_replacement_refuses(self):
        sampler=self.sampler(); self.proc.rename(self.root/'old-proc'); self.proc.mkdir()
        sampler.sample(1); report=self.finish(sampler)
        self.assertEqual(report['scan_errors']['proc_root_changed'],1)
        self.assertFalse(report['verified_program_observed'])

    def test_field_symlink_fifo_and_vanished_are_explicit(self):
        for kind in ('symlink','fifo','missing'):
            with self.subTest(kind=kind):
                path=self.proc/'11/environ'
                if path.exists() or path.is_symlink(): path.unlink()
                if kind=='symlink': path.symlink_to(self.exe)
                elif kind=='fifo': os.mkfifo(path)
                sampler=self.sampler(); sampler.sample(1); report=self.finish(sampler)
                self.assertTrue(report['observation_incomplete'])
                self.assertEqual(report['verified_program_reads']['environment']['readable'],0)

    def test_oversize_process_bytes_and_time_caps_remain_visible(self):
        sampler=self.sampler(); (self.proc/'11/environ').write_bytes(b'x'*65)
        with mock.patch.object(exposure,'MAX_READ_BYTES',64): sampler.sample(1)
        report=self.finish(sampler)
        self.assertEqual(report['verified_program_reads']['environment']['oversize'],1)
        for constant,value,error in [('MAX_PROCESS_COUNT',1,'process_cap'),
                                     ('MAX_TICK_BYTES',1,'tick_byte_cap'),
                                     ('MAX_TICK_NS',1,'tick_time_cap')]:
            sampler=self.sampler()
            with mock.patch.object(exposure,constant,value): sampler.sample(1)
            report=self.finish(sampler)
            self.assertGreater(report['scan_errors'][error],0)
            self.assertTrue(report['observation_incomplete'])

    def test_late_poll_counters_are_measurements_not_hidden_thresholds(self):
        sampler=self.sampler(); sampler.sample(100); sampler.sample(250_000_100)
        report=self.finish(sampler)
        self.assertEqual(report['maximum_gap_ns'],250_000_000)
        self.assertEqual(report['late_poll_count'],1)
        self.assertEqual(report['missed_tick_count'],1)
        self.assertFalse(report['observation_incomplete'])

    def test_receipt_binding_and_supervisor_mismatch_cannot_finish(self):
        for key,value in [('guest_boot_id','wrong'),('sampler_sha256','0'*64),('guest_attempt_id','att_other')]:
            sampler=self.sampler(); sampler.sample(1); bound=binding(); bound[key]=value
            with self.assertRaises(ValueError): sampler.finish(receipt(),bound)
        sampler=self.sampler(); sampler.sample(1)
        with self.assertRaises(ValueError): sampler.finish(receipt(start=999),binding())
        with self.assertRaises(ValueError): sampler.finish(b'{"attempt_id":1,"attempt_id":2}',binding())

    def test_no_samples_remains_incomplete_and_exact_record_scan_withholds(self):
        sampler=self.sampler(); report=self.finish(sampler)
        self.assertTrue(report['observation_incomplete']); self.assertEqual(report['tick_count'],0)
        sampler=self.sampler(); sampler.sample(1); bound=binding(); bound['host_attempt_id']=CANARY.decode()
        with self.assertRaisesRegex(ValueError,'withheld'): sampler.finish(receipt(),bound)
        self.assertFalse(sampler.finished)

    def test_boot_identity_change_is_explicit(self):
        sampler=self.sampler(); (self.proc/'sys/kernel/random/boot_id').write_text('other-boot')
        sampler.sample(1); report=self.finish(sampler)
        self.assertEqual(report['scan_errors']['boot_identity_changed'],1)
        self.assertTrue(report['observation_incomplete'])

    def test_receipt_containing_protected_value_is_withheld(self):
        sampler=self.sampler(); sampler.sample(1)
        raw=json.loads(receipt()); raw['accidental']=CANARY.decode()
        with self.assertRaisesRegex(ValueError,'withheld'):
            sampler.finish(json.dumps(raw).encode(),binding())

    def monitor(self, **changes):
        process = types.SimpleNamespace(pid=10, returncode=None)
        process.poll = lambda: process.returncode
        args=dict(proc_root=self.proc,boot_id=BOOT,process=process,workload_uid=1000,
                  infrastructure_identities=[],catalog_executable_path=self.exe,protected_values=[CANARY])
        args.update(changes)
        monitor=exposure.Monitor(**args)
        self.addCleanup(monitor.discard)
        return monitor,process

    def test_monitor_independent_ticks_and_known_exit_stop_order(self):
        monitor,process=self.monitor()
        deadline=time.monotonic()+1
        while monitor.sampler.ticks<2 and time.monotonic()<deadline: time.sleep(.005)
        self.assertGreaterEqual(monitor.sampler.ticks,2)
        process.returncode=0
        report=monitor.finish(receipt(),binding())
        self.assertTrue(report['verified_program_observed'])
        self.assertFalse(report['observation_incomplete'])
        self.assertEqual(report['lifecycle']['stop_reason'],'supervisor_exit')
        self.assertLessEqual(report['lifecycle']['supervisor_exit_observed_ns'],report['lifecycle']['stopped_ns'])
        self.assertEqual(monitor.patterns,[])

    def test_monitor_initialization_failure_emits_incomplete_bound_report(self):
        monitor,process=self.monitor(catalog_executable_path=self.root/'absent')
        process.returncode=0
        report=monitor.finish(receipt(),binding())
        self.assertTrue(report['observation_incomplete'])
        self.assertEqual(report['scan_errors'],{'monitor_initialization_failed':1})
        self.assertEqual(report['tick_count'],0)
        self.assertEqual(report['catalog_executable_identity'],{'dev':0,'ino':0})

    def test_monitor_worker_failure_cannot_be_erased_by_finish(self):
        with mock.patch.object(exposure.Sampler,'sample',side_effect=ValueError('private-error-never-export')):
            monitor,process=self.monitor()
            monitor.thread.join(1)
        process.returncode=0
        report=monitor.finish(receipt(),binding())
        self.assertTrue(report['observation_incomplete'])
        self.assertEqual(report['scan_errors'],{'monitor_worker_failed':1})
        self.assertNotIn('private-error',json.dumps(report))

    def test_monitor_join_timeout_does_not_read_live_counters(self):
        entered=threading.Event(); release=threading.Event()
        def blocked(sampler, now):
            entered.set(); release.wait(2)
        with mock.patch.object(exposure.Sampler,'sample',blocked):
            monitor,process=self.monitor()
            self.assertTrue(entered.wait(1)); monitor.JOIN_SECONDS=.01
            try:
                before=time.monotonic(); report=monitor.finish(receipt(),binding())
                self.assertLess(time.monotonic()-before,.2)
                self.assertEqual(report['scan_errors'],{'monitor_join_timeout':1})
                self.assertEqual(report['tick_count'],0)
                self.assertTrue(report['observation_incomplete'])
            finally:
                release.set(); monitor.thread.join(1)
        self.assertEqual(monitor.sampler.patterns,[])

    def test_invalid_constructor_inputs_and_time_order(self):
        for changes in ({'protected_values':[]},{'protected_values':[b'']},{'period_ns':True},
                        {'infrastructure_identities':[(10,100)]},{'supervisor_starttime':0}):
            with self.assertRaises(ValueError): self.sampler(**changes)
        sampler=self.sampler(); sampler.sample(1)
        with self.assertRaises(ValueError): sampler.sample(1)


@unittest.skipUnless(sys.platform.startswith('linux'), 'actual proc control requires Linux')
class RealProcControlTests(unittest.TestCase):
    def test_public_canary_detected_in_real_child_env_and_argv(self):
        # The unmatched UID prevents sweeping unrelated operator processes. Only
        # this owned child (the pinned supervisor) and its descendants are read.
        process=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)',CANARY.decode()],
                                 env={'LANG':'C','UKAI_PUBLIC_CANARY':CANARY.decode()},
                                 stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            root=Path('/proc'); boot=(root/'sys/kernel/random/boot_id').read_text().strip()
            _,start=exposure._stat((root/str(process.pid)/'stat').read_bytes(),process.pid)
            info=(root/str(process.pid)/'exe').stat()
            sampler=exposure.Sampler(root,boot,process.pid,start,2**32-2,[],(info.st_dev,info.st_ino),[CANARY])
            try:
                sampler.sample(time.monotonic_ns())
                bound=binding(); bound['guest_boot_id']=boot
                raw=json.loads(receipt(process.pid,start)); raw['process']['identity']['value']['boot_id']=boot
                report=sampler.finish(json.dumps(raw).encode(),bound)
            finally: sampler.close()
            self.assertTrue(report['verified_program_observed'])
            self.assertEqual({h['channel'] for h in report['hits']},{'environment','argv'})
            self.assertNotIn(CANARY,json.dumps(report).encode())
        finally:
            process.terminate(); process.wait(timeout=5)


if __name__=='__main__': unittest.main()
