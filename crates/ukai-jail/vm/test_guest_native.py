"""Native wire/staging controller regressions, driven through real main().

The kernel/jail is the existing explicit model; these are contract tests,
not evidence of a booted native program or a provider workflow.
"""
import base64
import copy
import json
import hashlib
import os
from pathlib import Path
import stat
import types
import unittest
from unittest import mock

import guest_program as gp
from guest_harness import GuestHarness, hold
from test_guest_program import intent_for, verified_catalog


def b64(data):
    return base64.b64encode(data).decode()


class NativeControllerTests(unittest.TestCase):
    def create(self, scenarios=(), catalog=True):
        h = GuestHarness(self, start=False, scenarios=scenarios)
        h.guest.NATIVE_CONFIG = h.root / 'run/ukai-vm/native-config'
        parent = h.guest.PROC_ROOT / 'self'; parent.mkdir(exist_ok=True)
        (parent/'mountinfo').write_text(f'1 0 0:1 / {h.root}/run rw - tmpfs tmpfs rw\n')
        h.guest.guest_program = types.SimpleNamespace(**gp.__dict__)
        h.verified = verified_catalog() if catalog else None
        h.guest.guest_program.verify_catalog = mock.Mock(return_value=h.verified)
        h.intent, h.argv = intent_for(verified_catalog())
        h.thread.start()
        return h

    def prepare(self, h):
        h.session()
        h.send(op='native_prepare', native_program=h.intent, argv=h.argv)
        self.assertEqual(h.expect('native_prepared')['native_program'], h.intent)

    def secret(self, h):
        h.send(op='secret', id='token', data=b64(b'synthetic-test-value'))
        reply = h.expect('secret')
        self.assertEqual(Path(reply['path']), h.guest.NATIVE_CONFIG/'credentials/token')

    def launch(self, h, **extra):
        h.run2(profile='agent', argv=gp.decode_argv(h.argv), native_program=h.intent, **extra)

    def test_session_native_contract_from_actual_catalog(self):
        h = self.create(); _, session = h.session()
        self.assertEqual(session['guest_contracts']['native_program'], gp.CONTRACT)
        self.assertEqual(session['guest_contracts']['sampled_exposure'], 'ukai.vm.sampled-exposure/1')
        self.assertEqual(session['guest_program_catalog_sha256'], h.verified['sha256'])

    def test_missing_catalog_keeps_legacy_but_refuses_native_prepare(self):
        h = self.create(catalog=False); _, session = h.session()
        self.assertNotIn('native_program', session['guest_contracts'])
        self.assertNotIn('guest_program_catalog_sha256', session)
        h.send(op='native_prepare', native_program=h.intent, argv=h.argv)
        self.assertEqual(h.ended(), 'native_prepare_refused')
        self.assertFalse(h.guest.NATIVE_CONFIG.exists())

    def test_bad_catalog_session_fails_before_any_secret(self):
        h = self.create(); h.guest.guest_program.verify_catalog.side_effect = ValueError('bad')
        h.expect('ready'); h.send(op='session')
        self.assertEqual(h.ended(), 'native_catalog_invalid')
        self.assertFalse(h.secrets.exists())

    def test_native_config_is_private_tmpfs_with_only_selected_source(self):
        h = self.create(scenarios=[hold()]); self.prepare(h); self.secret(h)
        config = h.guest.NATIVE_CONFIG
        self.assertEqual(sorted(p.name for p in config.iterdir()), ['credentials'])
        for p in [config, config/'credentials']:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o710)
            self.assertEqual((p.stat().st_uid, p.stat().st_gid), (os.geteuid(), h.gid))
        source = config/'credentials/token'
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
        self.assertEqual(source.stat().st_nlink, 1)
        self.assertEqual(source.read_bytes(), b'synthetic-test-value')
        self.launch(h); h.expect('running')
        jail = h.subprocess.jails[0]
        self.assertIn(b'--from-path', jail.argv)
        self.assertEqual(jail.option(b'--state'), b'attempt')
        self.assertEqual(jail.option(b'--launch'), b'example')
        self.assertEqual(jail.workload_argv(), [b'-p', b'test'])
        self.assertEqual(jail.kwargs['env']['UKAI_CONFIG_DIR'], str(config))
        self.assertTrue(jail.kwargs['env']['PATH'].startswith(h.verified['catalog']['entries'][0]['install_root']+':'))
        h.send(op='revoke_secrets', ids=['token']); h.expect('secrets_revoked')
        self.assertFalse(source.exists())
        h.send(op='cancel2'); h.expect('cancelled')
        self.assertFalse(config.exists())

    def test_non_tmpfs_config_refuses_before_secret(self):
        h = self.create(); p = h.guest.PROC_ROOT/'self/mountinfo'; p.write_text(p.read_text().replace('tmpfs', 'ext4'))
        h.session(); h.send(op='native_prepare', native_program=h.intent, argv=h.argv)
        self.assertEqual(h.ended(), 'native_prepare_refused')
        self.assertFalse(h.guest.NATIVE_CONFIG.exists())

    def test_wrong_secret_id_never_stages(self):
        h = self.create(); self.prepare(h)
        h.send(op='secret', id='other', data=b64(b'not-staged'))
        self.assertTrue(h.expect('error')['message'].startswith('secret_refused:'))
        self.assertFalse((h.guest.NATIVE_CONFIG/'credentials').exists())

    def test_legacy_secret_or_launch_toml_cannot_switch_into_native(self):
        for op in ('secret', 'launch_toml'):
            with self.subTest(op=op):
                h = self.create(); h.session()
                h.send(**({'op': op, 'id': 'token', 'data': b64(b'value')} if op == 'secret'
                          else {'op': op, 'toml': 'name="override"'}))
                h.expect(op)
                h.send(op='native_prepare', native_program=h.intent, argv=h.argv)
                self.assertEqual(h.ended(), 'native_prepare_refused')

    def test_native_cannot_install_launch_override_or_repeat_prepare(self):
        for request in ('launch_toml', 'native_prepare'):
            with self.subTest(request=request):
                h = self.create(); self.prepare(h)
                h.send(**({'op': 'launch_toml', 'toml': 'name="override"'} if request == 'launch_toml'
                          else {'op': 'native_prepare', 'native_program': h.intent, 'argv': h.argv}))
                self.assertEqual(h.ended(), 'native_launch_override' if request == 'launch_toml' else 'native_prepare_refused')

    def test_changed_catalog_between_ready_and_prepare_refuses(self):
        h = self.create(); h.session()
        h.guest.guest_program.verify_catalog.return_value = {**h.verified, 'sha256': '0'*64}
        h.send(op='native_prepare', native_program=h.intent, argv=h.argv)
        self.assertEqual(h.ended(), 'native_prepare_refused')

    def test_changed_catalog_between_prepare_and_run_refuses(self):
        h = self.create(); self.prepare(h); self.secret(h)
        h.guest.guest_program.verify_catalog.return_value = {**h.verified, 'sha256': '0'*64}
        self.launch(h)
        self.assertEqual(h.ended(), 'native_release_refused')
        self.assertEqual(h.subprocess.jails, [])

    def test_changed_intent_missing_source_and_unknown_run_field_refuse(self):
        for failure in ('intent', 'missing', 'unknown'):
            with self.subTest(failure=failure):
                h = self.create(); self.prepare(h)
                if failure != 'missing': self.secret(h)
                if failure == 'intent': h.intent = {**h.intent, 'selected_credential_id': 'other'}
                self.launch(h, **({'unexpected': True} if failure == 'unknown' else {}))
                self.assertEqual(h.ended(), 'native_release_refused')
                self.assertEqual(h.subprocess.jails, [])

    def test_bundled_profile_override_plant_refuses(self):
        h = self.create(); self.prepare(h); self.secret(h)
        (h.guest.NATIVE_CONFIG/'launch').mkdir()
        self.launch(h)
        self.assertEqual(h.ended(), 'native_release_refused')

    def test_duplicate_wire_key_refuses(self):
        h = self.create(); h.session()
        h.host.sendall(b'{"op":"native_prepare","op":"reset"}\n')
        self.assertEqual(h.ended(), 'invalid_json')

    def test_successful_native_receipt_binds_requested_and_resolved_argv(self):
        h = self.create()
        def complete(jail):
            jail.workload()
            receipt = {'schema': 'ukai.jail.receipt/1', 'attempt_id': 'att_00000000-0000-4000-8000-000000000123',
                       'argv_digest': h.intent['resolved_argv_digest'],
                       'policy': {'name': 'agent', 'digest': h.intent['expected_policy_digest']},
                       'process': {'identity': {'kind': 'linux_boot_start', 'value': {'boot_id': 'guest-boot-0001',
                           'pid': jail.pid, 'start_time_ticks': jail.process.starttime}}}}
            Path(os.fsdecode(jail.option(b'--receipt'))).write_text(json.dumps(receipt)); jail.exit(0)
        h.scenarios.append(complete)
        self.prepare(h); self.secret(h); self.launch(h)
        done = h.expect('done')
        self.assertEqual(done['binding']['native_program']['request_argv_digest'], h.intent['request_argv_digest'])
        self.assertEqual(done['binding']['argv_digest'], h.intent['resolved_argv_digest'])
        self.assertFalse(h.guest.NATIVE_CONFIG.exists())
        samples = [f for f in done['_seen'] if f['event'] == 'file' and f['path'] == 'sampled-exposure.json']
        self.assertEqual(len(samples), 1)
        raw = base64.b64decode(samples[0]['data'])
        self.assertEqual(done['binding']['sampled_exposure_sha256'], hashlib.sha256(raw).hexdigest())
        report = json.loads(raw)
        self.assertTrue(report['observation_incomplete'])  # modeled catalog path is absent
        self.assertEqual(report['scan_errors'], {'monitor_initialization_failed': 1})
        self.assertEqual(done['exit_code'], 0)  # sample failure never rewrites execution
        self.assertEqual(stat.S_IMODE((h.guest.EVIDENCE/'sampled-exposure.json').stat().st_mode), 0o600)
        h.send(op='reset'); h.expect('reset')
        h.send(op='native_prepare', native_program=h.intent, argv=h.argv); h.expect('native_prepared')


    def test_reserved_sampling_collision_is_not_adopted_and_execution_stays_true(self):
        for kind in ('file', 'directory', 'symlink'):
            with self.subTest(kind=kind):
                h = self.create()
                def complete(jail):
                    jail.workload()
                    receipt = {'schema': 'ukai.jail.receipt/1', 'attempt_id': 'att_00000000-0000-4000-8000-000000000123',
                               'argv_digest': h.intent['resolved_argv_digest'],
                               'policy': {'name': 'agent', 'digest': h.intent['expected_policy_digest']},
                               'process': {'identity': {'kind': 'linux_boot_start', 'value': {'boot_id': 'guest-boot-0001',
                                           'pid': jail.pid, 'start_time_ticks': jail.process.starttime}}}}
                    Path(os.fsdecode(jail.option(b'--receipt'))).write_text(json.dumps(receipt))
                    path = h.guest.EVIDENCE/'sampled-exposure.json'
                    if kind == 'file': path.write_text('workload collision must not be adopted')
                    elif kind == 'directory': path.mkdir()
                    else: path.symlink_to(h.guest.EVIDENCE/'jail.json')
                    jail.exit(0)
                h.scenarios.append(complete)
                self.prepare(h); self.secret(h); self.launch(h)
                done=h.expect('done')
                self.assertEqual(done['exit_code'],0)
                self.assertNotIn('sampled_exposure_sha256',done['binding'])
                self.assertFalse(any(f['event']=='file' and f['path']=='sampled-exposure.json' for f in done['_seen']))
                self.assertTrue(os.path.lexists(h.guest.EVIDENCE/'sampled-exposure.json'))


    def test_sampling_oversize_or_exception_never_rewrites_actual_done(self):
        for failure in ('oversize', 'finish_error', 'stop_error', 'discard_error'):
            with self.subTest(failure=failure):
                h=self.create()
                def complete(jail):
                    jail.workload()
                    receipt={'attempt_id':'att_00000000-0000-4000-8000-000000000123',
                             'argv_digest':h.intent['resolved_argv_digest'],
                             'policy':{'name':'agent','digest':h.intent['expected_policy_digest']},
                             'process':{'identity':{'kind':'linux_boot_start','value':{
                                 'boot_id':'guest-boot-0001','pid':jail.pid,'start_time_ticks':jail.process.starttime}}}}
                    Path(os.fsdecode(jail.option(b'--receipt'))).write_text(json.dumps(receipt));jail.exit(0)
                h.scenarios.append(complete)
                monitor=mock.Mock(source_digest='f'*64)
                monitor.finish.return_value={'oversized':'x'*(h.guest.MAX_FILE+1)}
                if failure=='finish_error':monitor.finish.side_effect=ValueError('sampler failure')
                if failure=='stop_error':monitor.stop.side_effect=ValueError('sampler stop failure')
                if failure=='discard_error':monitor.discard.side_effect=ValueError('sampler discard failure')
                with mock.patch.object(h.guest.guest_exposure,'Monitor',return_value=monitor):
                    self.prepare(h);self.secret(h);self.launch(h);done=h.expect('done')
                self.assertEqual(done['exit_code'],0)
                self.assertNotIn('sampled_exposure_sha256',done['binding'])
                self.assertFalse(any(f['event']=='file' and f['path']=='sampled-exposure.json' for f in done['_seen']))
