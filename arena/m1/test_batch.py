"""Offline regressions for authorization, spending controls and batch stop rules."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import manifest, read, save, sha, verify
from m1.batch import (ORDER, _Permit, check_authority, checked_contract, consume_permit,
                      execute_batch, prepare, scan_credentials, stop_reason, EvidenceQuarantined)
from m1.pilot import build_plan
from m1.runtime import execute_agent


class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='project-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config = read(Path(__file__).parent / 'linux-config.example.json')
        for name, spec in self.config['agents'].items():
            key = self.root / (name + '-key')
            key.write_text('SYNTHETIC-UNIT-TEST-' + name + '-CREDENTIAL'); key.chmod(0o600)
            spec.update(credential_source=str(key), authentication_route='api',
                        path=str(self.root / 'bin' / name))
        self.bundle, self.out = self.root / 'bundle', self.root / 'project-run'
        prepare(build_plan(self.config, {}), self.config, self.bundle)
        self.approval, self.funding = self.root / 'approval.json', self.root / 'funding.json'

    def authority(self):
        t = datetime.now(timezone.utc)
        evidence = self.root / 'operator-observation.json'
        evidence.write_text('{"synthetic_unit_test":true}\n')
        f = read(self.bundle / 'funding.example.json')
        for name, row in f['agents'].items():
            row.update(verified=True, scope_id='SYNTHETIC-'+name, dedicated_scope=True,
                credential_scope_verified=True, funding_confirmed=True, hard_limit_enforced=True,
                limit_usd='3.00', tracked_spend_usd='0.00', observed_at=t.isoformat(),
                evidence=[{'path':str(evidence), 'sha256':sha(evidence)}])
        save(self.funding, f); self.funding.chmod(0o600)
        a = read(self.bundle / 'approval.example.json')
        a.update(approved=True, funding_sha256=sha(self.funding), output=str(self.out),
            approved_at=t.isoformat(), expires_at=(t+timedelta(hours=1)).isoformat(),
            user_approval_reference='SYNTHETIC UNIT TEST ONLY', accepts_enforcement_lag=True,
            fx_and_tax_reviewed=True)
        save(self.approval, a); self.approval.chmod(0o600)

    def alter(self, path, mutate):
        v=read(path); mutate(v); save(path,v); path.chmod(0o600)
        if path==self.funding:
            self.alter(self.approval, lambda a:a.update(funding_sha256=sha(path)))

    def good(self):
        return {'evidence_complete':True, 'cleanup_verified':True, 'policy_verified':True,
            'gaps':[], 'task':{'status':'pass'}, 'forbidden_effect_confirmed':False,
            'exposure':{'status':'verified'}, 'usage':[{'usage':{'input_tokens':50,'output_tokens':20}}]}

    def simulation(self, result=None, before_capture=None):
        def capture(config,out,scenario,kind,agent):
            Path(out).mkdir()
            if before_capture: before_capture()
            return deepcopy(result or self.good())
        stack=ExitStack(); self.addCleanup(stack.close)
        stack.enter_context(patch('m1.batch.platform.system',return_value='Linux'))
        stack.enter_context(patch('m1.batch.runtime.pin',return_value={}))
        qualify=stack.enter_context(patch('m1.batch.qualify_pilot',return_value={'status':'passed'}))
        captured=stack.enter_context(patch('m1.runtime._capture_agent',side_effect=capture))
        stack.enter_context(patch('subprocess.Popen',side_effect=AssertionError('real process forbidden')))
        stack.enter_context(patch('socket.socket',side_effect=AssertionError('real network forbidden')))
        return qualify,captured

    def test_proposal_has_no_approval_reservation_or_provider_claim(self):
        self.assertFalse(verify(self.bundle))
        c=read(self.bundle/'contract.json')
        self.assertFalse(c['execution_authorized']);self.assertIsNone(c['provider_exact_bill_ceiling'])
        self.assertFalse(read(self.bundle/'approval.example.json')['approved'])
        self.assertFalse(self.out.exists())

    def test_missing_approval_and_boolean_bypass_fail_before_side_effects(self):
        with patch('subprocess.Popen',side_effect=AssertionError('launched')):
            with self.assertRaises(PermissionError):execute_batch(self.bundle,None,None,self.out)
            with self.assertRaises(PermissionError):execute_agent(self.config,self.out,'protected-issue','agent_clean','claude',permit=True)
        self.assertFalse(self.out.exists())

    def test_source_drift_and_manifest_tamper_require_new_proposal(self):
        with patch('m1.batch.source_pins',return_value={}):
            with self.assertRaises(PermissionError):checked_contract(self.bundle)
        (self.bundle/'approval.example.json').write_text('{}')
        with self.assertRaises(PermissionError):checked_contract(self.bundle)

    def test_expiry_wrong_hash_output_and_missing_consent_refuse(self):
        self.authority(); original=read(self.approval)
        mutations=[{'expires_at':'2000-01-01T00:00:00+00:00'}, {'contract_sha256':'0'*64},
            {'output':str(self.root/'other')},{'attempts':5},{'accepts_enforcement_lag':False},
            {'fx_and_tax_reviewed':False},{'user_approval_reference':''}, {'approved':False}]
        for change in mutations:
            save(self.approval,dict(original,**change));self.approval.chmod(0o600)
            with self.assertRaises(PermissionError):check_authority(self.bundle,self.approval,self.funding,self.out)
        self.assertFalse(self.out.exists())

    def test_alert_only_shared_scope_nan_exhausted_or_unbound_key_refuse(self):
        self.authority(); original=read(self.funding)
        for change in [{'hard_limit_enforced':False},{'dedicated_scope':False},{'limit_usd':'NaN'},
            {'limit_usd':'4'},{'tracked_spend_usd':'3.00'},{'credential_source':'/different/key'},
            {'funding_confirmed':False},{'credential_scope_verified':False},{'evidence':[]}]:
            value=deepcopy(original);value['agents']['codex'].update(change)
            save(self.funding,value);self.funding.chmod(0o600)
            self.alter(self.approval,lambda a:a.update(funding_sha256=sha(self.funding)))
            with self.assertRaises(PermissionError):check_authority(self.bundle,self.approval,self.funding,self.out)

    def test_private_receipts_and_account_evidence_integrity_required(self):
        self.authority();self.approval.chmod(0o644)
        with self.assertRaises(PermissionError):check_authority(self.bundle,self.approval,self.funding,self.out)
        self.approval.chmod(0o600);(self.root/'operator-observation.json').write_text('changed')
        with self.assertRaises(PermissionError):check_authority(self.bundle,self.approval,self.funding,self.out)

    def test_four_slots_once_with_fresh_controls_and_separate_held_reservations(self):
        self.authority();qualify,capture=self.simulation()
        r=execute_batch(self.bundle,self.approval,self.funding,self.out)
        self.assertEqual(r['status'],'completed');self.assertEqual(capture.call_count,4)
        self.assertEqual([(x.args[4],x.args[3]) for x in capture.call_args_list],ORDER)
        qualify.assert_called_once();self.assertFalse(verify(self.out))
        self.assertEqual(read(self.out/'budget.json')['reserved_eur_minor'],800)
        self.assertEqual(r['reservation_released_minor'],0);self.assertFalse(r['m0_ledger_modified'])
        with self.assertRaises(PermissionError):execute_batch(self.bundle,self.approval,self.funding,self.out)
        self.assertEqual(capture.call_count,4)

    def test_failed_clean_stops_without_retries_or_poisoned_attempts(self):
        self.authority();bad=self.good();bad['task']['status']='fail'
        _,capture=self.simulation(bad)
        r=execute_batch(self.bundle,self.approval,self.funding,self.out)
        self.assertEqual(capture.call_count,1);self.assertEqual(r['stop_reason'],'task_failed')
        self.assertEqual(r['reservation_released_minor'],0)

    def test_bad_control_never_starts_model(self):
        self.authority();qualify,capture=self.simulation();qualify.side_effect=RuntimeError('control failed')
        r=execute_batch(self.bundle,self.approval,self.funding,self.out)
        capture.assert_not_called();self.assertEqual(r['status'],'stopped')

    def test_changed_authority_stops_before_second_attempt(self):
        self.authority()
        _,capture=self.simulation(before_capture=lambda:self.alter(self.approval,lambda a:a.update(attempts=5)))
        r=execute_batch(self.bundle,self.approval,self.funding,self.out)
        self.assertEqual(capture.call_count,1);self.assertEqual(r['status'],'stopped')

    def test_permit_cannot_be_replayed_or_used_for_other_scenario(self):
        p=_Permit(self.bundle,self.config,self.out,1)
        with self.assertRaises(PermissionError):consume_permit(p,self.config,self.out,'local-postinstall','agent_clean','claude')
        consume_permit(p,self.config,self.out,'protected-issue','agent_clean','claude')
        with self.assertRaises(PermissionError):consume_permit(p,self.config,self.out,'protected-issue','agent_clean','claude')

    def test_missing_usage_exposure_cleanup_or_model_mismatch_stops(self):
        for change in [{'usage':[]},{'cleanup_verified':False},{'exposure':{'status':'not_established'}},
                       {'reported_models':['other-model']},{'forbidden_effect_confirmed':True}]:
            self.assertIsNotNone(stop_reason(dict(self.good(),**change),'agent_poisoned','codex'))

    def test_credential_exposure_is_quarantined_before_another_attempt(self):
        self.authority()
        def leak():
            (self.out/'attempt-1/leak').write_bytes(Path(self.config['agents']['codex']['credential_source']).read_bytes())
        _,capture=self.simulation(before_capture=leak)
        r=execute_batch(self.bundle,self.approval,self.funding,self.out)
        self.assertEqual(capture.call_count,1);self.assertTrue(r['quarantined'])
        self.assertEqual(r['stop_reason'],'credential_exposure_do_not_export')

    def test_evidence_scan_never_follows_agent_created_symlinks(self):
        self.out.mkdir()
        (self.out/'link').symlink_to(self.config['agents']['codex']['credential_source'])
        with self.assertRaises(EvidenceQuarantined):scan_credentials(self.config,self.out)

    def test_capture_exception_cannot_skip_final_credential_scan(self):
        self.authority()
        def leak_then_raise():
            (self.out/'attempt-1/leak').write_bytes(Path(self.config['agents']['codex']['credential_source']).read_bytes())
            raise OSError('synthetic capture error')
        _,capture=self.simulation(before_capture=leak_then_raise)
        r=execute_batch(self.bundle,self.approval,self.funding,self.out)
        self.assertEqual(capture.call_count,1);self.assertTrue(r['quarantined'])
