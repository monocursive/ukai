"""Offline regressions for Codex's observed fallback and explicit HTTP route."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from common import read, save, manifest
from m1.adapters import normalize, exposure
from m1.runtime import agent_configuration, agent_command
from m1 import test_integration
from m1.scoring import score
from m1.batch import stop_reason


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'agent.ndjson'
        self.rows = [json.loads(x) for x in (Path(__file__).parent /
            'fixtures/codex-0.163.0-recovered-http.jsonl').read_text().splitlines()]

    def parse(self, rows=None, ending='\n'):
        self.path.write_text('\n'.join(json.dumps(r) for r in (self.rows if rows is None else rows)) + ending)
        return normalize(self.path, 'codex')

    def test_observed_prefix_recovers_with_references_and_verified_exposure(self):
        t = self.parse()
        self.assertFalse(t['gaps']); self.assertFalse(t['provider_failed'])
        self.assertEqual(t['adapter'], 'codex/2')
        self.assertEqual([r['line'] for r in t['transport_warnings'][0]['refs']], [3,4,5,6,7])
        self.assertEqual(exposure(t, '/w/README.md', '/w', 'nonce abc\nfixture instruction', 'abc')['status'], 'verified')

    def test_missing_terminal_usage_and_truncation_never_recover(self):
        variants = [self.rows[:-1]]
        for usage in (None, {}, {'input_tokens':True,'output_tokens':4}, {'input_tokens':12,'output_tokens':-1}):
            r=deepcopy(self.rows);r[-1]['usage']=usage;variants.append(r)
        for r in variants:
            with self.subTest(rows=r):
                t=self.parse(r);self.assertTrue(t['gaps']);self.assertFalse(t['transport_warnings'])
        self.assertTrue(self.parse(ending='')['gaps'])

    def test_terminal_failures_unknown_errors_and_post_terminal_errors_remain_fatal(self):
        variants=[]
        r=deepcopy(self.rows);r[-1]['type']='turn.failed';variants.append(r)
        r=deepcopy(self.rows);r[2]['message']='API key rejected';variants.append(r)
        r=deepcopy(self.rows);r.insert(-1,{'type':'error','message':'Unknown failure'});variants.append(r)
        r=deepcopy(self.rows);r.append({'type':'error','message':'after terminal'});variants.append(r)
        r=deepcopy(self.rows);r[6]['item']['message']+=' extra unqualified detail';variants.append(r)
        for r in variants:
            t=self.parse(r);self.assertTrue(t['gaps']);self.assertTrue(t['provider_failed']);self.assertFalse(t['transport_warnings'])

    def test_mid_tool_reconnects_multiple_turns_and_incomplete_calls_remain_gaps(self):
        variants=[]
        r=deepcopy(self.rows);r.insert(2,r.pop(7));variants.append(r)
        r=deepcopy(self.rows);r.insert(-1,{'type':'turn.started'});variants.append(r)
        r=deepcopy(self.rows);del r[8];variants.append(r)
        r=deepcopy(self.rows);r.insert(8,deepcopy(r[7]));variants.append(r)
        r=deepcopy(self.rows);r[8]['item']['command']='cat OTHER.md';variants.append(r)
        r=deepcopy(self.rows);del r[9];variants.append(r)
        for r in variants:
            t=self.parse(r);self.assertTrue(t['gaps']);self.assertFalse(t['transport_warnings'])

    def test_http_configuration_is_explicit_and_old_configuration_is_retained(self):
        old=agent_configuration('codex',{})
        new=agent_configuration('codex',{'transport':'http_sse'})
        self.assertNotEqual(old['id'],new['id'])
        self.assertNotIn('model_provider="arena_openai_http"',old['argv_template'])
        for flag in ('supports_websockets=false','request_max_retries=0','stream_max_retries=0'):
            self.assertIn('model_providers.arena_openai_http.'+flag,new['argv_template'])
        self.assertIn('model_providers.arena_openai_http.env_key="CODEX_API_KEY"',new['argv_template'])
        self.assertEqual(new['model_requested'],old['model_requested'])
        with patch('subprocess.Popen',side_effect=AssertionError('launch')):
            argv=agent_command('/jail','codex','/workspace','/receipt',spec={'transport':'http_sse'})
        self.assertIn('model_provider="arena_openai_http"',argv)
        self.assertEqual(new['allowed_hosts_proposal'],['api.openai.com:443'])
        with self.assertRaises(ValueError):agent_configuration('codex',{'transport':'unqualified'})

    def test_score_requires_zero_exit_even_for_recovered_transcript(self):
        helper=test_integration.IntegrationTests('test_task_summary_without_offline_checker_receipt_is_unverified')
        helper.setUp();self.addCleanup(helper.doCleanups)
        root,_,_,_=helper.bundle(kind='agent_clean')
        (root/'raw/agent.ndjson').write_text('\n'.join(json.dumps(x) for x in self.rows)+'\n')
        run=read(root/'run.json');run['capture']['exit_code']=1;save(root/'run.json',run);manifest(root)
        s=score(root)
        self.assertTrue(s['transport_warnings']);self.assertFalse(s['evidence_complete'])
        self.assertIn('agent_exit_unverified_or_nonzero',s['gaps'])

    def test_explicit_http_pilot_stops_if_websocket_fallback_still_occurs(self):
        t=self.parse()
        result={'evidence_complete':True,'cleanup_verified':True,'policy_verified':True,
                'gaps':[],'task':{'status':'pass'},'usage':t['usage'],
                'transport_warnings':t['transport_warnings']}
        self.assertIsNone(stop_reason(result,'agent_clean','codex'))
        self.assertEqual(stop_reason(result,'agent_clean','codex','http_sse'),'http_only_transport_mismatch')
        result['transport_warnings']=[]
        self.assertIsNone(stop_reason(result,'agent_clean','codex','http_sse'))

