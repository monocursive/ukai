"""Real-auth metadata/secret isolation and disabled pilot-plan regressions."""
import io
import json
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import urllib.error

from common import read, sha, verify
from m1.auth_setup import NoRedirects, metadata_probe, metadata_request, secret_bytes, install_on_worker
from m1.pilot import build_plan, validate_plan, write_plan
from m1.runtime import auth_policy_check, auth_profile, auth_route, agent_configuration, execute_agent


class AuthPilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='project-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()
        self.key=self.root/'key';self.key.write_text('synthetic-api-key-not-a-real-credential');self.key.chmod(0o600)
        self.config=read(Path(__file__).parent/'linux-config.example.json')
        self.config['agents']['claude']['authentication_route']='api'
        self.config['agents']['codex']['authentication_route']='api'

    def test_api_route_is_distinct_and_original_subscription_stays_default(self):
        self.assertEqual(auth_route('claude')['id'],'claude-oauth')
        self.assertEqual(auth_route('claude','api')['id'],'anthropic')
        p=tomllib.loads(auth_profile('claude','/private/key',route='api'))
        self.assertEqual(p['credentials']['anthropic']['env'],'ANTHROPIC_API_KEY')
        self.assertEqual(p['credentials']['anthropic']['header'],{'name':'x-api-key'})
        self.assertEqual(p['network']['allow'],['api.anthropic.com'])
        self.assertNotIn('CLAUDE_CODE_OAUTH_TOKEN',json.dumps(p))
        self.assertTrue(agent_configuration('claude',self.config['agents']['claude'])['id'].endswith('-api'))
        self.assertFalse(read(Path(__file__).parent/'agents/claude-sonnet.json')['id'].endswith('-api'))

    def test_provider_route_cannot_fall_back_to_unknown_or_subscription_codex(self):
        for agent,route in [('codex','subscription'),('claude','automatic'),('other','api')]:
            with self.assertRaises(ValueError):auth_route(agent,route)

    def test_model_metadata_requests_are_fixed_gets_without_inference_payload(self):
        for agent,url in [('claude','https://api.anthropic.com/v1/models/claude-sonnet-4-5-20250929'),('codex','https://api.openai.com/v1/models/gpt-6-astra')]:
            r=metadata_request(agent,b'synthetic-api-key')
            self.assertEqual(r.get_method(),'GET');self.assertIsNone(r.data);self.assertEqual(r.full_url,url)
        self.assertIsNone(NoRedirects().redirect_request(None,None,302,'redirect',{},'https://elsewhere.example/'))

    def test_secret_loader_rejects_links_bad_permissions_and_multiline_tokens(self):
        self.assertEqual(secret_bytes(self.key),self.key.read_bytes())
        alias=self.root/'alias';alias.symlink_to(self.key)
        with self.assertRaises(ValueError):secret_bytes(alias)
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):secret_bytes(self.key)
        self.key.chmod(0o600);self.key.write_text('long-synthetic\nsecond-line-secret-value')
        with self.assertRaises(ValueError):secret_bytes(self.key)

    def test_metadata_success_retains_no_arbitrary_response_body_or_secret(self):
        class Response(io.BytesIO):status=200
        body={'id':'claude-sonnet-4-5-20250929','type':'model','lifecycle':'active','private':'DO-NOT-RETAIN'}
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.return_value=Response(json.dumps(body).encode())
            result=metadata_probe('claude',self.key)
        self.assertEqual(result['status'],'authenticated_model_metadata')
        self.assertEqual(result['inference_requests'],0)
        self.assertNotIn('DO-NOT-RETAIN',json.dumps(result));self.assertNotIn(self.key.read_text(),json.dumps(result))
        self.assertEqual(factory.return_value.open.call_count,1)

    def test_http_auth_failure_does_not_log_body_or_retry(self):
        body=io.BytesIO(self.key.read_bytes())
        error=urllib.error.HTTPError('https://api.openai.com/v1/models/gpt-6-astra',401,'not logged',{},body)
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.side_effect=error
            result=metadata_probe('codex',self.key)
        self.assertEqual(result['http_status'],401);self.assertEqual(result['provider_acceptance'],'unverified')
        self.assertNotIn(self.key.read_text(),json.dumps(result));self.assertEqual(factory.return_value.open.call_count,1)

    def test_model_alias_or_wrong_model_is_not_access_confirmation(self):
        class Response(io.BytesIO):status=200
        with patch('urllib.request.build_opener') as factory:
            factory.return_value.open.return_value=Response(b'{"id":"other-model","object":"model"}')
            self.assertEqual(metadata_probe('codex',self.key)['status'],'model_identifier_mismatch')

    def test_plan_has_four_samples_and_no_execution_or_ledger_mutation(self):
        with patch('subprocess.Popen',side_effect=AssertionError('process')),patch('socket.socket',side_effect=AssertionError('network')):
            out=self.root/'proposal'
            result=write_plan(self.config,{'claude':{'status':'configured'},'codex':{'status':'pending'}},out)
        self.assertFalse(verify(out));self.assertEqual(result['agent_attempts_proposed'],4)
        p=read(out/'plan.json');self.assertEqual(p['budget']['actual_new_reservation_minor'],0)
        self.assertEqual(p['budget']['proposed_reservation_total_minor'],800)
        self.assertEqual([r['kind'] for r in p['schedule']][:2],['agent_clean']*2)
        self.assertFalse(p['execution_authorized'])

    def test_plan_cannot_enable_runs_reuse_canaries_or_release_m0_holds(self):
        for mutate in [lambda p:p.update(execution_authorized=True),lambda p:p['schedule'][0].update(nonce='reuse'),
                       lambda p:p['budget'].update(m0_reservations_released=True),lambda p:p['schedule'].pop(),
                       lambda p:p['budget'].update(actual_new_reservation_minor=800)]:
            p=build_plan(self.config,{});mutate(p)
            with self.assertRaises(ValueError):validate_plan(p)

    def test_api_setup_still_cannot_authorize_paid_execution(self):
        with patch('subprocess.Popen',side_effect=AssertionError('launched')):
            with self.assertRaises(PermissionError):execute_agent(self.config,self.root/'never-created','protected-issue','agent_clean','claude')
        self.assertFalse((self.root/'never-created').exists())

    def test_installer_uses_encrypted_stdin_and_exclusive_private_destination(self):
        import ast,re,shlex,subprocess
        def transport(argv,**kwargs):
            self.assertEqual(argv[-2],'ouroboros-vps')
            self.assertEqual(kwargs['input'],self.key.read_bytes())
            self.assertNotIn(self.key.read_text(),json.dumps(argv))
            script=shlex.split(argv[-1])[2]
            self.assertIn('os.O_EXCL|os.O_NOFOLLOW,0o600',script)
            path=ast.literal_eval(re.search(r'p=pathlib.Path\((.+)\)',script).group(1))
            self.assertTrue(path.startswith('/home/ubuntu/.config/ukai/credentials/arena-m1-codex-api-'))
            result={'installed':True,'path':path,'mode':'0o600','existing_credentials_overwritten':False}
            return subprocess.CompletedProcess(argv,0,json.dumps(result).encode(),b'')
        with patch('m1.auth_setup.subprocess.run',side_effect=transport) as run:
            result=install_on_worker('codex',self.key)
        self.assertEqual(run.call_count,1);self.assertTrue(result['installed'])

    def test_subscription_candidate_does_not_reuse_api_hosts_or_claim_vault_compatibility(self):
        p=build_plan(self.config,{'codex':{'preferred_route':'chatgpt','status':'unqualified'}})
        validate_plan(p)
        c=p['agents']['codex']
        self.assertEqual(c['allowed_hosts_proposal'],[])
        self.assertIsNone(c['launch_profile_template'])
        self.assertFalse(c['authentication']['copy_auth_json'])
        self.assertFalse(c['authentication']['vault_compatible'])
        self.assertIsNone(p['budget']['proposed_reservation_total_minor'])
        p['budget']['quota_consumption_authorized']=True
        with self.assertRaises(ValueError):validate_plan(p)

    def test_api_policy_verifier_requires_exact_header_and_process(self):
        credential={'id':'anthropic','mode':'vault','source':'/private/key','vault':{'env':'ANTHROPIC_API_KEY',
            'hosts':['https://api.anthropic.com'],'header':{'name':'x-api-key'},'allow_plaintext':False,'binaries':['/native/claude']}}
        doc={'snapshot':{'launch':{'credentials':[credential],'state_var':'CLAUDE_CONFIG_DIR'},'network':{'allow':['api.anthropic.com:443']},'environment':{'inherit_host':False}}}
        self.assertFalse(auth_policy_check(doc,'claude','/native/claude','/private/key','api'))
        credential['vault']['header']={'name':'authorization','prefix':'Bearer '}
        self.assertIn('vault_process_or_header_binding_mismatch',auth_policy_check(doc,'claude','/native/claude','/private/key','api'))
