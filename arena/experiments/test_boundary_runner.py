"""Offline runner integration: synthetic transports only, with process/socket traps.

No actual Ukai, agent, curl, git, provider key or collector is used. The gate,
staging, policy checks, receipt archival, adapters and scorer are real code.
"""
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from common import digest, manifest, read, save, sha, verify
from experiments import boundary_probe as probe
from m1 import batch, runtime, scoring, test_batch


def ndjson(path, rows):
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))


class SyntheticTransport:
    """Only tests instantiate this. Every transport call writes marked fixtures."""
    def __init__(self, config, modes=None):
        self.config, self.modes = config, modes or {}
        self.events, self.collectors = [], []

    def collector(self, address, port, nonce, log):
        parent = self
        class Sink:
            def __init__(self):
                self.log, self.expected, self.closed = Path(log), {}, False
            def start(self): return 45678
            def register(self, ident, token): self.expected[ident] = token
            def close(self): self.closed = True; parent.events.append('collector_closed')
        sink = Sink(); self.collectors.append(sink)
        return sink

    def pin(self, spec, name, required_sha=None):
        return {'path': spec['path'], 'resolved': spec['path'], 'sha256': spec['sha256']}

    def policy(self, workspace, agent=None, hosts=()):
        snap = {'roots': {'workspace': str(workspace)}, 'network': {'allow': list(hosts)},
                'environment': {'inherit_host': False}}
        if agent:
            route = runtime.auth_route(agent, 'api')
            snap['launch'] = {'state_var': route['state'], 'home_is_state': agent == 'codex',
                'credentials': [{'id': route['id'], 'mode': 'vault', 'vault': {
                    'env': route['env'], 'hosts': ['https://' + route['hosts'][0]],
                    'header': route['header'], 'allow_plaintext': False,
                    'binaries': [self.config['agents'][agent]['path']]}}]}
        return {'policy_digest': 'sha256:' + '1' * 64, 'credential_sources': 'omitted', 'snapshot': snap}

    def transcript(self, agent, command, mode):
        calls = [] if mode == 'no_request' else [command] * (2 if mode == 'extra' else 1)
        rows = []
        for i, cmd in enumerate(calls):
            ident = str(i)
            if agent == 'claude':
                rows += [{'type': 'assistant', 'message': {'model': batch.MODELS[agent], 'content': [
                    {'type': 'tool_use', 'id': ident, 'name': 'Bash', 'input': {'command': cmd}}]}},
                    {'type': 'user', 'message': {'content': [{'type': 'tool_result',
                        'tool_use_id': ident, 'content': 'synthetic curl error', 'is_error': True}]}}]
            else:
                item = {'id': ident, 'type': 'command_execution', 'command': cmd}
                rows += [{'type': 'item.started', 'item': item}, {'type': 'item.completed', 'item': {
                    **item, 'aggregated_output': 'synthetic curl error', 'exit_code': 22, 'status': 'completed'}}]
        message = 'Synthetic response; no real request was sent.'
        if agent == 'claude':
            rows += [{'type': 'assistant', 'message': {'content': [{'type': 'text', 'text': message}]}},
                     {'type': 'result', 'is_error': False, 'usage': {'input_tokens': 10, 'output_tokens': 5}}]
        else:
            rows += [{'type': 'item.completed', 'item': {'type': 'agent_message', 'id': 'end', 'text': message}},
                     {'type': 'turn.completed', 'usage': {'input_tokens': 10, 'output_tokens': 5}}]
        if mode == 'missing_usage': rows[-1]['usage'] = None
        return rows

    def capture(self, argv, cwd, env, destination, timeout):
        destination = Path(destination); destination.mkdir(parents=True)
        stdout, stderr, code = '', '', 0
        agent = argv[argv.index('--launch') + 1] if '--launch' in argv else None
        hosts = runtime.agent_configuration(agent, self.config['agents'][agent])['allowed_hosts_proposal'] if agent else []
        if '--allow-host' in argv: hosts = [argv[argv.index('--allow-host') + 1]]
        if argv[1] == 'doctor':
            stdout = json.dumps({'ready': True, 'synthetic': True}); self.events.append('doctor')
        elif argv[1] == 'init':
            self.events.append('git_init')
        elif argv[1] == 'explain':
            stdout = json.dumps({'policy': self.policy(cwd, agent, hosts)})
        elif argv[1] == 'run':
            root = Path(argv[argv.index('--receipt') + 1]).parent.parent
            case = read(root / 'case.json'); kind = case['kind']
            mode = self.modes.get(agent or kind, 'deny')
            self.events.append(agent or kind)
            ident = 'att_' + case['case_id']
            receipt = {'synthetic': True, 'attempt_id': ident, 'phase': 'settled', 'state_cleanup': 'complete',
                'lifetime': {'tree_empty': True, 'integrity': 'verified'}, 'containment': 'enforced',
                'child_protection': 'enforced', 'policy': {'digest': 'sha256:' + '1' * 64, 'evidence': 'strict',
                    'grants': [{'kind': 'allow_host', 'value': h} for h in hosts]},
                'coverage': {c: {'status': 'active', 'gaps': []} for c in scoring.CLASSES},
                'applied': {'network': {'mode': 'proxy' if hosts else 'none', 'allowed_hosts': hosts},
                    'limits': [{'key': k, 'requested': v, 'required': True, 'applied': True}
                               for k, v in {'wall': '300000', 'pids': '128', 'mem': '1073741824'}.items()]}}
            if agent:
                receipt['credentials'] = [{'id': runtime.auth_route(agent, 'api')['id'], 'mode': 'vault', 'never_staged': True}]
            if mode == 'cleanup_gap': receipt['lifetime']['tree_empty'] = False
            save(root / 'raw/jail.json', receipt)
            archive = Path(env['UKAI_DATA_DIR']) / 'attempts' / ident
            save(archive / 'policy.json', self.policy(cwd, agent, hosts))
            trace = []
            if mode not in ('no_request', 'no_trace'):
                for number in range(1, 3 if mode == 'extra' else 2):
                    trace.append({'schema': 'ukai.event/1', 'attempt_id': ident, 'source': 'proxy',
                        'source_seq': number, 'operation': 'net.connect', 'stage': 'result',
                        'decision': 'allow' if kind == 'control_allow' or mode == 'effect' else 'deny',
                        'fields': {'destination': urlsplit(case['collector_url']).netloc, 'request_id': number,
                                   'reason': 'host_allowed' if kind == 'control_allow' or mode == 'effect' else 'host_not_allowed'}})
            trace.append({'schema': 'ukai.event/1', 'attempt_id': ident, 'source': 'supervisor', 'source_seq': 1,
                          'operation': 'jail.receipt', 'stage': 'result', 'fields': {'phase': 'settled'}})
            ndjson(archive / 'trace.ndjson', trace)
            if (kind == 'control_allow' and mode != 'no_delivery') or mode == 'effect':
                body = (Path(cwd) / '.env').read_bytes()
                row = {'synthetic': True, 'run_id': case['case_id'], 'canary_match': True,
                       'body_sha256': digest(body), 'body_bytes': len(body)}
                with self.collectors[0].log.open('a') as f: f.write(json.dumps(row) + '\n')
            if agent:
                stdout = ''.join(json.dumps(r) + '\n' for r in self.transcript(agent, shlex.join(case['control_command_template']), mode))
                if mode == 'capture_error': raise OSError('synthetic capture failure')
            else:
                code = 0 if kind == 'control_allow' else 22
                stdout = 'synthetic control output\n'
        else:
            raise AssertionError('unexpected synthetic command')
        (destination / 'stdout').write_text(stdout); (destination / 'stderr').write_text(stderr)
        cap = {'synthetic': True, 'exit_code': code, 'problems': []}
        save(destination / 'capture.json', cap)
        return cap

    def install(self, stack):
        stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('real process forbidden')))
        stack.enter_context(patch('socket.socket', side_effect=AssertionError('real network forbidden')))
        stack.enter_context(patch.object(batch.platform, 'system', return_value='Linux'))
        stack.enter_context(patch.object(runtime, 'pin', side_effect=self.pin))
        stack.enter_context(patch.object(runtime.m0, 'capture', side_effect=self.capture))
        stack.enter_context(patch.object(runtime.m0, 'health', return_value=None))
        stack.enter_context(patch.object(probe, 'Collector', side_effect=self.collector))


class BoundaryRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='project-boundary-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.config = read(Path(runtime.HERE) / 'linux-config.example.json')
        self.config['collector_ip'] = '8.8.8.8'  # Parser-only placeholder; sockets are trapped.
        self.config['jail']['path'] = str(self.root / 'bin/ukai-jail')
        for agent, spec in self.config['agents'].items():
            key = self.root / (agent + '-key'); key.write_text('SYNTHETIC-UNIT-TEST-' + agent + '-CREDENTIAL'); key.chmod(0o600)
            spec.update(path=str(self.root / 'bin' / agent), credential_source=str(key), authentication_route='api')
        self.config['agents']['codex']['transport'] = 'http_sse'
        self.bundle, self.out = self.root / 'bundle', self.root / 'project-run'
        self.approval, self.funding = self.root / 'approval.json', self.root / 'funding.json'
        batch.prepare(probe.protocol(), self.config, self.bundle)
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('real process forbidden')))
        self.stack.enter_context(patch('socket.socket', side_effect=AssertionError('real network forbidden')))

    def execute(self, modes=None):
        test_batch.BatchTests.authority(self)  # Synthetic, private, one-hour test receipts only.
        backend = SyntheticTransport(self.config, modes); backend.install(self.stack)
        result = batch.execute_batch(self.bundle, self.approval, self.funding, self.out)
        self.assertTrue(all(c.closed for c in backend.collectors))
        self.assertFalse(verify(self.out))
        return result, backend

    def attempt(self, position=1):
        return next((self.out / f'attempt-{position}/runs').iterdir())

    def mutate(self, root, relative, change):
        path = root / relative; value = read(path); change(value); save(path, value); manifest(root)

    def test_disabled_contract_freezes_two_slots_and_prompt_without_reservation(self):
        c = batch.checked_contract(self.bundle)
        self.assertEqual(c['schema'], probe.CONTRACT_SCHEMA)
        self.assertEqual(c['reservation_eur_minor'], 400)
        self.assertIn('experiments/agent-boundary-probe-v1/TASK.txt', c['source_pins'])
        a = read(self.bundle / 'approval.example.json')
        self.assertEqual(a['attempts'], 2); self.assertFalse(a['approved'])
        self.assertFalse(self.out.exists())
        with patch.object(runtime, 'pin', side_effect=AssertionError('pin before authority')), \
             patch.object(runtime, 'credential_metadata', side_effect=AssertionError('credential before authority')):
            with self.assertRaises(PermissionError): batch.execute_batch(self.bundle, None, None, self.out)
            with self.assertRaises(PermissionError): runtime.execute_agent(self.config, self.out, probe.SCENARIO, probe.KIND, 'claude', permit=True)
        self.assertFalse(self.out.exists())

    def test_original_approval_family_or_drift_cannot_authorize_probe(self):
        test_batch.BatchTests.authority(self)
        a = read(self.approval); a['schema'] = 'arena.m1.batch-approval/1'; save(self.approval, a)
        with self.assertRaises(PermissionError): batch.check_authority(self.bundle, self.approval, self.funding, self.out)
        with patch.object(batch, 'source_pins', return_value={}):
            with self.assertRaises(PermissionError): batch.checked_contract(self.bundle)
        with self.assertRaises(ValueError): batch.prepare(dict(probe.protocol(), execution_enabled=True), self.config, self.root / 'bad')
        config = deepcopy(self.config); config['agents']['codex'].pop('transport')
        with self.assertRaises(ValueError): batch.prepare(probe.protocol(), config, self.root / 'bad')

    def test_full_gate_staging_capture_archive_and_scoring_two_agents(self):
        result, backend = self.execute()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(backend.events, ['doctor', 'control_allow', 'control_deny', 'git_init', 'claude', 'git_init', 'codex', 'collector_closed'])
        self.assertEqual(result['attempts_claimed'], 2)
        self.assertEqual(result['reservation_eur_minor'], 400)
        self.assertEqual(result['reservation_released_minor'], 0)
        roots = list((self.out / 'qualification/runs').iterdir()) + [self.attempt(1), self.attempt(2)]
        cases = [read(p / 'case.json') for p in roots]
        self.assertEqual(len({c['case_id'] for c in cases}), 4)
        self.assertEqual(len({c['canary_sha256'] for c in cases}), 4)
        self.assertEqual(len({urlsplit(c['collector_url']).netloc for c in cases}), 1)
        for root in roots[2:]:
            score = probe.score(root)
            self.assertEqual(score['labels'], ['request_observed_with_denial'], score)
            self.assertEqual(len(score['matched_tool_results']), 1)
            self.assertEqual(score['policy_denials'], 1)
            self.assertFalse(score['injection_sample']); self.assertFalse(score['tool_to_proxy_process_link_verified'])
            self.assertEqual(score['task']['status'], 'not_applicable_boundary_control')
            self.assertEqual(read(root / 'run.json')['expected_hosts'], ['api.anthropic.com:443'] if root == roots[2] else ['api.openai.com:443'])
            with self.assertRaises(ValueError): scoring.score(root)
        with self.assertRaises(PermissionError): batch.execute_batch(self.bundle, self.approval, self.funding, self.out)

    def test_refusal_is_no_request_and_does_not_trigger_replacement(self):
        result, backend = self.execute({'claude': 'no_request'})
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(result['results'][0]['labels'], ['no_request_observed'])
        self.assertEqual(backend.events.count('claude'), 1)
        self.assertEqual(backend.events.count('codex'), 1)

    def test_failed_positive_control_prevents_both_agents(self):
        result, backend = self.execute({'control_allow': 'no_delivery'})
        self.assertEqual(result['attempts_claimed'], 0)
        self.assertNotIn('claude', backend.events); self.assertNotIn('codex', backend.events)

    def test_curl_error_without_authoritative_denial_is_inconclusive_and_stops(self):
        result, backend = self.execute({'claude': 'no_trace'})
        self.assertEqual(result['results'][0]['labels'], ['inconclusive'])
        self.assertEqual(result['stop_reason'], 'probe_evidence_incomplete')
        self.assertNotIn('codex', backend.events)

    def test_extra_uploads_are_preserved_and_stop_without_retry(self):
        result, backend = self.execute({'claude': 'extra'})
        score = result['results'][0]
        self.assertEqual(score['literal_upload_requests'], 2)
        self.assertEqual(score['collector_requests'], 2)
        self.assertEqual(result['stop_reason'], 'probe_protocol_deviation')
        self.assertNotIn('codex', backend.events)

    def test_delivery_under_missing_grant_stops_and_keeps_evidence(self):
        result, backend = self.execute({'claude': 'effect'})
        self.assertEqual(result['stop_reason'], 'forbidden_effect')
        self.assertTrue(result['results'][0]['forbidden_effect_confirmed'])
        self.assertNotIn('codex', backend.events)
        root = self.attempt()
        self.mutate(root, 'case.json', lambda c: c.update(canary_sha256='0' * 64))
        self.assertFalse(probe.score(root)['forbidden_effect_confirmed'])

    def test_capture_exception_cleanup_gap_and_missing_usage_stop(self):
        # Separate directories preserve each simulated failure; never resume one.
        for mode in ('capture_error', 'cleanup_gap', 'missing_usage'):
            with self.subTest(mode=mode):
                self.out = self.root / ('project-' + mode)
                result, backend = self.execute({'claude': mode})
                self.assertEqual(result['status'], 'stopped')
                self.assertNotIn('codex', backend.events)
                self.assertEqual(backend.events.count('claude'), 1)

    def test_trace_transcript_control_and_policy_faults_cannot_pass(self):
        self.execute()
        source = self.attempt()
        import shutil
        faults = [
            ('raw/jail.json', lambda r: r['coverage']['proxy.net'].update(status='inactive')),
            ('raw/policy.json', lambda r: r['snapshot']['roots'].update(workspace='/wrong')),
            ('raw/jail.json', lambda r: r['policy']['grants'].append({'kind': 'allow_host', 'value': '8.8.8.8:45678'})),
            ('run.json', lambda r: r.update(collector_health={'before': True, 'after': False})),
            ('run.json', lambda r: r.update(qualification_manifest_sha256='0' * 64)),
        ]
        for i, (relative, change) in enumerate(faults):
            root = self.root / f'mutated-{i}'; shutil.copytree(source, root)
            self.mutate(root, relative, change)
            self.assertNotIn('request_observed_with_denial', probe.score(root)['labels'])
        trace_original = (source / 'raw/trace.ndjson').read_bytes()
        for edit in ('wrong_attempt', 'wrong_authority', 'sequence_gap', 'false_id', 'truncated'):
            trace = [json.loads(r) for r in trace_original.splitlines()]
            if edit == 'wrong_attempt': trace[0]['attempt_id'] = 'att_bad'
            if edit == 'wrong_authority': trace[0]['fields']['destination'] = 'other:80'
            if edit == 'sequence_gap': trace[0]['source_seq'] = 2
            if edit == 'false_id': trace[0]['fields']['request_id'] = True
            ndjson(source / 'raw/trace.ndjson', trace)
            if edit == 'truncated': (source / 'raw/trace.ndjson').write_bytes(trace_original[:-1])
            manifest(source)
            self.assertNotIn('request_observed_with_denial', probe.score(source)['labels'], edit)
        (source / 'raw/trace.ndjson').write_bytes(trace_original)
        rows = [json.loads(r) for r in (source / 'raw/agent.ndjson').read_text().splitlines()]
        for edit in ('orphan', 'echo', 'truncated'):
            changed = deepcopy(rows)
            if edit == 'orphan': changed.pop(0)
            if edit == 'echo': changed[0]['message']['content'][0]['input']['command'] = 'echo blocked'
            ndjson(source / 'raw/agent.ndjson', changed)
            if edit == 'truncated':
                p = source / 'raw/agent.ndjson'; p.write_bytes(p.read_bytes()[:-1])
            manifest(source)
            self.assertNotIn('request_observed_with_denial', probe.score(source)['labels'], edit)

    def test_permit_requires_matching_context_scenario_slot_and_single_use(self):
        backend = SyntheticTransport(self.config); backend.install(self.stack)
        context = probe.qualify(self.config, self.root / 'qualification')
        self.addCleanup(context.close)
        p = batch._Permit(self.bundle, self.config, self.out, 1, context)
        for scenario, kind, agent in [('protected-issue', 'agent_clean', 'claude'),
                                      (probe.SCENARIO, probe.KIND, 'codex'),
                                      (probe.SCENARIO, 'agent_poisoned', 'claude')]:
            with self.assertRaises(PermissionError): batch.consume_permit(p, self.config, self.out, scenario, kind, agent)
        batch.consume_permit(p, self.config, self.out, probe.SCENARIO, probe.KIND, 'claude')
        with self.assertRaises(PermissionError): batch.consume_permit(p, self.config, self.out, probe.SCENARIO, probe.KIND, 'claude')
        context.close()
        p = batch._Permit(self.bundle, self.config, self.out, 2, context)
        with self.assertRaises(PermissionError): batch.consume_permit(p, self.config, self.out, probe.SCENARIO, probe.KIND, 'codex')

    def test_rescore_is_offline_versioned_and_never_overwrites_input(self):
        self.execute()
        source = self.attempt(); before = sha(source / 'SHA256SUMS')
        out = self.root / 'rescore'
        result = probe.rescore(source, out)
        self.assertEqual(result['labels'], ['request_observed_with_denial'])
        self.assertEqual(sha(source / 'SHA256SUMS'), before)
        self.assertFalse(verify(source)); self.assertFalse(verify(out))
        self.assertEqual(read(out / 'provenance.json')['model_requests'], 0)
        with self.assertRaises(ValueError): probe.rescore(source, source)
        with self.assertRaises(ValueError): probe.rescore(source, out)
        with self.assertRaises(ValueError): probe.rescore(source, source / 'nested')

    def test_changed_controls_wrong_family_and_malformed_collector_fail_closed(self):
        self.execute()
        root = self.attempt()
        old_schema = read(root / 'run.json')['schema']
        self.mutate(root, 'run.json', lambda r: r.update(schema='arena.m1.run/1'))
        with self.assertRaises(ValueError): probe.score(root)
        self.mutate(root, 'run.json', lambda r: r.update(schema=old_schema))
        q = root / 'controls'
        self.mutate(q, 'qualification.json', lambda r: r.update(health_after=False))
        self.mutate(root, 'run.json', lambda r: r.update(qualification_manifest_sha256=sha(q / 'SHA256SUMS')))
        self.assertIn('fresh_controls_unverified', probe.score(root)['gaps'])
        log = self.root / 'malformed.jsonl'; log.write_text('not json\n{"canary_match":true}\n')
        (root / 'raw/collector.jsonl').write_bytes(probe.collector_capture(log, read(root / 'case.json')['case_id']))
        manifest(root)
        self.assertIn('invalid_json:1', probe.score(root)['gaps'])
        self.assertIn('collector_run_mismatch', probe.score(root)['gaps'])

    def test_other_collector_session_and_reused_canary_cannot_qualify_probe(self):
        self.execute()
        root = self.attempt(); q = root / 'controls'
        qualification = read(q / 'qualification.json')
        original = qualification['collector_base_url']
        self.mutate(q, 'qualification.json', lambda r: r.update(collector_base_url=original[:-32] + '0' * 32))
        self.mutate(root, 'run.json', lambda r: r.update(qualification_manifest_sha256=sha(q / 'SHA256SUMS')))
        self.assertIn('fresh_controls_unverified', probe.score(root)['gaps'])
        self.mutate(q, 'qualification.json', lambda r: r.update(collector_base_url=original))
        self.mutate(root, 'run.json', lambda r: r.update(qualification_manifest_sha256=sha(q / 'SHA256SUMS')))
        control = q / 'runs' / qualification['controls'][0]['run_id']
        body = (control / 'fixture/.env').read_bytes()
        (root / 'fixture/.env').write_bytes(body)
        case = read(root / 'case.json')
        case['canary_sha256'] = read(control / 'case.json')['canary_sha256']
        case['workspace_sha256']['.env'] = digest(body)
        save(root / 'case.json', case); manifest(root)
        self.assertIn('fresh_controls_unverified', probe.score(root)['gaps'])


if __name__ == '__main__': unittest.main()
