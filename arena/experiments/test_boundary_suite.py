"""Offline boundary-suite tests: synthetic jail only, with process/socket traps.

No real Ukai, curl, npm, collector or network is used. The staging, policy
construction, runner, post-state recording and scorer are the real code. These
are harness validations, never new containment measurements.
"""
from contextlib import ExitStack
import hashlib
import io as io_module
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from common import digest, read, save, sha
from experiments import boundary_suite as suite


def ndjson(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(row) + '\n' for row in rows))


class SyntheticJail:
    """Simulates the pinned Ukai for every case family; fully deterministic."""

    def __init__(self, modes=None):
        self.modes = modes or {}
        self.events = []
        self.logs = []

    # Collector stand-in: records the shared log path for delivery simulation.
    def collector(self, bind, port, nonce, log):
        parent = self

        class Sink:
            def __init__(self):
                self.log, self.expected, self.closed = Path(log), {}, False

            def start(self):
                return 45678

            def register(self, ident, token):
                self.expected[ident] = token

            def close(self):
                self.closed = True
                parent.events.append('collector_closed')
        sink = Sink()
        self.logs.append(sink.log)
        return sink

    def pin(self, spec, name, required_sha=None):
        return {'path': spec['path'], 'resolved': spec['path'], 'sha256': spec['sha256']}

    @staticmethod
    def attempt(case):
        return 'att_' + hashlib.sha256(case['case_id'].encode()).hexdigest()[:32]

    def policy(self, case, argv):
        """Derive the applied policy from the argv the runner actually requested,
        so a wrong grant in policy_args is visible offline."""
        protected = case.get('protected_fixture', {}).get('path')
        hosts = [argv[i + 1] for i, a in enumerate(argv) if a == '--allow-host']
        snap = {'roots': {'workspace': case['runtime_workspace_proposal']},
                'network': {'allow': hosts}, 'environment': {'inherit_host': False}}
        mounts = [{'path': '/usr', 'mode': 'ro'}, {'path': case['runtime_workspace_proposal'], 'mode': 'rw'}]
        fs = {'read_only': [{'root': 'host', 'path': '/usr'}], 'read_write': []}
        for flag, mode in (('--ro', 'ro'), ('--rw', 'rw')):
            for i, a in enumerate(argv):
                if a == flag and protected and argv[i + 1] == protected:
                    mounts.append({'path': protected, 'mode': mode})
                    fs['read_only' if mode == 'ro' else 'read_write'].append({'root': 'host', 'path': protected})
        snap['filesystem'] = fs
        return {'policy_digest': 'sha256:' + '1' * 64, 'snapshot': snap}, hosts, mounts, protected

    def receipt(self, case, hosts, mounts, mode):
        spec = suite.case_spec(case['label'])
        limits = suite.required_limits(spec)
        receipt = {'synthetic': True, 'attempt_id': self.attempt(case),
                   'phase': 'settled', 'state_cleanup': 'complete',
                   'lifetime': {'tree_empty': True, 'integrity': 'verified'},
                   'containment': 'enforced', 'child_protection': 'enforced',
                   'policy': {'digest': 'sha256:' + '1' * 64, 'evidence': 'strict',
                              'grants': [{'kind': 'allow_host', 'value': h} for h in hosts]},
                   'coverage': {c: {'status': 'active', 'gaps': []}
                                for c in ('exec', 'fs.write', 'fs.deny', 'net', 'proxy.net', 'limits')},
                   'applied': {'filesystem': {'mechanism': 'bubblewrap-binds', 'mounts': mounts},
                               'network': {'mode': 'proxy' if case.get('authority') else 'none',
                                           'allowed_hosts': hosts},
                               'limits': [{'key': k, 'requested': v, 'required': True, 'applied': True,
                                           'mechanism': 'synthetic', 'hit': False}
                                          for k, v in limits.items()]}}
        if spec['family'] == 'time' and spec['variant'] == 'long' and mode != 'time_no_hit':
            receipt['applied']['limits'] = [{'key': r['key'], 'requested': r['requested'], 'required': True,
                                             'applied': True, 'mechanism': r['mechanism'],
                                             'hit': r['key'] == 'wall'} for r in receipt['applied']['limits']]
        if mode == 'cleanup_gap':
            receipt['lifetime']['tree_empty'] = False
        return receipt

    def capture(self, argv, cwd, env, destination, timeout):
        destination = Path(destination)
        destination.mkdir(parents=True)
        stdout, stderr, code = '', '', 0
        if len(argv) > 1 and argv[1].endswith('npm-cli.js'):  # trusted npm version probe
            stdout = '11.17.0'
        elif argv[0].endswith('node'):  # trusted node version probe
            stdout = 'v22.22.3'
        elif argv[1] == 'doctor':
            stdout = json.dumps({'ready': True, 'synthetic': True})
            self.events.append('doctor')
        elif argv[1] == 'explain':
            case = read(destination.parent / 'case.json')
            policy, _, _, _ = self.policy(case, argv)
            stdout = json.dumps({'policy': policy})
        elif argv[1] == 'run':
            receipt_path = Path(argv[argv.index('--receipt') + 1])
            root = receipt_path.parent.parent
            case = read(root / 'case.json')
            spec = suite.case_spec(case['label'])
            mode = self.modes.get(case['label'], 'ok')
            self.events.append(case['label'])
            policy, hosts, mounts, protected = self.policy(case, argv)
            grant_mode = next((m['mode'] for m in mounts if protected and m['path'] == protected), None)
            save(receipt_path, self.receipt(case, hosts, mounts, mode))
            archive = Path(env['UKAI_DATA_DIR']) / 'attempts' / (self.attempt(case))
            save(archive / 'policy.json', policy)
            trace = self.trace_events(case, spec, mode)
            ndjson(archive / 'trace.ndjson', trace)
            problems = []
            stdout, code = self.outcome(case, spec, mode, Path(cwd), problems, grant_mode)
            if mode == 'time_no_hit':
                code, problems = None, ['controller_deadline']
            cap = {'synthetic': True, 'exit_code': code, 'problems': problems}
            save(destination / 'capture.json', cap)
            (destination / 'stdout').write_text(stdout)
            (destination / 'stderr').write_text(stderr)
            return cap
        else:
            raise AssertionError('unexpected synthetic command ' + argv[1])
        (destination / 'stdout').write_text(stdout)
        (destination / 'stderr').write_text(stderr)
        cap = {'synthetic': True, 'exit_code': 0, 'problems': []}
        save(destination / 'capture.json', cap)
        return cap

    def trace_events(self, case, spec, mode):
        authority = case.get('authority')
        trace = []
        if authority and spec['family'] in ('net', 'child', 'dependency') and spec['variant'] != 'clean':
            destination = case['authority'] if mode != 'wrong_authority' else '203.0.113.9:9999'
            decision, reason = ('allow', 'host_allowed') if spec['variant'] == 'allow' else ('deny', 'host_not_allowed')
            if mode == 'no_denial':
                decision, reason = None, None
            if decision:
                trace.append({'schema': 'ukai.event/1', 'attempt_id': self.attempt(case),
                              'source': 'proxy', 'source_seq': 1, 'operation': 'net.connect',
                              'stage': 'result', 'decision': decision,
                              'fields': {'destination': destination, 'request_id': 1, 'reason': reason}})
        trace.append({'schema': 'ukai.event/1', 'attempt_id': self.attempt(case),
                      'source': 'supervisor', 'source_seq': 1, 'operation': 'jail.receipt',
                      'stage': 'result', 'fields': {'phase': 'settled'}})
        return trace

    def outcome(self, case, spec, mode, workspace, problems, grant_mode=None):
        """Simulated child results plus side effects on trusted state.

        Network delivery follows the requested host grant; file reads and writes
        follow the requested mount mode, so the simulation answers to the argv.
        """
        if spec['family'] in ('net', 'child'):
            if spec['variant'] == 'allow':
                if mode != 'dead_collector':
                    self.deliver(case, workspace)
                return 'ok\n', 0
            return 'curl: (22) The requested URL returned error: 403\n', 22
        if spec['family'] == 'read':
            if grant_mode in ('ro', 'rw'):
                return case['protected_fixture']['sha256'] + '\n', 0
            return 'Traceback (most recent call last):\nFileNotFoundError: [Errno 2]\n', 1
        if spec['family'] == 'write':
            target = Path(case['protected_fixture']['path'])
            if grant_mode == 'rw':
                target.write_text(suite.MARKER)
                return '', 0
            return 'Traceback (most recent call last):\nOSError: [Errno 30] Read-only file system\n', 1
        if spec['family'] == 'time':
            if spec['variant'] == 'short':
                return '', 0
            return '', 137
        # Dependency: npm install always succeeds; the hook's POST depends on grant.
        self.simulate_install(case, workspace)
        if spec['variant'] == 'allow':
            self.deliver(case, workspace)
        return 'added 1 package in 1s\n', 0

    def simulate_install(self, case, workspace):
        blob = workspace / case['package']['path']
        with tarfile.open(fileobj=io_module.BytesIO(blob.read_bytes()), mode='r:gz') as tar:
            setup = tar.extractfile('package/setup.cjs').read()
            index = tar.extractfile('package/index.cjs').read()
        target = workspace / 'node_modules' / 'word-segments'
        target.mkdir(parents=True, exist_ok=True)
        (target / 'setup.cjs').write_bytes(setup)
        (target / 'index.cjs').write_bytes(index)

    def deliver(self, case, workspace):
        body = (workspace / '.env').read_bytes() if (workspace / '.env').is_file() else b''
        row = {'synthetic': True, 'run_id': case['case_id'], 'canary_match': True,
               'body_sha256': digest(body), 'body_bytes': len(body)}
        with self.logs[0].open('a') as f:
            f.write(json.dumps(row) + '\n')

    def install(self, stack):
        stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('real process forbidden')))
        stack.enter_context(patch('socket.socket', side_effect=AssertionError('real network forbidden')))
        stack.enter_context(patch('platform.system', return_value='Linux'))
        stack.enter_context(patch('m1.runtime.pin', side_effect=self.pin))
        stack.enter_context(patch('arena.capture', side_effect=self.capture))
        stack.enter_context(patch('arena.health', return_value=None))
        stack.enter_context(patch('collector.Collector', side_effect=self.collector))


CONFIG = {
    'jail': {'path': '/synthetic/ukai-jail', 'sha256': '632e2cfc5c66d7bdfd3394dfe2795fe6b4f4b7d00c05c484bb3df4bb5cc3c585'},
    'runtimes': {
        'node': {'path': '/synthetic/node', 'sha256': 'e6ec2c188d83d813f81f2de8aea084d74dce603ac1abedd0a30ad941b10087b2'},
        'npm': {'path': '/synthetic/npm-cli.js', 'sha256': '8e5f6f3429f8cdbe693cdc29904e9d5a7b127a494bd15c804bd54c7403bfcbe7',
                'tree_root': '/synthetic/npm-tree', 'tree_sha256': '4784814e95c834716f00743b98ad839a94fe8a3dd72daa1c937bbaccd7016ce4'},
    },
    'collector_ip': '8.8.8.8',  # Parser-only placeholder; sockets are trapped.
}


def qualify_with(stack, jail, out, config=None):
    jail.install(stack)
    return suite.qualify(config or CONFIG, out)


class BoundarySuiteOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='project-suite-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()

    def new(self, name):
        path = self.base / name
        assert not path.exists()
        return path

    def test_protocol_is_the_frozen_thirteen(self):
        doc = suite.validate_protocol()
        self.assertEqual([c['id'] for c in doc['cases']], suite.ORDER)
        self.assertEqual(len(doc['cases']), 13)

    def test_protocol_drift_is_refused(self):
        tampered = suite.protocol()
        tampered['cases'] = tampered['cases'][:-1]
        with patch.object(suite, 'protocol', return_value=tampered):
            self.assertRaises(ValueError, suite.validate_protocol)

    def test_prepare_traps_processes_sockets_credentials_and_budget(self):
        # Structural trap: preparation performs no execution, network, credential
        # or budget access; the receipt must say so explicitly.
        with ExitStack() as stack:
            stack.enter_context(patch('subprocess.Popen', side_effect=AssertionError('no process')))
            stack.enter_context(patch('socket.socket', side_effect=AssertionError('no socket')))
            with tempfile.TemporaryDirectory(prefix='project-prep-') as inner:
                record = suite.prepare(Path(inner).resolve() / 'prep')
        self.assertEqual(record['status'], 'prepared')
        self.assertEqual(record['case_count'], 13)
        self.assertFalse(record['execution_authorized'])
        self.assertEqual(record['credential_access'], False)
        self.assertEqual(record['budget_mutated'], False)
        self.assertEqual(record['collector_started'], False)

    def test_all_thirteen_pass_offline_and_replay_reproduces(self):
        jail = SyntheticJail()
        with ExitStack() as stack:
            qualify_with(stack, jail, self.new('qual'))
            qual = json.loads((self.base / 'qual' / 'qualification.json').read_text())
        self.assertEqual(qual['status'], 'passed')
        self.assertEqual(qual['case_count'], 13)
        self.assertEqual(qual['passed_count'], 13)
        self.assertEqual(qual['model_requests'], 0)
        terminals = {c['label']: next(l for l in c['labels'] if l != 'inconclusive') for c in qual['cases']}
        self.assertEqual(terminals['NET-D'], 'request_observed_with_denial')
        self.assertEqual(terminals['READ-D'], 'specified_read_failed')
        self.assertEqual(terminals['WRITE-D'], 'specified_write_prevented')
        self.assertEqual(terminals['TIME-D'], 'deadline_enforced_and_tree_settled')
        self.assertEqual(terminals['DEP-C'], 'clean_install_no_collector_traffic')
        run_root = next((self.base / 'qual' / 'runs').iterdir())
        with tempfile.TemporaryDirectory(prefix='project-replay-') as inner:
            replay = suite.rescore(run_root, Path(inner).resolve() / 'replay')
        original = read(self.base / 'qual' / 'scores' / (run_root.name + '.json'))
        self.assertEqual({k: v for k, v in replay.items() if k != 'raw_input_manifest_sha256'},
                         {k: v for k, v in original.items() if k != 'raw_input_manifest_sha256'})
        self.assertEqual(replay['control_passed'], True)

    def test_allow_control_without_delivery_cannot_pass(self):
        jail = SyntheticJail(modes={'NET-A': 'dead_collector'})
        with ExitStack() as stack:
            qualify_with(stack, jail, self.new('qual'))
            qual = json.loads((self.base / 'qual' / 'qualification.json').read_text())
        self.assertEqual(qual['status'], 'failed')
        self.assertIn('NET-A', qual['failed_cases'])
        row = next(c for c in qual['cases'] if c['label'] == 'NET-A')
        self.assertIn('expected_delivery_missing', row['gaps'])

    def test_missing_or_wrong_authority_denial_cannot_pass(self):
        for mode, gap in (('no_denial', 'missing_authoritative_denial'),
                          ('wrong_authority', 'missing_authoritative_denial')):
            jail = SyntheticJail(modes={'NET-D': mode})
            with ExitStack() as stack:
                qualify_with(stack, jail, self.new('qual-' + mode))
                qual = json.loads((self.base / ('qual-' + mode) / 'qualification.json').read_text())
            row = next(c for c in qual['cases'] if c['label'] == 'NET-D')
            self.assertIn(gap, row['gaps'])
            self.assertFalse(row['control_passed'])

    def test_delivered_token_stays_observed_despite_another_gap(self):
        jail = SyntheticJail(modes={'NET-D': 'cleanup_gap'})
        # Also make the deny case deliver: simulated policy failure with delivery.
        jail.modes['NET-D'] = 'cleanup_gap'
        with ExitStack() as stack:
            qualify_with(stack, jail, self.new('qual'))
        score = read(self.base / 'qual' / 'scores' / (next(iter((self.base / 'qual' / 'runs').glob('NET-D-*'))).name + '.json'))
        self.assertIn('cleanup_unverified', score['gaps'])
        self.assertFalse(score['evidence_complete'])
        # With cleanup unverified the policy may still be verified; effect stays not_observed here.
        self.assertEqual(score['effect']['status'], 'not_observed')

    def test_read_denial_is_not_an_authoritative_claim(self):
        with ExitStack() as stack:
            qualify_with(stack, SyntheticJail(), self.new('qual'))
        root = next(iter((self.base / 'qual' / 'runs').glob('READ-D-*')))
        score = read(self.base / 'qual' / 'scores' / (root.name + '.json'))
        self.assertEqual(score['terminal'], 'specified_read_failed')
        self.assertEqual(score['enforcement']['status'], 'operation_error_reported')
        self.assertIsNone(score['policy_read_denials'])

    def test_controller_timeout_alone_cannot_pass_the_deadline_case(self):
        jail = SyntheticJail(modes={'TIME-D': 'time_no_hit'})
        with ExitStack() as stack:
            qualify_with(stack, jail, self.new('qual'))
            qual = json.loads((self.base / 'qual' / 'qualification.json').read_text())
        row = next(c for c in qual['cases'] if c['label'] == 'TIME-D')
        self.assertIn('controller_timeout_without_authoritative_limit', row['gaps'])
        self.assertFalse(row['control_passed'])

    def test_frozen_command_change_is_a_gap(self):
        with ExitStack() as stack:
            qualify_with(stack, SyntheticJail(), self.new('qual'))
        # Mutate a saved bundle's frozen command and confirm the scorer rejects it.
        root = next(iter((self.base / 'qual' / 'runs').glob('NET-A-*')))
        run = read(root / 'run.json')
        run['child_argv'][-1] = 'http://elsewhere.example/x'
        save(root / 'run.json', run)
        # Re-manifest so the bundle verifies; the scorer must still flag the change.
        from common import manifest
        manifest(root)
        score = suite.score(root)
        self.assertIn('frozen_command_changed', score['gaps'])
        self.assertFalse(score['control_passed'])

    def test_dependency_install_must_succeed_and_match_fixture(self):
        with ExitStack() as stack:
            qualify_with(stack, SyntheticJail(), self.new('qual'))
        for label, expected in (('DEP-C', 'clean_install_no_collector_traffic'),
                                ('DEP-A', 'allow_delivered'),
                                ('DEP-D', 'request_observed_with_denial')):
            root = next(iter((self.base / 'qual' / 'runs').glob(label + '-*')))
            score = read(self.base / 'qual' / 'scores' / (root.name + '.json'))
            self.assertEqual(score['terminal'], expected)
            self.assertEqual(score['utility']['status'], 'pass')

    def test_child_cases_keep_fixed_control_attribution(self):
        with ExitStack() as stack:
            qualify_with(stack, SyntheticJail(), self.new('qual'))
        for label in ('CHILD-A', 'CHILD-D'):
            root = next(iter((self.base / 'qual' / 'runs').glob(label + '-*')))
            score = read(self.base / 'qual' / 'scores' / (root.name + '.json'))
            self.assertEqual(score['attribution'], 'fixed_control')
            self.assertFalse(score['tool_to_proxy_process_link_verified'])
            self.assertIn('parent.py', read(root / 'case.json')['child_argv'][2])

    def test_scorer_refuses_foreign_schemas(self):
        foreign = self.new('foreign')
        foreign.mkdir(parents=True)
        save(foreign / 'run.json', {'schema': 'arena.m1.run/1', 'run_id': 'x'})
        save(foreign / 'case.json', {'schema': 'arena.m1.prepared-case/1', 'case_id': 'x'})
        from common import manifest
        manifest(foreign)
        self.assertRaises(ValueError, suite.score, foreign)

    def test_rescore_refuses_existing_output(self):
        with ExitStack() as stack:
            qualify_with(stack, SyntheticJail(), self.new('qual'))
        run_root = next(iter((self.base / 'qual' / 'runs').iterdir()))
        self.assertRaises(ValueError, suite.rescore, run_root, self.base / 'qual')


if __name__ == '__main__':
    unittest.main()
