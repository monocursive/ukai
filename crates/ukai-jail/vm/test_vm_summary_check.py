"""Synthetic protocol/evidence cases with literal independently stated summaries."""
import copy
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vm_summary_check as check

CLASSES = ['exec', 'fs.write', 'fs.deny', 'net', 'proxy.net', 'limits']
HOST_ID = 'att_11111111-1111-4111-8111-111111111111'
GUEST_ID = 'att_22222222-2222-4222-8222-222222222222'
ARGV_DIGEST = 'sha256:' + 'a' * 64


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def canonical_hash(value):
    return 'sha256:' + hashlib.sha256(encoded(value).rstrip(b'\n')).hexdigest()


def frame(source, sequence, operation, fields, **extra):
    return dict(schema='ukai.event/1', attempt_id=GUEST_ID, source=source, source_seq=sequence,
                operation=operation, fields=fields, **extra)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.guest = {
            'schema': 'ukai.jail.receipt/1', 'attempt_id': GUEST_ID, 'argv_digest': ARGV_DIGEST,
            'created_at': '2026-11-15T12:00:00Z', 'updated_at': '2026-11-15T12:00:02Z',
            'phase': 'settled', 'outcome': {'kind': 'exited', 'code': 0, 'signal': None, 'cause': None, 'error': None},
            'platform': {'os': 'linux', 'kernel': 'Linux 7.0.0-fixture', 'arch': 'aarch64'},
            'exec_observed': True, 'containment': 'enforced', 'child_protection': 'enforced',
            'process': {'identity': {'value': {'boot_id': 'guest-boot-fixture'}}},
            'policy': {'name': 'agent', 'observe': 'on', 'evidence': 'strict', 'digest': 'sha256:' + 'b' * 64},
            'applied': {'network': {'mode': 'proxy'}, 'filesystem': {}, 'syscalls': {},
                        'limits': [{'key': 'wall', 'requested': '10s', 'applied': True, 'hit': False}]},
            'observer': {'attached': True, 'gaps': []},
            'coverage': {name: {'status': 'active', 'observed_count': int(name in ('fs.write', 'proxy.net')), 'gaps': []}
                         for name in CLASSES},
            'credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True}],
            'state_cleanup': 'complete', 'cleanup_error': None, 'errors': [],
            'lifetime': {'boundary': 'pid_namespace', 'integrity': 'verified', 'tree_empty': True,
                         'verification_scope': 'attempt_tree'},
        }
        self.events = [
            frame('wrapper', 1, 'note', {'kind': 'credential', 'credential_id': 'test',
                                      'transition': 'loaded', 'uses_recorded': True}),
            frame('audit', 1, 'fs.write', {'action': 'opened_for_mutation',
                                         'path': {'kind': 'workspace_relative', 'value': 'greeting.txt'}},
                  outcome={'ok': True}),
            frame('proxy', 1, 'net.connect', {'destination': '192.0.2.10:443', 'reason': 'relayed', 'credentials': ['test']},
                  stage='result', decision='allow', outcome={'ok': True}),
        ]
        self.host = copy.deepcopy(self.guest)
        self.host.update(attempt_id=HOST_ID, credentials=[], state_cleanup='not_needed')
        self.host['platform']['os'] = 'macos'
        self.host['lifetime']['native'] = {'os': 'linux', 'details': {
            'transport': 'ukai.jail.vm-transport/1', 'vm_boot_id': 'vm-fixture',
            'disk_sha256': 'd' * 64, 'vsock_port': 1024, 'guest_receipt': 'evidence/jail.json'}}
        self.binding = {'attempt_id': HOST_ID, 'boot_id': 'vm-fixture', 'guest_attempt_id': GUEST_ID,
                        'guest_boot_id': 'guest-boot-fixture', 'profile': 'agent', 'argv_digest': ARGV_DIGEST}
        self.transport = {'schema': 'ukai.jail.vm-transport/1', 'attempt_id': HOST_ID,
                          'boot_id': 'vm-fixture', 'guest_kernel': '7.0.0-fixture', 'vsock_port': 1024,
                          'image': {'disk_sha256': 'd' * 64, 'seed_sha256': 'e' * 64,
                                    'helper_sha256': 'f' * 64, 'custodian_sha256': 'c' * 64}}
        self.write()

    def write(self):
        journal = self.root / 'evidence/guest-journal'
        journal.mkdir(parents=True, exist_ok=True)
        guest_bytes = encoded(self.guest)
        digest = hashlib.sha256(guest_bytes).hexdigest()
        self.transport['guest_receipt_sha256'] = digest
        self.host['lifetime']['native']['details']['guest_receipt_sha256'] = 'sha256:' + digest
        final = frame('wrapper', 2, 'jail.receipt', {'phase': 'settled', 'receipt_digest': canonical_hash(self.guest)})
        trace = b''.join(encoded(event) for event in self.events + [final])
        manifest = {'schema': 'ukai.vm.guest-journal/1', 'guest_attempt_id': GUEST_ID,
                    'guest_receipt_sha256': digest, 'state': 'exported', 'bytes': len(trace), 'parts': 1,
                    'sha256': hashlib.sha256(trace).hexdigest()}
        for path, data in [('jail.json', encoded(self.host)), ('evidence/jail.json', guest_bytes),
                           ('evidence/vm-binding.json', encoded(self.binding)),
                           ('vm-transport.json', encoded(self.transport)),
                           ('evidence/guest-journal/manifest.json', encoded(manifest)),
                           ('evidence/guest-journal/0000.part', trace)]:
            (self.root / path).write_bytes(data)
        self.write_host()

    def write_host(self):
        (self.root / 'jail.json').write_bytes(encoded(self.host))
        (self.root / 'trace.ndjson').write_bytes(encoded({
            'attempt_id': HOST_ID, 'source': 'wrapper', 'source_seq': 1, 'operation': 'jail.receipt',
            'fields': {'phase': self.host['phase'], 'receipt_digest': canonical_hash(self.host)}}))

    def expected(self):
        # These literal facts are specified independently of the verifier.
        summary = {'schema': 'ukai.jail.summary/1', 'attempt_id': HOST_ID,
                   'receipt_digest': canonical_hash(self.host), 'journal': 'complete', 'lines': [
            {'line': 'status', 'text': 'settled · exited 0 · 2s ±1s attempt (wall clock) · survivors: none (verified)',
             'facts': {'phase': 'settled', 'outcome': 'exited', 'code': 0, 'signal': None, 'cause': None,
                       'exec_to_settled_ms': None, 'attempt_wall_ms': 2000, 'survivors': 'none_verified',
                       'errors': [], 'integrity': 'verified'}},
            {'line': 'workspace', 'text': 'workspace: 1 path opened for writing',
             'facts': {'bound': 'exact', 'opened_for_writing': 1, 'renamed': 0, 'removed': 0, 'unnamed': 0,
                       'refused': 0, 'refused_bound': 'exact',
                       'paths': [{'kind': 'workspace_relative', 'value': 'greeting.txt'}], 'omitted': 0}},
            {'line': 'network', 'text': 'network: allowed 192.0.2.10:443 (1)',
             'facts': {'mode': 'proxy', 'bound': 'exact',
                       'allowed': [{'destination': '192.0.2.10:443', 'results': 1, 'connect_failed': 0}],
                       'denied': [], 'omitted': 0, 'resolver_refused': None}},
            {'line': 'credentials', 'text': 'credential test: vault, never staged · used on 1 proxy result · 0 credential refusals',
             'facts': {'credentials': [{'id': 'test', 'mode': 'vault', 'never_staged': True, 'uses': 1,
                                        'uses_bound': 'exact', 'unconfirmed': 0, 'transitions': ['loaded']}],
                       'omitted': 0, 'refusals': 0, 'refusals_bound': 'exact'}},
            {'line': 'evidence', 'text': 'evidence: 6/6 classes active, no gaps · reads and file contents are not observed',
             'facts': {'observe': 'on', 'evidence': 'strict', 'attached': True,
                       'classes': {name: 'active' for name in CLASSES}, 'gaps': [], 'disagree': []}},
        ]}
        text = ''.join('ukai-jail: ' + line['text'] + '\n' for line in summary['lines'])
        text += ('ukai-jail: vm: guest-reported facts in evidence/jail.json · boot vm-fixture · image '
                 + 'd' * 16 + ' · vsock 1024 · receipt sha256:' + self.transport['guest_receipt_sha256'][:16] + '\n')
        text += 'ukai-jail: receipt ' + str(self.root / 'jail.json') + '\n'
        return summary, text


def install_exposure(fixture, report=None, status=None, *, receipt_pid=67, receipt_start=1001, supervisor_pid=66):
    """Hand-stated controller report, independent of sampler/verifier code."""
    fixture.guest['process']['identity'] = {'kind': 'linux_boot_start', 'value': {
        'boot_id': fixture.binding['guest_boot_id'], 'pid': receipt_pid, 'start_time_ticks': receipt_start}}
    fixture.transport['supervisor_pid'] = supervisor_pid
    fixture.write()
    source_sha = hashlib.sha256(Path(__file__).with_name('guest_exposure.py').read_bytes()).hexdigest()
    if report is None:
        native = fixture.binding['native_program']
        counts = {'readable': 2, 'unreadable': 0, 'oversize': 0, 'vanished': 0, 'unstable': 0, 'capped': 0}
        report = {'schema': 'ukai.vm.sampled-exposure/2', 'host_attempt_id': HOST_ID,
            'service_boot_id': fixture.binding['boot_id'], 'guest_attempt_id': GUEST_ID,
            'guest_boot_id': fixture.binding['guest_boot_id'], 'catalog_sha256': native['catalog_sha256'],
            'executable_sha256': native['executable_sha256'], 'sampler_sha256': source_sha,
            'guest_receipt_sha256': fixture.transport['guest_receipt_sha256'], 'finished': True,
            'actual_values_retained': False, 'scope': 'periodic-readable-environment-and-argv-only',
            'continuous_coverage_claimed': False, 'arbitrary_memory_examined': False,
            'period_ns': 100_000_000, 'first_ns': 100, 'last_ns': 100, 'observed_interval_ns': 0,
            'maximum_gap_ns': 0, 'maximum_tick_duration_ns': 5, 'tick_count': 1,
            'late_poll_count': 0, 'missed_tick_count': 0,
            'reads': {name: dict(counts) for name in ('environment', 'argv')},
            'verified_program_reads': {name: dict(counts, readable=1) for name in ('environment', 'argv')},
            'receipt_program_reads': {name: dict(counts, readable=1) for name in ('environment', 'argv')},
            'receipt_program_observed': True, 'receipt_process': {'pid': receipt_pid, 'starttime': receipt_start},
            'verified_program_observed': True, 'observation_incomplete': False, 'scan_errors': {}, 'hits': [],
            'processes': [{'pid': supervisor_pid, 'starttime': 1000, 'roles': ['supervisor', 'workload_uid']},
                          {'pid': receipt_pid, 'starttime': receipt_start, 'roles': ['catalog_program', 'descendant', 'workload_uid']}],
            'lifecycle': {'started_ns': 90, 'supervisor_exit_observed_ns': 110, 'stopped_ns': 120, 'stop_reason': 'supervisor_exit'},
            'supervisor': {'pid': supervisor_pid, 'starttime': 1000}, 'catalog_executable_identity': {'dev': 1, 'ino': 200},
            'workload_uid': 1001, 'limits': {'read_bytes': 2 * 1024 * 1024, 'process_count': 4096,
                'tick_bytes': 16 * 1024 * 1024, 'tick_ns': 50_000_000, 'hit_count': 4096}}
    raw = encoded(report); sha = hashlib.sha256(raw).hexdigest()
    (fixture.root / 'evidence/sampled-exposure.json').write_bytes(raw)
    fixture.binding['sampled_exposure_sha256'] = sha
    fixture.transport['image']['sampler_sha256'] = source_sha
    fixture.transport['sampled_exposure'] = {'status': status or ('incomplete' if report['observation_incomplete'] else 'complete'),
                                           'path': 'evidence/sampled-exposure.json', 'sha256': sha}
    fixture.write()
    return report


class VmSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'attempt'
        self.fixture = Fixture(self.root)
        self.summary, self.text = self.fixture.expected()

    def verify(self, **kwargs):
        return check.verify_attempt(self.root, self.summary, self.text, **kwargs)

    def native_fixture(self):
        catalog = json.loads((Path(__file__).parent / 'fixtures/guest-program-catalog.json').read_bytes())
        entry = catalog['entries'][0]
        data = encoded(catalog)
        digest = hashlib.sha256(data).hexdigest()
        suffix = [b'-p', 'hello ☃'.encode(), b'\xff']
        def argv_hash(words):
            data = b'ukai.jail.argv/1\0' + len(words).to_bytes(8, 'big')
            data += b''.join(len(word).to_bytes(8, 'big') + word for word in words)
            return 'sha256:' + hashlib.sha256(data).hexdigest()
        intent = {'schema': 'ukai.vm.guest-native-launch/1', 'catalog_sha256': digest, 'entry_id': entry['id'],
                  'launch_name': entry['alias'], 'profile_sha256': entry['profile_sha256'], 'state': 'attempt',
                  'selected_credential_id': 'test', 'argv_suffix': [base64.b64encode(word).decode() for word in suffix],
                  'request_argv_digest': argv_hash([entry['alias'].encode(), *suffix]),
                  'resolved_argv_digest': argv_hash([entry['executable'].encode(), *suffix]),
                  'expected_policy_digest': self.fixture.guest['policy']['digest']}
        binding = {name: intent[name] for name in ('catalog_sha256', 'entry_id', 'profile_sha256',
                   'selected_credential_id', 'state', 'request_argv_digest', 'resolved_argv_digest')}
        binding.update(executable_sha256=entry['executable_sha256'], policy_digest=intent['expected_policy_digest'])
        self.fixture.binding.update(native_program=binding, argv_digest=intent['resolved_argv_digest'])
        self.fixture.host['argv_digest'] = self.fixture.guest['argv_digest'] = intent['resolved_argv_digest']
        self.fixture.transport['native_program'] = intent
        self.fixture.transport['image']['guest_program_catalog_sha256'] = digest
        (self.root / 'guest-native-catalog.json').write_bytes(data)
        self.fixture.write()
        self.summary, self.text = self.fixture.expected()
        return catalog

    def test_native_requested_and_resolved_program_evidence_is_bound(self):
        self.native_fixture()
        result = self.verify()
        self.assertEqual(result['scope'], 'bound_guest')
        self.assertIn('guest-native-catalog.json', result['evidence_sha256'])
        self.assertFalse(result['qualified'])

    def test_native_intent_and_binding_every_field_is_checked(self):
        self.native_fixture()
        for location in ('native_program', 'binding'):
            original = copy.deepcopy(self.fixture.transport if location == 'native_program' else self.fixture.binding)
            target = 'vm-transport.json' if location == 'native_program' else 'evidence/vm-binding.json'
            for field in original['native_program']:
                with self.subTest(location=location, field=field):
                    changed = copy.deepcopy(original); changed['native_program'][field] = 'different'
                    (self.root / target).write_bytes(encoded(changed))
                    with self.assertRaises(check.VerificationError): self.verify()
            (self.root / target).write_bytes(encoded(original))
        for bad in (None, {}, True):
            changed = copy.deepcopy(self.fixture.transport); changed['native_program'] = bad
            (self.root / 'vm-transport.json').write_bytes(encoded(changed))
            with self.assertRaises(check.VerificationError): self.verify()

    def test_native_catalog_cannot_disappear_be_rehashed_malformed_or_downgrade(self):
        catalog = self.native_fixture()
        path = self.root / 'guest-native-catalog.json'; data = path.read_bytes()
        path.unlink()
        with self.assertRaises(check.VerificationError): self.verify()
        path.write_bytes(data + b' ')
        with self.assertRaises(check.VerificationError): self.verify()
        catalog['entries'][0]['program_root'] = True
        data = encoded(catalog); path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        self.fixture.binding['native_program']['catalog_sha256'] = digest
        self.fixture.transport['native_program']['catalog_sha256'] = digest
        self.fixture.transport['image']['guest_program_catalog_sha256'] = digest
        self.fixture.write()
        with self.assertRaises(check.VerificationError): self.verify()
        del self.fixture.binding['native_program']; del self.fixture.transport['native_program']
        self.fixture.write()
        with self.assertRaises(check.VerificationError): self.verify()

    def test_native_expected_policy_cannot_disagree_with_receipt_even_when_binding_matches(self):
        self.native_fixture()
        self.fixture.transport['native_program']['expected_policy_digest'] = 'sha256:' + '9' * 64
        self.fixture.binding['native_program']['policy_digest'] = 'sha256:' + '9' * 64
        self.fixture.write()
        with self.assertRaises(check.VerificationError): self.verify()

    def test_native_suffix_requires_canonical_base64_without_nul(self):
        self.native_fixture()
        for suffix in (['A==='], ['AA=='], ['Zh=='], [True], 'not-a-list'):
            with self.subTest(suffix=suffix):
                changed = copy.deepcopy(self.fixture.transport)
                changed['native_program']['argv_suffix'] = suffix
                (self.root / 'vm-transport.json').write_bytes(encoded(changed))
                with self.assertRaises(check.VerificationError): self.verify()

    def test_literal_execution_in_catalog_image_does_not_claim_native_resolution(self):
        self.fixture.transport['image']['guest_program_catalog_sha256'] = 'a' * 64
        self.fixture.write()
        self.assertEqual(self.verify()['scope'], 'bound_guest')

    def test_independent_catalog_parser_obeys_shared_conformance_vectors(self):
        vectors = json.loads((Path(__file__).parent / 'fixtures/guest-program-catalog-vectors.json').read_bytes())
        for case in vectors['valid']:
            with self.subTest(case=case['name']):
                self.assertEqual(check.parse_native_catalog(case['data'].encode()), json.loads(case['data']))
        for case in vectors['invalid']:
            with self.subTest(case=case['name']), self.assertRaises((check.VerificationError, ValueError)):
                check.parse_native_catalog(case['data'].encode())

    def test_native_full_argv_bound_includes_executable_prefix(self):
        self.native_fixture()
        for words in ([b''] * 4096, [b'x' * (1024 * 1024)]):
            with self.subTest(arguments=len(words), bytes=sum(map(len, words))):
                changed = copy.deepcopy(self.fixture.transport)
                changed['native_program']['argv_suffix'] = [base64.b64encode(word).decode() for word in words]
                (self.root / 'vm-transport.json').write_bytes(encoded(changed))
                with self.assertRaisesRegex(check.VerificationError, 'resolved argv exceeds'):
                    self.verify()

    def test_sampling_is_independent_of_summary_rendering_and_runtime_outcome(self):
        self.native_fixture(); report = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        self.assertEqual(self.verify()['sampling']['state'], 'complete')
        self.assertTrue(self.verify()['sampling']['no_hits'])
        report['hits'] = [{'pid': 67, 'starttime': 1001, 'channel': 'environment', 'representation': 'raw', 'identity_stable': True}]
        install_exposure(self.fixture, report)
        result = self.verify()
        self.assertEqual(result['outcome'], 'PASS')
        self.assertEqual(result['sampling']['state'], 'complete')
        self.assertFalse(result['sampling']['no_hits'])
        report['reads']['environment']['unreadable'] = 1
        report['reads']['argv']['unreadable'] = 1
        report['scan_errors']['selected_process_unreadable'] = 1
        report['observation_incomplete'] = True
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'incomplete')
        self.assertEqual(self.summary['lines'][0]['facts']['outcome'], 'exited')

    def test_sampling_rehashed_identity_counter_scope_and_source_mutations_are_invalid(self):
        self.native_fixture(); original = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        mutations = [lambda r: r.update(guest_receipt_sha256='0' * 64), lambda r: r.update(host_attempt_id='att_other'),
                     lambda r: r.update(guest_boot_id='other'), lambda r: r.update(catalog_sha256='0' * 64),
                     lambda r: r.update(executable_sha256='0' * 64), lambda r: r.update(sampler_sha256='0' * 64),
                     lambda r: r.update(actual_values_retained=True), lambda r: r.update(arbitrary_memory_examined=True),
                     lambda r: r.update(period_ns=200_000_000), lambda r: r.update(observation_incomplete=True),
                     lambda r: r['reads']['environment'].update(readable=True),
                     lambda r: r['verified_program_reads']['argv'].update(readable=3),
                     lambda r: r['supervisor'].update(starttime=999),
                     lambda r: r['lifecycle'].update(started_ns=200),
                     lambda r: r['processes'][0].update(roles=['raw-command']),
                     lambda r: r.update(extra='not allowed')]
        for change in mutations:
            with self.subTest(mutation=change):
                report = copy.deepcopy(original); change(report)
                install_exposure(self.fixture, report)
                result = self.verify()
                self.assertEqual(result['outcome'], 'PASS')
                self.assertEqual(result['sampling']['state'], 'invalid')

    def test_sampling_distinguishes_captured_supervisor_from_receipt_workload(self):
        self.native_fixture()
        # The retained 23e --version probe released supervisor PID 640, while
        # its actual Linux receipt names workload PID 672/start tick 2673.
        # The remaining observations here are synthetic parser inputs; no
        # sampler report existed for that failed /1 export.
        report = install_exposure(self.fixture, receipt_pid=672, receipt_start=2673, supervisor_pid=640)
        self.summary, self.text = self.fixture.expected()
        result = self.verify()
        self.assertEqual(result['outcome'], 'PASS')
        self.assertEqual(result['sampling']['state'], 'complete')
        self.assertEqual(result['sampling']['supervisor']['pid'], 640)
        self.assertEqual(result['sampling']['receipt_process'], {'pid': 672, 'starttime': 2673})
        for change in (lambda r: r.update(receipt_process=dict(r['supervisor'])),
                       lambda r: r['receipt_process'].update(starttime=2674),
                       lambda r: r['receipt_process'].update(pid=True),
                       lambda r: r['supervisor'].update(pid=672),
                       lambda r: r['supervisor'].update(starttime=None),
                       lambda r: r.update(schema='ukai.vm.sampled-exposure/1'),
                       lambda r: r.pop('receipt_program_reads')):
            changed = copy.deepcopy(report); change(changed)
            install_exposure(self.fixture, changed, receipt_pid=672, receipt_start=2673, supervisor_pid=640)
            with self.subTest(change=change):
                self.assertEqual(self.verify()['sampling']['state'], 'invalid')
                self.assertEqual(self.verify()['outcome'], 'PASS')
        install_exposure(self.fixture, report, receipt_pid=672, receipt_start=2673, supervisor_pid=640)
        for value in (None, True, 672, 0, 2 ** 32):
            self.fixture.transport['supervisor_pid'] = value; self.fixture.write()
            self.assertEqual(self.verify()['sampling']['state'], 'invalid')
        self.fixture.transport.pop('supervisor_pid')
        self.fixture.transport['sampled_exposure']['status'] = 'unavailable'
        self.fixture.write()
        self.assertEqual(self.verify()['sampling'], {'state': 'unavailable', 'reason': 'released_supervisor_missing'})

    def test_sampling_receipt_root_needs_its_own_catalog_observations(self):
        self.native_fixture(); original = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        report = copy.deepcopy(original)
        for row in report['receipt_program_reads'].values(): row['readable'] = 0
        report.update(receipt_program_observed=False, observation_incomplete=True)
        install_exposure(self.fixture, report)
        result = self.verify()['sampling']
        self.assertEqual(result['state'], 'incomplete')
        self.assertTrue(result['verified_program_observed'])
        self.assertFalse(result['receipt_program_observed'])
        report['observation_incomplete'] = False
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')
        for change in (lambda r: r['receipt_program_reads']['argv'].update(readable=0),
                       lambda r: r['receipt_program_reads']['argv'].update(readable=True),
                       lambda r: [row.update(readable=2) for row in r['receipt_program_reads'].values()],
                       lambda r: r['processes'][1].update(roles=['descendant', 'workload_uid']),
                       lambda r: r['processes'][1].update(pid=68)):
            report = copy.deepcopy(original); change(report)
            install_exposure(self.fixture, report)
            with self.subTest(change=change): self.assertEqual(self.verify()['sampling']['state'], 'invalid')

    def test_sampling_unknown_supervisor_birth_is_only_zero_observation_initialization_failure(self):
        self.native_fixture(); report = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        report.update(tick_count=0, first_ns=None, last_ns=None, observed_interval_ns=0,
                      maximum_gap_ns=0, maximum_tick_duration_ns=0, late_poll_count=0, missed_tick_count=0,
                      processes=[], verified_program_observed=False, receipt_program_observed=False,
                      observation_incomplete=True, scan_errors={'monitor_initialization_failed': 1},
                      catalog_executable_identity={'dev': 0, 'ino': 0})
        report['supervisor']['starttime'] = None
        for name in ('reads', 'verified_program_reads', 'receipt_program_reads'):
            for row in report[name].values(): row.update({key: 0 for key in row})
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'incomplete')
        self.assertIsNone(self.verify()['sampling']['supervisor']['starttime'])
        report['hits'] = [{'pid': 67, 'starttime': 1001, 'channel': 'environment',
                           'representation': 'raw', 'identity_stable': False}]
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')
        report['hits'] = []
        report['scan_errors'] = {'monitor_worker_failed': 1}
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')

    def test_sampling_population_time_domain_and_complete_lifecycle_are_consistent(self):
        self.native_fixture(); original = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        mutations = [lambda r: r['reads']['environment'].update(readable=3),
                     lambda r: r['verified_program_reads']['argv'].update(readable=2),
                     lambda r: [row.update(readable=4097) for row in r['reads'].values()],
                     lambda r: r.update(workload_uid=0), lambda r: r.update(workload_uid=2 ** 32),
                     lambda r: r.update(maximum_tick_duration_ns=50_000_001),
                     lambda r: r['processes'][0].update(roles=['workload_uid']),
                     lambda r: r['lifecycle'].update(supervisor_exit_observed_ns=121),
                     lambda r: r.update(hits=[{'pid': 99, 'starttime': 1001, 'channel': 'environment',
                         'representation': 'raw', 'identity_stable': True}]),
                     lambda r: r.update(hits=[{'pid': 67, 'starttime': 1001, 'channel': 'environment',
                         'representation': 'raw', 'identity_stable': False}])]
        for change in mutations:
            with self.subTest(mutation=change):
                report = copy.deepcopy(original); change(report)
                install_exposure(self.fixture, report)
                result = self.verify()
                self.assertEqual(result['outcome'], 'PASS')
                self.assertEqual(result['sampling']['state'], 'invalid')
        # A real observer worker can fail before the supervisor exits. Preserve
        # those truthful timestamps as incomplete evidence, never reorder them.
        report = copy.deepcopy(original)
        report['scan_errors']['monitor_worker_failed'] = 1
        report['observation_incomplete'] = True
        report['lifecycle'].update(stop_reason='worker_failed', supervisor_exit_observed_ns=121)
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'incomplete')
        # Manual pure sampler observations remain valid, but the live native
        # harness separately requires a supervisor-exit lifecycle bracket.
        report = copy.deepcopy(original)
        report['lifecycle'] = dict(started_ns=None, stopped_ns=None, supervisor_exit_observed_ns=None, stop_reason='manual')
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'complete')

    def test_sampling_gap_counters_and_zero_inode_fallback_are_consistent(self):
        self.native_fixture(); report = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        report.update(tick_count=2, last_ns=200_000_100, observed_interval_ns=200_000_000,
                      maximum_gap_ns=200_000_000, late_poll_count=1, missed_tick_count=1)
        report['lifecycle'].update(supervisor_exit_observed_ns=200_000_110, stopped_ns=200_000_120)
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'complete')
        for field in ('late_poll_count', 'missed_tick_count'):
            altered = copy.deepcopy(report); altered[field] = 0
            install_exposure(self.fixture, altered)
            self.assertEqual(self.verify()['sampling']['state'], 'invalid')
        report.update(tick_count=0, first_ns=None, last_ns=None, observed_interval_ns=0,
                      maximum_gap_ns=0, maximum_tick_duration_ns=0, late_poll_count=0, missed_tick_count=0,
                      processes=[], verified_program_observed=False, receipt_program_observed=False, observation_incomplete=True,
                      scan_errors={'monitor_initialization_failed': 1}, catalog_executable_identity={'dev': 0, 'ino': 0})
        for name in ('reads', 'verified_program_reads', 'receipt_program_reads'):
            for row in report[name].values():
                row.update({key: 0 for key in row})
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'incomplete')
        report['catalog_executable_identity']['dev'] = 1
        install_exposure(self.fixture, report)
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')

    def test_sampling_missing_oversized_hash_and_status_contradictions_fail_only_sampling(self):
        self.native_fixture(); report = install_exposure(self.fixture)
        self.summary, self.text = self.fixture.expected()
        path = self.root / 'evidence/sampled-exposure.json'
        path.unlink()
        self.fixture.transport['sampled_exposure'] = {'status': 'unavailable', 'reason': 'report_missing'}
        self.fixture.write()
        self.assertEqual(self.verify()['sampling']['state'], 'unavailable')
        install_exposure(self.fixture, report)
        path.write_bytes(b' ' * (512 * 1024 + 1))
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')
        install_exposure(self.fixture, report)
        self.fixture.transport['sampled_exposure']['status'] = 'incomplete'; self.fixture.write()
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')
        install_exposure(self.fixture, report)
        self.fixture.binding['sampled_exposure_sha256'] = '0' * 64; self.fixture.write()
        self.assertEqual(self.verify()['sampling']['state'], 'invalid')

    def test_independent_validator_consumes_shared_sampler_report_fixture(self):
        directory = Path(__file__).parent / 'fixtures'
        report = json.loads((directory / 'sampled-exposure-report.json').read_bytes())
        raw = (directory / 'sampled-exposure-receipt.json').read_bytes()
        guest = json.loads(raw)
        context = json.loads((directory / 'sampled-exposure-context.json').read_bytes())
        binding = {'attempt_id': context['host_attempt_id'], 'boot_id': context['service_boot_id'],
                   'guest_boot_id': context['guest_boot_id']}
        native = {key: context[key] for key in ('catalog_sha256', 'executable_sha256')}
        result = check.sampled_exposure_report(report, guest, hashlib.sha256(raw).hexdigest(), binding, native,
                                               context['sampler_sha256'], context['supervisor_pid'])
        self.assertEqual(result['state'], 'complete')
        self.assertEqual(result['tick_count'], 2)

    def test_full_summary_with_guest_events_and_host_identity(self):
        result = self.verify()
        self.assertEqual(result['scope'], 'bound_guest')
        self.assertEqual((result['journal_frames'], result['lines']), (4, 5))
        self.assertFalse(result['qualified'])
        self.assertEqual(set(result['evidence_sha256']), {'jail.json', 'trace.ndjson', 'vm-transport.json',
            'evidence/jail.json', 'evidence/vm-binding.json', 'evidence/guest-journal/manifest.json',
            'evidence/guest-journal/0000.part'})

    def test_changed_numbers_including_bool_and_float_are_rejected(self):
        for value in (0, 2, True, 1.0, '1', None):
            with self.subTest(value=value):
                altered = copy.deepcopy(self.summary)
                altered['lines'][3]['facts']['credentials'][0]['uses'] = value
                with self.assertRaises(check.VerificationError):check.verify_attempt(self.root, altered, self.text)

    def test_changed_text_missing_duplicate_reordered_and_extra_lines_reject(self):
        mutations = [lambda j:j['lines'][0].update(text='settled'), lambda j:j['lines'].pop(),
                     lambda j:j['lines'].append(copy.deepcopy(j['lines'][0])), lambda j:j['lines'].reverse(),
                     lambda j:j.update(extra='unsupported')]
        for mutate in mutations:
            changed = copy.deepcopy(self.summary);mutate(changed)
            with self.subTest(mutation=mutate), self.assertRaises(check.VerificationError):
                check.verify_attempt(self.root, changed, self.text)
        for text in (self.text.replace('boot vm-fixture', 'boot other'), self.text.rstrip('\n'),
                     self.text.replace('ukai-jail: vm:', 'ukai-jail: forged:'), self.text+'extra\n'):
            with self.subTest(text=text[-40:]), self.assertRaises(check.VerificationError):
                check.verify_attempt(self.root, self.summary, text)

    def test_each_literal_binding_field_is_checked(self):
        for key in self.fixture.binding:
            with self.subTest(key=key):
                value = dict(self.fixture.binding);value[key] = 'different'
                (self.root/'evidence/vm-binding.json').write_bytes(encoded(value))
                with self.assertRaises(check.VerificationError):self.verify()
        self.fixture.write()
        value = dict(self.fixture.binding, native_program={})
        (self.root/'evidence/vm-binding.json').write_bytes(encoded(value))
        with self.assertRaisesRegex(check.VerificationError, 'native program'):self.verify()

    def test_transport_image_attempt_kernel_port_hash_and_boot_are_checked(self):
        changes = [('boot_id','other'), ('attempt_id','other'), ('guest_kernel','other'),
                   ('vsock_port',True), ('guest_receipt_sha256','0'*64), ('schema','different'),
                   ('image',dict(self.fixture.transport['image'],disk_sha256='a'*64))]
        for key,value in changes:
            with self.subTest(key=key):
                changed=dict(self.fixture.transport);changed[key]=value
                (self.root/'vm-transport.json').write_bytes(encoded(changed))
                with self.assertRaises(check.VerificationError):self.verify()

    def test_every_required_evidence_file_is_required(self):
        for relative in ['jail.json','trace.ndjson','vm-transport.json','evidence/jail.json',
                         'evidence/vm-binding.json','evidence/guest-journal/manifest.json',
                         'evidence/guest-journal/0000.part']:
            with self.subTest(relative=relative):
                path=self.root/relative;data=path.read_bytes();path.unlink()
                with self.assertRaises(check.VerificationError):self.verify()
                path.write_bytes(data)

    def test_named_guest_cannot_downgrade_by_losing_transport_or_hash_shape(self):
        details=self.fixture.host['lifetime']['native']['details']
        original=copy.deepcopy(details)
        for field,value in [('transport',None),('transport','different'),('transport','missing'),
                            ('guest_receipt_sha256',None),('guest_receipt_sha256',''),
                            ('guest_receipt_sha256','bad'),('guest_receipt_sha256',False)]:
            with self.subTest(field=field,value=value):
                details.clear();details.update(original)
                if value=='missing':details.pop(field)
                else:details[field]=value
                self.fixture.write_host()
                # Forge precisely the host-only rendering the old downgrade
                # branch would accept; an unchanged guest summary would reject
                # for unrelated text differences and miss this regression.
                trace=(self.root/'trace.ndjson').read_bytes()
                frames=[json.loads(line) for line in trace.splitlines()]
                forged=check.compute_summary(self.fixture.host,frames,'complete',len(trace))
                text=''.join('ukai-jail: '+line['text']+'\n' for line in forged['lines'])
                text+='ukai-jail: receipt '+str(self.root/'jail.json')+'\n'
                with self.assertRaises(check.VerificationError):
                    check.verify_attempt(self.root,forged,text)

    def test_part_bytes_extra_part_and_unavailable_manifest_fail(self):
        path=self.root/'evidence/guest-journal/0000.part';original=path.read_bytes();path.write_bytes(original+b' ')
        with self.assertRaises(check.VerificationError):self.verify()
        path.write_bytes(original);extra=path.with_name('0001.part');extra.write_bytes(b'')
        with self.assertRaises(check.VerificationError):self.verify()
        extra.unlink();manifest=path.with_name('manifest.json');value=json.loads(manifest.read_text())
        value.update(state='absent',bytes=None,parts=0,sha256=None);manifest.write_bytes(encoded(value));path.unlink()
        with self.assertRaises(check.VerificationError):self.verify()

    def test_rehashed_journal_still_requires_sequence_and_canonical_settlement(self):
        for change in ('sequence', 'receipt_note', 'foreign_attempt', 'duplicate_key'):
            with self.subTest(change=change):
                self.fixture.write();path=self.root/'evidence/guest-journal/0000.part';lines=path.read_bytes().splitlines()
                event=json.loads(lines[0])
                if change=='sequence':event['source_seq']=7;lines[0]=encoded(event).rstrip(b'\n')
                if change=='foreign_attempt':event['attempt_id']=HOST_ID;lines[0]=encoded(event).rstrip(b'\n')
                if change=='receipt_note':
                    event=json.loads(lines[-1]);event['fields']['receipt_digest']='sha256:'+'0'*64;lines[-1]=encoded(event).rstrip(b'\n')
                if change=='duplicate_key':lines[0]=lines[0].replace(b'"source_seq":1',b'"source_seq":1,"source_seq":1')
                data=b'\n'.join(lines)+b'\n';path.write_bytes(data);manifest=path.with_name('manifest.json');value=json.loads(manifest.read_text());value.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest());manifest.write_bytes(encoded(value))
                with self.assertRaises(check.VerificationError):self.verify()

    def test_changed_cleanup_changes_host_line_even_with_updated_digest(self):
        self.fixture.host['state_cleanup']='pending';self.fixture.write_host()
        self.summary['receipt_digest']=canonical_hash(self.fixture.host)
        with self.assertRaises(check.VerificationError):self.verify()
        cleanup={'line':'cleanup','text':'vendor state cleanup pending: run ukai-jail gc',
                 'facts':{'state_cleanup':'pending','child_protection':'enforced'}}
        self.summary['lines'].append(cleanup)
        self.text=self.text.replace('ukai-jail: vm:', 'ukai-jail: '+cleanup['text']+'\nukai-jail: vm:')
        self.assertEqual(self.verify()['outcome'],'PASS')

    def test_mirrored_environment_and_limits_cannot_silently_differ(self):
        for changed in ('environment', 'limit'):
            with self.subTest(changed=changed):
                self.fixture.write()
                original=copy.deepcopy(self.fixture.host)
                if changed=='environment':self.fixture.host['applied']['environment_names']=['UNEXPECTED']
                else:self.fixture.host['applied']['limits'][0]['requested']='999s'
                self.fixture.write_host()
                with self.assertRaises(check.VerificationError):self.verify()
                self.fixture.host=original

    def test_host_wall_hit_is_preserved_without_claiming_the_guest_hit_it(self):
        self.fixture.host['applied']['limits'][0]['hit']=True
        self.fixture.host['outcome']['cause']='wall_expiry';self.fixture.write_host()
        self.summary['receipt_digest']=canonical_hash(self.fixture.host)
        self.summary['lines'][0]['facts']['cause']='wall_expiry'
        self.summary['lines'][0]['text']=self.summary['lines'][0]['text'].replace('exited 0','exited 0 (wall_expiry)')
        line={'line':'limits','text':'limits: hit wall (10s)',
              'facts':{'hit':[{'key':'wall','requested':'10s'}],'not_applied':[]}}
        self.summary['lines'].append(line)
        self.text=self.text.replace('exited 0','exited 0 (wall_expiry)').replace('ukai-jail: vm:',
            'ukai-jail: '+line['text']+'\nukai-jail: vm:')
        self.assertEqual(self.verify()['outcome'],'PASS')
        self.assertFalse(self.fixture.guest['applied']['limits'][0]['hit'])

    def test_changed_host_journal_receipt_note_is_rejected(self):
        (self.root/'trace.ndjson').write_bytes(b'{}\n')
        with self.assertRaisesRegex(check.VerificationError,'host journal'):self.verify()

    def test_symlink_hardlink_directory_and_oversized_files_refuse(self):
        part=self.root/'evidence/guest-journal/0000.part';data=part.read_bytes();outside=self.root.parent/'outside';outside.write_bytes(data)
        part.unlink();part.symlink_to(outside)
        with self.assertRaises(check.VerificationError):self.verify()
        part.unlink();os.link(outside,part)
        with self.assertRaises(check.VerificationError):self.verify()
        part.unlink();part.mkdir()
        with self.assertRaises(check.VerificationError):self.verify()
        part.rmdir();part.write_bytes(b'x'*(check.JOURNAL_PART+1))
        with self.assertRaises(check.VerificationError):self.verify()

    def test_root_directory_symlink_refuses(self):
        alias=self.root.parent/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(check.VerificationError):check.verify_attempt(alias,self.summary,self.text)

    def test_explicit_address_mapping_is_required_and_keeps_identity(self):
        altered=json.loads(json.dumps(self.summary).replace('192.0.2.10','<peer>'))
        text=self.text.replace('192.0.2.10','<peer>')
        with self.assertRaises(check.VerificationError):check.verify_attempt(self.root,altered,text)
        result=check.verify_attempt(self.root,altered,text,display_mapping={'192.0.2.10':'<peer>'})
        self.assertTrue(result['display_mapping_applied'])
        for mapping in ({'1':'2'},{'exact':'at_least'},{'/':'~'},{'192.0.2.10':'x\ny'}):
            with self.subTest(mapping=mapping), self.assertRaises(check.VerificationError):self.verify(display_mapping=mapping)

    def test_explicit_relocated_receipt_path_is_not_inferred(self):
        old='/retained/original/jail.json';text=self.text.replace(str(self.root/'jail.json'),old)
        with self.assertRaises(check.VerificationError):check.verify_attempt(self.root,self.summary,text)
        self.assertEqual(check.verify_attempt(self.root,self.summary,text,
            display_mapping={str(self.root/'jail.json'):old})['outcome'],'PASS')

    def test_duplicate_json_in_retained_receipt_fails(self):
        path=self.root/'jail.json';data=path.read_bytes();path.write_bytes(data.replace(b'"phase":"settled"',b'"phase":"settled","phase":"settled"'))
        with self.assertRaises(check.VerificationError):self.verify()

    def test_journal_counts_are_recomputed_after_all_byte_bindings_are_updated(self):
        self.fixture.events[2]['fields']['credentials']=[];self.fixture.write()
        self.summary['receipt_digest']=canonical_hash(self.fixture.host)
        self.text=self.text.replace(self.text.split('receipt sha256:')[1].splitlines()[0],self.fixture.transport['guest_receipt_sha256'][:16])
        with self.assertRaises(check.VerificationError):self.verify()

    def test_unknown_legacy_vm_without_guest_authority_stays_host_only(self):
        host = {'schema': 'ukai.jail.receipt/1', 'attempt_id': HOST_ID, 'phase': 'prepared',
                'policy': {'name': 'tool', 'observe': 'off', 'evidence': 'best-effort'},
                'outcome': {'kind': 'unknown', 'code': None, 'signal': None, 'cause': 'wall_expiry', 'error': None},
                'lifetime': {'tree_empty': None, 'integrity': 'lost', 'boundary': 'pid_namespace',
                             'verification_scope': 'attempt_tree', 'native': {'details': {'transport': 'ukai.jail.vm-transport/1'}}},
                'applied': {'network': {'mode': 'pending'}}, 'observer': {'attached': False},
                'state_cleanup': 'pending', 'child_protection': 'enforced', 'errors': [{'code': 'tree_unknown'}]}
        (self.root/'jail.json').write_bytes(encoded(host));(self.root/'trace.ndjson').unlink()
        status = 'NOT settled (prepared) · outcome unknown (wall_expiry) · survivors: NOT verified · errors: tree_unknown: run ukai-jail gc · integrity lost: state retained'
        workspace = 'workspace: not observed (--observe off)'
        evidence = 'evidence: observation off: exec, file and connect classes not observed · proxy.net, limits not observed · no local journal'
        cleanup = 'vendor state cleanup pending: run ukai-jail gc'
        summary = {'schema':'ukai.jail.summary/1','attempt_id':HOST_ID,'receipt_digest':canonical_hash(host),
                   'journal':'absent','lines':[
            {'line':'status','text':status,'facts':{'phase':'prepared','outcome':'unknown','code':None,'signal':None,
                'cause':'wall_expiry','exec_to_settled_ms':None,'attempt_wall_ms':None,'survivors':'not_verified',
                'errors':['tree_unknown'],'integrity':'lost'}},
            {'line':'workspace','text':workspace,'facts':{'bound':'not_observed','opened_for_writing':None,
                'renamed':None,'removed':None,'unnamed':None,'refused':None,'refused_bound':'not_observed','paths':[],'omitted':0}},
            {'line':'network','text':'network: not applied','facts':{'mode':'pending','bound':'not_observed',
                'allowed':[],'denied':[],'omitted':0,'resolver_refused':None}},
            {'line':'evidence','text':evidence,'facts':{'observe':'off','evidence':'best-effort','attached':False,
                'classes':{name:'unsupported' for name in CLASSES},'gaps':[],'disagree':[]}},
            {'line':'cleanup','text':cleanup,'facts':{'state_cleanup':'pending','child_protection':'enforced'}}]}
        text=''.join('ukai-jail: '+line['text']+'\n' for line in summary['lines'])+'ukai-jail: receipt '+str(self.root/'jail.json')+'\n'
        result=check.verify_attempt(self.root,summary,text)
        self.assertEqual((result['scope'],result['journal']),('host_only','absent'))
        self.assertEqual(set(result['evidence_sha256']),{'jail.json'})
        with self.assertRaises(check.VerificationError):check.verify_attempt(self.root,summary,text+'ukai-jail: vm: fabricated\n')

    def test_cli_is_standalone_and_rejects_mutation_under_optimized_python(self):
        summary=self.root.parent/'summary.json';text=self.root.parent/'summary.txt';summary.write_bytes(encoded(self.summary));text.write_text(self.text)
        argv=[sys.executable,'-I','-O',check.__file__,str(self.root),str(summary),str(text)]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.summary['lines'][3]['facts']['credentials'][0]['uses']=2;summary.write_bytes(encoded(self.summary))
        result=subprocess.run(argv,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,1)
        self.assertNotIn('192.0.2.10',result.stderr)


if __name__ == '__main__':unittest.main()


class ManagedSamplingTests(unittest.TestCase):
    """Shared hand-specified vector and rehashed, semantically invalid variants."""
    def setUp(self):
        self.f = json.loads((Path(__file__).parent / 'fixtures/managed-sampled-exposure.json').read_text())
        self.prepared = json.loads(self.f['prepared_raw'])
        self.guest = json.loads(self.f['receipt_raw'])
        self.report = self.f['report']
        self.entry = json.loads(self.f['catalog_raw'])['entries'][0]

    def judge(self, *, prepared=None, raw=None):
        if prepared is not None:
            raw = encoded(prepared)
            self.report['managed_gate']['prepared_receipt_sha256'] = hashlib.sha256(raw).hexdigest()
            self.report['managed_gate']['prepared_receipt_digest'] = canonical_hash(prepared)
        return check.sampled_exposure_report(self.report, self.guest, self.report['guest_receipt_sha256'],
            self.f['binding'], self.f['native'], self.f['sampler_sha256'], self.f['supervisor_pid'],
            prepared_raw=self.f['prepared_raw'].encode() if raw is None else raw, native_entry=self.entry)

    def test_manual_vector_and_nonzero_target_can_have_complete_observation(self):
        self.assertEqual(self.judge()['state'], 'complete')
        self.assertEqual(self.judge()['schema'], 'ukai.vm.sampled-exposure/3')
        self.guest['outcome']['code'] = 1
        self.assertEqual(self.judge()['state'], 'complete')

    def test_duplicate_host_occurrences_and_explicit_port_keep_exact_authority(self):
        for record in (self.prepared, self.guest):
            record['policy']['grants'].append(copy.deepcopy(record['policy']['grants'][-1]))
            record['applied']['network']['allowed_hosts'].append('api.example.com:443')
            # A second explicit :443 occurrence removes the implicit TLS-only restriction.
            record['applied']['network'].pop('tls_only')
        self.assertEqual(self.judge(prepared=self.prepared)['state'], 'complete')
        self.prepared['policy']['grants'].pop()
        with self.assertRaises(check.VerificationError): self.judge(prepared=self.prepared)

    def test_rehashed_prepared_authority_mutations_refuse(self):
        for path, value in [
            (('platform','os'), 'macos'), (('jail','backend'), 'fake'), (('phase',), 'running'), (('exec_observed',), True), (('outcome','kind'), 'unknown'),
            (('outcome','code'), 0), (('containment',), 'unknown'), (('child_protection',), 'refused'),
            (('errors',), ['not_ready']), (('cleanup_error',), {}), (('vendor_state',), {}),
            (('process','pid'), 12), (('process','identity','value','start_time_ticks'), 102),
            (('process','identity','value','boot_id'), 'other'), (('policy','digest'), 'sha256:'+'a'*64),
            (('policy','requirements'), ['execution_boundary']), (('policy','grants'), []),
            (('observer','attached'), True), (('credentials',0,'id'), 'other'), (('argv_digest',), 'sha256:'+'a'*64),
            (('applied','filesystem','mounts'), []), (('applied','network','tls_only'), []),
            (('applied','syscalls','digest'), 'unbound'), (('applied','limits',0,'requested'), '21000'),
            (('applied','limits',1,'required'), 1), (('applied','limits',2,'hit'), True),
            (('applied','environment_names'), ['TOKEN=secret']), (('applied','terminal'), {}),
        ]:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.prepared); node = changed
                for key in path[:-1]: node = node[key]
                node[path[-1]] = value
                with self.assertRaises(check.VerificationError): self.judge(prepared=changed)

    def test_required_prepared_null_fields_cannot_disappear_under_rehashed_bindings(self):
        for parent, key in (((), 'cleanup_error'), (('lifetime',), 'tree_empty'), (('outcome',), 'error'),
                            (('observer',), 'backend'), (('credentials',0), 'digest'), (('applied','limits',0), 'hit')):
            with self.subTest(parent=parent,key=key):
                changed = copy.deepcopy(self.prepared); node = changed
                for field in parent: node = node[field]
                del node[key]
                with self.assertRaises(check.VerificationError): self.judge(prepared=changed)

    def test_managed_shape_causal_time_and_positive_binding_refuse(self):
        original = copy.deepcopy(self.report)
        for key, value in [('schema','unknown'), ('prepared_observed_ns',True), ('prepared_validated_ns',99),
                           ('armed_observed_ns',299), ('release_started_ns',399), ('release_completed_ns',499),
                           ('failure','new_failure'), ('prepared_process',{'pid':10,'starttime':100})]:
            with self.subTest(key=key):
                self.report = copy.deepcopy(original); self.report['managed_gate'][key] = value
                with self.assertRaises(check.VerificationError): self.judge()
        for mutation in ('null', 'extra', 'missing', 'downgrade'):
            self.report = copy.deepcopy(original)
            if mutation == 'null': self.report['managed_gate'] = None
            elif mutation == 'extra': self.report['managed_gate']['other'] = 0
            elif mutation == 'missing': del self.report['managed_gate']['failure']
            else: self.report['schema'] = 'ukai.vm.sampled-exposure/2'
            with self.assertRaises(check.VerificationError): self.judge()

    def test_fast_exit_and_partial_gate_are_incomplete_never_malformed_or_complete(self):
        for failure in (None, 'early_stop', 'release_failed', 'cancelled'):
            self.report['managed_gate']['failure'] = failure
            self.report['managed_gate']['release_completed_ns'] = 200000850
            self.report['observation_incomplete'] = True
            self.assertEqual(self.judge()['state'], 'incomplete')
            self.report['observation_incomplete'] = False
            with self.assertRaises(check.VerificationError): self.judge()
        self.report['managed_gate'].update(failure='arming_failed', armed_observed_ns=None,
                                          release_started_ns=None, release_completed_ns=None)
        self.report['observation_incomplete'] = True
        self.assertEqual(self.judge()['state'], 'incomplete')

    def test_zero_tick_valid_prepared_initialization_failure_is_explicit(self):
        for key in ('reads', 'verified_program_reads', 'receipt_program_reads'):
            for row in self.report[key].values():
                for state in row: row[state] = 0
        for key in ('tick_count','observed_interval_ns','maximum_gap_ns','maximum_tick_duration_ns','late_poll_count','missed_tick_count'):
            self.report[key] = 0
        self.report.update(first_ns=None,last_ns=None,processes=[],verified_program_observed=False,
                           receipt_program_observed=False,observation_incomplete=True,
                           scan_errors={'monitor_initialization_failed':1},catalog_executable_identity={'dev':0,'ino':0})
        self.report['supervisor']['starttime'] = None
        self.report['managed_gate'].update(failure='arming_failed',armed_observed_ns=None,release_started_ns=None,release_completed_ns=None)
        self.report['lifecycle'].update(stop_reason='worker_failed',supervisor_exit_observed_ns=None,stopped_ns=201)
        self.assertEqual(self.judge()['state'], 'incomplete')
        self.report['observation_incomplete'] = False
        with self.assertRaises(check.VerificationError): self.judge()

    def test_prepared_duplicate_float_and_raw_digest_refuse(self):
        raw = self.f['prepared_raw'].encode()
        for changed in (raw+b' ', raw.replace(b'"phase": "prepared"',b'"phase": "prepared", "phase": "prepared"'),
                        raw.replace(b'"pid": 11',b'"pid": 11.0',1)):
            with self.assertRaises(check.VerificationError): self.judge(raw=changed)
        # Even a correctly rehashed raw/canonical lookalike cannot introduce duplicate object keys.
        changed = raw.replace(b'"phase": "prepared"',b'"phase": "prepared", "phase": "prepared"')
        self.report['managed_gate']['prepared_receipt_sha256'] = hashlib.sha256(changed).hexdigest()
        with self.assertRaises(check.VerificationError): self.judge(raw=changed)

    def test_transport_contract_and_anchored_prepared_export_are_required(self):
        import struct
        def argv(words):
            words = [word.encode() for word in words]
            return 'sha256:' + hashlib.sha256(b'ukai.jail.argv/1\0' + struct.pack('>Q', len(words))
                + b''.join(struct.pack('>Q', len(word)) + word for word in words)).hexdigest()
        native = self.f['native']
        native['request_argv_digest'] = argv([self.entry['alias'], '--version'])
        native['resolved_argv_digest'] = argv([self.entry['executable'], '--version'])
        self.f['binding']['native_program'] = native
        self.f['binding']['argv_digest'] = native['resolved_argv_digest']
        self.prepared['argv_digest'] = self.guest['argv_digest'] = native['resolved_argv_digest']
        intent = {key: value for key, value in native.items() if key not in ('executable_sha256', 'policy_digest')}
        intent.update(schema='ukai.vm.guest-native-launch/1', launch_name=self.entry['alias'],
                      expected_policy_digest=native['policy_digest'], argv_suffix=[base64.b64encode(b'--version').decode()])
        pin = hashlib.sha256(Path(check.__file__).with_name('guest_exposure.py').read_bytes()).hexdigest()
        raw = encoded(self.prepared)
        self.report['managed_gate'].update(prepared_receipt_sha256=hashlib.sha256(raw).hexdigest(),
                                          prepared_receipt_digest=canonical_hash(self.prepared))
        self.report.update(sampler_sha256=pin,guest_receipt_sha256=hashlib.sha256(encoded(self.guest)).hexdigest())
        report_raw = encoded(self.report); report_sha = hashlib.sha256(report_raw).hexdigest()
        self.f['binding']['sampled_exposure_sha256'] = report_sha
        transport = {'native_program':intent, 'supervisor_pid':10, 'sampled_exposure_contract':check.MANAGED_SAMPLE_SCHEMA,
                     'image':{'guest_program_catalog_sha256':native['catalog_sha256'], 'sampler_sha256':pin},
                     'sampled_exposure':{'status':'complete','path':'evidence/sampled-exposure.json','sha256':report_sha}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / 'evidence').mkdir()
            (root / 'guest-native-catalog.json').write_text(self.f['catalog_raw'])
            (root / 'evidence/sampled-exposure.json').write_bytes(report_raw)
            prepared_path = root / 'evidence/managed-prepared.json'; prepared_path.write_bytes(raw)
            def verify():
                with check.EvidenceReader(root) as reader:
                    return check.sampled_exposure(reader,self.guest,transport,self.f['binding'],self.report['guest_receipt_sha256'])
            self.assertEqual(verify()['state'],'complete')
            for contract in (None,'ukai.vm.sampled-exposure/2','ukai.vm.sampled-exposure/4'):
                transport['sampled_exposure_contract'] = contract
                self.assertEqual(verify()['state'],'invalid')
            transport['sampled_exposure_contract'] = check.MANAGED_SAMPLE_SCHEMA
            prepared_path.unlink(); outside = root / 'outside'; outside.write_bytes(raw)
            prepared_path.symlink_to(outside)
            self.assertEqual(verify()['state'],'invalid')
            prepared_path.unlink(); os.link(outside,prepared_path)
            self.assertEqual(verify()['state'],'invalid')
            prepared_path.unlink(); prepared_path.write_bytes(b'x' * (512*1024+1))
            self.assertEqual(verify()['state'],'invalid')


if __name__ == '__main__':
    unittest.main()
