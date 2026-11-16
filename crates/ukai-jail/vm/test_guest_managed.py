"""Managed guest gate authority and real private-pipe regressions; no VM."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import guest_program as gp


def prepared_fixture():
    profile = b'name="example"\njail="agent"\n[network]\nallow=["api.example.test"]\n'
    entry = dict(alias='example', executable='/opt/ukai/programs/example/1/example', install_root='/opt/ukai/programs/example/1', profile_sha256=hashlib.sha256(profile).hexdigest())
    request = dict(wall_seconds=60, allow_hosts=[], native_program=dict(
        expected_policy_digest='sha256:' + 'a' * 64, resolved_argv_digest='sha256:' + 'b' * 64,
        selected_credential_id='token'))
    identity = dict(kind='linux_boot_start', value=dict(boot_id='boot-1', pid=11, start_time_ticks=101))
    receipt = dict(schema='ukai.jail.receipt/1', attempt_id='att_00000000-0000-4000-8000-000000000001',
        revision=2, phase='prepared', exec_observed=False, outcome=dict(kind='pending', code=None,
        signal=None, cause=None, error=None), errors=[], cleanup_error=None,
        argv_digest='sha256:' + 'b' * 64, platform=dict(os='linux', arch='aarch64', kernel='Linux test'),
        jail=dict(component='ukai-jail', backend='bubblewrap'), process=dict(pid=11, identity=identity),
        policy=dict(name='agent', digest='sha256:' + 'a' * 64, observe='on', evidence='strict',
            requirements=sorted(gp.NATIVE_REQUIREMENTS), grants=[
                dict(kind='read_only', value=entry['install_root'], by='program_resolution'),
                dict(kind='allow_host', value='api.example.test:443', by='operator')]),
        containment='enforced', child_protection='enforced',
        lifetime=dict(boundary='pid_namespace', tree_empty=None, integrity='verified', verification_scope='attempt_tree'),
        credentials=[dict(id='token', mode='vault', never_staged=True, digest=None, digest_unavailable_reason='never_staged')],
        observer=dict(backend=None, set=None, attached=False,
            sources=dict(wrapper='supported', audit='unsupported', proxy='unsupported'), gaps=[]),
        applied=dict(environment_names=['PATH', 'HOME'], removed_environment_names=[], filesystem=dict(mechanism='bubblewrap-binds', protected_coverage='existing_and_root', mounts=[
            dict(path=entry['install_root'], mode='ro'), dict(path='/work', mode='rw')]),
            network=dict(mode='proxy', mechanism='network-namespace+outside-http-proxy+loopback-bridge+unix-peer-mediation',
                allowed_hosts=['api.example.test:443'], tls_only=['api.example.test:443']),
            syscalls=dict(mechanism='seccomp-bpf+seccomp-user-notification', digest='sha256:' + 'c' * 64),
            limits=[dict(key=key, requested=value, mechanism=mechanism, scope='tree', required=True, applied=True, hit=False)
                for key, value, mechanism in [('wall', '60000', 'boottime-deadline'), ('pids', '64', 'pids.max'),
                    ('mem', '536870912', 'memory.max'), ('swap', '0', 'memory.swap.max')]]))
    return receipt, request, entry, profile


def control_for(receipt):
    return dict(schema='ukai.jail.control/1', attempt_id=receipt['attempt_id'], seq=1, kind='prepared',
        receipt_phase='prepared', receipt_digest=gp.canonical_digest(receipt), outcome=receipt['outcome'], error=None)


class PreparedCodecTests(unittest.TestCase):
    def validate(self, receipt, request, entry, profile, control=None):
        return gp.validate_prepared(json.dumps(receipt).encode(), control or control_for(receipt),
            request, entry, profile, 'boot-1', Path('/work'))

    def test_independent_shared_prepared_vector_matches_guest_authority(self):
        value = json.loads((Path(__file__).parent/'fixtures/managed-sampled-exposure.json').read_bytes())
        entry = json.loads(value['catalog_raw'])['entries'][0]
        _, identity = gp.validate_prepared(value['prepared_raw'].encode(), value['control'],
            value['request'], entry, value['profile_raw'].encode(), value['binding']['guest_boot_id'],
            Path('/mnt/workspace'))
        self.assertEqual(identity, value['report']['managed_gate']['prepared_process'])

    def test_actual_prepared_pending_observer_is_not_final_attached_observer(self):
        fixture = prepared_fixture()
        _, identity = self.validate(*fixture)
        self.assertEqual(identity, dict(pid=11, starttime=101))
        fixture[0]['observer']['attached'] = True
        with self.assertRaises(ValueError):
            self.validate(*fixture)

    def test_canonical_utf16_order_and_integer_domain(self):
        self.assertEqual(gp.canonical_value({'\ue000': 1, '\U00010000': 2}), '{"\U00010000":2,"\ue000":1}')
        for data in [b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{"x":18446744073709551616}',
                     b'{"x":"\\ud800"}', b'{}' * 2]:
            with self.subTest(data=data), self.assertRaises((ValueError, UnicodeError)):
                gp.strict_json(data, 512)

    def test_rehashed_prepared_cannot_choose_authority(self):
        mutations = [
            lambda r: r['policy'].update(digest='sha256:' + 'd' * 64),
            lambda r: r.update(argv_digest='sha256:' + 'd' * 64),
            lambda r: r['policy']['requirements'].pop(),
            lambda r: r['policy']['grants'].append(dict(kind='allow_host', value='other.test:443', by='operator')),
            lambda r: r['credentials'][0].update(id='other'),
            lambda r: r['process']['identity']['value'].update(boot_id='other'),
            lambda r: r['process']['identity']['value'].update(start_time_ticks=True),
            lambda r: r['process'].update(pid=12),
            lambda r: r.update(exec_observed=True),
            lambda r: r['outcome'].update(kind='unknown'),
            lambda r: r['applied']['limits'][0].update(requested='60001'),
            lambda r: r['applied']['limits'][0].update(applied=1),
            lambda r: r['applied']['network'].update(tls_only=[]),
            lambda r: r['lifetime'].update(integrity='lost'),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = prepared_fixture(); mutation(fixture[0])
                with self.assertRaises(ValueError):
                    self.validate(*fixture)

    def test_control_raw_digest_and_duplicate_or_float_are_not_canonical(self):
        fixture = prepared_fixture(); control = control_for(fixture[0])
        control['receipt_digest'] = 'sha256:' + hashlib.sha256(json.dumps(fixture[0]).encode()).hexdigest()
        with self.assertRaises(ValueError):
            self.validate(*fixture, control=control)
        valid = json.dumps(control_for(fixture[0])).encode()
        self.assertEqual(gp.control_message(valid)['seq'], 1)
        for bad in [valid.replace(b'"seq": 1', b'"seq": true'), valid.replace(b'"seq": 1', b'"seq": 1.0'),
                    valid.replace(b'"seq": 1', b'"seq": 1, "seq": 1'), b' ' * (gp.CONTROL_MAX + 1)]:
            with self.subTest(data=bad[:50]), self.assertRaises(ValueError):
                gp.control_message(bad)

    def test_post_prepared_control_states_and_typed_outcome(self):
        value = control_for(prepared_fixture()[0])
        value.update(seq=2, kind='settled', receipt_phase='settled',
                     outcome=dict(kind='exited', code=0, signal=None, cause=None, error=None))
        self.assertEqual(gp.control_message(json.dumps(value).encode()), value)
        for mutate in (lambda v: v.update(receipt_phase='arbitrary'),
                       lambda v: v['outcome'].update(code=True),
                       lambda v: v.update(error='not-an-error-object'),
                       lambda v: v['outcome'].pop('signal')):
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(ValueError): gp.control_message(json.dumps(changed).encode())

    def test_mount_and_environment_rows_must_have_typed_shapes(self):
        for mutate in (lambda r: r['applied']['filesystem']['mounts'].append({'path':'/x', 'mode':True}),
                       lambda r: r['applied'].update(environment_names='PATH'),
                       lambda r: r['applied'].update(removed_environment_names=[None])):
            fixture = prepared_fixture(); mutate(fixture[0])
            with self.assertRaises(ValueError): self.validate(*fixture)

    def test_network_occurrence_order_and_explicit_port_override_match_snapshot(self):
        self.assertEqual(gp.native_network(['z.test', 'a.test', 'z.test', 'a.test:443']),
            (['z.test:443', 'a.test:443', 'z.test:443', 'a.test:443'], ['z.test:443', 'z.test:443']))
        receipt, request, entry, profile = prepared_fixture()
        request['allow_hosts'] = ['api.example.test:443', 'a.test']
        receipt['policy']['grants'] += [dict(kind='allow_host', value='api.example.test:443', by='operator'),
                                       dict(kind='allow_host', value='a.test:443', by='operator')]
        receipt['applied']['network'].update(allowed_hosts=['api.example.test:443','api.example.test:443','a.test:443'],
                                            tls_only=['a.test:443'])
        self.validate(receipt, request, entry, profile)

    def test_network_expected_authority_preserves_explicit_port_semantics(self):
        self.assertEqual(gp.native_network(['API.EXAMPLE.TEST.', 'api.example.test:443', '*.example.test', '[::1]']),
            (['api.example.test:443', 'api.example.test:443', '*.example.test:443', '[::1]:443'],
             ['*.example.test:443', '[::1]:443']))
        for value in ['a.test:0443', 'user@a.test', 'a.test/x', 'é.test', 'a..test', '127.1', 'a.test:65536']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                gp.native_network([value])




class ManagedSamplingTests(unittest.TestCase):
    """Existing proc fixtures; /2 stays unchanged and /3 adds causal scope."""
    def setUp(self):
        from test_guest_exposure import SamplerTests
        self.fixture = SamplerTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def gate(self, started=1):
        return dict(schema=gp.GATE_SCHEMA, prepared_receipt_sha256='a'*64,
            prepared_receipt_digest='sha256:'+'b'*64, prepared_process=dict(pid=11, starttime=101),
            prepared_observed_ns=0, prepared_validated_ns=started,
            armed_observed_ns=11, release_started_ns=12, release_completed_ns=13, failure=None)

    def final(self):
        from test_guest_exposure import receipt
        value = json.loads(receipt())
        value.update(phase='settled', exec_observed=True, cleanup_error=None,
                     lifetime=dict(tree_empty=True, integrity='verified'))
        return json.dumps(value).encode()

    def test_complete_requires_managed_release_and_verified_normal_tree_endpoint(self):
        from test_guest_exposure import binding
        for mutation, incomplete in [
            (lambda g, r: None, False),
            (lambda g, r: g.update(release_completed_ns=31), True),
            (lambda g, r: g.update(failure='early_stop'), True),
            (lambda g, r: r['lifetime'].update(tree_empty=None), True),
            (lambda g, r: r.update(exec_observed=False), True),
        ]:
            with self.subTest(incomplete=incomplete):
                sample = self.fixture.sampler(); sample.sample(10); sample.sample(20)
                sample.lifecycle = dict(started_ns=1, supervisor_exit_observed_ns=30,
                                        stopped_ns=32, stop_reason='supervisor_exit')
                gate, receipt = self.gate(), json.loads(self.final()); mutation(gate, receipt)
                result = sample.finish(json.dumps(receipt).encode(), binding(), gate)
                self.assertEqual(result['schema'], 'ukai.vm.sampled-exposure/3')
                self.assertIs(result['observation_incomplete'], incomplete)
                self.assertEqual(result['managed_gate'], gate)

    def test_arming_requires_actual_first_tick_but_not_preexec_catalog_observation(self):
        import time
        self.fixture.process(11, 10, 101, 1000, self.fixture.other)
        monitor, process = self.fixture.monitor(prepared_process=(11, 101))
        self.assertTrue(monitor.armed_event.wait(1))
        self.assertFalse(monitor.arm_failed)
        self.assertGreaterEqual(monitor.armed_observed_ns, monitor.started)
        self.assertEqual(monitor.sampler.program_counts['argv']['readable'], 0)
        # A later exact executable observation is still required for completion.
        process.returncode = 0
        self.assertTrue(monitor.stop())
        self.assertIn((11, 101), monitor.sampler.identities)
        self.assertEqual(monitor.sampler.errors, {})

    def test_first_tick_loss_or_hit_refuses_arming_without_resetting_counters(self):
        from test_guest_exposure import CANARY
        for bad in ('missing', 'hit'):
            with self.subTest(bad=bad):
                if bad == 'missing': (self.fixture.proc/'11/environ').unlink()
                else: (self.fixture.proc/'11/environ').write_bytes(b'TOKEN='+CANARY+b'\0')
                monitor, process = self.fixture.monitor(prepared_process=(11, 101))
                self.assertTrue(monitor.armed_event.wait(1))
                self.assertTrue(monitor.arm_failed)
                self.assertIsNone(monitor.armed_observed_ns)
                process.returncode = 0; self.assertTrue(monitor.stop())
                self.assertTrue(monitor.sampler.hits or monitor.sampler.counts['environment']['vanished'])

    def test_armed_ack_does_not_authorize_after_monitor_failure_or_stop(self):
        monitor, process = self.fixture.monitor(prepared_process=(11, 101))
        self.assertTrue(monitor.armed_event.wait(1))
        self.assertTrue(monitor.ready_for_release())
        monitor.failure = 'monitor_worker_failed'
        self.assertFalse(monitor.ready_for_release())
        monitor.failure = None
        self.assertTrue(monitor.stop())
        self.assertFalse(monitor.ready_for_release())

    def test_initialization_failure_retains_valid_nullable_prefix_not_fake_release(self):
        from test_guest_exposure import binding
        import time
        observed = time.monotonic_ns()
        monitor, process = self.fixture.monitor(catalog_executable_path=self.fixture.root/'absent',
                                                prepared_process=(11, 101))
        gate = self.gate(observed)
        gate.update(prepared_observed_ns=observed, armed_observed_ns=None,
                    release_started_ns=None, release_completed_ns=None, failure='arming_failed')
        process.returncode = 125
        result = monitor.finish(self.final(), binding(), gate)
        self.assertTrue(result['observation_incomplete'])
        self.assertEqual(result['tick_count'], 0)
        self.assertIsNone(result['first_ns'])
        self.assertEqual(result['scan_errors'], {'monitor_initialization_failed': 1})
        self.assertGreaterEqual(result['lifecycle']['started_ns'], observed)


class PrivateGateTests(unittest.TestCase):
    def setUp(self):
        import os, tempfile, threading, types
        from guest_harness import load_guest
        self.guest = load_guest()
        temporary = tempfile.TemporaryDirectory(prefix='ukai-managed-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.guest.WORKSPACE = Path('/work')
        self.receipt, self.request, self.entry, self.profile = prepared_fixture()
        self.account = types.SimpleNamespace(pw_dir=str(self.root), pw_uid=os.getuid())
        self.infrastructure = types.SimpleNamespace(pids={})
        self.source_check = mock.Mock()
        self.gate = self.guest.ManagedNativeGate(self.account, self.request, self.entry, {'catalog':1},
            self.infrastructure, 'boot-1', [b'public-protected-value'], self.source_check)
        self.addCleanup(self.gate.close)
        self.addCleanup(self.gate.stop)
        self.gate.process = types.SimpleNamespace(pid=10, poll=lambda: None)
        self.path = self.root/'.local/share/ukai/attempts'/self.receipt['attempt_id']/'jail.json'
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps(self.receipt))
        self.guest.guest_program = types.SimpleNamespace(**vars(gp))
        self.guest.guest_program._read = mock.Mock(return_value=self.profile)
        self.guest.guest_program.verify_catalog = mock.Mock(return_value={'catalog':1})
        self.guest.guest_exposure = types.SimpleNamespace(**vars(self.guest.guest_exposure))
        def monitor(*args, **kwargs):
            event = threading.Event(); event.set()
            return types.SimpleNamespace(armed_event=event, arm_failed=False,
                armed_observed_ns=self.guest.managed_ns(), stop=mock.Mock(return_value=True),
                ready_for_release=mock.Mock(return_value=True))
        self.guest.guest_exposure.Monitor = mock.Mock(side_effect=monitor)

    def prepare(self):
        self.gate.receive(json.dumps(control_for(self.receipt)).encode()+b'\n')
        self.assertTrue(self.gate.ready.wait(2))
        self.gate.worker.join(1)

    def test_worker_cannot_release_and_exact_single_frame_closes_writer(self):
        import os, select
        self.prepare()
        self.assertIsNone(self.gate.failure)
        self.assertFalse(select.select([self.gate.child_gate], [], [], 0)[0])
        self.assertEqual(self.gate.prepared, self.path.read_bytes())
        self.gate.progress()
        wire = os.read(self.gate.child_gate, 2048)
        self.assertEqual(json.loads(wire), dict(schema='ukai.jail.gate/1', action='release',
            attempt_id=self.receipt['attempt_id'], policy_digest=self.request['native_program']['expected_policy_digest']))
        self.assertEqual(os.read(self.gate.child_gate, 1), b'')
        self.assertIsNone(self.gate.writer)
        self.gate.progress()  # No resend.
        self.assertEqual(self.source_check.call_count, 2)

    def test_source_change_cancellation_and_control_eof_never_release(self):
        import os
        self.prepare(); self.source_check.side_effect = ValueError('synthetic change')
        self.gate.progress()
        self.assertEqual(self.gate.failure, 'source_changed')
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')
        self.assertIsNone(self.gate.context['release_started_ns'])

    def test_cancelled_worker_cannot_release_even_if_validation_finishes(self):
        import os, threading
        entered, proceed = threading.Event(), threading.Event()
        def verify(**kwargs):
            entered.set(); proceed.wait(1); kwargs['notify'](); return {'catalog':1}
        self.guest.guest_program.verify_catalog.side_effect = verify
        self.gate.receive(json.dumps(control_for(self.receipt)).encode()+b'\n')
        self.assertTrue(entered.wait(1))
        self.gate.refuse('cancelled'); proceed.set()
        self.assertTrue(self.gate.ready.wait(1)); self.gate.progress()
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')
        self.assertEqual(self.gate.failure, 'cancelled')
        self.guest.guest_exposure.Monitor.assert_not_called()

    def test_duplicate_control_and_early_eof_close_private_gate(self):
        import os
        self.gate.receive(b'{"schema":1,"schema":2}\n')
        self.assertEqual(self.gate.failure, 'control_invalid')
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')

    def test_control_eof_after_prepared_before_release_is_not_authorization(self):
        import os
        self.prepare(); self.gate.receive(b''); self.gate.progress()
        self.assertEqual(self.gate.failure, 'control_invalid')
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')

    def test_prepared_symlink_or_protected_bytes_never_start_monitor(self):
        import os
        self.path.unlink(); self.path.symlink_to(self.root/'other')
        self.prepare()
        self.assertEqual(self.gate.failure, 'prepared_invalid')
        self.gate.progress(); self.assertEqual(os.read(self.gate.child_gate, 1024), b'')
        self.guest.guest_exposure.Monitor.assert_not_called()

    def test_protected_prepared_field_refused_before_retention(self):
        self.receipt['accidental'] = 'public-protected-value'
        self.path.write_text(json.dumps(self.receipt)); self.prepare()
        self.assertEqual(self.gate.failure, 'prepared_invalid')
        self.assertIsNone(self.gate.prepared)
        self.guest.guest_exposure.Monitor.assert_not_called()

    def test_rehashed_wrong_authority_is_refused(self):
        self.receipt['policy']['digest'] = 'sha256:'+'f'*64
        self.path.write_text(json.dumps(self.receipt)); self.prepare()
        self.assertEqual(self.gate.failure, 'prepared_invalid')
        self.assertIsNone(self.gate.prepared)

    def test_observer_failure_after_ack_never_releases(self):
        import os
        self.prepare()
        self.gate.monitor.ready_for_release.return_value = False
        self.gate.progress()
        self.assertEqual(self.gate.failure, 'arming_failed')
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')
        self.assertIsNone(self.gate.context['release_started_ns'])

    def later_control(self, kind, sequence=2):
        value = control_for(self.receipt)
        value.update(seq=sequence, kind=kind, receipt_phase={
            'exec_confirmed':'enforced', 'settled':'settled', 'refused':'refused', 'unsettled':'prepared'}[kind])
        if kind == 'settled':
            value['outcome'] = dict(kind='exited', code=0, signal=None, cause=None, error=None)
        elif kind == 'refused':
            error = dict(code='gate_refused', stage='prepared', message='public refusal',
                         remediation_category='inspect_state')
            value.update(error=error, outcome=dict(kind='refused', code=None, signal=None, cause=None, error=error))
        return json.dumps(value).encode()+b'\n'

    def test_positive_control_before_release_cannot_authorize_gate(self):
        import os
        self.prepare()
        self.gate.receive(self.later_control('exec_confirmed'))
        self.gate.progress()
        self.assertEqual(self.gate.failure, 'control_invalid')
        self.assertIsNone(self.gate.context['release_started_ns'])
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')

    def test_settled_before_release_is_not_valid_completion(self):
        import os
        self.prepare()
        self.gate.receive(self.later_control('settled'))
        self.gate.progress()
        self.assertEqual(self.gate.failure, 'control_invalid')
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')

    def test_terminal_refusal_before_release_closes_gate_without_relabeling_control(self):
        import os
        self.prepare()
        self.gate.receive(self.later_control('refused'))
        self.gate.progress()
        self.assertEqual(self.gate.failure, 'early_stop')
        self.assertEqual(self.gate.last_kind, 'refused')
        self.assertIsNone(self.gate.context['release_started_ns'])
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')

    def test_unsettled_before_release_cannot_release_lost_tree(self):
        import os
        self.prepare()
        self.gate.receive(self.later_control('unsettled'))
        self.gate.progress()
        self.assertEqual(self.gate.failure, 'early_stop')
        self.assertEqual(os.read(self.gate.child_gate, 1024), b'')

    def test_near_cap_frame_split_and_coalesced_next_frame_keep_exact_bounds(self):
        self.prepare(); self.gate.progress()
        first = json.loads(self.later_control('exec_confirmed'))
        first['outcome']['cause'] = ''
        empty = json.dumps(first, separators=(',', ':')).encode()+b'\n'
        first['outcome']['cause'] = 'x'*(gp.CONTROL_MAX-len(empty))
        wire = json.dumps(first, separators=(',', ':')).encode()+b'\n'
        self.assertEqual(len(wire), gp.CONTROL_MAX)
        self.gate.receive(wire[:60000])
        self.assertIsNone(self.gate.failure)
        self.gate.receive(wire[60000:]+self.later_control('settled', 3))
        self.assertIsNone(self.gate.failure)
        self.assertEqual(self.gate.last_kind, 'settled')
        with self.assertRaises(ValueError): gp.control_message(wire[:-1]+b' ')

    def test_actual_positive_control_order_after_release_is_accepted(self):
        self.prepare(); self.gate.progress()
        self.gate.receive(self.later_control('exec_confirmed'))
        self.gate.receive(self.later_control('settled', 3))
        self.assertIsNone(self.gate.failure)
        self.assertEqual(self.gate.last_kind, 'settled')

    def test_post_release_bad_control_retains_incomplete_failure(self):
        self.prepare(); self.gate.progress()
        completed = self.gate.context['release_completed_ns']
        self.gate.receive(b'not-json\n'); self.gate.stop(normal=True)
        self.assertEqual(self.gate.context['failure'], 'control_invalid')
        self.assertEqual(self.gate.context['release_completed_ns'], completed)

if __name__ == '__main__':
    unittest.main()
