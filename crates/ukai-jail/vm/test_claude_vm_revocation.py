"""Provider-free stream, custody, attribution and persisted replay controls."""
import copy
import json
import hashlib
import base64
import shutil
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import claude_vm_revocation as m
import claude_vm_row as n
import test_claude_vm_compatibility as fixtures
import test_vm_summary_check as sf
import vm_summary_check as checker
import harness
import credential_revocation_measurement as lifecycle


def event(value, **extra):
    return dict(type='stream_event', session_id='session-fixture', parent_tool_use_id=None, event=value, **extra)


def frames():
    return [event({'type': 'message_start', 'message': {'id': 'message-fixture', 'role': 'assistant'}}),
            event({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}}),
            event({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'A'}})]


def encode(value): return (json.dumps(value) + '\n').encode()


def failure():
    result = fixtures.vendor_result(); result.update(subtype='error_during_execution', is_error=True, result='interrupted')
    return result


def chunks():
    return b''.join(map(encode, frames())), encode(event({'type': 'message_stop'})) + encode(failure())


def capture():
    first, last = chunks(); stream = m.Stream(); candidate = stream.feed(first, 100)
    return first + last, {'started_ns': 90, 'finished_ns': 200, 'reads': [
        {'end': len(first), 'ns': 100}, {'end': len(first + last), 'ns': 150}], 'exit': 1, 'intervened': False,
        'unlink': {'trigger': candidate, 'unlink_before_ns': 101, 'unlink_after_ns': 102, 'unlinked_nlink': 0,
                   'copy_identity': {'ino': 123, 'nlink': 1, 'mode': stat.S_IFREG | 0o600, 'uid': os.getuid()}}}


def proxy(request=1, when=110, *, credential=True, revoked=True):
    return dict(source='proxy', operation='net.connect', stage='result', decision='allow', monotonic_ns=str(when),
        source_seq=request, fields={'request_id': request, 'reason': 'relayed',
        'end': 'credential_revoked' if revoked else 'upstream_closed', 'transport': 'http', 'kind': 'connect',
        'origin': 'api.anthropic.com', 'destination': 'api.anthropic.com:443', 'origin_verification': 'mitm_http_host',
        **({'credentials': ['anthropic']} if credential else {})},
        outcome={'completion': 'proxy_close', 'ok': True, 'bytes_in': 128, 'bytes_out': 64})


def note():
    return dict(source='wrapper', operation='note', monotonic_ns='100', source_seq=1,
        fields={'kind': 'credential', 'credential_id': 'anthropic', 'transition': 'revoked', 'uses_recorded': True})


def denied(request=2):
    result = proxy(request, 120, credential=False); result['decision'] = 'deny'
    result['fields'].update(reason='credential_revoked', end=None)
    result['outcome'].update(ok=False, bytes_in=0, bytes_out=0)
    return result


class StreamTests(unittest.TestCase):
    def test_split_utf8_frames_trigger_once(self):
        values = frames(); values[2]['event']['delta']['text'] = 'é test'
        raw = b''.join((json.dumps(v, ensure_ascii=False) + '\n').encode() for v in values)
        for width in (1, 3, 17, len(raw)):
            stream = m.Stream(); seen = []
            for offset in range(0, len(raw), width):
                found = stream.feed(raw[offset:offset + width], offset + 1)
                if found: seen.append(found)
            stream.finish(); self.assertEqual(len(seen), 1); self.assertEqual(seen[0]['characters'], 6)

    def test_only_active_main_text_is_a_trigger(self):
        stream = m.Stream()
        self.assertIsNone(stream.feed(encode({'type': 'system', 'subtype': 'api_retry'}) + encode({'type': 'assistant'}), 1))
        empty = frames(); empty[-1]['event']['delta']['text'] = ''
        self.assertIsNone(stream.feed(b''.join(map(encode, empty)), 2))
        self.assertIsNone(stream.feed(encode(event({'type': 'content_block_delta', 'index': 0,
            'delta': {'type': 'thinking_delta', 'thinking': 'not trigger'}})), 3))
        for mutate in (lambda f: f[0].update(parent_tool_use_id='child'), lambda f: f[2].update(session_id='other'),
                       lambda f: f[2]['event'].update(index=9), lambda f: f[2].pop('session_id'),
                       lambda f: f[2].update(session_id=None), lambda f: f[2]['event']['delta'].update(text=1),
                       lambda f: f[0]['event']['message'].update(role='user')):
            changed = frames(); mutate(changed)
            with self.assertRaises(m.Refusal): m.Stream().feed(b''.join(map(encode, changed)), 1)

    def test_already_complete_batch_never_unlinks(self):
        with self.assertRaisesRegex(m.Refusal, 'complete-in-trigger-read'): m.Stream().feed(b''.join(chunks()), 1)

    def test_bad_json_caps_and_incomplete_eof_refuse(self):
        for raw in (b'{"type":"system","type":"stream_event"}\n', b'{"type":"system","n":NaN}\n', b'\xff\n',
                    b'{"type":"system","nested":' + b'[' * 33 + b'0' + b']' * 33 + b'}\n'):
            with self.assertRaises(m.Refusal): m.Stream().feed(raw, 1)
        with mock.patch.object(m, 'FRAME_MAX', 20):
            with self.assertRaises(m.Refusal): m.Stream().feed(b'x' * 21, 1)
        with mock.patch.object(m, 'FRAME_COUNT', 1):
            with self.assertRaises(m.Refusal): m.Stream().feed(b'{"type":"system"}\n' * 2, 1)
        stream = m.Stream(); stream.feed(b'{', 1)
        with self.assertRaises(m.Refusal): stream.finish()
        with self.assertRaises(m.Refusal): m.Stream().feed(encode(failure()) * 2, 1)

    def test_real_child_partial_stdout_and_large_stderr_drained(self):
        first, last = chunks()
        script = ('import os,time;os.write(2,b"e"*131072);'
                  f'os.write(1,{first[:17]!r});time.sleep(.03);os.write(1,{first[17:]!r});'
                  f'time.sleep(.05);os.write(1,{last!r});raise SystemExit(1)')
        seen = []; result = m.collect([sys.executable, '-c', script], {}, lambda v: seen.append(v), timeout=5)
        self.assertNotIn('error_type', result, result); self.assertEqual(result['exit'], 1)
        self.assertFalse(result['intervened']); self.assertEqual(len(result['stderr']), 131072)
        self.assertEqual(len(seen), 1); self.assertEqual(m.replay_stream(result['stdout'], result).candidate, seen[0])

    def test_real_child_deadline_and_caps_reap(self):
        start = time.monotonic()
        result = m.collect([sys.executable, '-c', 'import time;time.sleep(20)'], {}, timeout=.05)
        self.assertTrue(result['intervened']); self.assertEqual(result['error_code'], 'client-deadline')
        self.assertLess(time.monotonic() - start, 4)
        with mock.patch.object(m, 'STDERR_MAX', 4096):
            result = m.collect([sys.executable, '-c', 'import os;os.write(2,b"x"*100000)'], {}, timeout=2)
        self.assertEqual(result['error_code'], 'stderr-cap'); self.assertLessEqual(len(result['stderr']), 4096)

    def test_actual_child_stdin_is_closed_and_split_encoded_output_is_detected(self):
        token=b'synthetic-"quoted"-credential'
        spelling=json.dumps(token.decode())[1:-1]
        payload=encode({'type':'system','text':spelling})
        script=('import os,time;assert os.read(0,1)==b"";'
                f'os.write(1,{payload[:len(payload)//2]!r});time.sleep(.02);os.write(1,{payload[len(payload)//2:]!r})')
        result=m.collect([sys.executable,'-c',script],{},timeout=2)
        self.assertEqual(result['exit'],0);self.assertNotIn('error_type',result)
        hit,safe=n.native_output(result['stdout'].decode(),n.native_secret_spellings(token))
        self.assertTrue(hit);self.assertFalse(n.native_output(safe,n.native_secret_spellings(token))[0])

    def test_auxiliary_plain_output_not_parsed_as_vendor_json(self):
        result = m.collect([sys.executable, '-c', 'print("plain output")'], {}, timeout=2, parse_stream=False)
        self.assertEqual(result['exit'], 0); self.assertNotIn('error_type', result)

    def test_replay_partition_and_clocks_exact(self):
        stdout, value = capture(); self.assertEqual(m.replay_stream(stdout, value).result, failure())
        for change in (lambda c: c['reads'][1].update(end=len(stdout)-1), lambda c: c['reads'][1].update(ns=1),
                       lambda c: c.update(finished_ns=1), lambda c: c['reads'][0].update(end=True)):
            other = copy.deepcopy(value); change(other)
            with self.assertRaises(m.Refusal): m.replay_stream(stdout, other)


class CustodyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.directory = self.root / 'credentials'; self.directory.mkdir(mode=0o700)

    def test_original_preserved_and_only_private_copy_removed_once(self):
        original = self.root / 'original'; original.write_bytes(b'synthetic'); original.chmod(0o600)
        before = m.identity(original.stat())
        source = m.SourceCopy(self.directory, n.private_source(original)); self.addCleanup(source.close)
        self.assertEqual((self.directory / 'anthropic').stat().st_mode & 0o777, 0o600)
        result = source.unlink(trigger={'read_ns': 1})
        self.assertEqual(result['unlinked_nlink'], 0); self.assertTrue(source.removed)
        self.assertEqual(original.read_bytes(), b'synthetic'); self.assertEqual(m.identity(original.stat()), before)
        with self.assertRaises(m.Refusal): source.unlink()

    def test_replacement_links_and_renamed_parent_not_removed(self):
        for kind in ('replacement', 'symlink', 'hardlink', 'parent'):
            directory = self.root / kind; directory.mkdir(mode=0o700)
            source = m.SourceCopy(directory, b'synthetic'); target = directory / 'anthropic'
            if kind in ('replacement', 'symlink'):
                target.unlink()
                if kind == 'replacement': target.write_bytes(b'other')
                else: target.symlink_to(self.root / 'absent')
            elif kind == 'hardlink': os.link(target, directory / 'extra')
            else:
                directory.rename(self.root / 'moved'); directory.mkdir(mode=0o700); target.write_bytes(b'other')
            try:
                with self.assertRaises(m.Refusal): source.unlink(trigger={'read_ns': 1})
                self.assertTrue(os.path.lexists(target))
            finally: source.close()

    def test_creation_failure_removes_its_partial_copy(self):
        with mock.patch.object(os, 'write', side_effect=OSError('test')):
            with self.assertRaises(OSError): m.SourceCopy(self.directory, b'synthetic')
        self.assertFalse((self.directory / 'anthropic').exists())

    def test_six_encodings_nested_json_long_token_refuse_exact_write(self):
        token = ('quoted-"-\\-é-secret-' + 'x' * 210).encode(); spellings = n.native_secret_spellings(token)
        for index, spelling in enumerate(spellings):
            for raw in (spelling.encode(), encode({'result': spelling}), encode({'nested': [spelling]})):
                with self.assertRaises(m.Refusal): m.safe_write(self.root / f'unsafe-{index}', raw, spellings)
        safe = self.root / 'safe'; m.safe_write(safe, b'hello\n', spellings); self.assertEqual(safe.read_bytes(), b'hello\n')


class AttributionTests(unittest.TestCase):
    def test_actual_counts_and_zero_retries_unobserved(self):
        result = m.revocation_events([proxy(3, 50, revoked=False), note(), proxy(5)], ['api.anthropic.com'])
        self.assertEqual(result['confirmed_uses'], 2); self.assertEqual(result['retry_observation'], 'unobserved')
        self.assertEqual(result['pre_revocation_completed_requests'], [3])
        result = m.revocation_events([note(), proxy(), denied()], ['api.anthropic.com'])
        self.assertEqual(result['observed_revocation_denials'], [2]); self.assertEqual(result['confirmed_uses'], 1)

    def test_active_stream_origin_bytes_and_end_are_required(self):
        for mutate in (lambda e: e['outcome'].update(bytes_in=0), lambda e: e['outcome'].update(bytes_in=True),
                       lambda e: e['fields'].update(end='upstream_closed'), lambda e: e['fields'].update(origin_verification='tls_sni'),
                       lambda e: e['fields'].update(credentials_unconfirmed=['anthropic']),
                       lambda e: e['fields'].update(origin='other'), lambda e: e.update(monotonic_ns='-1')):
            value = proxy(); mutate(value)
            with self.assertRaises(m.Refusal): m.revocation_events([note(), value], ['api.anthropic.com'])

    def test_retry_has_no_attribution_or_upstream_bytes(self):
        for mutate in (lambda e: e['outcome'].update(bytes_out=1), lambda e: e['outcome'].update(bytes_in=1),
                       lambda e: e['fields'].update(credentials=['anthropic']), lambda e: e['fields'].update(credentials_unconfirmed=['anthropic']),
                       lambda e: e['fields'].update(reason='relayed'), lambda e: e.update(decision='allow')):
            value = denied(); mutate(value)
            with self.assertRaises(m.Refusal): m.revocation_events([note(), proxy(), value], ['api.anthropic.com'])
        with self.assertRaises(m.Refusal): m.revocation_events([note(), proxy(), proxy(2, 130, revoked=False)], ['api.anthropic.com'])

    def test_nonzero_outcome_and_explicit_security_adaptation(self):
        outcome = dict(kind='exited', code=1, signal=None, cause=None, error=None)
        self.assertTrue(m.nonzero_outcome(outcome))
        for key, values in {'code': [0, True, 1.0, '1', -1, 256], 'kind': ['unknown'],
                            'signal': [9], 'cause': ['wall_expiry'], 'error': ['failure']}.items():
            for value in values: self.assertFalse(m.nonzero_outcome({**outcome, key: value}))
        base = {key: False for key in m.REPLACED_FACTS}; base.update(coverage=True, identity=True, sampling=True, future_fact=True)
        receipt = dict(phase='settled', outcome=outcome, errors=[], exec_observed=True, containment='enforced',
                       child_protection='enforced', state_cleanup='complete', cleanup_error=None,
                       lifetime={'tree_empty': True, 'integrity': 'verified'})
        observed = dict(agent_result=failure(), run_exit=1, tail_exit=0, tail_json_exit=0)
        self.assertTrue(all(m.adapt_facts(base, observed, receipt, receipt).values()))
        for key in base.keys() - m.REPLACED_FACTS:
            changed = dict(base); changed[key] = False
            self.assertFalse(all(m.adapt_facts(changed, observed, receipt, receipt).values()), key)
        for key in m.REPLACED_FACTS:
            changed = dict(base); del changed[key]
            with self.assertRaises(m.Refusal): m.adapt_facts(changed, observed, receipt, receipt)
        self.assertEqual(m.REPLACED_FACTS, {'task_passed','guest_settled_clean','strict_successful_outcome',
            'host_settled_clean','vendor_reported_success','run_and_both_tail_commands_succeeded'})

    def test_direct_fixed_single_api_only_argv(self):
        command, suffix = m.argv('/installed/bin/ukai-jail', '/workspace')
        self.assertEqual(command[command.index('--') + 1:], suffix); self.assertEqual(suffix[-2:], ['--tools', ''])
        self.assertIn('--bare', suffix); self.assertNotIn('--max-turns', suffix)
        self.assertEqual(suffix[suffix.index('--max-budget-usd') + 1], '0.50')
        self.assertEqual(command[1:7], ['run', '--vm', '--from-path', '--launch', 'claude', '--state'])



class PersistedTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.NativeModeTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.fixture = fixture; self.root = fixture.root / 'record'; self.root.mkdir()
        fixture.metadata.update(disk_sha256='d'*64, seed_sha256='e'*64, helper_sha256='f'*64, custodian_sha256='c'*64)
        (fixture.image / 'image.json').write_text(json.dumps(fixture.metadata))
        self.context = n.native_context(fixture.home, fixture.jail)
        self.suffix = m.argv(fixture.jail, fixture.workspace)[1]
        f = sf.Fixture(self.root / 'attempt'); self.native = f
        f.guest['outcome']['code'] = f.host['outcome']['code'] = 1
        f.guest['jail'] = {'component': 'ukai-jail', 'version': '0.1.0', 'backend': 'bubblewrap'}
        entry = self.context['entry']; resolved = harness.argv_digest(entry['argv_prefix'] + self.suffix)
        native_binding = {'catalog_sha256': self.context['catalog_sha256'], 'entry_id': entry['id'],
            'profile_sha256': entry['profile_sha256'], 'executable_sha256': entry['executable_sha256'],
            'selected_credential_id': 'anthropic', 'state': 'attempt',
            'request_argv_digest': harness.argv_digest(['claude', *self.suffix]), 'resolved_argv_digest': resolved,
            'policy_digest': f.guest['policy']['digest']}
        f.binding.update(native_program=native_binding, argv_digest=resolved)
        f.guest['argv_digest'] = f.host['argv_digest'] = resolved
        f.guest['credentials'][0]['id'] = 'anthropic'
        f.host['credentials'] = [{'id':'anthropic','mode':'vault','never_staged':True,'digest':None,
                                  'digest_unavailable_reason':'never_staged'}]
        f.guest['policy']['grants'] = [{'kind':'read_only','value':entry['install_root'],'by':'program_resolution'}]
        f.guest['policy']['grants'] += [{'kind':'allow_host','value':host+':443','by':'operator'}
                                      for host in self.context['profile']['network']['allow']]
        f.events[0].update(note()); f.events[2].update(proxy())
        intent = {k:v for k,v in native_binding.items() if k not in ('executable_sha256','policy_digest')}
        intent.update(schema='ukai.vm.guest-native-launch/1',launch_name='claude',expected_policy_digest=native_binding['policy_digest'],
                      argv_suffix=[base64.b64encode(word.encode()).decode() for word in self.suffix])
        f.transport.update(native_program=intent, guest_stop_boundaries=['ukai-attempts.slice/attempt-1'])
        f.transport['image']['guest_program_catalog_sha256'] = self.context['catalog_sha256']
        (f.root / 'guest-native-catalog.json').write_bytes(fixture.catalog_bytes)
        self.write_native()
        sync = sf.Fixture(self.root / 'sync-attempt'); self.sync = sync
        sync.host['attempt_id'] = 'att_33333333-3333-4333-8333-333333333333'
        sync.guest['attempt_id'] = 'att_44444444-4444-4444-8444-444444444444'
        sync.binding.update(attempt_id=sync.host['attempt_id'],guest_attempt_id=sync.guest['attempt_id'],profile='tool',argv_digest=harness.argv_digest(['/bin/sync']))
        for r in (sync.host,sync.guest):
            r['argv_digest']=sync.binding['argv_digest']; r['policy']['name']='tool'; r['credentials']=[]
            for item in r['coverage'].values(): item['observed_count']=0
        sync.events=[dict(schema='ukai.event/1',attempt_id=sync.guest['attempt_id'],source='wrapper',source_seq=1,operation='note',fields={'kind':'fixture'})];sync.transport['attempt_id']=sync.host['attempt_id']
        sync.transport['guest_stop_boundaries']=['ukai-attempts.slice/attempt-2']
        self.write_sync()
        stdout,capture_value=capture();(self.root/'stream.stdout').write_bytes(stdout);(self.root/'stream.stderr').write_bytes(b'')
        self.observed={'credential_id':'anthropic','run_exit':1,'tail_exit':0,'tail_json_exit':0,
            'capture':capture_value,'agent_result':failure(),'vendor_usage':n.native_vendor_usage(failure()),
            'source_removed_before_stop':True,'stop_exit':0,'service_shutdown':{'complete':True},
            'leaks':[],'files_scanned':5,'output_leaks':[],'installed_identity_unchanged':True,
            'original_source_unchanged':True,'original_source_before':{'ino':1,'mode':0o100600},'original_source_after':{'ino':1,'mode':0o100600},'retention_complete':True,'same_boot_sync_verified':True,
            'disk_scan':{'bytes':4096,'findings':[],'encoding_classes':['raw','json','url','hex','base64','base64url']},
            'sync_original':str(sync.root),'sync_run_exit':0,'sync_tail_exit':0,'sync_tail_json_exit':0}
        self.refresh()

    def write_native(self):
        self.native.write();sf.install_exposure(self.native)

    def write_sync(self):
        with mock.patch.object(sf,'GUEST_ID',self.sync.guest['attempt_id']), mock.patch.object(sf,'HOST_ID',self.sync.host['attempt_id']): self.sync.write()

    def summary(self, fixture):
        # Integration fixture generation only: the independent renderer already
        # has its own literal expected-output tests. Mutations below are judged
        # against these retained bytes, not against a fresh altered rendering.
        with checker.EvidenceReader(fixture.root) as reader:
            value,transport,scope,frames_value,sampling=checker.expected_summary(reader)
        text=''.join('ukai-jail: '+line['text']+'\n' for line in value['lines'])
        if transport is not None:text+='ukai-jail: '+transport+'\n'
        text+='ukai-jail: receipt '+str(fixture.root/'jail.json')+'\n'
        return value,text

    def refresh(self, *, rerender=True):
        if rerender:
            self.summary_value,self.tail=self.summary(self.native)
            self.observed['sync_summary'],self.observed['sync_tail']=self.summary(self.sync)
        self.observed['sync_attempt_sha256']=lifecycle.normal_attempt_hashes(self.sync.root)
        value={'schema':m.SCHEMA,'tooling_sha256':{name:hashlib.sha256(Path(m.__file__).with_name(name).read_bytes()).hexdigest() for name in m.TOOL_NAMES},'context':self.context,'context_after':self.context,'controls':m.controls(),'suffix':self.suffix,'observed':self.observed,
            'summary':self.summary_value,'tail':self.tail,'original_attempt':str(self.native.root),
            'attempt_sha256':lifecycle.normal_attempt_hashes(self.native.root),
            'output_sha256':{name:hashlib.sha256((self.root/name).read_bytes()).hexdigest() for name in ('stream.stdout','stream.stderr')}}
        raw=m.json_bytes(value);(self.root/'inputs.json').write_bytes(raw)
        (self.root/'measurement.json').write_bytes(m.json_bytes({'schema':m.SCHEMA,'qualified':False,'inputs_sha256':hashlib.sha256(raw).hexdigest()}))

    def test_real_independent_summary_journal_and_relocated_replay_pass(self):
        result=m.replay(self.root);self.assertEqual(result['outcome'],'PASS',result)
        self.assertFalse(result['qualified']);self.assertEqual(result['journal']['confirmed_uses'],1)
        other=self.fixture.root/'relocated';shutil.copytree(self.root,other)
        with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('no process')):
            self.assertEqual(m.replay(other)['outcome'],'PASS')

    def test_api_error_terminal_with_success_subtype_replays_as_failure(self):
        # Claude's agent loop can complete while its last turn is an API error.
        # This is the actual revocation terminal shape, not a successful task.
        terminal = failure()
        terminal.update(subtype='success', is_error=True, terminal_reason='api_error')

        def install(value):
            first, _ = chunks()
            last = encode(event({'type': 'message_stop'})) + encode(value)
            (self.root / 'stream.stdout').write_bytes(first + last)
            self.observed['capture']['reads'][-1]['end'] = len(first + last)
            self.observed['agent_result'] = value
            self.observed['vendor_usage'] = n.native_vendor_usage(value)
            self.refresh()

        install(terminal)
        result = m.replay(self.root)
        self.assertEqual(result['outcome'], 'PASS', result)
        self.assertTrue(result['facts']['vendor_reported_failure'])
        self.assertFalse(result['qualified'])
        for changes in ({'is_error': False}, {'is_error': 1}, {'is_error': 'true'},
                        {'is_error': None}, {'subtype': ''}, {'subtype': 'unknown'},
                        {'subtype': None}, {'type': 'assistant'}):
            with self.subTest(changes=changes):
                install({**terminal, **changes})
                failed = m.replay(self.root)
                self.assertEqual(failed['outcome'], 'FAIL', failed)
                self.assertFalse(failed['facts']['vendor_reported_failure'])

    def test_relocated_replay_denies_original_reads_network_processes_and_writes(self):
        other=self.fixture.root/'isolated';shutil.copytree(self.root,other)
        script = r"""import json,os,sys
import claude_vm_revocation as m
original=sys.argv[1];target=sys.argv[2]
def audit(event,args):
    if event=='open':
        path,mode,flags=args
        if isinstance(path,(str,bytes)) and os.fsdecode(path).startswith(original):raise AssertionError('original read')
        if isinstance(mode,str) and any(c in mode for c in 'wax+'):raise AssertionError('write mode')
        if isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):raise AssertionError('write flags')
    if event.startswith(('socket.','subprocess.','os.exec','os.spawn')):raise AssertionError('external action')
sys.addaudithook(audit)
result=m.replay(target)
print(json.dumps({'outcome':result['outcome'],'qualified':result['qualified']}))
"""
        done=subprocess.run([sys.executable,'-B','-c',script,str(self.root),str(other)],stdin=subprocess.DEVNULL,
                            capture_output=True,text=True,timeout=10,cwd=Path(__file__).resolve().parent)
        self.assertEqual(done.returncode,0,done.stderr)
        self.assertEqual(json.loads(done.stdout),{'outcome':'PASS','qualified':False})

    def test_identity_and_original_metadata_are_compared_not_label_trusted(self):
        self.observed['original_source_after']['ino']=2
        self.observed['original_source_unchanged']=True
        self.refresh()
        self.assertFalse(m.replay(self.root)['facts']['original_source_metadata_unchanged'])
        self.observed['original_source_after']['ino']=1;self.refresh()
        value=json.loads((self.root/'inputs.json').read_bytes())
        value['context_after']['identity']['client']['sha256']='0'*64
        raw=m.json_bytes(value);(self.root/'inputs.json').write_bytes(raw)
        (self.root/'measurement.json').write_bytes(m.json_bytes({'schema':m.SCHEMA,'qualified':False,'inputs_sha256':hashlib.sha256(raw).hexdigest()}))
        self.assertFalse(m.replay(self.root)['facts']['installed_identity_unchanged'])

    def test_rehashed_tooling_claim_must_match_actual_bounded_replay_modules(self):
        value=json.loads((self.root/'inputs.json').read_bytes())
        for name in m.TOOL_NAMES:
            changed=copy.deepcopy(value);changed['tooling_sha256'][name]='0'*64
            raw=m.json_bytes(changed);(self.root/'inputs.json').write_bytes(raw)
            (self.root/'measurement.json').write_bytes(m.json_bytes({'schema':m.SCHEMA,'qualified':False,'inputs_sha256':hashlib.sha256(raw).hexdigest()}))
            with self.assertRaisesRegex(m.Refusal,'tooling-source-mismatch'):m.replay(self.root)
        self.refresh();self.assertEqual(m.replay(self.root)['outcome'],'PASS')

    def test_rehashed_usage_cannot_disagree_with_actual_terminal_vendor_frame(self):
        self.observed['vendor_usage']['total_cost_usd']=0.0001
        self.refresh()
        result=m.replay(self.root)
        self.assertEqual(result['outcome'],'FAIL')
        self.assertFalse(result['facts']['reported_usage_matches_terminal_result'])

    def test_rehashed_journal_active_stream_mutations_refuse(self):
        for mutate in (lambda e:e['outcome'].update(bytes_in=0),lambda e:e['fields'].update(end='upstream_closed'),
                       lambda e:e['fields'].update(credentials_unconfirmed=['anthropic'])):
            before=copy.deepcopy(self.native.events);mutate(self.native.events[2]);self.write_native();self.refresh()
            self.assertEqual(m.replay(self.root)['outcome'],'FAIL')
            self.native.events=before;self.write_native();self.refresh()

    def test_rehashed_sync_command_statuses_never_become_invented_zero(self):
        for key in ('sync_run_exit','sync_tail_exit','sync_tail_json_exit'):
            for value in (None,True,0.0,'0',1):
                self.observed[key]=value;self.refresh()
                with self.assertRaises(m.Refusal):m.replay(self.root)
            self.observed.pop(key);self.refresh()
            with self.assertRaises(m.Refusal):m.replay(self.root)
            self.observed[key]=0
        self.refresh();self.assertEqual(m.replay(self.root)['outcome'],'PASS')

    def test_rehashed_sync_nonexecution_unknown_tree_or_uncovered_stop_refuses(self):
        for key,value in [('exec_observed',False),('outcome',dict(kind='unknown',code=None,signal=None,cause=None,error=None)),
                          ('lifetime',{'tree_empty':None,'integrity':'lost'})]:
            prior=copy.deepcopy(self.sync.guest);prior_host=copy.deepcopy(self.sync.host);self.sync.guest[key]=value
            if key=='lifetime': self.sync.host[key].update(value)
            else:self.sync.host[key]=copy.deepcopy(value)
            self.write_sync()
            # Keep otherwise valid summary bytes when possible, so failures are
            # not merely the manifest's pre-change SHA comparison.
            self.refresh()
            self.assertEqual(m.replay(self.root)['outcome'],'FAIL')
            self.sync.guest=prior;self.sync.host=prior_host;self.write_sync();self.refresh()
        self.sync.transport['guest_stop_boundaries']=[];self.write_sync();self.refresh()
        self.assertEqual(m.replay(self.root)['outcome'],'FAIL')

    def test_live_orchestration_with_synthetic_child_and_source_replays_and_cleans(self):
        source=self.fixture.root/'original-source';source.write_bytes(b'synthetic-provider-free-token');source.chmod(0o600)
        original=m.identity(source.stat());out=self.fixture.root/'live-out';seen={}
        def fake_collect(command,environment,on_delta=None,**options):
            self.assertEqual(environment['HOME'],str(Path(environment['UKAI_CONFIG_DIR'])/'home'))
            self.assertNotIn('ANTHROPIC_API_KEY',environment)
            data=Path(environment['UKAI_DATA_DIR']);config=Path(environment['UKAI_CONFIG_DIR'])
            seen.update(data=data,config=config)
            if on_delta is not None:
                target=data/'attempts'/self.native.host['attempt_id'];target.parent.mkdir()
                shutil.copytree(self.native.root,target)
                (data/'vm').mkdir();(data/'vm/serve.lock').touch()
                self.assertEqual((config/'credentials/anthropic').read_bytes(),source.read_bytes())
                stdout,value=capture();first,last=chunks();now=time.monotonic_ns()
                value['started_ns']=now-1;value['reads'][0]['ns']=now
                stream=m.Stream();candidate=stream.feed(first,now)
                value['unlink']=on_delta(candidate)
                self.assertFalse((config/'credentials/anthropic').exists())
                value['reads'][1]['ns']=time.monotonic_ns();value['finished_ns']=time.monotonic_ns()
                return dict(value,stdout=stdout,stderr=b'')
            self.assertFalse(options['parse_stream'])
            if 'tail' in command:
                target=data/'attempts'/command[command.index('--attempt')+1]
                with checker.EvidenceReader(target) as reader:
                    summary,transport,_,_,_=checker.expected_summary(reader)
                text=''.join('ukai-jail: '+line['text']+'\n' for line in summary['lines'])
                if transport is not None:text+='ukai-jail: '+transport+'\n'
                text+='ukai-jail: receipt '+str(target/'jail.json')+'\n'
                return dict(stdout=(json.dumps(summary) if '--json' in command else text).encode(),stderr=b'',exit=0,intervened=False)
            if '/bin/sync' in command:
                shutil.copytree(self.sync.root,data/'attempts'/self.sync.host['attempt_id'])
                return dict(stdout=b'',stderr=b'',exit=0,intervened=False)
            self.assertEqual(command[-1],'stop')
            return dict(stdout=b'',stderr=b'',exit=0,intervened=False)
        disk=self.fixture.root/'disk';disk.write_bytes(b'clean'+bytes(100))
        args=SimpleNamespace(home=str(self.fixture.home),jail=str(self.fixture.jail),workspace=str(self.fixture.workspace),
                             out=str(out),credential_source=str(source))
        with mock.patch.object(m,'collect',side_effect=fake_collect), \
             mock.patch.object(lifecycle,'running_service_lock',side_effect=lambda data:(data/'vm/serve.lock').open('rb')), \
             mock.patch.object(lifecycle,'stopped_service_lock',return_value={'complete':True}), \
             mock.patch.object(m.vault_measurement,'boot_disk',return_value=(disk,True)):
            result=m.live(args)
        self.addCleanup(shutil.rmtree,seen['data'],True)
        report=json.loads((out/'result.json').read_bytes())
        self.assertEqual(result,0,report);self.assertEqual(m.replay(out)['outcome'],'PASS')
        self.assertFalse(seen['config'].exists());self.assertEqual(m.identity(source.stat()),original)
        for file in out.rglob('*'):
            if file.is_file():self.assertNotIn(source.read_bytes(),file.read_bytes())

    def test_summary_counts_text_binding_parts_and_missing_data_refuse(self):
        original=(self.root/'inputs.json').read_bytes()
        for change in (lambda v:v['summary']['lines'][1]['facts'].update(opened_for_writing=999),
                       lambda v:v.update(tail=v['tail']+'invented\n'),
                       lambda v:v['context']['identity']['image'].update(disk_sha256='0'*64)):
            value=json.loads(original);change(value);raw=m.json_bytes(value);(self.root/'inputs.json').write_bytes(raw)
            (self.root/'measurement.json').write_bytes(m.json_bytes({'schema':m.SCHEMA,'qualified':False,'inputs_sha256':hashlib.sha256(raw).hexdigest()}))
            with self.assertRaises((ValueError,checker.VerificationError)):m.replay(self.root)
        self.refresh()
        part=self.native.root/'evidence/guest-journal/0000.part';raw=part.read_bytes();part.write_bytes(raw+b'broken')
        with self.assertRaises(ValueError):m.replay(self.root)
        part.write_bytes(raw);self.refresh();part.unlink()
        with self.assertRaises(ValueError):m.replay(self.root)


if __name__ == '__main__': unittest.main()
