#!/usr/bin/env python3
"""Synthetic Linux @program control through the explicit warm-service transport.

This is a literal component probe, not native catalog admission, Claude/provider
compatibility, host source-watch proof, or K113 qualification. It uses a fresh
synthetic value and the image's existing Python. No provider source is accepted.
"""
import argparse
import base64
import contextlib
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
import tomllib
import urllib.parse

import claude_vm_row as compatibility
import credential_revocation_measurement as lifecycle
import harness
import vault_measurement
import vm_summary_check

NAME = 'program-binding-measurement'
CREDENTIAL = 'test'
COPY = 'program-binding-copy'
SCHEMA = 'ukai.vm.program-binding-component/1'
INPUTS = 'ukai.vm.program-binding-inputs/1'
MAX_OUTPUT = 2 * 1024 * 1024
MAX_ARTIFACT = 32 * 1024 * 1024


def endpoint(address, port):
    if type(address) is not str or ipaddress.ip_address(address).version != 4 or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('the control needs one explicit IPv4 listener')
    return f'{address}:{port}'


def declaration(address, port):
    origin = endpoint(address, port)
    # The frozen Linux launcher supports @program with an absolute PROGRAM
    # without --from-path (supervisor::Purpose.argv0). The literal controller
    # passes this profile and argv unchanged; no native intent is supplied.
    return f'''name = "{NAME}"
jail = "agent"
credentials_one_of = ["test"]
[credentials.test]
mode = "vault"
source = "/run/ukai-vm/credentials/test"
env = "AGENT_TOKEN"
hosts = ["http://{origin}"]
allow_plaintext = true
header = {{ name = "x-test-token" }}
binaries = ["@program"]
[network]
allow = ["{origin}"]
'''


def guest_script(address, port):
    origin = 'http://' + endpoint(address, port)
    child = '''import json,os,urllib.error,urllib.request
request=urllib.request.Request(ORIGIN+'/other',headers={'x-test-token':os.environ['AGENT_TOKEN']})
try:
    with urllib.request.urlopen(request,timeout=10) as response:
        result={'status':response.status,'reason':None}
except urllib.error.HTTPError as error:
    result={'status':error.code,'reason':error.headers.get('X-Ukai-Proxy-Reason')}
print(json.dumps(result,sort_keys=True))
'''.replace('ORIGIN', repr(origin))
    return '''import hashlib,json,os,re,stat,subprocess,sys,urllib.error,urllib.request
COPY=__COPY__
ORIGIN=__ORIGIN__
CHILD=__CHILD__
out={}
created=False
def identity(info): return {'device':info.st_dev,'inode':info.st_ino,'size':info.st_size}
try:
    token=os.environ['AGENT_TOKEN']
    out['placeholder']={'sha256':hashlib.sha256(token.encode()).hexdigest(),'bytes':len(token.encode()),
                        'shape':re.fullmatch(r'vault:att_[0-9a-f-]+:test',token) is not None}
    with urllib.request.urlopen(urllib.request.Request(ORIGIN+'/own',headers={'x-test-token':token}),timeout=10) as response:
        out['own']={'status':response.status,'body_ok':response.read(16)==b'accepted'}
    source=os.open('/proc/self/exe',os.O_RDONLY)
    try:
        before=os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=32*1024*1024: raise ValueError()
        target=os.open(COPY,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
        created=True
        digest=hashlib.sha256(); size=0
        with os.fdopen(target,'wb') as output:
            while data:=os.read(source,1024*1024):
                size+=len(data)
                if size>32*1024*1024: raise ValueError()
                digest.update(data);output.write(data)
        after=os.fstat(source)
        if identity(before)!=identity(after) or size!=before.st_size: raise ValueError()
    finally: os.close(source)
    other=os.stat(COPY,follow_symlinks=False)
    with open(COPY,'rb') as stream: copied=hashlib.file_digest(stream,'sha256').hexdigest()
    out['original']=identity(before);out['copy']=identity(other)
    out['original_sha256']=digest.hexdigest();out['copy_sha256']=copied
    done=subprocess.run([os.path.abspath(COPY),'-I','-c',CHILD],stdin=subprocess.DEVNULL,
                        capture_output=True,text=True,timeout=15)
    out['other_exit']=done.returncode;out['other']=json.loads(done.stdout)
    out['other_stderr_empty']=done.stderr==''
except Exception as error:
    out['error_type']=type(error).__name__
finally:
    if created:
        try: os.unlink(COPY)
        except OSError: out['cleanup_error']=True
    out['copy_absent']=not os.path.lexists(COPY)
print('PROGRAM_BINDING '+json.dumps(out,sort_keys=True),flush=True)
sys.exit(0 if 'error_type' not in out and 'cleanup_error' not in out else 1)
'''.replace('__COPY__', repr(COPY)).replace('__ORIGIN__', repr(origin)).replace('__CHILD__', repr(child))


class Witness:
    """Retain only exact-path labels and equality booleans, never headers."""
    def __init__(self, secret):
        self.secret = secret.decode()
        self.lock = threading.Lock()
        self.requests = []
        self.overflow = False

    def record(self, path, header):
        with self.lock:
            if len(self.requests) >= 16:
                self.overflow = True
            else:
                self.requests.append({'path': path if path in ('/own', '/other') else 'other',
                                      'credential_matches': header == self.secret})
        return path == '/own' and header == self.secret

    def snapshot(self):
        with self.lock:
            return {'requests': list(self.requests), 'overflow': self.overflow}


class Peer(http.server.BaseHTTPRequestHandler):
    READ_TIMEOUT = 5

    def setup(self):
        # setup precedes request-line/header parsing, not just do_GET.
        self.request.settimeout(self.READ_TIMEOUT)
        super().setup()

    def log_message(self, *_):
        pass

    def do_GET(self):
        accepted = self.server.witness.record(self.path, self.headers.get('x-test-token'))
        # Never reflect a header, including on the negative path.
        body = b'accepted' if accepted else b'refused'
        self.send_response(200 if accepted else 403)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def attempt(service, artifact, argv, *, launch=None, secret=None, allow_host=None):
    """One finite literal exchange; every failure remains in the record."""
    profile = 'agent' if launch is not None else 'tool'
    record = {'attempt_id': 'program-binding-' + harness.nonce(), 'profile': profile,
              'argv_digest': harness.argv_digest(argv), 'started_at': harness.rfc3339_now(),
              'events': [], 'error': None, 'stdout': '', 'stderr': '', 'exit_code': None}
    channel = None
    seen = set(); total = 0
    try:
        channel = service.connect(timeout=120)
        frames = lifecycle.BoundedFrames(channel)
        ready = frames.receive(120)
        if ready.get('event') != 'ready' or ready.get('schema') != 'ukai.jail.vm-attempt/1':
            raise harness.HarnessError('raw service not ready')
        record.update(ready=ready, boot_id=ready.get('boot_id'))
        request = dict(op='prepare', attempt_id=record['attempt_id'], profile=profile, wall_seconds=50,
                       argv=[harness.b64(word) for word in argv], secrets=[])
        expected = []
        if launch is not None:
            if secret is None or allow_host is None:
                raise harness.HarnessError('missing synthetic declaration')
            request.update(launch={'name': NAME, 'toml': launch}, allow_hosts=[allow_host],
                           secrets=[{'id': CREDENTIAL, 'data': harness.b64(secret)}])
            expected = [[CREDENTIAL, '/run/ukai-vm/credentials/test']]
        channel.send(**request)
        prepared = frames.receive(120)
        if prepared.get('event') != 'prepared' or prepared.get('staged_secrets', []) != expected:
            raise harness.HarnessError('unexpected staging acknowledgment')
        record['prepared'] = prepared
        channel.send(op='run')
        released = received = False
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            frame = frames.receive(max(.001, deadline - time.monotonic()))
            event = frame.get('event'); record['events'].append(event)
            if event == 'released' and not released:
                released = True; record['supervisor_pid'] = frame.get('supervisor_pid')
            elif event in ('stdout', 'stderr') and released:
                raw = base64.b64decode(frame['data'], validate=True)
                if len(record[event].encode()) + len(raw) > MAX_OUTPUT:
                    raise harness.HarnessError('output exceeds bound')
                record[event] += raw.decode(errors='replace')
            elif event == 'file' and released:
                raw = base64.b64decode(frame['data'], validate=True); total += len(raw)
                if total > MAX_ARTIFACT or len(seen) >= 5000:
                    raise harness.HarnessError('export exceeds bound')
                lifecycle.store_raw_file(artifact, frame.get('group'), frame.get('path'), raw, seen)
            elif event == 'bound_receipt' and released and not received:
                raw = base64.b64decode(frame['data'], validate=True)
                if hashlib.sha256(raw).hexdigest() != frame.get('sha256') or type(frame.get('binding')) is not dict:
                    raise harness.HarnessError('receipt binding invalid')
                lifecycle.store_raw_file(artifact, 'evidence', 'jail.json', raw, seen)
                record.update(receipt=compatibility.strict_json(raw), receipt_sha256=frame['sha256'],
                              receipt_digest_ok=True, binding=frame['binding'])
                received = True
            elif event == 'done' and released and received:
                record.update(exit_code=frame.get('exit_code'), guest_stop=frame.get('stop'))
                return record
            else:
                raise harness.HarnessError('unexpected raw event order')
        raise TimeoutError('raw attempt deadline')
    except (OSError, ValueError, TypeError, KeyError, harness.HarnessError, harness.StreamEnded) as error:
        record['error'] = type(error).__name__
    finally:
        if channel is not None:
            channel.close()
    return record


def driver_result(stdout):
    lines = stdout.splitlines()
    if len(lines) != 1 or not lines[0].startswith('PROGRAM_BINDING ') or len(stdout.encode()) > 65536:
        return {}
    value = compatibility.strict_json(lines[0][len('PROGRAM_BINDING '):])
    return value if type(value) is dict else {}


def clean_sync(record, original):
    """Disk scanning needs an actually executed, settled sync on the same boot."""
    guest = record.get('receipt') or {}; stop = record.get('guest_stop') or {}
    return (harness.receipt_bound(record) and type(record.get('exit_code')) is int and record['exit_code'] == 0
            and record.get('error') is None and record.get('profile') == 'tool'
            and record.get('argv_digest') == harness.argv_digest(['/bin/sync'])
            and record.get('attempt_id') != original.get('attempt_id')
            and record.get('boot_id') == original.get('boot_id')
            and harness.guest_boot(record) == harness.guest_boot(original)
            and guest.get('phase') == 'settled' and lifecycle.successful_outcome(guest.get('outcome'))
            and guest.get('exec_observed') is True and guest.get('errors') == []
            and guest.get('containment') == guest.get('child_protection') == 'enforced'
            and guest.get('state_cleanup') == 'complete' and guest.get('cleanup_error') is None
            and guest.get('credentials') == [] and guest.get('vendor_state') is None
            and (guest.get('lifetime') or {}).get('tree_empty') is True
            and (guest.get('lifetime') or {}).get('integrity') == 'verified'
            and harness.stop_covered_the_attempt(stop)
            and all(stop.get(key) == [] for key in ('populated_before_kill', 'live_before_kill', 'strays_killed')))


def judge(record, guest, events, journal, summary, peer):
    """Actual proxy/journal evidence, never a reported PASS label."""
    try:
        result = driver_result(record.get('stdout', ''))
        original, copied = result.get('original', {}), result.get('copy', {})
        shape = all(set(row) == {'device', 'inode', 'size'} and all(type(v) is int and v >= 0 for v in row.values())
                    and row['inode'] > 0 and 0 < row['size'] <= 32 * 1024 * 1024 for row in (original, copied))
        placeholder = f"vault:{guest.get('attempt_id')}:{CREDENTIAL}".encode()
        expected_placeholder = dict(sha256=hashlib.sha256(placeholder).hexdigest(), bytes=len(placeholder), shape=True)
        proxy = [event for event in events or [] if event.get('source') == 'proxy' and event.get('operation') == 'net.connect']
        used = [event for event in proxy if (event.get('fields') or {}).get('credentials') == [CREDENTIAL]]
        denied = [event for event in proxy if event.get('decision') == 'deny'
                  and (event.get('fields') or {}).get('reason') == 'credential_process_denied']
        execs = [event for event in events or [] if event.get('source') == 'audit' and event.get('operation') == 'proc.exec'
                 and (event.get('fields') or {}).get('path') == {'kind': 'workspace_relative', 'value': COPY}
                 and (event.get('fields') or {}).get('path_complete') is True]
        lines = {line.get('line'): line.get('facts') or {} for line in summary.get('lines', [])}
        credentials = lines.get('credentials', {}).get('credentials') or []
        coverage = guest.get('coverage') or {}
        stop = record.get('guest_stop') or {}
        return {
            'literal_component_scope': 'native_program' not in record.get('binding', {}),
            'bound_actual_guest_receipt': harness.receipt_bound(record) and vm_summary_check.equal(record.get('receipt'), guest)
                and type(record.get('exit_code')) is int and record['exit_code'] == 0 and record.get('error') is None,
            'exact_staging_ack': (record.get('prepared') or {}).get('staged_secrets') == [[CREDENTIAL, '/run/ukai-vm/credentials/test']],
            'placeholder_only_child_value': vm_summary_check.equal(result.get('placeholder'), expected_placeholder),
            'copied_executable_same_bytes_different_identity': shape and original['size'] == copied['size']
                and (original['device'], original['inode']) != (copied['device'], copied['inode'])
                and type(result.get('original_sha256')) is str and re.fullmatch(r'[0-9a-f]{64}', result['original_sha256']) is not None
                and result.get('copy_sha256') == result['original_sha256'],
            'copied_program_actually_exec_observed': len(execs) == 1,
            'own_request_succeeded': vm_summary_check.equal(result.get('own'), {'status': 200, 'body_ok': True}),
            'other_program_exact_proxy_refusal': type(result.get('other_exit')) is int and result['other_exit'] == 0
                and vm_summary_check.equal(result.get('other'), {'status': 403, 'reason': 'credential_process_denied'})
                and result.get('other_stderr_empty') is True,
            'one_substitution_and_one_later_program_denial': len(proxy) == 2 and len(used) == len(denied) == 1
                and used[0].get('decision') == 'allow' and used[0]['fields'].get('reason') == 'relayed'
                and type(used[0].get('source_seq')) is int and type(denied[0].get('source_seq')) is int
                and used[0]['source_seq'] < denied[0]['source_seq']
                and not denied[0]['fields'].get('credentials') and not denied[0]['fields'].get('credentials_unconfirmed'),
            'independent_upstream_received_only_authorized_request': vm_summary_check.equal(peer,
                {'requests': [{'path': '/own', 'credential_matches': True}], 'overflow': False}),
            'bound_complete_journal': events is not None and journal.get('verified') is True,
            'exact_summary_credential_count': len(credentials) == 1 and credentials[0].get('id') == CREDENTIAL
                and type(credentials[0].get('uses')) is int and credentials[0]['uses'] == len(used) == 1
                and credentials[0].get('uses_bound') == 'exact',
            'strict_six_classes': set(coverage) == set(harness.SUMMARY_CLASSES)
                and all(row.get('status') == 'active' and row.get('gaps') == [] for row in coverage.values())
                and (coverage.get('proxy.net') or {}).get('observed_count') == len(proxy)
                and lines.get('evidence', {}).get('observe') == 'on' and lines.get('evidence', {}).get('evidence') == 'strict',
            'vault_never_staged': len(guest.get('credentials') or []) == 1
                and guest['credentials'][0].get('id') == CREDENTIAL and guest['credentials'][0].get('mode') == 'vault'
                and guest['credentials'][0].get('never_staged') is True,
            'settled_clean_guest': guest.get('phase') == 'settled' and guest.get('errors') == []
                and guest.get('containment') == guest.get('child_protection') == 'enforced'
                and guest.get('exec_observed') is True and lifecycle.successful_outcome(guest.get('outcome'))
                and guest.get('state_cleanup') == 'complete' and guest.get('cleanup_error') is None
                and (guest.get('lifetime') or {}).get('tree_empty') is True
                and (guest.get('lifetime') or {}).get('integrity') == 'verified',
            'controller_cleanup': harness.stop_covered_the_attempt(stop)
                and all(stop.get(key) == [] for key in ('populated_before_kill', 'live_before_kill', 'strays_killed')),
            'fixture_removed_without_error': result.get('copy_absent') is True
                and 'error_type' not in result and 'cleanup_error' not in result,
        }
    except (ValueError, TypeError, KeyError, AttributeError):
        return {'component_evidence_valid': False}


def snapshot(root):
    result = {}; total = 0
    def fail(error): raise error
    with vm_summary_check.EvidenceReader(root) as reader:
        for directory, directories, files in os.walk(root, followlinks=False, onerror=fail):
            if any((Path(directory) / name).is_symlink() for name in directories):
                raise ValueError('artifact directory is linked')
            for name in files:
                relative = str((Path(directory) / name).relative_to(root))
                raw = reader.read(relative, 16 * 1024 * 1024); total += len(raw)
                if total > MAX_ARTIFACT or len(result) >= 5000: raise ValueError('artifact bound')
                result[relative] = raw
    return result


def retain_tree(source, destination, spellings):
    files = snapshot(source)
    if any(value in name.encode() or value in raw for value in spellings for name, raw in files.items()):
        raise ValueError('artifact contains a protected spelling')
    destination.mkdir(mode=0o700)
    for name, raw in files.items():
        path = destination / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(raw)
    return {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}


def replay(root):
    """Recompute the bounded retained component proof; does not run any binary."""
    result = {'schema': SCHEMA, 'qualified': False, 'outcome': 'FAIL', 'facts': {}}
    try:
        with vm_summary_check.EvidenceReader(root) as reader:
            metadata = compatibility.strict_json(reader.read('measurement.json', 256 * 1024))
            raw = reader.read('inputs.json', 8 * 1024 * 1024)
            if (metadata.get('schema') != SCHEMA or metadata.get('qualified') is not False
                    or metadata.get('inputs_sha256') != hashlib.sha256(raw).hexdigest()): raise ValueError('inputs digest')
        inputs = compatibility.strict_json(raw)
        if inputs.get('schema') != INPUTS: raise ValueError('inputs schema')
        record, before, after = inputs['record'], inputs['identity_before'], inputs['identity_after']
        image = before['image']; address, port = inputs['upstream']['address'], inputs['upstream']['port']
        guest, events, journal = compatibility.verified_guest_journal(root / 'guest-artifact')
        if record.get('receipt_sha256') != journal['guest_receipt_sha256']: raise ValueError('record receipt hash')
        offline = root / 'guest-attempt'
        raw_receipt = lifecycle.bounded_file(offline / 'jail.json', compatibility.RECEIPT_MAX)
        trace = lifecycle.bounded_file(offline / 'trace.ndjson', compatibility.JOURNAL_MAX)
        if (hashlib.sha256(raw_receipt).hexdigest() != journal['guest_receipt_sha256']
                or hashlib.sha256(trace).hexdigest() != journal['sha256']): raise ValueError('offline guest bytes')
        tail = inputs['tail']; summary = compatibility.strict_json(tail['json'])
        verified = vm_summary_check.verify_attempt(offline, summary, tail['text'],
                    display_mapping={str(offline): inputs['offline_attempt']})
        facts = judge(record, guest, events, journal, summary, inputs['peer'])
        ready = record['ready']; sync = inputs['sync']; scans = inputs['scans']
        sync_guest, sync_events, sync_journal = compatibility.verified_guest_journal(root / 'sync-artifact')
        facts.update(
            exact_literal_declaration_and_argv=inputs['launch_toml'] == declaration(address, port)
                and inputs['argv'] == ['/usr/bin/python3', '-I', '-c', guest_script(address, port)]
                and record.get('argv_digest') == harness.argv_digest(inputs['argv']),
            exact_installed_image_and_binaries=before == after
                and before['service']['sha256'] == image['ukai_vm_sha256']
                and before['client']['sha256'] == image['ukai_jail_sha256']
                and hashlib.sha256(before['image_manifest_json'].encode()).hexdigest() == before['image_manifest_sha256']
                and compatibility.strict_json(before['image_manifest_json']) == image
                and ready.get('boot_id') == inputs['service_status'].get('boot_id')
                and all(ready.get(key) == image.get(key) and bool(image.get(key))
                        for key in ('disk_sha256', 'seed_sha256', 'helper_sha256', 'custodian_sha256')),
            independent_complete_summary=verified['outcome'] == 'PASS' and verified['journal'] == 'complete'
                and type(tail['exit']) is int and tail['exit'] == 0
                and type(tail['json_exit']) is int and tail['json_exit'] == 0,
            same_boot_sync=clean_sync(sync, record)
                and vm_summary_check.equal(sync.get('receipt'), sync_guest) and sync_events is not None
                and sync.get('receipt_sha256') == sync_journal['guest_receipt_sha256']
                and sync_guest.get('attempt_id') != guest.get('attempt_id'),
            stopped_and_quiescent=type(inputs['service_exit']) is int and inputs['service_exit'] == 0
                and inputs['shutdown'].get('complete') is True and inputs['shutdown'].get('held_before_stop') is True
                and inputs['shutdown'].get('sockets_absent') is True and inputs['shutdown'].get('boot_entries_remaining') == [],
            complete_spelling_scans=type(scans) is list and len(scans) == 6
                and {row.get('encoding') for row in scans} == {'raw', 'base64', 'base64url', 'hex', 'url', 'json'}
                and all(set(row) == {'encoding', 'file_hits', 'files_scanned', 'disk_hits', 'disk_bytes'}
                        and type(row['files_scanned']) is int and row['files_scanned'] > 0
                        and row['file_hits'] == [] and type(row['disk_hits']) is int and row['disk_hits'] == 0
                        and type(row['disk_bytes']) is int and row['disk_bytes'] > 0 for row in scans),
            no_harness_error=inputs.get('error_type') is None,
        )
        result.update(facts=facts, outcome='PASS' if all(value is True for value in facts.values()) else 'FAIL',
                      inputs_sha256=hashlib.sha256(raw).hexdigest(), independent_summary=verified)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, harness.HarnessError) as error:
        result['error_type'] = type(error).__name__
        result['facts']['retained_inputs_valid'] = False
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path)
    parser.add_argument('--jail', type=Path)
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--replay', type=Path)
    args = parser.parse_args(argv)
    if args.replay is not None:
        result = replay(args.replay.resolve(strict=True)); print(json.dumps(result, indent=2))
        return 0 if result['outcome'] == 'PASS' else 1
    if any(getattr(args, field) is None for field in ('home', 'jail', 'workspace', 'out')):
        parser.error('live component mode requires --home --jail --workspace --out')
    return measure(args)


def measure(args):
    home = args.home.resolve(strict=True)
    jail = harness.required_binary('UKAI_JAIL_BINARY', str(args.jail))
    binary = harness.required_binary('UKAI_VM_BINARY', str(home / 'bin/ukai-vm'))
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out); harness.clean_workspace(workspace)
    data = Path(tempfile.mkdtemp(prefix='ukpbind-', dir='/tmp')).resolve()
    artifact = data / 'guest-artifact'; artifact.mkdir()
    sync_artifact = data / 'sync-artifact'; sync_artifact.mkdir()
    config = data / 'config'; config.mkdir(mode=0o700)
    secret = ('ukai-program-binding-' + os.urandom(24).hex()).encode()
    spellings = {'raw': secret, 'base64': base64.b64encode(secret), 'hex': secret.hex().encode(),
                 'base64url': base64.urlsafe_b64encode(secret), 'url': urllib.parse.quote_from_bytes(secret).encode(),
                 'json': json.dumps(secret.decode(), ensure_ascii=True)[1:-1].encode()}
    address = vault_measurement.mac_address(); endpoint(address, 1)
    witness = Witness(secret)
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), Peer)
    server.daemon_threads = True; server.witness = witness
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    command = ['/usr/bin/python3', '-I', '-c', guest_script(address, port)]
    launch = declaration(address, port)
    environment = harness.vm_client_environment(PATH=f'{home}/bin:/usr/bin:/bin', UKAI_VM_HOME=home,
                                                UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    inputs = dict(schema=INPUTS, argv=command, launch_toml=launch, upstream=dict(address=address, port=port))
    service = None; record = {}; disk = {}; offline = None; tail = {}; extra = []
    with contextlib.ExitStack() as cleanup:
        lock = None
        try:
            inputs['identity_before'] = lifecycle.normal_identity(home, jail)
            inputs['identity_before']['measurement'] = harness.fingerprint(__file__)
            service = harness.Service(binary, home, workspace, data, extra=('--guest-nat',), environment=environment)
            inputs['service_status'] = service.wait_warm()
            lock = cleanup.enter_context(lifecycle.running_service_lock(data))
            record = attempt(service, artifact, command, launch=launch, secret=secret, allow_host=endpoint(address, port))
            guest, events, journal = compatibility.verified_guest_journal(artifact)
            if events is None: raise ValueError('guest journal unavailable')
            offline = data / 'attempts' / guest['attempt_id']; offline.mkdir(parents=True)
            (offline / 'jail.json').write_bytes(lifecycle.bounded_file(artifact / 'evidence/jail.json', compatibility.RECEIPT_MAX))
            (offline / 'trace.ndjson').write_bytes(b''.join(lifecycle.bounded_file(
                artifact / 'evidence/guest-journal' / f'{index:04}.part', compatibility.JOURNAL_PART) for index in range(journal['parts'])))
            for json_mode in (False, True):
                printed = subprocess.run([str(jail), 'tail', '--summary', *(['--json'] if json_mode else []),
                    '--attempt', guest['attempt_id']], env=environment, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=60)
                tail['json' if json_mode else 'text'] = printed.stdout
                tail['json_exit' if json_mode else 'exit'] = printed.returncode
                extra.append(printed.stderr)
            inputs['sync'] = attempt(service, sync_artifact, ['/bin/sync'])
            if not clean_sync(inputs['sync'], record): raise ValueError('same-boot clean executed sync failed')
            path = service.boot_dir() / 'image/base.raw'
            disk = {name: {'disk_bytes': path.stat().st_size, 'disk_hits': int(vault_measurement.file_holds(path, value))}
                    for name, value in spellings.items()}
        except Exception as error:
            inputs['error_type'] = type(error).__name__
        finally:
            server.shutdown(); server.server_close()
            if service is not None:
                try:
                    inputs['service_exit'] = service.stop(); extra.append(service.stderr_text())
                    if lock is not None: inputs['shutdown'] = lifecycle.stopped_service_lock(data, lock)
                except Exception as error: inputs['error_type'] = type(error).__name__
        inputs.update(record=record, peer=witness.snapshot(), tail=tail, auxiliary=extra,
                      offline_attempt=str(offline) if offline else None)
        try:
            inputs['identity_after'] = lifecycle.normal_identity(home, jail)
            inputs['identity_after']['measurement'] = harness.fingerprint(__file__)
            inputs['scans'] = []
            for name, value in spellings.items():
                hits, count = vault_measurement.leak_scan([data, workspace], value)
                inputs['scans'].append(dict(encoding=name, file_hits=hits, files_scanned=count,
                                           **disk.get(name, {'disk_bytes': 0, 'disk_hits': 0})))
            encoded = (json.dumps(inputs, indent=2, ensure_ascii=False) + '\n').encode()
            if len(encoded) > 8 * 1024 * 1024 or any(value in encoded for value in spellings.values()):
                raise ValueError('protected or oversized retained inputs')
            if any(row['file_hits'] or row['disk_hits'] or row['disk_bytes'] <= 0 for row in inputs['scans']):
                raise ValueError('incomplete or positive exposure scan')
            if offline is None: raise ValueError('no settled offline guest attempt')
            retain_tree(artifact, out / 'guest-artifact', spellings.values())
            retain_tree(offline, out / 'guest-attempt', spellings.values())
            retain_tree(sync_artifact, out / 'sync-artifact', spellings.values())
            (out / 'inputs.json').write_bytes(encoded)
            metadata = {'schema': SCHEMA, 'inputs_sha256': hashlib.sha256(encoded).hexdigest(), 'qualified': False}
            (out / 'measurement.json').write_text(json.dumps(metadata, indent=2) + '\n')
            result = replay(out)
        except Exception as error:
            # Retain diagnostics with source spellings removed; never label a
            # partial, unscanned tree exact or replayable evidence.
            safe = json.dumps(inputs, indent=2, ensure_ascii=False)
            for value in sorted(spellings.values(), key=len, reverse=True): safe = safe.replace(value.decode(), '<synthetic-credential>')
            (out / 'failed-inputs.redacted.json').write_text(safe + '\n')
            result = {'schema': SCHEMA, 'outcome': 'FAIL', 'qualified': False, 'error_type': type(error).__name__,
                      'facts': {'exact_scanned_replayable_evidence': False}}
        result['scope'] = 'Literal warm-service component: actual Linux @program own/copy proxy control; not native catalog, vendor, host source-watch or K113 qualification.'
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'outcome': result['outcome'], 'qualified': False, 'evidence': str(out)}))
    return 0 if result['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
