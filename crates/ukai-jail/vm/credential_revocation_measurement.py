#!/usr/bin/env python3
"""Measure host-source deletion during a live guest proxy stream.

Uses a fresh synthetic source and an independent HTTP peer on this Mac. It
does not bypass the installed client's capability gate, read provider keys,
qualify TLS/vendor compatibility, or promote K113. A refused run is retained.
"""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time

import claude_vm_row as compatibility
import harness
import vault_measurement


CREDENTIAL = 'test'
DISCONNECT_BOUND = 5.0
ACK_BOUND = 2.0


class StreamWitness:
    """Only booleans, labels and local monotonic times are retained, no headers."""
    def __init__(self, secret):
        self.secret = secret.decode()
        self.accepted = threading.Event()
        self.finished = threading.Event()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests = []
        self.accepted_at = self.deleted_at = self.disconnected_at = None
        self.revocation_sent_at = None
        self.expired = False

    def snapshot(self):
        with self.lock:
            return {'requests': list(self.requests), 'accepted_at': self.accepted_at,
                    'deleted_at': self.deleted_at, 'disconnected_at': self.disconnected_at,
                    'revocation_sent_at': self.revocation_sent_at,
                    'expired': self.expired}

    def delete_source(self, source):
        # An arbitrary client connection is not the trigger: this event is set
        # only after the expected substituted header and first stream write.
        if not self.accepted.is_set():
            raise harness.HarnessError('the independent peer has not accepted a credentialed stream')
        source.unlink()
        with self.lock:
            self.deleted_at = time.monotonic()


class StreamingPeer(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        witness = self.server.witness
        matches = self.headers.get('x-test-token') == witness.secret
        with witness.lock:
            witness.requests.append({'path': self.path if self.path in ('/stream', '/after') else 'other',
                                     'credential_matches': matches, 'at': time.monotonic()})
        if self.path != '/stream' or not matches:
            self.send_response(403)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        try:
            self.wfile.write(b'5\r\nready\r\n')
            self.wfile.flush()
            with witness.lock:
                witness.accepted_at = time.monotonic()
            witness.accepted.set()
            deadline = time.monotonic() + 40
            while not witness.stop.is_set() and time.monotonic() < deadline:
                readable, _, _ = select.select([self.connection], [], [], 0.05)
                if readable and self.connection.recv(1, socket.MSG_PEEK) == b'':
                    with witness.lock:
                        witness.disconnected_at = time.monotonic()
                    break
            else:
                with witness.lock:
                    witness.expired = True
        except (OSError, ValueError):
            # Socket errors establish closure, but before acceptance they can
            # never cause source deletion or satisfy the ordered witness.
            with witness.lock:
                witness.disconnected_at = time.monotonic()
        finally:
            self.close_connection = True
            witness.finished.set()


def guest_script(address, port):
    # The child holds a placeholder, not the synthetic credential. No value
    # or vendor key is embedded in this argv. The first read cannot finish
    # normally: the peer never sends the terminating chunk.
    return f'''import hashlib, os, re, urllib.error, urllib.request
token = os.environ.get('UKAI_VAULT_TEST', '')
shown = token if re.fullmatch({vault_measurement.PLACEHOLDER_SHAPE!r}, token) else '-'
print('PLACEHOLDER', hashlib.sha256(token.encode()).hexdigest(), len(token), shown, flush=True)
def request(path):
    return urllib.request.Request('http://{address}:{port}' + path, headers={{'x-test-token': token}})
try:
    with urllib.request.urlopen(request('/stream'), timeout=30) as response:
        response.read()
    print('STREAM_ENDED', flush=True)
except Exception as error:
    print('STREAM_INTERRUPTED', type(error).__name__, flush=True)
print('AFTER_ATTEMPT', flush=True)
try:
    with urllib.request.urlopen(request('/after'), timeout=10) as response:
        response.read()
    print('AFTER_ALLOWED', flush=True)
    raise SystemExit(1)
except urllib.error.HTTPError as error:
    print('AFTER_REFUSED', error.code, flush=True)
    raise SystemExit(0 if error.code == 403 else 2)
'''


def judge(observed, guest, events, summary):
    try:
        return _judge(observed, guest, events, summary)
    except (AttributeError, KeyError, TypeError, ValueError):
        return {'evidence_well_formed': False}


def _judge(observed, guest, events, summary):
    peer = observed.get('peer') or {}
    accepted, deleted, disconnected = (peer.get(key) for key in ('accepted_at', 'deleted_at', 'disconnected_at'))
    ordered = (all(type(value) in (int, float) for value in (accepted, deleted, disconnected))
               and accepted < deleted <= disconnected and disconnected - deleted <= DISCONNECT_BOUND)
    requests = peer.get('requests') or []
    frames = [] if events is None else [event for event in events
        if event.get('source') == 'proxy' and event.get('operation') == 'net.connect']
    used = [event for event in frames if CREDENTIAL in (event.get('fields', {}).get('credentials') or [])]
    first = used[0] if len(used) == 1 else {}
    later = [event for event in frames if event.get('source_seq', 0) > first.get('source_seq', 2 ** 64)]
    notes = [] if events is None else [event.get('fields') or {} for event in events
        if event.get('source') == 'wrapper' and event.get('operation') == 'note']
    lines = {line.get('line'): line.get('facts') or {} for line in summary.get('lines', [])}
    credentials = lines.get('credentials', {}).get('credentials') or []
    guest_credentials = guest.get('credentials') or []
    coverage = guest.get('coverage') or {}
    return {
        'independent_stream_before_delete_then_prompt_disconnect': ordered and peer.get('expired') is False,
        'exactly_one_upstream_substitution': len(requests) == 1
            and requests[0].get('path') == '/stream' and requests[0].get('credential_matches') is True,
        'bound_complete_guest_journal': events is not None and (observed.get('guest_journal') or {}).get('verified') is True,
        'allowed_stream_ended_credential_revoked': len(used) == 1 and first.get('decision') == 'allow'
            and first.get('fields', {}).get('reason') == 'relayed'
            and first.get('fields', {}).get('end') == 'credential_revoked',
        'later_request_denied_without_substitution': bool(later) and all(
            event.get('decision') == 'deny' and event.get('fields', {}).get('reason') == 'credential_revoked'
            and not event.get('fields', {}).get('credentials')
            and not event.get('fields', {}).get('credentials_unconfirmed') for event in later)
            and len(frames) == 2 and observed.get('after_refused') is True,
        'guest_revocation_note': any(note.get('kind') == 'credential' and note.get('credential_id') == CREDENTIAL
            and note.get('transition') == 'revoked' and note.get('uses_recorded') is True for note in notes),
        'receipt_and_tail_use_count_match': len(credentials) == 1 and credentials[0].get('id') == CREDENTIAL
            and credentials[0].get('uses') == len(used) == 1 and credentials[0].get('uses_bound') == 'exact'
            and type((coverage.get('proxy.net') or {}).get('observed_count')) is int
            and coverage['proxy.net']['observed_count'] == len(frames),
        'vault_never_staged': len(guest_credentials) == 1 and guest_credentials[0].get('id') == CREDENTIAL
            and guest_credentials[0].get('mode') == 'vault' and guest_credentials[0].get('never_staged') is True,
        'child_placeholder_bound': vault_measurement.placeholder_facts(observed.get('placeholder'), guest.get('attempt_id')),
        'strict_six_class_coverage': set(coverage) == set(harness.SUMMARY_CLASSES)
            and all(value.get('status') == 'active' and value.get('gaps') == [] for value in coverage.values())
            and lines.get('evidence', {}).get('observe') == 'on' and lines.get('evidence', {}).get('evidence') == 'strict',
        'settled_clean_guest': guest.get('phase') == 'settled' and guest.get('errors') == []
            and guest.get('containment') == 'enforced' and guest.get('child_protection') == 'enforced'
            and guest.get('exec_observed') is True
            and guest.get('outcome') == {'kind': 'exited', 'code': 0}
            and guest.get('state_cleanup') == 'complete' and guest.get('cleanup_error') is None
            and (guest.get('lifetime') or {}).get('tree_empty') is True
            and (guest.get('lifetime') or {}).get('integrity') == 'verified',
        'host_binding_and_settlement': observed.get('receipt_bound') is True
            and observed.get('host_receipt_contradictions') == [] and observed.get('host_clean') is True,
        'client_and_summary_succeeded': observed.get('run_exit') == 0 and observed.get('tail_exit') == 0
            and observed.get('tail_json_exit') == 0 and observed.get('tail_agrees') is True
            and observed.get('client_thread_settled') is True and 'harness_error_type' not in observed,
        'source_removed_before_stop': observed.get('source_removed_before_stop') is True,
        'all_exported_bytes_scanned': observed.get('leaks') == [] and observed.get('files_scanned', 0) > 0
            and observed.get('output_leak') is False,
        'same_boot_disk_scanned': observed.get('same_boot') is True and observed.get('disk_scan') == 'clean'
            and observed.get('sync_exit') == 0,
        'service_stopped': observed.get('stop_exit') == 0,
    }


class BoundedFrames:
    """One raw socket, preserving partial frames across short poll timeouts."""
    def __init__(self, channel):
        self.channel = channel
        self.buffer = b''
        self.total = 0

    def receive(self, timeout):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            if time.monotonic() >= deadline:
                raise TimeoutError('raw frame read deadline')
            self.channel.stream.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = self.channel.stream.recv(65536)
            if not chunk:
                raise harness.StreamEnded('raw transport ended before a frame')
            self.buffer += chunk
            self.total += len(chunk)
            if len(self.buffer) > 2 * 1024 * 1024 or self.total > 64 * 1024 * 1024:
                raise harness.HarnessError('raw transport size bound exceeded')
        line, self.buffer = self.buffer.split(b'\n', 1)
        value = compatibility.strict_json(line)
        if type(value) is not dict:
            raise harness.HarnessError('raw frame is not an object')
        return value


def store_raw_file(root, group, name, raw, seen):
    """Only fresh regular files beneath this probe's private artifact root."""
    if (group not in ('workspace', 'evidence') or type(name) is not str or '\0' in name
            or any(part in ('', '.', '..') for part in name.split('/'))
            or name.startswith('/') or len(raw) > 512 * 1024 or (group, name) in seen):
        raise harness.HarnessError('invalid or duplicated raw exported file')
    current = root / group
    current.mkdir(exist_ok=True)
    if current.is_symlink():
        raise harness.HarnessError('raw export directory is a link')
    for part in name.split('/')[:-1]:
        current = current / part
        current.mkdir(exist_ok=True)
        if current.is_symlink():
            raise harness.HarnessError('raw export directory is a link')
    descriptor = os.open(current / name.split('/')[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
    seen.add((group, name))


def raw_attempt(service, artifact, command, launch, secret, witness, allow_host):
    """Explicit component probe; it neither constructs nor claims a host run receipt."""
    record = {'attempt_id': 'k113-raw-' + harness.nonce(), 'profile': 'agent',
              'argv_digest': harness.argv_digest(command), 'started_at': harness.rfc3339_now(),
              'events': [], 'error': None, 'stdout': '', 'stderr': '', 'exit_code': None,
              'revocation_ack': False}
    channel = None
    files = set()
    total = 0
    try:
        channel = service.connect(timeout=120)
        frames = BoundedFrames(channel)
        ready = frames.receive(120)
        if ready.get('event') != 'ready' or ready.get('schema') != 'ukai.jail.vm-attempt/1':
            raise harness.HarnessError('raw transport was not ready')
        record['ready'], record['boot_id'] = ready, ready.get('boot_id')
        channel.send(op='prepare', attempt_id=record['attempt_id'], profile='agent', wall_seconds=50,
                     argv=[harness.b64(word) for word in command], allow_hosts=[allow_host],
                     launch={'name': 'revocation-measurement', 'toml': launch},
                     secrets=[{'id': CREDENTIAL, 'data': harness.b64(secret)}])
        prepared = frames.receive(120)
        if (prepared.get('event') != 'prepared'
                or prepared.get('staged_secrets') != [[CREDENTIAL, '/run/ukai-vm/credentials/test']]):
            raise harness.HarnessError('raw transport did not stage the exact source')
        record['prepared'] = prepared
        channel.send(op='run')
        released = False
        sent = False
        receipt = False
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            # The peer can observe the guest request before this thread reads
            # the already-written Released frame. Retain its real timestamp,
            # and wait for both facts rather than treating scheduling as loss.
            if released and witness.accepted.is_set() and not sent:
                with witness.lock:
                    witness.revocation_sent_at = time.monotonic()
                channel.send(op='revoke_secrets', ids=[CREDENTIAL])
                sent = True
            try:
                message = frames.receive(0.05)
            except TimeoutError:
                continue
            event = message.get('event')
            record['events'].append(event)
            if event == 'released' and not released:
                released = True
                record['supervisor_pid'] = message.get('supervisor_pid')
            elif event == 'secrets_revoked':
                if not sent or record['revocation_ack'] or message.get('ids') != [CREDENTIAL]:
                    raise harness.HarnessError('unexpected raw revocation acknowledgment')
                record['revocation_ack'] = True
                record['revocation_ack_at'] = time.monotonic()
            elif event in ('stdout', 'stderr'):
                raw = base64.b64decode(message.get('data', ''), validate=True)
                if len(record[event]) + len(raw) > 2 * 1024 * 1024:
                    raise harness.HarnessError('raw output bound exceeded')
                record[event] += raw.decode(errors='replace')
            elif event == 'file':
                raw = base64.b64decode(message.get('data', ''), validate=True)
                total += len(raw)
                if total > 32 * 1024 * 1024 or len(files) >= 5000:
                    raise harness.HarnessError('raw export bound exceeded')
                store_raw_file(artifact, message.get('group'), message.get('path'), raw, files)
            elif event == 'bound_receipt' and not receipt:
                raw = base64.b64decode(message.get('data', ''), validate=True)
                if hashlib.sha256(raw).hexdigest() != message.get('sha256'):
                    raise harness.HarnessError('raw receipt digest mismatch')
                parsed = compatibility.strict_json(raw)
                if type(parsed) is not dict or type(message.get('binding')) is not dict:
                    raise harness.HarnessError('raw receipt or binding is not an object')
                store_raw_file(artifact, 'evidence', 'jail.json', raw, files)
                record.update(receipt_sha256=message['sha256'], receipt_digest_ok=True,
                              receipt=parsed, binding=message['binding'])
                receipt = True
            elif event == 'done':
                record['exit_code'], record['guest_stop'] = message.get('exit_code'), message.get('stop')
                if not receipt or not sent or not record['revocation_ack']:
                    raise harness.HarnessError('raw attempt completed without bound revocation evidence')
                return record
            else:
                raise harness.HarnessError('unexpected raw transport event')
        raise harness.HarnessError('raw attempt timed out')
    except (OSError, ValueError, TypeError, KeyError, harness.HarnessError, harness.StreamEnded) as error:
        record['error'] = type(error).__name__  # Never retain arbitrary peer/error text.
    finally:
        if channel is not None:
            channel.close()
    return record


def raw_judge(observed, guest, events, summary, record):
    try:
        return _raw_judge(observed, guest, events, summary, record)
    except (AttributeError, KeyError, TypeError, ValueError):
        return {'evidence_well_formed': False}


def _raw_judge(observed, guest, events, summary, record):
    # Share the proxy/count/peer proof, with an explicitly different trigger.
    component = dict(observed, peer=dict(observed.get('peer') or {}))
    component['peer']['deleted_at'] = component['peer'].get('revocation_sent_at')
    facts = judge(component, guest, events, summary)
    for name in ('host_binding_and_settlement', 'client_and_summary_succeeded', 'source_removed_before_stop'):
        facts.pop(name, None)
    facts['explicit_revoke_after_peer_accept_then_disconnect'] = facts.pop(
        'independent_stream_before_delete_then_prompt_disconnect', False)
    binding = record.get('binding') or {}
    stop = record.get('guest_stop') or {}
    guest_boot = (((guest.get('process') or {}).get('identity') or {}).get('value') or {}).get('boot_id')
    sent, ack = component['peer'].get('revocation_sent_at'), record.get('revocation_ack_at')
    facts.update(
        exact_revocation_ack=record.get('revocation_ack') is True
            and record.get('events', []).count('secrets_revoked') == 1
            and type(sent) in (int, float) and type(ack) in (int, float) and 0 <= ack - sent <= ACK_BOUND,
        bound_guest_component=harness.receipt_bound(record)
            and binding.get('guest_attempt_id') == guest.get('attempt_id')
            and bool(guest_boot) and binding.get('guest_boot_id') == guest_boot
            and record.get('receipt') == guest and record.get('exit_code') == 0 and record.get('error') is None,
        guest_controller_cleanup=harness.stop_covered_the_attempt(stop)
            and all(stop.get(key) == [] for key in ('populated_before_kill', 'live_before_kill', 'strays_killed')),
        offline_guest_tail=observed.get('tail_exit') == 0 and observed.get('tail_json_exit') == 0
            and observed.get('tail_agrees') is True and 'harness_error_type' not in observed,
        image_and_service_bound=observed.get('image_binding') is True,
    )
    return facts


def bounded_file(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
            raise harness.HarnessError('unbounded or nonregular evidence file')
        value = stream.read(cap + 1)
        after = os.fstat(fd)
    stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(value) != before.st_size or stamp(before) != stamp(after):
        raise harness.HarnessError('evidence changed during bounded read')
    return value


def raw_main(args):
    """Developer-only transport measurement, selected explicitly on the CLI."""
    home = args.home.resolve(strict=True)
    jail = harness.required_binary('UKAI_JAIL_BINARY', str(args.jail))
    binary = harness.required_binary('UKAI_VM_BINARY', str(home / 'bin/ukai-vm'))
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    harness.clean_workspace(workspace)
    data = Path(tempfile.mkdtemp(prefix='ukai-raw-revoke-')).resolve()
    artifact = data / 'raw-attempt'; artifact.mkdir()
    config = data / 'config'; config.mkdir(mode=0o700)
    secret = ('ukai-raw-revoke-' + os.urandom(24).hex()).encode()
    spellings = vault_measurement.value_spellings(secret)
    address = vault_measurement.mac_address()
    witness = StreamWitness(secret)
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), StreamingPeer)
    server.daemon_threads = True; server.witness = witness
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    allow_host = f'{address}:{port}'
    launch = f'''name = "revocation-measurement"
jail = "agent"
credentials_one_of = ["test"]
[credentials.test]
mode = "vault"
source = "/run/ukai-vm/credentials/test"
hosts = ["http://{address}:{port}"]
allow_plaintext = true
header = {{ name = "x-test-token" }}
env = "UKAI_VAULT_TEST"
[network]
allow = ["{allow_host}"]
'''
    command = ['/usr/bin/python3', '-c', guest_script(address, port)]
    env = harness.vm_client_environment(PATH=f'{home}/bin:/usr/bin:/bin', UKAI_VM_HOME=home,
                                        UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    service = None
    record, observed, guest, summary = {}, {}, {}, {}
    events = None
    tail = tail_json = tail_error = ''
    auxiliary_output = []
    image_bytes = b''
    try:
        image_bytes = bounded_file(home / 'image/image.json', 1024 * 1024)
        image = compatibility.strict_json(image_bytes)
        service = harness.Service(binary, home, workspace, data, extra=('--guest-nat',), environment=env)
        status = service.wait_warm()
        record = raw_attempt(service, artifact, command, launch, secret, witness, allow_host)
        guest, events, observed['guest_journal'] = compatibility.verified_guest_journal(artifact)
        ready = record.get('ready') or {}
        # The live ready frame names the immutable image bytes. Retain full
        # image metadata separately, including its source/client provenance.
        observed['image_binding'] = (ready.get('boot_id') == status.get('boot_id')
            and all(ready.get(key) == image.get(key) and ready.get(key)
                    for key in ('disk_sha256', 'helper_sha256', 'custodian_sha256', 'seed_sha256'))
            and harness.sha256_file(binary) == image.get('ukai_vm_sha256')
            and harness.sha256_file(jail) == image.get('ukai_jail_sha256'))
        if events is not None:
            # Materialize only the exact verified journal bytes in a separate
            # offline guest attempt. This is not a fabricated host VM receipt.
            trace = b''.join(bounded_file(artifact / 'evidence/guest-journal' / f'{index:04}.part', compatibility.JOURNAL_PART)
                             for index in range(observed['guest_journal']['parts']))
            if hashlib.sha256(trace).hexdigest() != observed['guest_journal']['sha256']:
                raise harness.HarnessError('guest trace changed after verification')
            offline = data / 'attempts' / guest['attempt_id']; offline.mkdir(parents=True)
            receipt_bytes = bounded_file(artifact / 'evidence/jail.json', compatibility.RECEIPT_MAX)
            if hashlib.sha256(receipt_bytes).hexdigest() != observed['guest_journal']['guest_receipt_sha256']:
                raise harness.HarnessError('guest receipt changed after verification')
            (offline / 'jail.json').write_bytes(receipt_bytes)
            (offline / 'trace.ndjson').write_bytes(trace)
            for json_mode in (False, True):
                printed = subprocess.run([str(jail), 'tail', '--summary', *(['--json'] if json_mode else []),
                    '--attempt', guest['attempt_id']], env=env, capture_output=True, text=True, timeout=60)
                if json_mode:
                    observed['tail_json_exit'], tail_json, tail_error = printed.returncode, printed.stdout, printed.stderr
                    try:
                        summary = compatibility.strict_json(tail_json)
                        if type(summary) is not dict: raise ValueError('summary shape')
                    except (ValueError, TypeError): summary = {}
                else: observed['tail_exit'], tail = printed.returncode, printed.stdout + printed.stderr
            observed['tail_agrees'] = ([f"ukai-jail: {line.get('text', '')}" for line in summary.get('lines', [])]
                == [line for line in tail.splitlines() if line.startswith('ukai-jail: ')
                    and not line.startswith('ukai-jail: receipt ')])
        sync = harness.run_attempt(service.connect, 'k113-sync-' + harness.nonce(), ['/bin/sync'], wall=20)
        observed['sync_exit'] = sync.get('exit_code')
        observed['same_boot'] = (harness.receipt_bound(sync) and sync.get('boot_id') == record.get('boot_id')
            and harness.guest_boot(sync) == harness.guest_boot(record))
        auxiliary_output.extend([sync.get('stdout', ''), sync.get('stderr', '')])
        disk = service.boot_dir() / 'image/base.raw'
        observed['disk_scan'] = ('clean' if observed['same_boot'] and all(
            not vault_measurement.file_holds(disk, value.encode()) for value in spellings) else 'unverified-or-value-present')
        observed['sync'] = {key: value for key, value in sync.items() if key not in ('files', 'stdout', 'stderr')}
    except Exception as error:
        observed['harness_error_type'] = type(error).__name__
    finally:
        witness.stop.set(); server.shutdown(); server.server_close()
        if service is not None:
            observed['stop_exit'] = service.stop()
            auxiliary_output.append(service.stderr_text())
        else: observed['stop_exit'] = None
    observed['peer'] = witness.snapshot()
    stdout, stderr = record.get('stdout', ''), record.get('stderr', '')
    observed['placeholder'] = vault_measurement.placeholder(stdout)
    observed['after_refused'] = 'AFTER_ATTEMPT' in stdout and 'AFTER_REFUSED 403' in stdout and 'AFTER_ALLOWED' not in stdout
    observed['output_leak'] = any(value in stdout + stderr + tail + tail_json + tail_error
                                 + ''.join(auxiliary_output) for value in spellings)
    scans = [vault_measurement.leak_scan([data, workspace], value.encode()) for value in spellings]
    observed['leaks'] = sorted({path for hits, _ in scans for path in hits})
    observed['files_scanned'] = max(scanned for _, scanned in scans)
    facts = raw_judge(observed, guest, events, summary, record)
    outcome = 'PASS' if all(facts.values()) else 'FAIL'
    def redacted(text):
        for value in sorted(spellings, key=len, reverse=True): text = text.replace(value, '<synthetic-credential>')
        return vault_measurement.redact(text, address)
    for name, text in [('raw-stdout.txt', stdout), ('raw-stderr.txt', stderr), ('guest-tail.txt', tail),
                       ('guest-tail.json', tail_json), ('guest-tail.stderr', tail_error),
                       ('auxiliary-output.txt', '\n'.join(auxiliary_output))]:
        (out / name).write_text(redacted(text))
    if not observed['leaks']:
        shutil.copytree(artifact, out / 'guest-artifact')
    (out / 'image.json').write_bytes(image_bytes)
    report = {'schema': 'ukai.vm.raw-credential-revocation/1', 'outcome': outcome, 'qualified': False,
              'scope': 'Explicit raw guest/transport component proof; no host source-watch, installed-client or K113 qualification.',
              'binary': harness.fingerprint(binary), 'summary_binary': harness.fingerprint(jail),
              'image_manifest_sha256': hashlib.sha256(image_bytes).hexdigest(),
              'launch_toml': launch, 'argv_digest': harness.argv_digest(command),
              'record': record, 'observed': observed, 'facts': facts}
    harness.write_json(out / 'raw-credential-revocation.json', json.loads(redacted(json.dumps(report))))
    print(json.dumps({'outcome': outcome, 'qualified': False, 'component_only': True, 'facts': facts}))
    return 0 if outcome == 'PASS' else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('home', 'workspace', 'out', 'jail'): parser.add_argument(name, type=Path)
    parser.add_argument('--raw-transport', action='store_true',
                        help='explicit guest/service component probe, without the host client/source watcher')
    args = parser.parse_args(argv)
    if args.raw_transport:
        return raw_main(args)
    home = args.home.resolve(strict=True)
    jail = harness.required_binary('UKAI_JAIL_BINARY', str(args.jail))
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    harness.clean_workspace(workspace)
    secret = ('ukai-revocation-' + os.urandom(24).hex()).encode()
    spellings = vault_measurement.value_spellings(secret)
    address = vault_measurement.mac_address()
    witness = StreamWitness(secret)
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), StreamingPeer)
    server.daemon_threads = True
    server.witness = witness
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    source_dir = Path(tempfile.mkdtemp(prefix='ukai-revoke-source-')).resolve()
    source = source_dir / 'token'
    config = Path(tempfile.mkdtemp(prefix='ukai-revoke-config-')).resolve()
    (config / 'launch').mkdir(mode=0o700)
    profile = f'''name = "revocation-measurement"
jail = "agent"
credentials_one_of = ["test"]
[credentials.test]
mode = "vault"
source = {json.dumps(str(source))}
hosts = ["http://{address}:{port}"]
allow_plaintext = true
header = {{ name = "x-test-token" }}
env = "UKAI_VAULT_TEST"
[network]
allow = ["{address}:{port}"]
'''
    (config / 'launch/revocation-measurement.toml').write_text(profile)
    (config / 'launch/revocation-measurement.toml').chmod(0o600)
    data = Path(tempfile.mkdtemp(prefix='ukai-revoke-data-')).resolve()
    env = harness.vm_client_environment(PATH=f'{home}/bin:/usr/bin:/bin', UKAI_VM_HOME=home,
                                        UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    command = ['/usr/bin/python3', '-c', guest_script(address, port)]
    observed = {}
    result = {}
    stdout = stderr = tail = tail_json = tail_error = ''
    auxiliary_output = []
    guest, events, summary = {}, None, {}
    attempt = None
    worker = None
    def run():
        try:
            result['run'] = subprocess.run([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'agent',
                '--launch', 'revocation-measurement', *harness.vm_wall(50), '--workspace', str(workspace), '--', *command],
                env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=420)
        except (OSError, subprocess.SubprocessError) as error:
            result['error_type'] = type(error).__name__
    try:
        source.write_bytes(secret); source.chmod(0o600)
        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        while worker.is_alive() and not witness.accepted.wait(0.05):
            pass
        if witness.accepted.is_set():
            witness.delete_source(source)
        worker.join()
        done = result.get('run')
        if done is not None:
            observed['run_exit'], stdout, stderr = done.returncode, done.stdout, done.stderr
        else:
            observed['run_exit'] = None
            observed['run_error_type'] = result.get('error_type')
        attempts = sorted((data / 'attempts').glob('att_*'))
        if len(attempts) == 1:
            attempt = attempts[0]
            guest, events, observed['guest_journal'] = compatibility.verified_guest_journal(attempt)
            host = compatibility.read_json(attempt / 'jail.json')
            observed['receipt_bound'] = harness.attempt_dir_bound(attempt, command)
            observed['host_receipt_contradictions'] = harness.receipt_contradictions(host, guest)
            observed['host_clean'] = (host.get('phase') == 'settled' and host.get('errors') == []
                and host.get('state_cleanup') == 'complete' and host.get('cleanup_error') is None
                and host.get('outcome') == {'kind': 'exited', 'code': 0}
                and (host.get('lifetime') or {}).get('tree_empty') is True)
            for json_mode in (False, True):
                printed = subprocess.run([str(jail), 'tail', '--summary', *(['--json'] if json_mode else []),
                    '--attempt', attempt.name], env=env, capture_output=True, text=True, timeout=60)
                if json_mode:
                    observed['tail_json_exit'], tail_json, tail_error = printed.returncode, printed.stdout, printed.stderr
                    try:
                        summary = compatibility.strict_json(tail_json)
                        if type(summary) is not dict: raise ValueError('summary shape')
                    except (ValueError, TypeError): summary = {}
                else:
                    observed['tail_exit'], tail = printed.returncode, printed.stdout + printed.stderr
            observed['tail_agrees'] = ([f"ukai-jail: {line.get('text', '')}" for line in summary.get('lines', [])]
                == [line for line in tail.splitlines() if line.startswith('ukai-jail: ')
                    and not line.startswith('ukai-jail: receipt ') and not line.startswith('ukai-jail: vm: ')])
            sync = subprocess.run([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                *harness.vm_wall(20), '--workspace', str(workspace), '--', '/bin/sync'], env=env,
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
            observed['sync_exit'] = sync.returncode
            auxiliary_output.extend([sync.stdout, sync.stderr])
            disk, observed['same_boot'] = vault_measurement.boot_disk(data)
            observed['disk_scan'] = ('clean' if disk is not None and all(
                not vault_measurement.file_holds(disk, value.encode()) for value in spellings) else 'unverified-or-value-present')
    except Exception as error:
        observed['harness_error_type'] = type(error).__name__
    finally:
        try:
            source.unlink(missing_ok=True)
            source_dir.rmdir()
        except OSError as error:
            observed['source_cleanup_error_type'] = type(error).__name__
        observed['source_removed_before_stop'] = not source.exists()
        witness.stop.set()
        server.shutdown(); server.server_close()
        try:
            stopped = subprocess.run([str(home / 'bin/ukai-vm'), 'stop'], env=env, capture_output=True, text=True, timeout=60)
            observed['stop_exit'] = stopped.returncode
            auxiliary_output.extend([stopped.stdout, stopped.stderr])
        except (OSError, subprocess.SubprocessError):
            observed['stop_exit'] = None
        if worker is not None:
            worker.join(timeout=5)
            observed['client_thread_settled'] = not worker.is_alive()
    observed['peer'] = witness.snapshot()
    observed['placeholder'] = vault_measurement.placeholder(stdout)
    observed['after_refused'] = 'AFTER_ATTEMPT' in stdout and 'AFTER_REFUSED 403' in stdout and 'AFTER_ALLOWED' not in stdout
    observed['output_leak'] = any(value in stdout + stderr + tail + tail_json + tail_error
                                 + ''.join(auxiliary_output) for value in spellings)
    scans = [vault_measurement.leak_scan([data, workspace], value.encode()) for value in spellings]
    observed['leaks'] = sorted({path for hits, _ in scans for path in hits})
    observed['files_scanned'] = max(scanned for _, scanned in scans)
    facts = judge(observed, guest, events, summary)
    refusals = harness.vm_refusals(stdout + '\n' + stderr)
    outcome = 'REFUSED' if refusals else ('PASS' if all(facts.values()) else 'FAIL')
    def redacted(text):
        for value in sorted(spellings, key=len, reverse=True): text = text.replace(value, '<synthetic-credential>')
        return vault_measurement.redact(text, address)
    for name, text in [('stdout.txt', stdout), ('stderr.txt', stderr), ('tail.txt', tail),
                       ('tail.json', tail_json), ('tail.stderr', tail_error),
                       ('auxiliary-output.txt', '\n'.join(auxiliary_output))]:
        (out / name).write_text(redacted(text))
    # The raw bound receipt/journal is useful evidence, but never export a
    # detected secret copy. Diagnostics still retain every failed condition.
    if attempt is not None and not observed['leaks']:
        shutil.copytree(attempt, out / 'attempt')
    report = {'schema': 'ukai.vm.credential-revocation/1', 'outcome': outcome, 'qualified': False,
              'scope': 'Synthetic plaintext stream on installed VM client; no vendor/TLS/K113 qualification.',
              'binary': harness.fingerprint(jail), 'observed': observed, 'facts': facts, 'refusals': refusals}
    harness.write_json(out / 'credential-revocation.json', json.loads(redacted(json.dumps(report))))
    print(json.dumps({'outcome': outcome, 'qualified': False, 'facts': facts}))
    return 0 if outcome == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
