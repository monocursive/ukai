#!/usr/bin/env python3
"""One explicit API-only native vendor-stream revocation measurement.

No automatic provider run, retries, raw transport fallback, or gate promotion.
`live` is a paid operation requiring separately reviewed authorization. `replay`
and the test suite never contact a provider. See the result's observational scope.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import time
import tomllib

import claude_vm_row as native
import credential_revocation_measurement as lifecycle
import harness
import vault_measurement
import vm_summary_check

SCHEMA = 'ukai.vm.native-vendor-revocation/1'
PROMPT = ('Write a plain-text numbered list from 1 to 500, giving one short sentence about a harmless '
          'everyday object at each number. Start directly with item 1. Do not use tools or read or write files.')
FRAME_MAX = 1024 * 1024
STDOUT_MAX = 8 * FRAME_MAX
STDERR_MAX = 2 * FRAME_MAX
FRAME_COUNT = 4096
READ_MAX = 32768
READ_COUNT = 32768
CLIENT_SECONDS = 300
INPUT_MAX = 8 * FRAME_MAX
TOOL_NAMES = ('claude_vm_revocation.py', 'claude_vm_row.py', 'credential_revocation_measurement.py',
              'vm_summary_check.py', 'vault_measurement.py', 'harness.py')
SCOPE = ('One API-only normal native vendor stream. Proxy events describe completed requests, not header '
         'substitution times. Zero observed retries means unobserved. Host/guest clocks are not compared; '
         'normal source-watch ACK timing is not exposed. Periodic readable env/argv sampling is not full '
         'memory coverage. Reported cost is not billing attestation. No OAuth, full K113 or release qualification.')
REPLACED_FACTS = frozenset({'task_passed', 'guest_settled_clean', 'strict_successful_outcome',
    'host_settled_clean', 'vendor_reported_success', 'run_and_both_tail_commands_succeeded'})


class Refusal(ValueError):
    """Closed diagnostic codes only: never include output or a source value."""


def argv(jail, workspace):
    suffix = ['-p', PROMPT, '--output-format', 'stream-json', '--include-partial-messages', '--verbose',
              '--model', 'sonnet', '--max-budget-usd', '0.50', '--bare', '--no-session-persistence', '--tools', '']
    return ([str(jail), 'run', '--vm', '--from-path', '--launch', 'claude', '--state', 'attempt',
             '--terminal', 'detach', '--profile', 'agent', '--limit', 'wall=240s', '--workspace', str(workspace),
             '--', *suffix], suffix)


def controls():
    return {'requested_model': 'sonnet', 'max_budget_usd': '0.50', 'auth_mode': 'bare-api-key-only',
            'session_persistence': False, 'tools': [], 'wall_seconds': 240,
            'client_timeout_seconds': CLIENT_SECONDS, 'turn_limit': None,
            'pinned_vendor_help_sha256': native.CLAUDE_HELP_SHA256}


def integer(value, low=0, high=2 ** 64 - 1):
    return type(value) is int and low <= value <= high


def json_value(raw):
    # Bound nesting before invoking the recursive JSON decoder (inside strings,
    # brackets are data). strict_json rejects repeated keys/nonfinite numbers.
    depth = 0; quoted = False; escaped = False
    for char in raw:
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '[{':
            depth += 1
            if depth > 32: raise Refusal('json-depth')
        elif char in ']}': depth -= 1
    return native.strict_json(raw)


class Stream:
    """Bounded NDJSON state machine. Feed exactly one OS read per call."""
    def __init__(self):
        self.pending = b''; self.frames = []; self.session = None
        self.message = None; self.blocks = {}; self.finished = False
        self.candidate = None; self.result = None; self.bytes = 0

    def feed(self, chunk, now):
        if not isinstance(chunk, bytes) or not integer(now, 1): raise Refusal('read-shape')
        self.bytes += len(chunk)
        if self.bytes > STDOUT_MAX: raise Refusal('stdout-cap')
        self.pending += chunk
        lines = self.pending.split(b'\n'); self.pending = lines.pop()
        if len(self.pending) > FRAME_MAX: raise Refusal('frame-cap')
        first = None
        for raw in lines:
            if not raw or len(raw) > FRAME_MAX: raise Refusal('frame-shape')
            if len(self.frames) >= FRAME_COUNT: raise Refusal('frame-count')
            try: item = json_value(raw.decode('utf-8'))
            except (UnicodeError, ValueError, RecursionError): raise Refusal('frame-json') from None
            if type(item) is not dict or type(item.get('type')) is not str: raise Refusal('event-shape')
            index = len(self.frames)
            self.frames.append(item)
            candidate = self.event(item, index, now)
            if candidate is not None and self.candidate is None and first is None: first = candidate
            if first is not None and (self.finished or self.message is None):
                raise Refusal('response-complete-in-trigger-read')
        if first is not None:
            self.candidate = first
            return first
        return None

    def event(self, item, index, now):
        session = item.get('session_id')
        if item['type'] == 'stream_event' and session is None:
            raise Refusal('missing-stream-session')
        if session is not None:
            if type(session) is not str or not 1 <= len(session) <= 256: raise Refusal('session-shape')
            if self.session is not None and self.session != session: raise Refusal('session-changed')
            self.session = session
        if item['type'] == 'result':
            if self.result is not None: raise Refusal('duplicate-result')
            self.result = item; self.finished = True
            return None
        if item['type'] != 'stream_event': return None
        if self.finished or item.get('parent_tool_use_id', 'absent') is not None or not self.session:
            raise Refusal('stream-attribution')
        event = item.get('event')
        if type(event) is not dict: raise Refusal('stream-shape')
        kind = event.get('type')
        if kind == 'message_start':
            message = event.get('message')
            if (self.message is not None or type(message) is not dict or message.get('role') != 'assistant'
                    or type(message.get('id')) is not str or not 1 <= len(message['id']) <= 256):
                raise Refusal('message-start')
            self.message = message['id']; self.blocks = {}
        elif kind == 'message_stop':
            if self.message is None: raise Refusal('message-stop')
            self.message = None; self.blocks = {}
        elif kind in ('content_block_start', 'content_block_delta', 'content_block_stop'):
            slot = event.get('index')
            if self.message is None or not integer(slot, 0, 4095): raise Refusal('block-identity')
            if kind == 'content_block_start':
                block = event.get('content_block')
                if slot in self.blocks or type(block) is not dict or type(block.get('type')) is not str:
                    raise Refusal('block-start')
                self.blocks[slot] = block['type']
            elif kind == 'content_block_stop':
                if slot not in self.blocks: raise Refusal('block-stop')
                del self.blocks[slot]
            else:
                delta = event.get('delta')
                if slot not in self.blocks or type(delta) is not dict: raise Refusal('block-delta')
                if delta.get('type') == 'text_delta':
                    text = delta.get('text')
                    if self.blocks[slot] != 'text' or type(text) is not str: raise Refusal('text-delta')
                    if text and self.candidate is None:
                        return {'frame': index, 'read_ns': now, 'session_id': self.session,
                                'message_id': self.message, 'block': slot, 'characters': len(text)}
        return None

    def finish(self):
        if self.pending: raise Refusal('unfinished-json')


def identity(info):
    return {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'size', 'mtime_ns', 'ctime_ns', 'mode', 'uid', 'nlink')}


class SourceCopy:
    """Own exactly one new inode beneath a pinned, private directory."""
    def __init__(self, directory, token):
        self.path = Path(directory)
        self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.fd = None; self.removed = False; self.trigger = None
        try:
            info = os.fstat(self.directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o077: raise Refusal('copy-directory')
            self.dir_identity = (info.st_dev, info.st_ino)
            self.fd = os.open('anthropic', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
            view = memoryview(token)
            while view:
                n = os.write(self.fd, view)
                if not n: raise Refusal('copy-write')
                view = view[n:]
            os.fsync(self.fd)
            self.created = identity(os.fstat(self.fd))
        except BaseException:
            if self.fd is not None:
                held = os.fstat(self.fd)
                try:
                    entry = os.stat('anthropic', dir_fd=self.directory, follow_symlinks=False)
                    if (held.st_dev, held.st_ino) == (entry.st_dev, entry.st_ino):
                        os.unlink('anthropic', dir_fd=self.directory)
                except OSError: pass
            self.close()
            raise

    def unlink(self, *, trigger=None):
        if self.removed: raise Refusal('copy-already-removed')
        info = self.path.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.dir_identity:
            raise Refusal('copy-directory-changed')
        entry = os.stat('anthropic', dir_fd=self.directory, follow_symlinks=False)
        if (identity(entry) != self.created or identity(os.fstat(self.fd)) != self.created
                or not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1):
            raise Refusal('copy-identity-changed')
        before = time.monotonic_ns()
        os.unlink('anthropic', dir_fd=self.directory)
        after = time.monotonic_ns()
        if os.fstat(self.fd).st_nlink != 0: raise Refusal('copy-still-linked')
        self.removed = True
        if trigger is not None:
            self.trigger = {'trigger': trigger, 'unlink_before_ns': before, 'unlink_after_ns': after,
                            'copy_identity': self.created, 'unlinked_nlink': 0}
        return self.trigger

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd = None
        if getattr(self, 'directory', None) is not None: os.close(self.directory); self.directory = None


def collect(command, environment, on_delta=None, *, timeout=CLIENT_SECONDS, popen=subprocess.Popen, parse_stream=True):
    """No unbounded pipe read, output file, inherited stdin or failure exception text."""
    capture = {'stdout': b'', 'stderr': b'', 'reads': [], 'started_ns': time.monotonic_ns(),
               'exit': None, 'intervened': False}
    stream = Stream(); child = None
    try:
        child = popen(command, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            for label in ('stdout', 'stderr'):
                pipe = getattr(child, label); os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            deadline = time.monotonic() + timeout
            while selector.get_map() or child.poll() is None:
                if time.monotonic() >= deadline: raise Refusal('client-deadline')
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), READ_MAX)
                    if not chunk:
                        selector.unregister(key.fileobj); continue
                    label = key.data
                    limit = STDOUT_MAX if label == 'stdout' else STDERR_MAX
                    if len(capture[label]) + len(chunk) > limit: raise Refusal(label + '-cap')
                    capture[label] += chunk
                    if label == 'stdout':
                        now = time.monotonic_ns()
                        capture['reads'].append({'end': len(capture[label]), 'ns': now})
                        if len(capture['reads']) > READ_COUNT: raise Refusal('read-count')
                        candidate = stream.feed(chunk, now) if parse_stream else None
                        if candidate is not None and on_delta is not None:
                            capture['unlink'] = on_delta(candidate)
            if parse_stream: stream.finish()
            capture['exit'] = child.wait(timeout=1)
    except Exception as error:
        capture['error_type'] = type(error).__name__
        if type(error) is Refusal: capture['error_code'] = str(error)
    finally:
        if child is not None:
            if child.poll() is None:
                capture['intervened'] = True
                try: child.terminate()
                except ProcessLookupError: pass
                try: child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    try: child.kill()
                    except ProcessLookupError: pass
                    child.wait(timeout=2)
            capture['exit'] = child.returncode
            for label in ('stdout', 'stderr'):
                if getattr(child, label): getattr(child, label).close()
        capture['finished_ns'] = time.monotonic_ns()
    return capture


def replay_stream(stdout, capture):
    if (not isinstance(stdout, bytes) or len(stdout) > STDOUT_MAX or type(capture.get('reads')) is not list
            or not 1 <= len(capture['reads']) <= READ_COUNT): raise Refusal('reads-shape')
    stream = Stream(); prior = 0; last = capture['started_ns']
    if not integer(last, 1): raise Refusal('clock-shape')
    for item in capture['reads']:
        if (type(item) is not dict or set(item) != {'end', 'ns'} or not integer(item['end'], prior + 1, len(stdout))
                or item['end'] - prior > READ_MAX or not integer(item['ns'], last)):
            raise Refusal('read-boundary')
        stream.feed(stdout[prior:item['end']], item['ns']); prior = item['end']; last = item['ns']
    stream.finish()
    if prior != len(stdout) or not integer(capture.get('finished_ns'), last): raise Refusal('read-finish')
    return stream


def nonzero_outcome(value):
    return (type(value) is dict and set(value) == {'kind', 'code', 'signal', 'cause', 'error'}
            and value['kind'] == 'exited' and integer(value['code'], 1, 255)
            and all(value[key] is None for key in ('signal', 'cause', 'error')))


def clean_settlement(receipt, *, host=False):
    source_only = receipt.get('credentials') == [{'id': 'anthropic', 'mode': 'vault', 'never_staged': True,
                                                'digest': None, 'digest_unavailable_reason': 'never_staged'}]
    return (receipt.get('phase') == 'settled' and receipt.get('errors') == []
            and nonzero_outcome(receipt.get('outcome')) and receipt.get('exec_observed') is True
            and receipt.get('containment') == receipt.get('child_protection') == 'enforced'
            and (receipt.get('lifetime') or {}).get('tree_empty') is True
            and (receipt.get('lifetime') or {}).get('integrity') == 'verified'
            and receipt.get('cleanup_error') is None and (receipt.get('state_cleanup') == 'complete'
                or host and source_only and receipt.get('vendor_state') is None and receipt.get('state_cleanup') == 'not_needed'))


def revocation_events(events, provider_hosts):
    """Conservative completed-result accounting; no inferred header/ACK clock."""
    notes = [e for e in events if e.get('source') == 'wrapper' and e.get('operation') == 'note'
             and e.get('fields', {}).get('kind') == 'credential'
             and e['fields'].get('credential_id') == 'anthropic' and e['fields'].get('transition') == 'revoked']
    if len(notes) != 1 or notes[0]['fields'].get('uses_recorded') is not True: raise Refusal('revoked-note')
    def clock(event):
        value = event.get('monotonic_ns')
        if type(value) is not str or not value.isascii() or not value.isdecimal() or len(value) > 20:
            raise Refusal('guest-clock')
        result = int(value)
        if not integer(result): raise Refusal('guest-clock')
        return result
    revoked_at = clock(notes[0])
    rows = [e for e in events if e.get('source') == 'proxy' and e.get('operation') == 'net.connect']
    active = []; earlier = []; denied = []; requests = set(); used = 0
    for event in rows:
        fields = event.get('fields') or {}; outcome = event.get('outcome') or {}
        request = fields.get('request_id')
        if not integer(request, 1) or request in requests: raise Refusal('request-id')
        requests.add(request)
        if fields.get('credentials_unconfirmed'): raise Refusal('unconfirmed-attribution')
        credentials = fields.get('credentials', [])
        if credentials not in ([], ['anthropic']): raise Refusal('credential-attribution')
        when = clock(event)
        if credentials:
            used += 1
            if event.get('decision') != 'allow' or fields.get('reason') != 'relayed': raise Refusal('attributed-refusal')
            if when < revoked_at:
                earlier.append(request)
            elif (fields.get('end') == 'credential_revoked' and fields.get('transport') == 'http' and fields.get('kind') == 'connect'
                    and fields.get('origin') in provider_hosts and fields.get('origin_verification') == 'mitm_http_host'
                    and fields.get('destination') == fields['origin'] + ':443'
                    and outcome.get('completion') == 'proxy_close' and outcome.get('ok') is True
                    and integer(outcome.get('bytes_in'), 1)):
                active.append(request)
            else: raise Refusal('ambiguous-post-revocation-attribution')
        elif fields.get('reason') == 'credential_revoked':
            if (when < revoked_at or event.get('decision') != 'deny'
                    or type(outcome.get('bytes_in')) is not int or outcome['bytes_in'] != 0
                    or type(outcome.get('bytes_out')) is not int or outcome['bytes_out'] != 0):
                raise Refusal('retry-attribution-or-bytes')
            denied.append(request)
    if not active: raise Refusal('no-revoked-active-stream')
    cutoff = max(active)
    active_origins = {e['fields']['origin'] for e in rows if e['fields']['request_id'] in active}
    for event in rows:
        fields = event['fields']; outcome = event.get('outcome') or {}
        if fields['request_id'] > cutoff and fields.get('origin') in active_origins:
            if (event.get('decision') != 'deny' or fields.get('reason') != 'credential_revoked'
                    or fields.get('credentials') or fields.get('credentials_unconfirmed')
                    or type(outcome.get('bytes_in')) is not int or outcome['bytes_in'] != 0
                    or type(outcome.get('bytes_out')) is not int or outcome['bytes_out'] != 0):
                raise Refusal('newer-provider-request')
    return {'confirmed_uses': used, 'pre_revocation_completed_requests': sorted(earlier),
            'revoked_active_requests': sorted(active), 'observed_revocation_denials': sorted(denied),
            'retry_observation': 'observed' if denied else 'unobserved',
            'scope': 'Completed proxy results, not header-substitution times or independent provider logging.'}


def adapt_facts(base, observed, guest, host):
    if not REPLACED_FACTS <= base.keys(): raise Refusal('native-fact-contract-changed')
    facts = {name: value for name, value in base.items() if name not in REPLACED_FACTS}
    vendor = observed.get('agent_result') or {}
    facts.update(guest_settled_nonzero_clean=clean_settlement(guest), host_settled_nonzero_clean=clean_settlement(host, host=True),
        run_matches_nonzero_receipts=integer(observed.get('run_exit'), 1, 255)
            and observed['run_exit'] == guest.get('outcome', {}).get('code') == host.get('outcome', {}).get('code'),
        both_tail_commands_succeeded=all(type(observed.get(k)) is int and observed[k] == 0 for k in ('tail_exit', 'tail_json_exit')),
        vendor_reported_failure=vendor.get('type') == 'result' and vendor.get('is_error') is True
            and type(vendor.get('subtype')) is str and vendor['subtype'].startswith('error_'))
    return facts


def judge(observed, guest, events, summary, context, suffix, binding, host, stdout):
    try:
        facts = adapt_facts(native.native_facts(observed, guest, events, summary, context, suffix, binding, host), observed, guest, host)
        stream = replay_stream(stdout, observed['capture'])
        unlink = observed['capture'].get('unlink') or {}
        source = unlink.get('copy_identity') or {}
        before, after = unlink.get('unlink_before_ns'), unlink.get('unlink_after_ns')
        facts.update(actual_partial_delta_before_owned_unlink=stream.candidate is not None
                and stream.candidate == unlink.get('trigger') and integer(before, stream.candidate['read_ns'])
                and integer(after, before, observed['capture']['finished_ns']) and unlink.get('unlinked_nlink') == 0
                and integer(source.get('ino'), 1) and source.get('nlink') == 1
                and integer(source.get('uid')) and integer(source.get('mode'))
                and stat.S_ISREG(source['mode']) and source['mode'] & 0o077 == 0,
            no_collection_intervention=observed['capture'].get('intervened') is False
                and 'error_type' not in observed['capture'] and observed['capture']['exit'] == observed['run_exit'],
            terminal_result_matches_capture=stream.result == observed.get('agent_result'),
            reported_usage_matches_terminal_result=native.native_vendor_usage(stream.result) == observed.get('vendor_usage'),
            bounded_collector_elapsed=0 < observed['capture']['finished_ns'] - observed['capture']['started_ns'] <= (CLIENT_SECONDS + 5) * 1_000_000_000,
            reported_cost_within_requested_budget=native.native_api_reported_cost_within_budget(observed.get('vendor_usage'), controls()),
            original_source_metadata_unchanged=observed.get('original_source_unchanged') is True,
            exact_attempt_and_inputs_retained=observed.get('retention_complete') is True,
            same_boot_executed_sync=observed.get('same_boot_sync_verified') is True,
            bounded_same_boot_disk_scan=type(observed.get('disk_scan')) is dict
                and integer(observed['disk_scan'].get('bytes'), 1, 32 * 1024 ** 3)
                and observed['disk_scan'].get('findings') == []
                and observed['disk_scan'].get('encoding_classes') == ['raw', 'json', 'url', 'hex', 'base64', 'base64url'])
        journal = revocation_events(events, context['profile']['network']['allow'])
        facts['revocation_journal_evidence'] = True
        return {'facts': facts, 'journal': journal, 'outcome': 'PASS' if all(v is True for v in facts.values()) else 'FAIL'}
    except (KeyError, ValueError, TypeError, AttributeError, RecursionError):
        return {'facts': {'well_formed_replayable_evidence': False}, 'outcome': 'FAIL'}


def safe_write(path, data, spellings):
    text = data.decode('utf-8')
    hit, safe = native.native_output(text, spellings)
    if hit or safe != text: raise Refusal('unsafe-exact-retention')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream: stream.write(data)
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode()


def read_attempt(attempt, jail, execute, label):
    host = native.strict_json(lifecycle.bounded_file(attempt / 'jail.json', native.RECEIPT_MAX))
    guest, events, journal = native.verified_guest_journal(attempt)
    binding = native.strict_json(lifecycle.bounded_file(attempt / 'evidence/vm-binding.json', native.RECEIPT_MAX))
    plain = execute(label + '-tail', [str(jail), 'tail', '--summary', '--attempt', attempt.name], 60)
    encoded = execute(label + '-json', [str(jail), 'tail', '--summary', '--json', '--attempt', attempt.name], 60)
    summary = native.strict_json(encoded.stdout)
    check = vm_summary_check.verify_attempt(attempt, summary, plain.stdout)
    return host, guest, events, journal, binding, summary, plain, encoded, check


def sync_clean(attempt, original, checked):
    host, guest, events, journal, binding, _, plain, encoded, check = checked
    transport = native.strict_json(lifecycle.bounded_file(attempt / 'vm-transport.json', native.RECEIPT_MAX))
    old = native.strict_json(lifecycle.bounded_file(original / 'evidence/vm-binding.json', native.RECEIPT_MAX))
    return (host.get('attempt_id') != old.get('attempt_id')
        and binding.get('attempt_id') == host.get('attempt_id')
        and binding.get('argv_digest') == guest.get('argv_digest') == host.get('argv_digest') == harness.argv_digest(['/bin/sync'])
        and binding.get('guest_attempt_id') != old.get('guest_attempt_id')
        and binding['boot_id'] == old['boot_id'] and binding['guest_boot_id'] == old['guest_boot_id']
        and journal.get('verified') is True and check.get('outcome') == 'PASS' and check.get('scope') == 'bound_guest'
        and type(plain.returncode) is int and type(encoded.returncode) is int
        and plain.returncode == encoded.returncode == 0 and events is not None
        and all(lifecycle.successful_outcome(r.get('outcome')) and r.get('exec_observed') is True
                and r.get('phase') == 'settled' and r.get('errors') == [] and r.get('cleanup_error') is None
                and r.get('containment') == r.get('child_protection') == 'enforced'
                and (r.get('lifetime') or {}).get('tree_empty') is True
                and (r.get('lifetime') or {}).get('integrity') == 'verified' for r in (host, guest))
        and guest.get('state_cleanup') == 'complete' and guest.get('credentials') == []
        and guest.get('vendor_state') is None
        and harness.stop_covered_the_attempt({'boundaries': transport.get('guest_stop_boundaries')}))


def disk_scan(path, spellings):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 32 * 1024 ** 3: raise Refusal('disk-shape')
        deadline = time.monotonic() + 90; total = 0; tail = b''
        needles = [s.encode() for s in spellings]; overlap = max(map(len, needles)) - 1
        while True:
            if time.monotonic() > deadline: raise Refusal('disk-scan-deadline')
            block = stream.read(1024 * 1024)
            if not block: break
            total += len(block)
            if total > info.st_size or any(n in tail + block for n in needles): raise Refusal('disk-scan-failed')
            tail = (tail + block)[-overlap:] if overlap else b''
        if total != info.st_size or os.fstat(fd).st_size != total: raise Refusal('disk-size-changed')
    return {'bytes': total, 'findings': [], 'encoding_classes': ['raw', 'json', 'url', 'hex', 'base64', 'base64url']}



def bound_context(context, attempt):
    """Recheck retained artifact metadata against the actual attempt, offline."""
    entry = context['entry']; identity = context['identity']; image = identity['image']
    raw = context['catalog_json'].encode()
    catalog = vm_summary_check.parse_native_catalog(raw)
    profile = lifecycle.bounded_file(Path(native.__file__).resolve().parents[1] / 'profiles/launch/claude.toml', 65536)
    retained_catalog = lifecycle.bounded_file(attempt / 'guest-native-catalog.json', 256 * 1024)
    transport = native.strict_json(lifecycle.bounded_file(attempt / 'vm-transport.json', native.RECEIPT_MAX))
    if (raw != retained_catalog or hashlib.sha256(raw).hexdigest() != context['catalog_sha256']
            or [e for e in catalog['entries'] if e['alias'] == 'claude'] != [entry]
            or entry['version'] != native.CLAUDE_VERSION or entry['executable_sha256'] != native.CLAUDE_SHA256
            or entry['guest_jail_sha256'] != native.NATIVE_GUEST_JAIL_SHA256
            or entry['profile_sha256'] != hashlib.sha256(profile).hexdigest()
            or context['profile'] != tomllib.loads(profile.decode())
            or context['exposure_control'] != native.native_exposure_control(image)
            or native.strict_json(identity['image_manifest_json']) != image
            or hashlib.sha256(identity['image_manifest_json'].encode()).hexdigest() != identity['image_manifest_sha256']
            or identity['service']['sha256'] != image['ukai_vm_sha256']
            or identity['client']['sha256'] != image['ukai_jail_sha256']):
        raise Refusal('native-context')
    expected = {key: image[key] for key in ('disk_sha256', 'seed_sha256', 'helper_sha256', 'custodian_sha256')}
    expected.update(guest_program_catalog_sha256=context['catalog_sha256'],
                    sampler_sha256=image['source_sha256']['guest_exposure.py'])
    if transport['image'] != expected: raise Refusal('context-transport-image')
    candidate = image['jail_candidate']
    if (candidate['binary_sha256'] != native.NATIVE_GUEST_JAIL_SHA256
            or candidate['source_revision'] != native.NATIVE_GUEST_REVISION
            or candidate['build_inputs'] != native.NATIVE_GUEST_INPUTS): raise Refusal('guest-candidate')


def replay_sync(root, original, observed):
    attempt = root / 'sync-attempt'
    if lifecycle.normal_attempt_hashes(attempt) != observed['sync_attempt_sha256']: raise Refusal('sync-hash')
    host = native.strict_json(lifecycle.bounded_file(attempt / 'jail.json', native.RECEIPT_MAX))
    guest, events, journal = native.verified_guest_journal(attempt)
    binding = native.strict_json(lifecycle.bounded_file(attempt / 'evidence/vm-binding.json', native.RECEIPT_MAX))
    summary, tail = observed['sync_summary'], observed['sync_tail']
    check = vm_summary_check.verify_attempt(attempt, summary, tail, display_mapping={str(attempt): observed['sync_original']})
    if not all(type(observed.get(key)) is int and observed[key] == 0 for key in
               ('sync_run_exit', 'sync_tail_exit', 'sync_tail_json_exit')):
        raise Refusal('sync-command-exit')
    plain = subprocess.CompletedProcess([], observed['sync_tail_exit'], tail, '')
    encoded = subprocess.CompletedProcess([], observed['sync_tail_json_exit'], json.dumps(summary), '')
    return sync_clean(attempt, original, (host, guest, events, journal, binding, summary, plain, encoded, check))


def replay(root):
    root = Path(root)
    report = native.strict_json(lifecycle.bounded_file(root / 'measurement.json', INPUT_MAX))
    if report.get('schema') != SCHEMA or report.get('qualified') is not False: raise Refusal('measurement-schema')
    inputs_raw = lifecycle.bounded_file(root / 'inputs.json', INPUT_MAX)
    if hashlib.sha256(inputs_raw).hexdigest() != report.get('inputs_sha256'): raise Refusal('inputs-hash')
    inputs = native.strict_json(inputs_raw)
    if inputs.get('schema') != SCHEMA: raise Refusal('inputs-schema')
    tooling = inputs.get('tooling_sha256')
    if (type(tooling) is not dict or set(tooling) != set(TOOL_NAMES)
            or any(type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value) for value in tooling.values())):
        raise Refusal('tooling-provenance')
    actual_tooling = {name: hashlib.sha256(lifecycle.bounded_file(Path(__file__).with_name(name), 1024 * 1024)).hexdigest()
                      for name in TOOL_NAMES}
    if tooling != actual_tooling: raise Refusal('tooling-source-mismatch')
    stdout = lifecycle.bounded_file(root / 'stream.stdout', STDOUT_MAX)
    stderr = lifecycle.bounded_file(root / 'stream.stderr', STDERR_MAX)
    for name, data in (('stream.stdout', stdout), ('stream.stderr', stderr)):
        if hashlib.sha256(data).hexdigest() != inputs['output_sha256'][name]: raise Refusal('output-hash')
    attempt = root / 'attempt'
    if lifecycle.normal_attempt_hashes(attempt) != inputs['attempt_sha256']: raise Refusal('attempt-hash')
    guest, events, journal = native.verified_guest_journal(attempt)
    host = native.strict_json(lifecycle.bounded_file(attempt / 'jail.json', native.RECEIPT_MAX))
    binding = native.strict_json(lifecycle.bounded_file(attempt / 'evidence/vm-binding.json', native.RECEIPT_MAX))
    _, suffix = argv('unused', 'unused')
    if inputs['suffix'] != suffix or inputs['controls'] != controls(): raise Refusal('command-controls')
    bound_context(inputs['context'], attempt)
    observed = dict(inputs['observed'])
    observed['installed_identity_unchanged'] = inputs.get('context_after') == inputs['context']
    observed['original_source_unchanged'] = (type(observed.get('original_source_before')) is dict
        and observed['original_source_before'] == observed.get('original_source_after'))
    observed['same_boot_sync_verified'] = replay_sync(root, attempt, observed)
    observed['independent_summary'] = vm_summary_check.verify_attempt(attempt, inputs['summary'], inputs['tail'],
                                                                      display_mapping={str(attempt): inputs['original_attempt']})
    observed['retention_complete'] = True
    result = judge(observed, guest, events, inputs['summary'], inputs['context'], suffix, binding, host, stdout)
    result.update(schema=SCHEMA, qualified=False, scope=SCOPE, guest_journal=journal)
    return result


def live(args):
    home = Path(args.home).resolve(strict=True); jail = harness.required_binary('UKAI_JAIL_BINARY', args.jail)
    workspace = harness.guarded_workspace(args.workspace); out = harness.fresh_out_dir(args.out)
    context = native.native_context(home, jail)  # Before reading any credential.
    import tempfile
    data = Path(tempfile.mkdtemp(prefix='k113v-', dir='/tmp')).resolve()
    config = Path(tempfile.mkdtemp(prefix='k113v-config-')).resolve()
    private_home = config / 'home'; private_home.mkdir(mode=0o700)
    credentials = config / 'credentials'; credentials.mkdir(mode=0o700)
    environment = harness.vm_client_environment(base={}, PATH=f'{home}/bin:/usr/bin:/bin', HOME=private_home,
        TMPDIR='/private/tmp', UKAI_VM_HOME=home, UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    outputs = {}; spellings = []; copy = None; attempt = None; token = b''
    observed = {'credential_id': 'anthropic', 'retention_complete': False}; checked = None
    capture = {}; summary = {}; tail = ''; host = {}; guest = {}; events = None; binding = {}
    def execute(label, command, timeout):
        done = collect(command, environment, timeout=timeout, parse_stream=False)
        for name in ('stdout', 'stderr'):
            outputs[label + '.' + name] = done[name].decode('utf-8', errors='replace')
        if 'error_type' in done or done['intervened']: raise Refusal('auxiliary-command-failed')
        return subprocess.CompletedProcess(command, done['exit'], outputs[label + '.stdout'], outputs[label + '.stderr'])
    with contextlib.ExitStack() as cleanup:
        try:
            harness.clean_workspace(workspace)
            source = Path(args.credential_source)
            original = identity(source.lstat())
            observed['original_source_before'] = original
            token = native.private_source(source); spellings = native.native_secret_spellings(token)
            if identity(source.lstat()) != original: raise Refusal('original-source-changed')
            copy = SourceCopy(credentials, token); cleanup.callback(copy.close)
            command, suffix = argv(jail, workspace)
            capture = collect(command, environment, lambda event: copy.unlink(trigger=event))
            observed['capture'] = {k: v for k, v in capture.items() if k not in ('stdout', 'stderr')}
            observed['run_exit'] = capture['exit']
            observed['original_source_after'] = identity(source.lstat())
            observed['original_source_unchanged'] = observed['original_source_after'] == original
            outputs['run.stdout'] = capture['stdout'].decode('utf-8', errors='replace')
            outputs['run.stderr'] = capture['stderr'].decode('utf-8', errors='replace')
            stream = replay_stream(capture['stdout'], capture)
            observed['agent_result'] = stream.result
            observed['vendor_usage'] = native.native_vendor_usage(stream.result)
            attempts = sorted((data / 'attempts').glob('att_*'))
            if len(attempts) != 1: raise Refusal('attempt-count')
            attempt = attempts[0]
            checked = read_attempt(attempt, jail, execute, 'run')
            host, guest, events, journal, binding, summary, plain, encoded, check = checked
            tail = plain.stdout
            observed.update(tail_exit=plain.returncode, tail_json_exit=encoded.returncode,
                            independent_summary=check, guest_journal=journal)
            sync = execute('sync', [str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                                   *harness.vm_wall(20), '--workspace', str(workspace), '--', '/bin/sync'], 90)
            observed['sync_run_exit'] = sync.returncode
            extra = [p for p in (data / 'attempts').glob('att_*') if p != attempt]
            if sync.returncode != 0 or len(extra) != 1: raise Refusal('sync-attempt')
            sync_checked = read_attempt(extra[0], jail, execute, 'sync')
            observed['sync_tail_exit'] = sync_checked[6].returncode
            observed['sync_tail_json_exit'] = sync_checked[7].returncode
            if not sync_clean(extra[0], attempt, sync_checked): raise Refusal('sync-evidence')
            observed['same_boot_sync_verified'] = True
            disk, same = vault_measurement.boot_disk(data)
            if not same or disk is None: raise Refusal('disk-boot')
            observed['disk_scan'] = disk_scan(disk, spellings)
            observed['sync_attempt_sha256'] = lifecycle.normal_attempt_hashes(extra[0])
            observed['sync_summary'] = sync_checked[5]; observed['sync_tail'] = sync_checked[6].stdout
            observed['sync_original'] = str(extra[0])
        except Exception as error:
            observed['error_type'] = type(error).__name__
        finally:
            try:
                if copy is not None and not copy.removed: copy.unlink()
                observed['source_removed_before_stop'] = not os.path.lexists(credentials / 'anthropic')
            except Exception as error:
                observed['source_removed_before_stop'] = False; observed['source_cleanup_error_type'] = type(error).__name__
            try:
                if os.path.lexists(data / 'vm/serve.lock'):
                    lock = cleanup.enter_context(lifecycle.running_service_lock(data))
                    observed['stop_exit'] = execute('stop', [str(home / 'bin/ukai-vm'), 'stop'], 60).returncode
                    observed['service_shutdown'] = lifecycle.stopped_service_lock(data, lock)
                else: observed['service_shutdown'] = {'complete': False, 'not_started': True}
            except Exception as error:
                observed['service_shutdown'] = {'complete': False, 'error_type': type(error).__name__}
                try: execute('stop-fallback', [str(home / 'bin/ukai-vm'), 'stop'], 60)
                except Exception: pass
        context_after = None
        try:
            context_after = native.native_context(home, jail)
            observed['installed_identity_unchanged'] = context_after == context
        except Exception: observed['installed_identity_unchanged'] = False
        safe = {name: native.native_output(value, spellings) for name, value in outputs.items()}
        observed['output_leaks'] = sorted(name for name, (hit, _) in safe.items() if hit)
        scans = ([vault_measurement.leak_scan([data, workspace, config], s.encode()) for s in spellings]
                 if observed.get('service_shutdown', {}).get('complete') else [(['scan-error:service-shutdown-unverified'], 0)])
        observed['leaks'] = sorted({p for hits, _ in scans for p in hits})
        observed['files_scanned'] = max((count for _, count in scans), default=0)
        for name, (_, text) in safe.items(): (out / name).write_text(text)
        result = {'schema': SCHEMA, 'outcome': 'FAIL', 'qualified': False, 'scope': SCOPE}
        try:
            if attempt is None or observed['leaks'] or observed['output_leaks']: raise Refusal('unsafe-or-missing-retention')
            observed['retention_complete'] = True
            hashes = lifecycle.retain_normal_attempt(attempt, out / 'attempt', spellings)
            sync_path = Path(observed['sync_original'])
            if lifecycle.retain_normal_attempt(sync_path, out / 'sync-attempt', spellings) != observed['sync_attempt_sha256']:
                raise Refusal('sync-changed-before-retention')
            output_hashes = {name: safe_write(out / name, capture[label], spellings)
                             for name, label in [('stream.stdout', 'stdout'), ('stream.stderr', 'stderr')]}
            inputs = {'schema': SCHEMA, 'tooling_sha256': {name: hashlib.sha256(lifecycle.bounded_file(Path(__file__).with_name(name), 1024 * 1024)).hexdigest() for name in TOOL_NAMES}, 'context': context, 'context_after': context_after, 'controls': controls(), 'suffix': argv(jail, workspace)[1],
                      'observed': observed, 'summary': summary, 'tail': tail, 'original_attempt': str(attempt),
                      'attempt_sha256': hashes, 'output_sha256': output_hashes}
            raw = json_bytes(inputs)
            if len(raw) > INPUT_MAX: raise Refusal('inputs-cap')
            digest = safe_write(out / 'inputs.json', raw, spellings)
            safe_write(out / 'measurement.json', json_bytes({'schema': SCHEMA, 'qualified': False, 'inputs_sha256': digest}), spellings)
            result = replay(out)
        except Exception as error:
            result['error_type'] = type(error).__name__
        result['observations'] = native.native_redact(observed, spellings)
        encoded = json_bytes(result)
        _, sanitized = native.native_output(encoded.decode(), spellings)
        (out / 'result.json').write_text(sanitized)
        if observed.get('source_removed_before_stop'): shutil.rmtree(config)
    return 0 if result['outcome'] == 'PASS' else 1


def main(argv_in=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    replay_parser = commands.add_parser('replay'); replay_parser.add_argument('root')
    run = commands.add_parser('live', help='one explicitly authorized paid API-only attempt')
    for name in ('home', 'workspace', 'out', 'jail', 'credential_source'):
        run.add_argument('--' + name.replace('_', '-'), required=True)
    run.add_argument('--api-model', choices=['sonnet'], required=True)
    run.add_argument('--api-max-budget-usd', choices=['0.50'], required=True)
    args = parser.parse_args(argv_in)
    if args.command == 'live': return live(args)
    try: result = replay(args.root)
    except (OSError, ValueError, KeyError, TypeError): result = {'schema': SCHEMA, 'outcome': 'FAIL', 'qualified': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
