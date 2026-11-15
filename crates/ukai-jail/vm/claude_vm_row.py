#!/usr/bin/env python3
"""The K113 row: Claude Code headless in the guest, on the installed package.

The J18 §9.4 compatibility record this tier needs: one `ukai-jail run --vm`
attempt, agent profile, the operator's OAuth token as a vault-mode
credential (the child holds only the placeholder, bound to
CLAUDE_CODE_OAUTH_TOKEN by the vault's `env`), the guest's own proxy
substituting it in flight, and the agent doing one real task — a file
created in the live workspace, reaching this host through the share.

K113's own clause is that the record's summary names its transport. It is
judged on `ukai-jail tail --summary` ALONE (recorded verbatim as
k113-tail-summary.txt), never on the run's terminal output: the transport
line must carry the transport record's values, and the network and observer
lines must state the verified guest receipt's applied facts (D5).

The token is read at run time from the operator's Claude Code credentials
(refreshed by running `claude` once beforehand) with at least
EXPIRY_MARGIN_SECONDS of life left, written to a 0600 single-use source
outside the repository and deleted on every path out of this script —
FIRST, before `ukai-vm stop`, so a stop that raises or hangs never leaves it
— and never printed or passed in an argv: the record carries its shape and
byte length, and the leak scan proves the value appears in no exported file
(the attempt directory, this run's output copy, the workspace, the run's own
stdout/stderr and the tail summary), with no size cap. `ukai-vm stop` runs
on every path, a timeout included. A previous run's output directory is
never reused. No field of the host receipt may contradict the verified
guest receipt (D5), as K111 judges it.

Not measured here (J18 §9.4's Linux-row conditions, which a supported row
also needs): the A01 fixture, ten repetitions, the no-source refusal,
revocation, six active classes and the credential use count. The record
lists them under `not_measured`.

Use --compatibility to retain A01, a small task, ten fresh repetitions and a
missing-source control. This is a measurement matrix, never an automatic K113
promotion: guest revocation, exported guest journal/counts and remaining Linux
row conditions must still be demonstrated. --credential-source with
--credential-kind api-key uses an explicitly supplied private Anthropic source;
its value is never supplied in argv or the child environment.

Guest-native matrices run the missing-source control first and stop scheduling
after the first failed lane. They retain typed vendor-reported cost/model usage
and scan six credential encoding classes; these checks do not independently
meter provider billing or qualify the missing revocation and credential rows.

Usage: claude_vm_row.py <installed-root> <workspace> <out> <ukai-jail> [options]
"""
import argparse
import base64
import contextlib
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402
import vault_measurement  # noqa: E402

CLAUDE_BINARY = 'claude'          # staged in the workspace by the caller
CLAUDE_VERSION = '2.1.311'        # downloads.claude.ai manifest, linux-arm64
CLAUDE_SHA256 = ('2e2496c9a8065df93acb0fca2d341f59'
                 'a6b8777649b2e025ab8c9bcd5eef61f3')
# Exact signed Linux guest candidate used by the native image preparation.
# A self-consistent catalog alone cannot select another jail artifact.
NATIVE_GUEST_JAIL_SHA256 = '118c8bdda8c7bd5b5957bce15171ff418fb7df0350de795770532beaee2e3462'
NATIVE_GUEST_REVISION = '6ffff05dc6ae08602a39630b947c704bf9cf05a9'
NATIVE_GUEST_INPUTS = 'sha256:efdc169e8e09f514c908e02bb6f972bc8761d2efc9af94d9b53d914a436f14e6'
RUN_TIMEOUT_SECONDS = 420
EXPIRY_MARGIN_SECONDS = 30 * 60   # the run's timeout and the summary, with room
PROMPT = ('In the current directory, create a file named k113-marker.txt '
          'whose entire content is the single word contained followed by '
          'one newline. Then reply with just the word done.')
NOT_MEASURED = ['A01 fixture', 'ten repetitions', 'no-source refusal', 'revocation',
                'six active classes', 'credential use count']
COMPATIBILITY_PENDING = ['revocation mid-stream', 'full independent summary recomputation',
                         'sampled child environments', 'alias-derived executable grants',
                         'installed notarized candidate qualification']
NATIVE_PENDING = ['vendor mid-stream source revocation',
                  'both credential-kind records', 'native installer and --version evidence',
                  'installed notarized candidate qualification']
A01_PROMPT = 'Create a file named greeting.txt containing the single word hello.'
TASK_PROMPT = ('Fix slugify in slug.py so it lowercases its input. Run the existing '
               'test_slug.py tests without changing that test file.')
SLUG = 'def slugify(text):\n    return "-".join(text.strip().split())\n'
SLUG_TEST = '''import unittest
from slug import slugify
class SlugTests(unittest.TestCase):
    def test_lowercase(self): self.assertEqual(slugify("Hello World"), "hello-world")
    def test_spaces(self): self.assertEqual(slugify("  Many   Spaces "), "many-spaces")
    def test_empty(self): self.assertEqual(slugify(""), "")
if __name__ == "__main__": unittest.main()
'''

PROFILE = '''# K113 measurement-only profile: the OAuth token through the vault
name = "claude-vm"
jail = "agent"

[credentials.claude]
mode = "vault"
source = "{source}"
hosts = ["https://api.anthropic.com"]
header = {{ name = "authorization", prefix = "Bearer " }}
env = "CLAUDE_CODE_OAUTH_TOKEN"

[network]
allow = ["api.anthropic.com"]
'''


def private_source(path):
    """Read only a caller-selected regular private file, never a symlink/FIFO."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1 or not 0 < before.st_size <= 65536):
            raise harness.HarnessError('credential source must be one private, owned regular file')
        value = stream.read(65537)
        after = os.fstat(stream.fileno())
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(value) != before.st_size):
        raise harness.HarnessError('credential source changed during the bounded read')
    if not value.strip() or any(char in value for char in (b'\0', b'\r', b'\n')):
        raise harness.HarnessError('credential source must contain a single nonempty value without newlines')
    try:
        value.decode('utf-8')
    except UnicodeError:
        raise harness.HarnessError('credential source is not UTF-8') from None
    return value


def launch_profile(source, kind):
    credential = 'anthropic' if kind == 'api-key' else 'claude'
    variable = 'ANTHROPIC_API_KEY' if kind == 'api-key' else 'CLAUDE_CODE_OAUTH_TOKEN'
    header = '{ name = "x-api-key" }' if kind == 'api-key' else '{ name = "authorization", prefix = "Bearer " }'
    return (f'name = "claude-vm"\njail = "agent"\ncredentials_one_of = ["{credential}"]\n\n'
            f'[credentials.{credential}]\nmode = "vault"\nsource = {json.dumps(str(source))}\n'
            f'hosts = ["https://api.anthropic.com"]\nheader = {header}\nenv = "{variable}"\n'
            f'hint = "supply the selected {credential} measurement source"\n\n'
            '[network]\nallow = ["api.anthropic.com"]\n')


def missing_source_facts(row, text, attempts):
    """A capability refusal is not evidence of credential-source validation."""
    return {'missing_source_refusal': row.get('run_exit') not in (None, 0)
            and 'credential_unavailable' in text and 'none is present' in text
            and 'launch.credentials_one_of' in text and row['credential_id'] in text,
            'selected_source_hint': f'supply the selected {row["credential_id"]} measurement source' in text,
            'no_attempt_or_workload': not attempts and row.get('unexpected_exec') is False,
            'not_a_vm_capability_refusal': not harness.vm_refusals(text)}


JOURNAL_MAX = 16 * 1024 * 1024
JOURNAL_PART = 512 * 1024
RECEIPT_MAX = 4 * 1024 * 1024


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('non-JSON constant')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def canonical_receipt(value):
    """The receipt's integer-only JCS domain, including UTF-16 member order."""
    if value is None or type(value) in (bool, str):
        return json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    if type(value) is int and -(2 ** 63) <= value < 2 ** 64:
        return str(value)
    if type(value) is list:
        return '[' + ','.join(canonical_receipt(item) for item in value) + ']'
    if type(value) is dict:
        return '{' + ','.join(canonical_receipt(key) + ':' + canonical_receipt(value[key])
                              for key in sorted(value, key=lambda key: key.encode('utf-16-be'))) + '}'
    raise ValueError('unsupported canonical receipt value')


def verified_guest_journal(attempt):
    """Bounded, anchored independent evidence reads; no host journal fallback.

    A malformed/new unavailable export yields no events. Error text and journal
    values never enter the diagnostic, which can be retained before a leak scan.
    This qualification judge intentionally rejects all source-sequence holes,
    even a documented loss that the general summary can describe as a lower bound.
    """
    result = {'state': 'invalid', 'verified': False}
    guest = {}
    try:
        with contextlib.ExitStack() as stack:
            def directory(path, parent=None):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                stack.callback(os.close, fd)
                return fd
            def read(parent, name, cap):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                with os.fdopen(fd, 'rb') as stream:
                    before = os.fstat(fd)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > cap:
                        raise ValueError('invalid evidence file')
                    value = stream.read(cap + 1)
                    after = os.fstat(fd)
                identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if len(value) != before.st_size or identity(before) != identity(after):
                    raise ValueError('evidence changed while reading')
                return value
            root = directory(attempt)
            evidence = directory('evidence', root)
            receipt_bytes = read(evidence, 'jail.json', RECEIPT_MAX)
            guest = strict_json(receipt_bytes)
            if type(guest) is not dict or re.fullmatch(
                    r'att_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
                    guest.get('attempt_id', '')) is None:
                raise ValueError('invalid guest identity')
            receipt_hash = hashlib.sha256(receipt_bytes).hexdigest()
            result.update(guest_attempt_id=guest['attempt_id'], guest_receipt_sha256=receipt_hash)
            try:
                journal = directory('guest-journal', evidence)
            except FileNotFoundError:
                result['state'] = 'absent'
                return guest, None, result
            manifest = strict_json(read(journal, 'manifest.json', 4096))
            keys = {'schema', 'guest_attempt_id', 'guest_receipt_sha256', 'state', 'bytes', 'parts', 'sha256'}
            if (type(manifest) is not dict or set(manifest) != keys
                    or manifest['schema'] != 'ukai.vm.guest-journal/1'
                    or manifest['guest_attempt_id'] != guest['attempt_id']
                    or manifest['guest_receipt_sha256'] != receipt_hash
                    or type(manifest['parts']) is not int or not 0 <= manifest['parts'] <= JOURNAL_MAX // JOURNAL_PART):
                raise ValueError('invalid journal manifest')
            expected = {'manifest.json'} | {f'{index:04}.part' for index in range(manifest['parts'])}
            with os.scandir(journal) as listing:
                names = []
                for entry in listing:
                    names.append(entry.name)
                    if len(names) > len(expected):
                        raise ValueError('unexpected journal entry')
            if set(names) != expected or len(names) != len(expected):
                raise ValueError('journal parts disagree')
            if manifest['state'] != 'exported':
                if (manifest['parts'] != 0 or manifest['sha256'] is not None
                        or not ((manifest['state'] == 'absent' and manifest['bytes'] is None)
                                or (manifest['state'] == 'unreadable' and (manifest['bytes'] is None
                                    or type(manifest['bytes']) is int and manifest['bytes'] >= 0))
                                or (manifest['state'] == 'not_scanned' and type(manifest['bytes']) is int
                                    and manifest['bytes'] > JOURNAL_MAX))):
                    raise ValueError('invalid unavailable journal')
                result['state'] = manifest['state']
                return guest, None, result
            size = manifest['bytes']
            if (type(size) is not int or not 0 < size <= JOURNAL_MAX
                    or (size + JOURNAL_PART - 1) // JOURNAL_PART != manifest['parts']):
                raise ValueError('invalid journal size')
            payload = bytearray()
            for index in range(manifest['parts']):
                part = read(journal, f'{index:04}.part', JOURNAL_PART)
                if len(part) != min(JOURNAL_PART, size - len(payload)):
                    raise ValueError('invalid journal part size')
                payload.extend(part)
            digest = hashlib.sha256(payload).hexdigest()
            if digest != manifest['sha256'] or not payload.endswith(b'\n'):
                raise ValueError('invalid journal bytes')
            events, sequences = [], {}
            for line in payload.splitlines():
                if not 0 < len(line) <= 65536:
                    raise ValueError('invalid journal frame size')
                event = strict_json(line)
                if (type(event) is not dict or event.get('attempt_id') != guest['attempt_id']
                        or type(event.get('source')) is not str or not event['source']
                        or type(event.get('source_seq')) is not int
                        or event['source_seq'] != sequences.get(event['source'], 0) + 1
                        or type(event.get('fields', {})) is not dict):
                    raise ValueError('invalid journal frame')
                sequences[event['source']] = event['source_seq']
                if event['source'] == 'proxy' and event.get('operation') == 'net.connect':
                    fields = event.get('fields', {})
                    if (event.get('stage') != 'result' or event.get('decision') not in ('allow', 'deny')
                            or any(type(fields.get(key, [])) is not list
                                   or any(type(item) is not str for item in fields.get(key, []))
                                   for key in ('credentials', 'credentials_unconfirmed'))):
                        raise ValueError('invalid proxy result')
                events.append(event)
            last = events[-1]
            canonical_hash = 'sha256:' + hashlib.sha256(canonical_receipt(guest).encode()).hexdigest()
            if (guest.get('phase') != 'settled' or last['source'] != 'wrapper'
                    or last.get('operation') != 'jail.receipt'
                    or last.get('fields', {}).get('phase') != 'settled'
                    or last['fields'].get('receipt_digest') != canonical_hash):
                raise ValueError('journal does not settle this receipt')
            result.update(state='complete', verified=True, bytes=size, parts=manifest['parts'],
                          sha256=digest, events=len(events), receipt_digest=canonical_hash)
            return guest, events, result
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError, UnicodeError):
        return guest if type(guest) is dict else {}, None, result


def compatibility_facts(row, guest, summary, events):
    """Required per-run facts; absent guest journal/counts fail, never become zero."""
    try:
        return _compatibility_facts(row, guest, summary, events)
    except (AttributeError, KeyError, TypeError, ValueError):
        return {'evidence_well_formed': False}


def _compatibility_facts(row, guest, summary, events):
    lines = {line.get('line'): line for line in summary.get('lines', [])}
    evidence = (lines.get('evidence') or {}).get('facts') or {}
    credentials = guest.get('credentials') or []
    counted = ((lines.get('credentials') or {}).get('facts') or {}).get('credentials') or []
    uses = None if events is None else sum(
        event.get('source') == 'proxy' and event.get('operation') == 'net.connect'
        and event.get('stage') == 'result' and row['credential_id'] in ((event.get('fields') or {}).get('credentials') or [])
        for event in events)
    proxy_results = [] if events is None else [event for event in events
        if event.get('source') == 'proxy' and event.get('operation') == 'net.connect']
    coverage = guest.get('coverage') or {}
    return {'strict_observation': evidence.get('observe') == 'on' and evidence.get('evidence') == 'strict',
            'six_active_classes_no_gaps': set(coverage) == set(harness.SUMMARY_CLASSES)
            and all(value.get('status') == 'active' and value.get('gaps') == [] for value in coverage.values()),
            'guest_settled_clean': guest.get('phase') == 'settled' and guest.get('errors') == []
            and guest.get('containment') == 'enforced' and guest.get('child_protection') == 'enforced'
            and guest.get('exec_observed') is True
            and (guest.get('outcome') or {}).get('kind') == 'exited'
            and (guest.get('outcome') or {}).get('code') == 0
            and guest.get('state_cleanup') == 'complete' and guest.get('cleanup_error') is None
            and (guest.get('lifetime') or {}).get('tree_empty') is True
            and (guest.get('lifetime') or {}).get('integrity') == 'verified',
            'one_vault_credential_never_staged': len(credentials) == 1
            and credentials[0].get('id') == row['credential_id'] and credentials[0].get('mode') == 'vault'
            and credentials[0].get('never_staged') is True,
            'guest_journal_available': events is not None,
            'guest_proxy_count_matches_receipt': events is not None
            and type((coverage.get('proxy.net') or {}).get('observed_count')) is int
            and coverage['proxy.net']['observed_count'] == len(proxy_results),
            'credential_use_recording_confirmed': events is not None and any(
                event.get('source') == 'wrapper' and event.get('operation') == 'note'
                and (event.get('fields') or {}).get('kind') == 'credential'
                and event['fields'].get('credential_id') == row['credential_id']
                and event['fields'].get('uses_recorded') is True for event in events),
            'exact_credential_uses_match': uses is not None and uses > 0 and len(counted) == 1
            and counted[0].get('id') == row['credential_id'] and counted[0].get('uses_bound') == 'exact'
            and counted[0].get('uses') == uses,
            'tail_json_text_matches_text': row.get('tail_json_text_matches_text') is True,
            'task_passed': row.get('task_passed') is True,
            'measurement_passed': row.get('outcome') == 'PASS'}


def parse_args(argv):
    parser = argparse.ArgumentParser(description='Measure a scoped warm-VM Claude row; no qualification is implied.')
    for name in ('home', 'workspace', 'out', 'jail'):
        parser.add_argument(name)
    parser.add_argument('--credential-kind', choices=('oauth', 'api-key'), default='oauth')
    parser.add_argument('--credential-source', type=Path)
    parser.add_argument('--case', choices=('marker', 'a01', 'small-task', 'missing-source'), default='marker')
    parser.add_argument('--compatibility', action='store_true')
    parser.add_argument('--execution-mode', choices=('workspace-literal', 'guest-native'),
                        default='workspace-literal', help='explicit native catalog mode; no workspace executable or launch override')
    args = parser.parse_args(argv)
    if args.credential_kind == 'api-key' and args.credential_source is None and args.case != 'missing-source':
        parser.error('--credential-kind api-key requires --credential-source')
    if args.execution_mode == 'guest-native' and args.credential_source is None and (args.compatibility or args.case != 'missing-source'):
        parser.error('guest-native mode requires an explicit --credential-source; it never discovers operator credentials')
    return args


def compatibility_matrix(args, **injected):
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    staged = workspace / CLAUDE_BINARY
    if not staged.is_file() or staged.is_symlink() or harness.sha256_file(staged) != CLAUDE_SHA256:
        raise harness.HarnessError('stage the pinned Claude binary before the compatibility matrix')
    lanes = [('a01', 'a01'), ('small-task', 'small-task')]
    lanes += [(f'repetition-{number:02}', 'a01') for number in range(1, 11)]
    lanes += [('missing-source', 'missing-source')]
    rows = []
    for label, case in lanes:
        trial = workspace / ('a01' if case == 'small-task' else label)
        if case != 'small-task':
            trial.mkdir()
            harness.mark_workspace(trial)
            shutil.copyfile(staged, trial / CLAUDE_BINARY)
            (trial / CLAUDE_BINARY).chmod(0o755)
        argv = [args.home, str(trial), str(out / label), args.jail,
                '--credential-kind', args.credential_kind, '--case', case]
        if args.credential_source is not None:
            argv += ['--credential-source', str(args.credential_source)]
        try:
            code = main(argv, **injected)
            row = read_json(out / label / 'k113-claude.json')
            rows.append({'case': label, 'exit': code, 'outcome': row.get('outcome'),
                         'compatibility_facts': row.get('compatibility_facts', {})})
        except Exception as error:
            # Keep every failed lane, but never serialize exception messages that
            # may carry vendor output or credentials.
            rows.append({'case': label, 'exit': None, 'outcome': 'ERROR', 'error_type': type(error).__name__})
        harness.write_json(out / f'k113-progress-{len(rows):02}.json', {'rows': rows, 'qualified': False,
            'outcome': 'UNMEASURED', 'not_measured': COMPATIBILITY_PENDING})
    measured = all(row.get('compatibility_facts') and all(row['compatibility_facts'].values()) for row in rows)
    result = {'schema': 'ukai.vm.claude-compatibility/1', 'credential_kind': args.credential_kind,
              'rows': rows, 'qualified': False, 'outcome': 'UNMEASURED' if measured else 'FAIL',
              'not_measured': COMPATIBILITY_PENDING,
              'scope': 'Explicit workspace executable; no native alias, revocation or release promotion.'}
    harness.write_json(out / 'k113-matrix.json', result)
    print(json.dumps({'outcome': result['outcome'], 'qualified': False, 'runs_retained': len(rows)}))
    return 1  # An incomplete compatibility record can never signal qualification.


def credential_candidates():
    """Claude Code's OAuth sections: the keychain item, then the file copy."""
    candidates = []
    keychain = subprocess.run(['security', 'find-generic-password', '-s', 'Claude Code-credentials', '-w'],
                              capture_output=True, text=True)
    if keychain.returncode == 0:
        try:
            candidates.append(json.loads(keychain.stdout)['claudeAiOauth'])
        except (ValueError, KeyError):
            pass
    try:
        candidates.append(json.loads(Path.home().joinpath('.claude/.credentials.json').read_text())['claudeAiOauth'])
    except (OSError, ValueError, KeyError):
        pass
    return candidates


def select_token(candidates, now_ms, margin_seconds=EXPIRY_MARGIN_SECONDS):
    """The freshest token with at least `margin_seconds` left, or None."""
    floor = now_ms + margin_seconds * 1000
    live = [section for section in candidates if isinstance(section, dict)
            and isinstance(section.get('expiresAt'), (int, float)) and section['expiresAt'] > floor
            and section.get('accessToken')]
    return max(live, key=lambda section: section['expiresAt']) if live else None


def write_token(section, destination):
    token = section['accessToken'].encode()
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(token)
    expires = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(section['expiresAt'] / 1000))
    return token, {'bytes': len(token), 'sha256': hashlib.sha256(token).hexdigest(),
                   'kind': 'claudeAiOauth.accessToken', 'expires_at': expires}


def agent_result(text):
    """The agent's own JSON result line (the last one); a pty prefixes render bytes."""
    result = None
    for line in text.splitlines():
        if '"type":"result"' not in line and '"type": "result"' not in line:
            continue
        start = line.find('{')
        if start < 0:
            continue
        try:
            result = json.loads(line[start:])
        except ValueError:
            continue
    return result


def text_leaks(token, **texts):
    return sorted(name for name, text in texts.items()
                  if any(spelling in (text or '') for spelling in secret_spellings(token)))


def secret_spellings(token):
    text = token.decode()
    return sorted({text, json.dumps(text, ensure_ascii=True)[1:-1],
                   json.dumps(text, ensure_ascii=False)[1:-1]}, key=len, reverse=True)


def redact_text(text, token):
    for spelling in secret_spellings(token):
        text = text.replace(spelling, '<token>')
    return text


def redact_value(value, token):
    """Redact parsed values before shortening or JSON escaping can hide a match."""
    if isinstance(value, str):
        return redact_text(value, token)
    if isinstance(value, list):
        return [redact_value(entry, token) for entry in value]
    if isinstance(value, dict):
        return {redact_value(key, token): redact_value(entry, token) for key, entry in value.items()}
    return value


def judge(row):
    facts = {
        'settled_exit_zero_tree_empty': (row.get('phase') == 'settled' and row.get('exit') == 0
                                         and row.get('tree_empty') is True),
        'agent_succeeded': bool(row.get('agent_result')) and row['agent_result'].get('subtype') == 'success'
        and row['agent_result'].get('is_error') is False,
        'marker_on_host': ((row.get('marker_content') or '') == 'contained\n'
                           if row.get('case', 'marker') == 'marker' else row.get('task_passed') is True),
        'guest_receipt_linux': row.get('guest_receipt_linux') is True,
        'receipt_bound_to_this_attempt': row.get('receipt_bound') is True,
        'token_in_no_export': row.get('token_in_exports') == [] and row.get('files_scanned', 0) > 0,
        'token_in_no_output': row.get('token_in_outputs') == [],
        'tail_summary_ran': row.get('tail_summary_exit') == 0,
        'host_receipt_never_contradicts_guest': row.get('host_receipt_contradictions') == [],
    }
    facts.update({f'tail_summary_{name}': value is True
                  for name, value in (row.get('tail_summary_facts') or {'transport_line_from_record': False}).items()})
    return facts, 'PASS' if all(facts.values()) else 'FAIL'


def main(argv=None, now=time.time, candidates=credential_candidates, run=subprocess.run):
    argv = sys.argv[1:] if argv is None else argv
    args = parse_args(argv)
    if args.execution_mode == 'guest-native':
        return native_matrix(args, run=run) if args.compatibility else native_main(args, run=run)
    if args.compatibility:
        return compatibility_matrix(args, now=now, candidates=candidates, run=run)
    home = Path(args.home).resolve(strict=True)
    workspace = harness.guarded_workspace(args.workspace)
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.jail)
    out = harness.fresh_out_dir(args.out)
    keep = (CLAUDE_BINARY, '.git', 'greeting.txt') if args.case == 'small-task' else (CLAUDE_BINARY,)
    harness.clean_workspace(workspace, keep=keep)
    staged = workspace / CLAUDE_BINARY
    if not staged.is_file() or staged.is_symlink():
        raise harness.HarnessError(f'stage the {CLAUDE_VERSION} linux-arm64 binary in {staged} first')
    if harness.sha256_file(staged) != CLAUDE_SHA256:
        raise harness.HarnessError('the staged claude binary does not match its manifest digest')
    section = None
    if args.case != 'missing-source' and args.credential_source is None:
        section = select_token(candidates(), now() * 1000)
    if section is None and args.credential_source is None and args.case != 'missing-source':
        raise harness.HarnessError(f'no Claude Code OAuth token with {EXPIRY_MARGIN_SECONDS // 60} min of life '
                                   'left: run `claude` once on this Mac to refresh the session, then rerun')
    if args.case in ('a01', 'small-task'):
        subprocess.run(['git', '-c', 'init.defaultBranch=main', 'init', '-q', str(workspace)], check=True,
                       env=harness.vm_client_environment(), capture_output=True, timeout=30)
    if args.case == 'small-task':
        (workspace / 'slug.py').write_text(SLUG)
        (workspace / 'test_slug.py').write_text(SLUG_TEST)

    source_dir = Path(tempfile.mkdtemp(prefix='k113-vault-')).resolve()
    source = source_dir / 'token'
    config = Path(tempfile.mkdtemp(prefix='k113-cfg-'))
    data = Path(tempfile.mkdtemp(prefix='k113-'))
    # LANG=C.UTF-8 and no TERM/TZ: the guest jail admits nothing else, so the
    # host refuses any other environment (vm:not-carried:environment).
    environment = harness.vm_client_environment(PATH=f'{home}/bin:/usr/bin:/bin', UKAI_VM_HOME=home,
                                                UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    row = {'claude_version': CLAUDE_VERSION, 'claude_sha256': CLAUDE_SHA256,
           'binary': harness.fingerprint(jail), 'not_measured': NOT_MEASURED,
           'case': args.case, 'credential_kind': args.credential_kind,
           'credential_id': 'anthropic' if args.credential_kind == 'api-key' else 'claude',
           'qualified': False, 'compatibility_outcome': 'UNMEASURED'}
    token = b''
    stdout = stderr = tail = tail_json = tail_json_error = ''
    try:
        if args.case != 'missing-source':
            if args.credential_source is not None:
                token = private_source(args.credential_source)
                descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as output:
                    output.write(token)
                row['token_shape'] = {'bytes': len(token), 'kind': args.credential_kind}
            else:
                token, row['token_shape'] = write_token(section, source)
        os.chmod(config, 0o700)
        (config / 'launch').mkdir()
        (config / 'launch' / 'claude-vm.toml').write_text(launch_profile(source, args.credential_kind))
        os.chmod(config / 'launch' / 'claude-vm.toml', 0o600)
        prompt = {'marker': PROMPT, 'a01': A01_PROMPT, 'small-task': TASK_PROMPT}.get(args.case, PROMPT)
        script = ('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 '
                  f'./{CLAUDE_BINARY} -p {json.dumps(prompt)} '
                  '--dangerously-skip-permissions --output-format json')
        if args.case == 'small-task':
            script += " && /usr/bin/python3 -m unittest -q && printf 'K113_TESTS_PASSED\\n'"
        if args.case == 'missing-source':
            script = "printf 'unexpected execution\\n' > k113-unexpected-exec.txt"
        row['argv_digest'] = harness.argv_digest(['/bin/sh', '-c', script])
        started = time.monotonic()
        try:
            done = run(['script', '-q', '/dev/null', str(jail), 'run', '--vm', '--terminal', 'detach',
                        '--profile', 'agent', '--launch', 'claude-vm', *harness.vm_wall(240),
                        '--workspace', str(workspace), '--', '/bin/sh', '-c', script],
                       env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                       timeout=RUN_TIMEOUT_SECONDS)
            row['run_exit'], stdout, stderr = done.returncode, done.stdout, done.stderr
        except subprocess.TimeoutExpired as error:
            row['run_exit'] = None
            row['run_timeout'] = True
            stdout = error.stdout.decode(errors='replace') if isinstance(error.stdout, bytes) else (error.stdout or '')
            stderr = error.stderr.decode(errors='replace') if isinstance(error.stderr, bytes) else (error.stderr or '')
        row['elapsed_s'] = round(time.monotonic() - started, 1)
        attempts = sorted((data / 'attempts').glob('att_*'), key=lambda p: p.stat().st_mtime)
        if attempts:
            attempt = attempts[-1]
            summary = run([str(jail), 'tail', '--summary', '--attempt', attempt.name],
                          env=environment, capture_output=True, text=True, timeout=60)
            tail = summary.stdout + summary.stderr
            row['tail_summary_exit'] = summary.returncode
            if args.case != 'marker':
                json_summary = run([str(jail), 'tail', '--summary', '--json', '--attempt', attempt.name],
                                   env=environment, capture_output=True, text=True, timeout=60)
                tail_json = json_summary.stdout
                tail_json_error = json_summary.stderr
                row['tail_summary_json_exit'] = json_summary.returncode
    finally:
        # The token goes first: `ukai-vm stop` may raise or time out, and
        # nothing after a raise would run.
        try:
            source.unlink(missing_ok=True)
            shutil.rmtree(source_dir, ignore_errors=True)
        finally:
            try:
                stop = run([str(home / 'bin/ukai-vm'), 'stop'], env=environment, capture_output=True,
                           text=True, timeout=60)
                row['stop_exit'] = stop.returncode
            except (OSError, subprocess.SubprocessError) as error:
                row['stop_exit'] = None
                row['stop_error'] = type(error).__name__
    row['token_source_removed'] = not source.exists()

    attempts = sorted((data / 'attempts').glob('att_*'), key=lambda p: p.stat().st_mtime)
    if attempts:
        attempt = attempts[-1]
        shutil.copytree(attempt, out / 'k113-attempt')
        stored = read_json(attempt / 'jail.json')
        transport = read_json(attempt / 'vm-transport.json')
        guest = read_json(attempt / 'evidence/jail.json')
        result = agent_result(stdout + stderr)
        if token:
            result = redact_value(result, token)
        marker = workspace / 'k113-marker.txt'
        greeting = workspace / 'greeting.txt'
        if args.case == 'a01':
            row['task_passed'] = greeting.is_file() and not greeting.is_symlink() and greeting.read_text().strip() == 'hello'
        elif args.case == 'small-task':
            tests = workspace / 'test_slug.py'
            row['task_passed'] = (tests.is_file() and not tests.is_symlink() and tests.read_text() == SLUG_TEST
                                  and 'K113_TESTS_PASSED' in stdout and row.get('run_exit') == 0)
        row.update({
            'attempt_id': attempt.name,
            'phase': stored.get('phase'),
            'exit': (stored.get('outcome') or {}).get('code'),
            'tree_empty': (stored.get('lifetime') or {}).get('tree_empty'),
            'agent_result': None if result is None else {
                'subtype': result.get('subtype'), 'is_error': result.get('is_error'),
                'num_turns': result.get('num_turns'),
                'model': next(iter(result.get('modelUsage') or {}), None),
                'total_cost_usd': result.get('total_cost_usd'),
                'result_text': (result.get('result') or '')[:200]},
            'marker_content': marker.read_text() if marker.is_file() else None,
            'guest_receipt_linux': (guest.get('platform') or {}).get('os') == 'linux',
            'receipt_bound': harness.attempt_dir_bound(attempt, ['/bin/sh', '-c', script]),
            'transport_schema': transport.get('schema'),
            'tail_summary_facts': harness.summary_facts(tail, guest, transport),
            'run_summary_facts': harness.summary_facts(stdout + stderr, guest, transport),
            'host_receipt_contradictions': harness.receipt_contradictions(stored, guest),
        })
    if token:
        # The texts are scanned in memory first; a copy on disk never carries the value.
        row['token_in_outputs'] = text_leaks(token, stdout=stdout, stderr=stderr, tail=tail,
                                           tail_json=tail_json, tail_json_error=tail_json_error)
        stdout, stderr, tail, tail_json, tail_json_error = (
            redact_text(text, token) for text in (stdout, stderr, tail, tail_json, tail_json_error))
    (out / 'k113-tail-summary.txt').write_text(tail)
    (out / 'k113-run-stdout.txt').write_text(stdout)
    (out / 'k113-run-stderr.txt').write_text(stderr)
    if args.case != 'marker':
        (out / 'k113-tail-summary.json').write_text(tail_json)
        (out / 'k113-tail-summary-json.stderr').write_text(tail_json_error)
    if token:
        scans = [vault_measurement.leak_scan([data, out, workspace], spelling.encode())
                 for spelling in secret_spellings(token)]
        row['token_in_exports'] = sorted({path for hits, _ in scans for path in hits})
        row['files_scanned'] = max(scanned for _, scanned in scans)
    if args.case == 'missing-source':
        row['unexpected_exec'] = (workspace / 'k113-unexpected-exec.txt').exists()
        facts = missing_source_facts(row, stdout + '\n' + stderr, attempts)
        outcome = 'PASS' if all(facts.values()) else 'FAIL'
        row['compatibility_facts'] = facts
    else:
        facts, outcome = judge(row)
    row['refusals'] = harness.vm_refusals(stdout + '\n' + stderr)
    if row['refusals']:
        outcome = 'REFUSED'  # recorded as what it is, never a pass
    row.update({'facts': facts, 'outcome': outcome})
    if args.case in ('a01', 'small-task'):
        try:
            summary_value = json.loads(tail_json)
            if type(summary_value) is not dict:
                raise ValueError('summary shape')
        except ValueError:
            summary_value = {}
        summary_lines = [f"ukai-jail: {line.get('text', '')}" for line in summary_value.get('lines', [])]
        printed = [line for line in tail.splitlines()
                   if line.startswith('ukai-jail: ') and not line.startswith('ukai-jail: receipt ')
                   and not line.startswith('ukai-jail: vm: ')]
        row['tail_json_text_matches_text'] = (row.get('tail_summary_json_exit') == 0
                                            and bool(summary_lines) and printed == summary_lines)
        guest, events, row['guest_journal'] = verified_guest_journal(out / 'k113-attempt')
        row['compatibility_facts'] = compatibility_facts(row, guest, summary_value, events)
        row['not_measured'] = COMPATIBILITY_PENDING
    if token:
        # The parsed vendor result is captured before output redaction. It too
        # must never export a value the agent happened to print in its result.
        row = redact_value(row, token)
    harness.write_json(out / 'k113-claude.json', row)
    print(json.dumps({'facts': facts, 'outcome': outcome}))
    return 0 if outcome == 'PASS' else 1


def native_exposure_control(metadata):
    """Validate the image-bound detector control, not merely its PASS label."""
    import credential_revocation_measurement as lifecycle
    control = metadata.get('guest_exposure_control')
    fields = {'schema', 'passed', 'scope', 'actual_values_retained', 'jail_execution_claimed', 'facts', 'sampling',
              'errors', 'control_source_sha256', 'sampler_sha256', 'guest_boot_id', 'guest_kernel', 'process'}
    facts = {'environment_canary_detected', 'argv_canary_detected', 'verified_program_environment_read',
             'verified_program_argv_read', 'only_owned_child_observed', 'sampler_source_unchanged', 'owned_child_reaped'}
    if type(control) is not dict or set(control) != fields:
        raise harness.HarnessError('image lacks the exact guest exposure detector control')
    for key, name in [('sampler_sha256', 'guest_exposure.py'), ('control_source_sha256', 'guest_exposure_control.py')]:
        digest = hashlib.sha256(lifecycle.bounded_file(Path(__file__).with_name(name), 512 * 1024)).hexdigest()
        if control[key] != digest or (metadata.get('source_sha256') or {}).get(name) != digest:
            raise harness.HarnessError('detector control does not match archived source')
    raw = (json.dumps(control, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if (hashlib.sha256(raw).hexdigest() != metadata.get('guest_exposure_control_sha256')
            or control['schema'] != 'ukai.vm.sampled-exposure-control/1'
            or control['scope'] != 'owned-public-canary-process-detector-control'
            or control['passed'] is not True or control['actual_values_retained'] is not False
            or control['jail_execution_claimed'] is not False or control['errors'] != []
            or type(control['facts']) is not dict or set(control['facts']) != facts
            or any(value is not True for value in control['facts'].values())):
        raise harness.HarnessError('detector control facts differ')
    for key in ('guest_boot_id', 'guest_kernel'):
        if type(control[key]) is not str or re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', control[key]) is None:
            raise harness.HarnessError('detector control guest identity differs')
    process = control['process']
    if (type(process) is not dict or set(process) != {'pid', 'starttime', 'executable_dev', 'executable_ino'}
            or any(type(value) is not int or not (0 if key == 'executable_dev' else 1) <= value < 2 ** 64
                   for key, value in process.items())):
        raise harness.HarnessError('detector control process identity differs')
    sample = control['sampling']; states = {'readable', 'unreadable', 'oversize', 'vanished', 'unstable', 'capped'}
    if (type(sample) is not dict or set(sample) != {'ticks', 'verified_program_reads', 'scan_errors'}
            or type(sample['ticks']) is not int or not 1 <= sample['ticks'] <= 1000
            or type(sample['verified_program_reads']) is not dict
            or set(sample['verified_program_reads']) != {'environment', 'argv'}):
        raise harness.HarnessError('detector control read evidence differs')
    for counts in sample['verified_program_reads'].values():
        if (type(counts) is not dict or set(counts) != states or counts['readable'] < 1
                or any(type(value) is not int or not 0 <= value < 2 ** 64 for value in counts.values())):
            raise harness.HarnessError('detector control lacks positive program reads')
    if (type(sample['scan_errors']) is not dict
            or any(type(key) is not str or re.fullmatch(r'[a-z_]{1,64}', key) is None
                   or type(value) is not int or not 1 <= value < 2 ** 64 for key, value in sample['scan_errors'].items())):
        raise harness.HarnessError('detector control error evidence differs')
    return {'verified': True, 'sha256': metadata['guest_exposure_control_sha256'],
            'guest_kernel': control['guest_kernel'], 'scope': control['scope']}


def native_context(home, jail):
    """Read metadata only; catalog guest paths are never opened on the Mac."""
    import guest_program
    import credential_revocation_measurement as lifecycle
    import run as image_tools
    identity = lifecycle.normal_identity(home, jail)
    metadata = identity['image']
    raw = image_tools.optional_program_catalog(Path(home) / 'image', metadata)
    if raw is None:
        raise harness.HarnessError('guest-native measurement requires an image-bound catalog')
    entries = [entry for entry in guest_program.parse_catalog(raw)['entries'] if entry['alias'] == 'claude']
    profile_bytes = lifecycle.bounded_file(Path(__file__).resolve().parents[1] / 'profiles/launch/claude.toml', 65536)
    if (len(entries) != 1 or entries[0]['version'] != CLAUDE_VERSION
            or entries[0]['executable_sha256'] != CLAUDE_SHA256
            or entries[0]['profile_sha256'] != hashlib.sha256(profile_bytes).hexdigest()):
        raise harness.HarnessError('catalog does not match this pinned vendor and unchanged bundled profile')
    if (identity['service']['sha256'] != metadata.get('ukai_vm_sha256')
            or identity['client']['sha256'] != metadata.get('ukai_jail_sha256')):
        raise harness.HarnessError('installed service/client do not match image provenance')
    sampler_hash = hashlib.sha256(lifecycle.bounded_file(Path(__file__).with_name('guest_exposure.py'), 512 * 1024)).hexdigest()
    if (metadata.get('source_sha256') or {}).get('guest_exposure.py') != sampler_hash:
        raise harness.HarnessError('installed image does not bind this archived guest sampler source')
    candidate = metadata.get('jail_candidate') or {}
    version = candidate.get('version') or {}
    build = version.get('build') or {}
    trusted_key = Path(__file__).resolve().parents[1] / 'dist/release.pub'
    if (candidate.get('kind') != 'signed-local-candidate' or candidate.get('signature_verified') is not True
            or candidate.get('verifier') != 'publish_release.check'
            or candidate.get('trusted_key_sha256') != hashlib.sha256(lifecycle.bounded_file(trusted_key, 8192)).hexdigest()
            or candidate.get('target') != 'aarch64-unknown-linux-gnu'
            or candidate.get('binary_sha256') != entries[0]['guest_jail_sha256']
            or candidate.get('binary_sha256') != NATIVE_GUEST_JAIL_SHA256
            or candidate.get('source_revision') != NATIVE_GUEST_REVISION
            or candidate.get('build_inputs') != NATIVE_GUEST_INPUTS
            or candidate.get('archive_sha256') != metadata.get('jail_archive_sha256')
            or re.fullmatch(r'[0-9a-f]{64}', candidate.get('archive_sha256', '')) is None
            or version.get('component') != 'ukai-jail' or version.get('version') != '0.1.0'
            or version.get('frozen') is not True or build.get('revision') != NATIVE_GUEST_REVISION
            or build.get('inputs') != NATIVE_GUEST_INPUTS or build.get('dirty') is not False
            or build.get('debug_assertions') is not False or build.get('opt_level') != '3'
            or build.get('target') != 'aarch64-unknown-linux-gnu'
            or not build.get('rustc', '').startswith('rustc 1.98.1 ')):
        raise harness.HarnessError('guest jail candidate does not match the pinned native measurement artifact')
    identity['measurement'] = {'sha256': harness.sha256_file(__file__)}
    return {'identity': identity, 'entry': entries[0], 'catalog_sha256': hashlib.sha256(raw).hexdigest(),
            'catalog_json': raw.decode(), 'profile': tomllib.loads(profile_bytes.decode()),
            'exposure_control': native_exposure_control(metadata)}


def native_argv(jail, workspace, case):
    prompt = {'marker': PROMPT, 'a01': A01_PROMPT, 'small-task': TASK_PROMPT, 'missing-source': PROMPT}[case]
    suffix = ['-p', prompt, '--dangerously-skip-permissions', '--output-format', 'json']
    command = [str(jail), 'run', '--vm', '--from-path', '--launch', 'claude', '--state', 'attempt',
               '--terminal', 'detach', '--profile', 'agent', *harness.vm_wall(240),
               '--workspace', str(workspace), '--', *suffix]
    return command, suffix


def native_secret_spellings(token):
    """Six encoding classes and common variants; the literal lane is unchanged."""
    return sorted(set(secret_spellings(token)) | {
        base64.b64encode(token).decode(), base64.b64encode(token).decode().rstrip('='),
        base64.urlsafe_b64encode(token).decode(), base64.urlsafe_b64encode(token).decode().rstrip('='),
        token.hex(), token.hex().upper(), urllib.parse.quote_from_bytes(token, safe=''),
    }, key=len, reverse=True)


def native_redact(value, spellings):
    """Sanitize parsed strings before truncation and JSON escaping."""
    if isinstance(value, str):
        for spelling in spellings:
            value = value.replace(spelling, '<token>')
        return value
    if isinstance(value, list):
        return [native_redact(item, spellings) for item in value]
    if isinstance(value, dict):
        return {native_redact(key, spellings): native_redact(item, spellings) for key, item in value.items()}
    return value


def _native_output_pass(text, spellings):
    """Detect encoded strings inside JSON before re-escaping them for retention."""
    if not spellings:
        return False, text
    hit = False
    retained = []
    for line in text.splitlines(keepends=True):
        safe = native_redact(line, spellings)
        hit |= safe != line
        try:
            # agent_result accepts a terminal prefix before its JSON object.
            prefix = ''
            try:
                value = strict_json(line)
            except ValueError:
                start = line.find('{')
                if start <= 0:
                    raise
                prefix = line[:start]
                value = strict_json(line[start:])
            redacted = native_redact(value, spellings)
            if redacted != value:
                hit = True
                safe = native_redact(prefix, spellings) + json.dumps(redacted, ensure_ascii=True)
                safe += '\n' if line.endswith('\n') else ''
        except (ValueError, TypeError, RecursionError):
            pass
        retained.append(safe)
    return hit, ''.join(retained)


def native_output(text, spellings):
    """Check the serialized redaction too; an unsafe result is withheld."""
    hit, safe = _native_output_pass(text, spellings)
    if _native_output_pass(safe, spellings)[0]:
        return True, ''
    return hit, safe


def native_vendor_usage(vendor):
    """Typed vendor-reported usage, not independently metered billing."""
    result = {'schema': 'ukai.vm.vendor-reported-usage/1', 'state': 'unavailable',
              'scope': 'Vendor-reported usage; not independently metered provider billing.'}
    if not isinstance(vendor, dict):
        return result
    def count(value):
        return type(value) is int and 0 <= value < 2 ** 63
    def cost(value):
        return type(value) in (int, float) and 0 <= value <= 1_000_000 and math.isfinite(value)
    def model(value):
        return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}', value) is not None
    total, turns, usage, models = (vendor.get(key) for key in ('total_cost_usd', 'num_turns', 'usage', 'modelUsage'))
    result['state'] = 'invalid'
    if (not cost(total) or not count(turns) or type(usage) is not dict or type(models) is not dict
            or not 1 <= len(models) <= 16):
        return result
    usage_keys = ('input_tokens', 'output_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens')
    if any(not count(usage.get(key)) for key in usage_keys):
        return result
    typed_models = []
    model_keys = ('inputTokens', 'outputTokens', 'cacheReadInputTokens', 'cacheCreationInputTokens')
    for name, details in sorted(models.items(), key=lambda item: str(item[0])):
        if (not model(name) or type(details) is not dict or not cost(details.get('costUSD'))
                or any(not count(details.get(key)) for key in model_keys)
                or ('canonicalModel' in details and not model(details['canonicalModel']))):
            return result
        typed = {'model': name, 'cost_usd': details['costUSD'],
                 'usage': {key: details[key] for key in model_keys}}
        if 'canonicalModel' in details:
            typed['canonical_model'] = details['canonicalModel']
        typed_models.append(typed)
    result.update(state='complete', total_cost_usd=total, num_turns=turns,
                  usage={key: usage[key] for key in usage_keys}, models=typed_models)
    return result


def native_usage_valid(value):
    """Validate retained usage fields, rather than trusting a complete label."""
    try:
        if type(value) is not dict or type(value.get('models')) is not list or not 1 <= len(value['models']) <= 16:
            return False
        models = {}
        for item in value['models']:
            name = item['model']
            if name in models:
                return False
            details = {**item['usage'], 'costUSD': item['cost_usd']}
            if 'canonical_model' in item:
                details['canonicalModel'] = item['canonical_model']
            models[name] = details
        return native_vendor_usage({'total_cost_usd': value['total_cost_usd'], 'num_turns': value['num_turns'],
                                    'usage': value['usage'], 'modelUsage': models}) == value and value['state'] == 'complete'
    except (KeyError, TypeError, ValueError):
        return False


def native_missing_source_facts(observed, text, attempts, profile):
    ids = profile['credentials_one_of']
    return {'missing_source_refusal': type(observed.get('run_exit')) is int and observed['run_exit'] != 0
                and 'credential_unavailable' in text and 'none is present' in text
                and 'launch.credentials_one_of' in text and all(name in text for name in ids),
            'both_bundled_hints': all(profile['credentials'][name]['hint'] in text for name in ids),
            'no_attempt_or_workload': attempts == [],
            'not_a_vm_capability_refusal': not harness.vm_refusals(text)}


def native_facts(observed, guest, events, summary, context, suffix, binding, host):
    """Qualification facts, independent of a reported PASS label."""
    import credential_revocation_measurement as lifecycle
    facts = compatibility_facts(observed, guest, summary, events)
    facts.pop('measurement_passed', None)
    facts.pop('tail_json_text_matches_text', None)
    entry = context['entry']
    wanted = {'catalog_sha256': context['catalog_sha256'], 'entry_id': entry['id'],
              'profile_sha256': entry['profile_sha256'], 'executable_sha256': entry['executable_sha256'],
              'selected_credential_id': observed['credential_id'], 'state': 'attempt',
              'request_argv_digest': harness.argv_digest(['claude', *suffix]),
              'resolved_argv_digest': harness.argv_digest([*entry['argv_prefix'], *suffix]),
              'policy_digest': (guest.get('policy') or {}).get('digest')}
    grants = [{'kind': 'read_only', 'value': entry['install_root'], 'by': 'program_resolution'}]
    grants += [{'kind': 'allow_host', 'value': host + ':443', 'by': 'operator'}
               for host in context['profile']['network']['allow']]
    actual = (guest.get('policy') or {}).get('grants')
    normalized = lambda values: sorted(json.dumps(value, sort_keys=True) for value in values)
    host_sources = [{'id': observed['credential_id'], 'mode': 'vault', 'never_staged': True,
                     'digest': None, 'digest_unavailable_reason': 'never_staged'}]
    host_source_only = (type(host.get('credentials')) is list
                        and normalized(host['credentials']) == normalized(host_sources))
    sampling = (observed.get('independent_summary') or {}).get('sampling') or {}
    sample_lifecycle = sampling.get('lifecycle') or {}
    monitored_exit = sample_lifecycle.get('supervisor_exit_observed_ns')
    monitored_stop = sample_lifecycle.get('stopped_ns')
    facts.update(
        exact_native_binding=type(binding) is dict and binding.get('native_program') == wanted
            and guest.get('argv_digest') == wanted['resolved_argv_digest'],
        derived_program_root_and_only_declared_grants=type(actual) is list and normalized(actual) == normalized(grants),
        strict_successful_outcome=lifecycle.successful_outcome(guest.get('outcome')),
        vendor_reported_success=type(observed.get('agent_result')) is dict
            and observed['agent_result'].get('subtype') == 'success'
            and observed['agent_result'].get('is_error') is False,
        typed_vendor_usage_reported=native_usage_valid(observed.get('vendor_usage')),
        actual_guest_version_matches_pinned_candidate=(guest.get('jail') or {}).get('component') == 'ukai-jail'
            and (guest.get('jail') or {}).get('version') == context['identity']['image']['jail_candidate']['version']['version']
            and (guest.get('jail') or {}).get('backend') == 'bubblewrap'
            and (guest.get('platform') or {}).get('os') == 'linux'
            and (guest.get('platform') or {}).get('arch') == 'aarch64',
        image_bound_sampler_positive_control=(context.get('exposure_control') or {}).get('verified') is True
            and 'Linux ' + context['exposure_control']['guest_kernel'] == (guest.get('platform') or {}).get('kernel'),
        host_settled_clean=host.get('phase') == 'settled' and host.get('errors') == []
            and lifecycle.successful_outcome(host.get('outcome')) and host.get('exec_observed') is True
            and (host.get('lifetime') or {}).get('tree_empty') is True
            and (host.get('lifetime') or {}).get('integrity') == 'verified'
            and host.get('cleanup_error') is None
            and (host.get('state_cleanup') == 'complete' or (host.get('state_cleanup') == 'not_needed'
                 and host.get('vendor_state') is None and host_source_only)),
        exact_host_source_only_provenance=host_source_only and host.get('vendor_state') is None,
        independent_full_summary=(observed.get('independent_summary') or {}).get('outcome') == 'PASS'
            and (observed.get('independent_summary') or {}).get('scope') == 'bound_guest',
        complete_bound_periodic_guest_samples=sampling.get('state') == 'complete'
            and sampling.get('verified_program_observed') is True and sampling.get('no_hits') is True
            and sampling.get('scan_errors') == {}
            and sampling.get('sampler_sha256') == context['identity']['image']['source_sha256']['guest_exposure.py']
            and sample_lifecycle.get('stop_reason') == 'supervisor_exit'
            and type(monitored_exit) is int and type(monitored_stop) is int and monitored_stop >= monitored_exit
            and type(sampling.get('last_ns')) is int and monitored_exit >= sampling['last_ns'],
        installed_identity_unchanged=observed.get('installed_identity_unchanged') is True,
        run_and_both_tail_commands_succeeded=all(type(observed.get(key)) is int and observed[key] == 0
            for key in ('run_exit', 'tail_exit', 'tail_json_exit')),
        source_removed_before_stop=observed.get('source_removed_before_stop') is True,
        service_shutdown_complete=(observed.get('service_shutdown') or {}).get('complete') is True
            and type(observed.get('stop_exit')) is int and observed['stop_exit'] == 0,
        all_exports_and_outputs_scanned=observed.get('leaks') == [] and observed.get('files_scanned', 0) > 0
            and observed.get('output_leaks') == [],
        no_harness_failure='error_type' not in observed,
    )
    return facts


def native_matrix(args, *, run=subprocess.run):
    """Keep every attempted outcome, stop on failure, and name unrun lanes."""
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    rows = []
    lanes = [('missing-source', 'missing-source'), ('a01', 'a01'), ('small-task', 'small-task')]
    lanes += [(f'repetition-{number:02}', 'a01') for number in range(1, 11)]
    stopped_after = None
    for label, case in lanes:
        if stopped_after is not None:
            rows.append({'case': label, 'outcome': 'NOT_RUN', 'reason': 'prior_lane_failed',
                         'stopped_after': stopped_after})
            continue
        trial = workspace / ('a01' if case == 'small-task' else label)
        if case != 'small-task':
            trial.mkdir(); harness.mark_workspace(trial)
        argv = [args.home, str(trial), str(out / label), args.jail, '--execution-mode', 'guest-native',
                '--credential-kind', args.credential_kind, '--case', case]
        if args.credential_source is not None:
            argv += ['--credential-source', str(args.credential_source)]
        try:
            code = main(argv, run=run)
            report = read_json(out / label / 'k113-native.json')
            rows.append({'case': label, 'exit': code, 'outcome': report.get('outcome'),
                         'facts': report.get('facts', {}), 'vendor_usage': report.get('vendor_usage')})
        except Exception as error:
            rows.append({'case': label, 'exit': None, 'outcome': 'ERROR', 'error_type': type(error).__name__})
        latest = rows[-1]
        if (type(latest.get('exit')) is not int or latest['exit'] != 0 or latest.get('outcome') != 'PASS'
                or type(latest.get('facts')) is not dict or not latest['facts']
                or any(value is not True for value in latest['facts'].values())
                or (case != 'missing-source' and not native_usage_valid(latest.get('vendor_usage')))):
            stopped_after = label
        harness.write_json(out / f'k113-native-progress-{len(rows):02}.json', {'rows': rows, 'qualified': False})
    passed = stopped_after is None and len(rows) == len(lanes)
    result = {'schema': 'ukai.vm.native-claude-matrix/1', 'credential_kind': args.credential_kind,
              'rows': rows, 'qualified': False, 'outcome': 'UNMEASURED' if passed else 'FAIL',
              'stopped_after': stopped_after,
              'not_measured': NATIVE_PENDING,
              'scope': 'Guest-native attempt-state measurement for the named credential kind; not full K113.'}
    harness.write_json(out / 'k113-native-matrix.json', result)
    return 1


def native_main(args, *, run=subprocess.run):
    """Explicit installed-client path. No fallback, provider credentials in argv, or launch override."""
    import credential_revocation_measurement as lifecycle
    import vm_summary_check
    home = Path(args.home).resolve(strict=True)
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.jail)
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    observed = {'schema': 'ukai.vm.native-claude/1', 'execution_mode': 'guest-native', 'case': args.case,
                'credential_kind': args.credential_kind,
                'credential_id': 'anthropic' if args.credential_kind == 'api-key' else 'claude-oauth',
                'qualified': False, 'not_measured': NATIVE_PENDING}
    token = b''; spellings = []; outputs = {}; attempt = None; source = None
    structured_vendor_leak = False
    host, guest, events, summary, binding, context, suffix = {}, {}, None, {}, {}, {}, []
    # Keep socket paths short even on the default long macOS temporary directory.
    data = Path(tempfile.mkdtemp(prefix='k113n-', dir='/tmp')).resolve()
    config = Path(tempfile.mkdtemp(prefix='k113n-config-')).resolve()
    private_home = config / 'home'
    private_home.mkdir(mode=0o700)
    environment = harness.vm_client_environment(base={}, PATH=f'{home}/bin:/usr/bin:/bin', HOME=private_home,
                                                TMPDIR='/private/tmp', UKAI_VM_HOME=home,
                                                UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    def execute(label, argv, timeout):
        done = run(argv, env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
        outputs[label + '.stdout'] = done.stdout
        outputs[label + '.stderr'] = done.stderr
        return done
    with contextlib.ExitStack() as cleanup:
        shutdown_lock = None
        try:
            context = native_context(home, jail)
            harness.clean_workspace(workspace, keep=('.git', 'greeting.txt') if args.case == 'small-task' else ())
            if args.case in ('a01', 'small-task'):
                if execute('git-init', ['git', '-c', 'init.defaultBranch=main', 'init', '-q', str(workspace)], 30).returncode != 0:
                    raise harness.HarnessError('fresh git repository initialization failed')
            if args.case == 'small-task':
                (workspace / 'slug.py').write_text(SLUG)
                (workspace / 'test_slug.py').write_text(SLUG_TEST)
            (config / 'credentials').mkdir(mode=0o700)
            source = config / 'credentials' / observed['credential_id']
            if args.case != 'missing-source':
                token = private_source(args.credential_source)
                spellings = native_secret_spellings(token)
                descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'wb') as target: target.write(token)
            command, suffix = native_argv(jail, workspace, args.case)
            observed['request_argv_digest'] = harness.argv_digest(['claude', *suffix])
            observed['resolved_argv_digest'] = harness.argv_digest([*context['entry']['argv_prefix'], *suffix])
            started = time.monotonic()
            observed['run_exit'] = execute('run', command, RUN_TIMEOUT_SECONDS).returncode
            observed['elapsed_seconds'] = time.monotonic() - started
            vendor = agent_result(outputs['run.stdout'])
            if type(vendor) is dict:
                # Sanitize parsed strings before truncation/serialization.
                if token:
                    redacted = native_redact(vendor, spellings)
                    structured_vendor_leak = redacted != vendor
                    vendor = redacted
                observed['agent_result'] = {key: vendor.get(key) for key in ('subtype', 'is_error', 'num_turns')}
                if type(vendor.get('result')) is str:
                    observed['agent_result']['result_text'] = vendor['result'][:200]
            observed['vendor_usage'] = native_vendor_usage(vendor)
            attempts = sorted((data / 'attempts').glob('att_*'))
            if args.case == 'missing-source':
                observed['facts'] = native_missing_source_facts(observed, outputs['run.stdout'] + outputs['run.stderr'],
                                                               attempts, context['profile'])
            elif len(attempts) == 1:
                attempt = attempts[0]
                observed['attempt_id'] = attempt.name
                host = strict_json(lifecycle.bounded_file(attempt / 'jail.json', RECEIPT_MAX))
                guest, events, observed['guest_journal'] = verified_guest_journal(attempt)
                binding = strict_json(lifecycle.bounded_file(attempt / 'evidence/vm-binding.json', RECEIPT_MAX))
                observed['tail_exit'] = execute('tail', [str(jail), 'tail', '--summary', '--attempt', attempt.name], 60).returncode
                observed['tail_json_exit'] = execute('tail-json', [str(jail), 'tail', '--summary', '--json', '--attempt', attempt.name], 60).returncode
                summary = strict_json(outputs['tail-json.stdout'])
                observed['independent_summary'] = vm_summary_check.verify_attempt(attempt, summary, outputs['tail.stdout'])
                target = workspace / ('greeting.txt' if args.case == 'a01' else 'k113-marker.txt')
                if args.case in ('a01', 'marker'):
                    observed['task_passed'] = lifecycle.bounded_file(target, 1024).strip() == (b'hello' if args.case == 'a01' else b'contained')
                else:
                    tests = workspace / 'test_slug.py'
                    unchanged = lifecycle.bounded_file(tests, 4096) == SLUG_TEST.encode()
                    if unchanged:
                        # Load stdlib unittest in isolated mode before making the
                        # workspace importable; a vendor-created unittest.py
                        # must not replace the fixed checker.
                        check_argv = ['/usr/bin/python3', '-I', '-c',
                            'import os,sys,unittest;sys.path.insert(0,os.getcwd());exec(' + repr(SLUG_TEST) + ')']
                        checked = execute('task-check', [str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                            *harness.vm_wall(20), '--workspace', str(workspace), '--', *check_argv], 300)
                        check_attempts = sorted(p for p in (data / 'attempts').glob('att_*') if p != attempt)
                        check_guest = read_json(check_attempts[0] / 'evidence/jail.json') if len(check_attempts) == 1 else {}
                        observed['task_passed'] = (checked.returncode == 0 and lifecycle.bounded_file(tests, 4096) == SLUG_TEST.encode()
                            and len(check_attempts) == 1 and harness.attempt_dir_bound(check_attempts[0], check_argv)
                            and lifecycle.successful_outcome(check_guest.get('outcome'))
                            and check_guest.get('phase') == 'settled' and check_guest.get('errors') == []
                            and check_guest.get('containment') == 'enforced' and check_guest.get('child_protection') == 'enforced'
                            and check_guest.get('exec_observed') is True
                            and (check_guest.get('lifetime') or {}).get('tree_empty') is True
                            and (check_guest.get('lifetime') or {}).get('integrity') == 'verified')
                        observed['task_check_attempts'] = [p.name for p in check_attempts]
                    else:
                        observed['task_passed'] = False
            else:
                raise harness.HarnessError('native run did not create exactly one attempt')
        except Exception as error:
            observed['error_type'] = type(error).__name__
            if isinstance(error, subprocess.TimeoutExpired):
                for key, value in [('timeout.stdout', error.stdout), ('timeout.stderr', error.stderr)]:
                    outputs[key] = value.decode(errors='replace') if isinstance(value, bytes) else (value or '')
        finally:
            try:
                if source is not None: source.unlink(missing_ok=True)
                observed['source_removed_before_stop'] = source is None or not source.exists()
            except OSError as error:
                observed['source_removed_before_stop'] = False
                observed['source_cleanup_error_type'] = type(error).__name__
            try:
                if os.path.lexists(data / 'vm/serve.lock'):
                    shutdown_lock = lifecycle.running_service_lock(data)
                    cleanup.enter_context(shutdown_lock)
                    observed['stop_exit'] = execute('stop', [str(home / 'bin/ukai-vm'), 'stop'], 60).returncode
                    observed['service_shutdown'] = lifecycle.stopped_service_lock(data, shutdown_lock)
                else:
                    observed['service_shutdown'] = {'complete': args.case == 'missing-source', 'not_started': True}
            except Exception as error:
                observed['service_shutdown'] = {'complete': False, 'error_type': type(error).__name__}
                # A failed lock witness must still attempt to stop this isolated service.
                try: observed['stop_exit'] = execute('stop-fallback', [str(home / 'bin/ukai-vm'), 'stop'], 60).returncode
                except Exception: observed['stop_exit'] = None
        try:
            observed['installed_identity_unchanged'] = native_context(home, jail) == context
        except Exception:
            observed['installed_identity_unchanged'] = False
        safe_outputs = {name: native_output(value, spellings) for name, value in outputs.items()}
        output_leaks = {name for name, (hit, _) in safe_outputs.items() if hit}
        if structured_vendor_leak:
            output_leaks.add('run.stdout')
        observed['output_leaks'] = sorted(output_leaks)
        observed['scan_encoding_classes'] = ['raw', 'base64', 'base64url', 'hex', 'url', 'json'] if token else []
        scans = ([vault_measurement.leak_scan([data, workspace, config], spelling.encode()) for spelling in spellings]
                 if observed['service_shutdown']['complete'] else [(['scan-error:service-shutdown-unverified'], 0)])
        observed['leaks'] = sorted({path for hits, _ in scans for path in hits})
        observed['files_scanned'] = max((count for _, count in scans), default=0)
        for name, (_, value) in safe_outputs.items():
            (out / name).write_text(value)
        if attempt is not None and not observed['leaks'] and not observed['output_leaks']:
            try:
                observed['retained_attempt_sha256'] = lifecycle.retain_normal_attempt(attempt, out / 'attempt', spellings)
                # Exact caller mapping accounts only for relocation of the receipt's display path.
                mapping = {str(out / 'attempt'): str(attempt)}
                observed['retained_summary'] = vm_summary_check.verify_attempt(out / 'attempt', summary, outputs['tail.stdout'],
                                                                             display_mapping=mapping)
                inputs = {'schema': 'ukai.vm.native-claude-inputs/1', 'context': context, 'argv_suffix': suffix,
                          'display_mapping': mapping, 'summary': summary, 'attempt_id': attempt.name}
                encoded = (json.dumps(inputs, ensure_ascii=False, indent=2) + '\n').encode()
                if len(encoded) > 8 * 1024 * 1024 or any(spelling.encode() in encoded for spelling in spellings):
                    raise harness.HarnessError('native input retention refused a secret spelling')
                (out / 'native-inputs.json').write_bytes(encoded)
                observed['inputs_sha256'] = hashlib.sha256(encoded).hexdigest()
            except Exception as error:
                observed['error_type'] = type(error).__name__
        if args.case != 'missing-source':
            try: observed['facts'] = native_facts(observed, guest, events, summary, context, suffix, binding, host)
            except (KeyError, TypeError, ValueError): observed['facts'] = {'evidence_well_formed': False}
            observed['facts']['exact_attempt_and_inputs_retained'] = bool(observed.get('inputs_sha256'))
        else:
            observed.setdefault('facts', {'missing_source_refusal': False})
            observed['facts']['service_cleanup_verified'] = observed['service_shutdown']['complete']
            observed['facts']['no_harness_failure'] = 'error_type' not in observed
        observed['outcome'] = 'PASS' if observed['facts'] and all(observed['facts'].values()) else 'FAIL'
        observed['compatibility_outcome'] = 'UNMEASURED' if observed['outcome'] == 'PASS' else 'FAIL'
        if token: observed = native_redact(observed, spellings)
        harness.write_json(out / 'k113-native.json', observed)
    # Leave the isolated data directory as failure evidence, but never a source.
    if observed.get('source_removed_before_stop'):
        shutil.rmtree(config)
    return 0 if observed['outcome'] == 'PASS' else 1


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


if __name__ == '__main__':
    sys.exit(main())
