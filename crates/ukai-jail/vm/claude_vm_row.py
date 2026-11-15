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

Usage: claude_vm_row.py <installed-root> <workspace> <out> <ukai-jail> [options]
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402
import vault_measurement  # noqa: E402

CLAUDE_BINARY = 'claude'          # staged in the workspace by the caller
CLAUDE_VERSION = '2.1.311'        # downloads.claude.ai manifest, linux-arm64
CLAUDE_SHA256 = ('2e2496c9a8065df93acb0fca2d341f59'
                 'a6b8777649b2e025ab8c9bcd5eef61f3')
RUN_TIMEOUT_SECONDS = 420
EXPIRY_MARGIN_SECONDS = 30 * 60   # the run's timeout and the summary, with room
PROMPT = ('In the current directory, create a file named k113-marker.txt '
          'whose entire content is the single word contained followed by '
          'one newline. Then reply with just the word done.')
NOT_MEASURED = ['A01 fixture', 'ten repetitions', 'no-source refusal', 'revocation',
                'six active classes', 'credential use count']
COMPATIBILITY_PENDING = ['revocation mid-stream', 'full independent summary recomputation',
                         'guest journal / independently matched credential use count',
                         'sampled child environments', 'alias-derived executable grants',
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


def compatibility_facts(row, guest, summary, events):
    """Required per-run facts; absent guest journal/counts fail, never become zero."""
    lines = {line.get('line'): line for line in summary.get('lines', [])}
    evidence = (lines.get('evidence') or {}).get('facts') or {}
    credentials = guest.get('credentials') or []
    counted = ((lines.get('credentials') or {}).get('facts') or {}).get('credentials') or []
    uses = None if events is None else sum(
        event.get('source') == 'proxy' and event.get('operation') == 'net.connect'
        and event.get('stage') == 'result' and row['credential_id'] in ((event.get('fields') or {}).get('credentials') or [])
        for event in events)
    coverage = guest.get('coverage') or {}
    return {'strict_observation': evidence.get('observe') == 'on' and evidence.get('evidence') == 'strict',
            'six_active_classes_no_gaps': set(coverage) == set(harness.SUMMARY_CLASSES)
            and all(value.get('status') == 'active' and value.get('gaps') == [] for value in coverage.values()),
            'guest_settled_clean': guest.get('phase') == 'settled' and guest.get('errors') == []
            and (guest.get('outcome') or {}).get('kind') == 'exited'
            and (guest.get('outcome') or {}).get('code') == 0
            and guest.get('state_cleanup') == 'complete' and guest.get('cleanup_error') is None
            and (guest.get('lifetime') or {}).get('tree_empty') is True
            and (guest.get('lifetime') or {}).get('integrity') == 'verified',
            'one_vault_credential_never_staged': len(credentials) == 1
            and credentials[0].get('id') == row['credential_id'] and credentials[0].get('mode') == 'vault'
            and credentials[0].get('never_staged') is True,
            'guest_journal_available': events is not None,
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
    args = parser.parse_args(argv)
    if args.credential_kind == 'api-key' and args.credential_source is None and args.case != 'missing-source':
        parser.error('--credential-kind api-key requires --credential-source')
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
        except ValueError:
            summary_value = {}
        summary_lines = [f"ukai-jail: {line.get('text', '')}" for line in summary_value.get('lines', [])]
        printed = [line for line in tail.splitlines()
                   if line.startswith('ukai-jail: ') and not line.startswith('ukai-jail: receipt ')
                   and not line.startswith('ukai-jail: vm: ')]
        row['tail_json_text_matches_text'] = (row.get('tail_summary_json_exit') == 0
                                            and bool(summary_lines) and printed == summary_lines)
        # Current VM transport exports no guest journal. Never count the host's
        # unrelated lifecycle journal as credential uses or invent zero uses.
        row['compatibility_facts'] = compatibility_facts(row, read_json(out / 'k113-attempt/evidence/jail.json'),
                                                       summary_value, None)
        row['not_measured'] = COMPATIBILITY_PENDING
    if token:
        # The parsed vendor result is captured before output redaction. It too
        # must never export a value the agent happened to print in its result.
        row = redact_value(row, token)
    harness.write_json(out / 'k113-claude.json', row)
    print(json.dumps({'facts': facts, 'outcome': outcome}))
    return 0 if outcome == 'PASS' else 1


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


if __name__ == '__main__':
    sys.exit(main())
