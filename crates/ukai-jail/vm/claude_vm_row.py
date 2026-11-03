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
outside the repository and deleted on every path out of this script, and
never printed or passed in an argv: the record carries its shape and byte
length, and the leak scan proves the value appears in no exported file (the
attempt directory, this run's output copy, the workspace, the run's own
stdout/stderr and the tail summary), with no size cap. `ukai-vm stop` runs
on every path, a timeout included. A previous run's output directory is
never reused.

Not measured here (J18 §9.4's Linux-row conditions, which a supported row
also needs): the A01 fixture, ten repetitions, the no-source refusal,
revocation, six active classes and the credential use count. The record
lists them under `not_measured`.

Usage: claude_vm_row.py <installed-root> <workspace> <out> <ukai-jail>
"""
import hashlib
import json
import os
import shutil
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
    return sorted(name for name, text in texts.items() if token.decode() in (text or ''))


def judge(row):
    facts = {
        'settled_exit_zero_tree_empty': (row.get('phase') == 'settled' and row.get('exit') == 0
                                         and row.get('tree_empty') is True),
        'agent_succeeded': bool(row.get('agent_result')) and row['agent_result'].get('subtype') == 'success'
        and row['agent_result'].get('is_error') is False,
        'marker_on_host': (row.get('marker_content') or '') == 'contained\n',
        'guest_receipt_linux': row.get('guest_receipt_linux') is True,
        'token_in_no_export': row.get('token_in_exports') == [] and row.get('files_scanned', 0) > 0,
        'token_in_no_output': row.get('token_in_outputs') == [],
        'tail_summary_ran': row.get('tail_summary_exit') == 0,
    }
    facts.update({f'tail_summary_{name}': value is True
                  for name, value in (row.get('tail_summary_facts') or {'transport_line_from_record': False}).items()})
    return facts, 'PASS' if all(facts.values()) else 'FAIL'


def main(argv=None, now=time.time, candidates=credential_candidates, run=subprocess.run):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    home = Path(argv[0]).resolve(strict=True)
    workspace = harness.guarded_workspace(argv[1])
    jail = harness.required_binary('UKAI_JAIL_BINARY', argv[3])
    out = harness.fresh_out_dir(argv[2])
    harness.clean_workspace(workspace, keep=(CLAUDE_BINARY,))
    staged = workspace / CLAUDE_BINARY
    if not staged.is_file() or staged.is_symlink():
        raise harness.HarnessError(f'stage the {CLAUDE_VERSION} linux-arm64 binary in {staged} first')
    if harness.sha256_file(staged) != CLAUDE_SHA256:
        raise harness.HarnessError('the staged claude binary does not match its manifest digest')
    section = select_token(candidates(), now() * 1000)
    if section is None:
        raise harness.HarnessError(f'no Claude Code OAuth token with {EXPIRY_MARGIN_SECONDS // 60} min of life '
                                   'left: run `claude` once on this Mac to refresh the session, then rerun')

    source_dir = Path(tempfile.mkdtemp(prefix='k113-vault-')).resolve()
    source = source_dir / 'token'
    config = Path(tempfile.mkdtemp(prefix='k113-cfg-'))
    data = Path(tempfile.mkdtemp(prefix='k113-'))
    # LANG=C.UTF-8 and no TERM/TZ: the guest jail admits nothing else, so the
    # host refuses any other environment (vm:not-carried:environment).
    environment = harness.vm_client_environment(PATH=f'{home}/bin:/usr/bin:/bin', UKAI_VM_HOME=home,
                                                UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    row = {'claude_version': CLAUDE_VERSION, 'claude_sha256': CLAUDE_SHA256,
           'binary': harness.fingerprint(jail), 'not_measured': NOT_MEASURED}
    token = b''
    stdout = stderr = tail = ''
    try:
        token, row['token_shape'] = write_token(section, source)
        os.chmod(config, 0o700)
        (config / 'launch').mkdir()
        (config / 'launch' / 'claude-vm.toml').write_text(PROFILE.format(source=source))
        os.chmod(config / 'launch' / 'claude-vm.toml', 0o600)
        script = ('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 '
                  f'./{CLAUDE_BINARY} -p {json.dumps(PROMPT)} '
                  '--dangerously-skip-permissions --output-format json')
        started = time.monotonic()
        try:
            done = run(['script', '-q', '/dev/null', str(jail), 'run', '--vm', '--terminal', 'detach',
                        '--profile', 'agent', '--launch', 'claude-vm', *harness.vm_wall(240),
                        '--workspace', str(workspace), '--', '/bin/sh', '-c', script],
                       env=environment, capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS)
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
    finally:
        stop = run([str(home / 'bin/ukai-vm'), 'stop'], env=environment, capture_output=True,
                   text=True, timeout=60)
        row['stop_exit'] = stop.returncode
        source.unlink(missing_ok=True)
        shutil.rmtree(source_dir, ignore_errors=True)
    row['token_source_removed'] = not source.exists()

    attempts = sorted((data / 'attempts').glob('att_*'), key=lambda p: p.stat().st_mtime)
    if attempts:
        attempt = attempts[-1]
        shutil.copytree(attempt, out / 'k113-attempt')
        stored = read_json(attempt / 'jail.json')
        transport = read_json(attempt / 'vm-transport.json')
        guest = read_json(attempt / 'evidence/jail.json')
        result = agent_result(stdout + stderr)
        marker = workspace / 'k113-marker.txt'
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
            'transport_schema': transport.get('schema'),
            'tail_summary_facts': harness.summary_facts(tail, guest, transport),
            'run_summary_facts': harness.summary_facts(stdout + stderr, guest, transport),
            'host_receipt_contradictions': harness.receipt_contradictions(stored, guest),
        })
    if token:
        # The texts are scanned in memory first; a copy on disk never carries the value.
        row['token_in_outputs'] = text_leaks(token, stdout=stdout, stderr=stderr, tail=tail)
        stdout, stderr, tail = (text.replace(token.decode(), '<token>') for text in (stdout, stderr, tail))
    (out / 'k113-tail-summary.txt').write_text(tail)
    (out / 'k113-run-stdout.txt').write_text(stdout)
    (out / 'k113-run-stderr.txt').write_text(stderr)
    if token:
        row['token_in_exports'], row['files_scanned'] = vault_measurement.leak_scan([data, out, workspace], token)
    facts, outcome = judge(row)
    row['refusals'] = harness.vm_refusals(stdout + '\n' + stderr)
    if row['refusals']:
        outcome = 'REFUSED'  # recorded as what it is, never a pass
    row.update({'facts': facts, 'outcome': outcome})
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
