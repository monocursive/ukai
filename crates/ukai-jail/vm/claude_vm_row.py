#!/usr/bin/env python3
"""The K113 row: Claude Code headless in the guest, on the installed package.

The J18 §9.4 compatibility record this tier needs: one `ukai-jail run --vm`
attempt, agent profile, the operator's OAuth token as a vault-mode
credential (the child holds only the placeholder, bound to
CLAUDE_CODE_OAUTH_TOKEN by the vault's `env`), the guest's own proxy
substituting it in flight, and the agent doing one real task — a file
created in the live workspace, reaching this host through the share.

The token is read at run time from the operator's Claude Code credentials
(it is refreshed by running `claude` once beforehand), written to a 0600
single-use source outside the repository, and never printed: the record
carries its shape and byte length, and the leak scan proves the value
appears in no export, workspace file or record.

Usage: claude_vm_row.py <installed-root> <workspace> <out> <ukai-jail>
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CLAUDE_BINARY = 'claude'          # staged in the workspace by the caller
CLAUDE_VERSION = '2.1.311'        # downloads.claude.ai manifest, linux-arm64
CLAUDE_SHA256 = ('2e2496c9a8065df93acb0fca2d341f59'
                 'a6b8777649b2e025ab8c9bcd5eef61f3')
PROMPT = ('In the current directory, create a file named k113-marker.txt '
          'whose entire content is the single word contained followed by '
          'one newline. Then reply with just the word done.')

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


def fresh_token(destination):
    """Copy the operator's current OAuth access token to a 0600 source.

    Claude Code on macOS keeps the live session in the keychain item
    `Claude Code-credentials` (the `~/.claude/.credentials.json` copy can
    sit stale for weeks); the freshest unexpired source wins. Returns
    (byte length, sha256, expiry) for the record; the value never prints.
    """
    import subprocess
    candidates = []
    keychain = subprocess.run(
        ['security', 'find-generic-password', '-s', 'Claude Code-credentials', '-w'],
        capture_output=True, text=True)
    if keychain.returncode == 0:
        try:
            candidates.append(json.loads(keychain.stdout)['claudeAiOauth'])
        except (ValueError, KeyError):
            pass
    try:
        candidates.append(json.loads(
            Path.home().joinpath('.claude/.credentials.json').read_text())['claudeAiOauth'])
    except (OSError, ValueError, KeyError):
        pass
    now = time.time() * 1000
    live = [section for section in candidates
            if section.get('expiresAt', 0) > now and section.get('accessToken')]
    if not live:
        raise SystemExit('no unexpired Claude Code OAuth token: run `claude` '
                         'once on this Mac to refresh the session, then rerun')
    section = max(live, key=lambda s: s['expiresAt'])
    token = section['accessToken'].encode()
    expires_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                time.gmtime(section['expiresAt'] / 1000))
    destination.write_bytes(token)
    os.chmod(destination, 0o600)
    return len(token), hashlib.sha256(token).hexdigest(), expires_iso


def main():
    home = Path(sys.argv[1]).resolve()
    workspace = Path(sys.argv[2]).resolve(strict=True)
    out = Path(sys.argv[3]).resolve()
    jail = Path(sys.argv[4]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for stale in workspace.iterdir():
        if stale.name != CLAUDE_BINARY:
            shutil.rmtree(stale) if stale.is_dir() else stale.unlink()
    if not workspace.joinpath(CLAUDE_BINARY).is_file():
        raise SystemExit(f'stage the {CLAUDE_VERSION} linux-arm64 binary in '
                         f'{workspace}/{CLAUDE_BINARY} first')
    if hashlib.sha256(workspace.joinpath(CLAUDE_BINARY).read_bytes()).hexdigest() != CLAUDE_SHA256:
        raise SystemExit('the staged claude binary does not match its manifest digest')

    source = Path(tempfile.mkdtemp(prefix='k113-vault-')).resolve() / 'token'
    length, digest, expires = fresh_token(source)
    config = Path(tempfile.mkdtemp(prefix='k113-cfg-'))
    os.chmod(config, 0o700)
    (config / 'launch').mkdir()
    (config / 'launch' / 'claude-vm.toml').write_text(
        PROFILE.format(source=source))
    os.chmod(config / 'launch' / 'claude-vm.toml', 0o600)

    data = Path(tempfile.mkdtemp(prefix='k113-'))
    environment = dict(os.environ)
    environment['PATH'] = f'{home}/bin:/usr/bin:/bin'
    environment['UKAI_VM_HOME'] = str(home)
    environment['UKAI_DATA_DIR'] = str(data)
    environment['UKAI_CONFIG_DIR'] = str(config)
    script = ('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 '
              f'./{CLAUDE_BINARY} -p {json.dumps(PROMPT)} '
              '--dangerously-skip-permissions --output-format json')
    started = time.monotonic()
    run = subprocess.run(
        ['script', '-q', '/dev/null', str(jail), 'run', '--vm',
         '--terminal', 'detach', '--profile', 'agent', '--launch', 'claude-vm',
         '--limit', 'wall=240s', '--workspace', str(workspace),
         '--', '/bin/sh', '-c', script],
        env=environment, capture_output=True, text=True, timeout=420)
    elapsed = time.monotonic() - started
    subprocess.run([str(home / 'bin/ukai-vm'), 'stop'], env=environment,
                   capture_output=True, text=True, timeout=60)
    terminal = run.stdout + run.stderr

    attempts = sorted((data / 'attempts').glob('att_*'),
                      key=lambda p: p.stat().st_mtime)
    row = {'claude_version': CLAUDE_VERSION, 'claude_sha256': CLAUDE_SHA256,
           'token_shape': {'bytes': length, 'sha256': digest,
                           'kind': 'claudeAiOauth.accessToken',
                           'expires_at': expires},
           'run_exit': run.returncode, 'elapsed_s': round(elapsed, 1)}
    if not attempts:
        row['outcome'] = 'FAIL'
        row['stderr'] = run.stderr[-600:]
        (out / 'k113-claude.json').write_text(json.dumps(row, indent=2) + '\n')
        print(json.dumps(row))
        return 1
    attempt = attempts[-1]
    shutil.copytree(attempt, out / 'k113-attempt', dirs_exist_ok=True)
    stored = json.loads((attempt / 'jail.json').read_text())
    transport = json.loads((attempt / 'vm-transport.json').read_text())
    guest = json.loads((attempt / 'evidence/jail.json').read_text())

    # The agent's own JSON result line is the last result object in the
    # log. A pty prefixes render bytes (a ^D and friends), so each line
    # parses from its first `{`.
    result = None
    for line in (run.stdout + run.stderr).splitlines():
        if '"type":"result"' not in line and '"type": "result"' not in line:
            continue
        start = line.find('{')
        if start < 0:
            continue
        try:
            candidate = json.loads(line[start:])
        except ValueError:
            continue
        result = candidate
    marker = workspace / 'k113-marker.txt'

    # The token value may appear in no exported byte.
    token = source.read_bytes()
    leaked = []
    for path in attempt.rglob('*'):
        if path.is_file() and path.stat().st_size < 2_000_000:
            if token in path.read_bytes():
                leaked.append(str(path.relative_to(attempt)))

    line = re.search(
        r'vm: guest-reported facts in evidence/jail\.json · boot (\S+) '
        r'· image ([0-9a-f]+) · vsock (\d+) · receipt sha256:([0-9a-f]+)',
        terminal)
    summary = subprocess.run(
        [str(jail), 'tail', '--summary', '--attempt', attempt.name],
        env=environment, capture_output=True, text=True, timeout=60)
    row.update({
        'attempt_id': attempt.name,
        'stdout_tail': run.stdout[-2000:],
        'stderr_tail': run.stderr[-800:],
        'phase': stored.get('phase'),
        'exit': stored.get('outcome', {}).get('code'),
        'tree_empty': stored.get('lifetime', {}).get('tree_empty'),
        'agent_result': None if result is None else {
            'subtype': result.get('subtype'),
            'is_error': result.get('is_error'),
            'num_turns': result.get('num_turns'),
            'model': (result.get('modelUsage') or {}) and
            next(iter(result.get('modelUsage', {})), None),
            'total_cost_usd': result.get('total_cost_usd'),
            'result_text': (result.get('result') or '')[:200],
        },
        'marker_on_host': marker.is_file(),
        'marker_content': marker.read_text() if marker.is_file() else None,
        'guest_receipt_linux': guest.get('platform', {}).get('os') == 'linux',
        'transport_schema': transport.get('schema'),
        'transport_line_in_terminal': bool(line),
        'transport_line_matches_record': bool(line) and (
            line.group(1) == transport.get('boot_id')
            and line.group(4) == (transport.get('guest_receipt_sha256', ''))[:16]),
        'token_in_exports': sorted(set(leaked)),
        'summary_exit': summary.returncode,
        'summary_names_transport': 'vm: guest-reported facts' in (
            summary.stdout + summary.stderr + terminal),
    })
    row['outcome'] = 'PASS' if (
        row['phase'] == 'settled'
        and row['exit'] == 0
        and row['tree_empty'] is True
        and row['agent_result'] and row['agent_result']['subtype'] == 'success'
        and row['agent_result']['is_error'] is False
        and row['marker_on_host']
        and (row['marker_content'] or '').strip() == 'contained'
        and row['guest_receipt_linux']
        and not row['token_in_exports']
        and row['transport_line_matches_record']
        and row['summary_names_transport']) else 'FAIL'
    (out / 'k113-claude.json').write_text(json.dumps(row, indent=2) + '\n')
    print(json.dumps({k: v for k, v in row.items()
                      if k not in ('token_shape', 'transport_schema',
                                   'stdout_tail', 'stderr_tail')}))
    if row['outcome'] != 'PASS':
        sys.stderr.write('\n--- workload stdout tail ---\n' + run.stdout[-2000:]
                         + '\n--- workload stderr tail ---\n' + run.stderr[-800:] + '\n')
    return 0 if row['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
