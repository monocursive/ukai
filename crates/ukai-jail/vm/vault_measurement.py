#!/usr/bin/env python3
"""Live measurement of vault-value consumption (J18 §6).

An agent attempt with a vaulted launch profile: the credential value
crosses over vsock once, lands in the guest's tmpfs, the guest jail's
`--launch` resolves it, and the guest proxy injects it into an admitted
request. The echo server (this Mac, reached through the guest NAT) records
the header, which proves injection end to end. PASS also needs:

- the child saw the placeholder, not the value: its environment variable
  is exactly `vault:<the guest jail's attempt id>:test` (vault.rs's
  format), so it holds no part of the value in any encoding; the child
  prints the variable only when it has that shape (otherwise only its
  SHA-256 and length), and the host also checks that neither the value nor
  its base64 or hex spelling occurs in what was printed;
- the guest receipt records the credential `test` as mode `vault`,
  `never_staged` (the jail never wrote it into the attempt);
- no exported byte holds the value: every regular file under the run's data
  directory (receipts, policy.json, trace.ndjson, transport and binding
  records, console logs), the workspace, and the client's own stdout and
  stderr, with no size cap;
- the value never reached the guest's disk: after a `sync` attempt on the
  same boot (its transport record names the vault attempt's serve boot,
  and its binding the same guest kernel boot), THAT boot's raw disk image,
  `vm/<boot id>/image/base.raw`, is scanned for the value's bytes (the
  only staging place left is the guest tmpfs, which is not on it).

The value's source file is deleted before `ukai-vm stop` runs, so a stop
that fails or hangs never leaves it behind.

The Mac's LAN address the echo server needs is redacted in the record.

Usage: vault_measurement.py <home> <workspace> <out> [--ukai-jail PATH]
       (or UKAI_JAIL_BINARY=...)
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness  # noqa: E402

SECRET = b'ukai-vault-measurement-token-773f'
CHUNK = 8 * 1024 * 1024


class Echo(http.server.BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        Echo.received.append({h.lower(): v for h, v in self.headers.items()})
        self.send_response(200)
        self.send_header('content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'echo')

    def log_message(self, *_):
        pass


def mac_address():
    for interface in ('en0', 'en1'):
        result = subprocess.run(['ipconfig', 'getifaddr', interface], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    raise harness.HarnessError('no Mac interface address for the echo server')


def file_holds(path, needle, chunk=CHUNK):
    """Whether `needle` occurs in the file at `path`, streamed with overlap."""
    overlap = len(needle) - 1
    tail = b''
    with open(path, 'rb') as source:
        while block := source.read(chunk):
            if needle in tail + block:
                return True
            tail = (tail + block)[-overlap:] if overlap else b''
    return False


def leak_scan(roots, needle, skip=()):
    """Every regular file under each root (never following links), no size cap."""
    hits, scanned = [], 0
    skip = {Path(path).resolve() for path in skip}
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        for directory, _, names in os.walk(root, followlinks=False):
            for name in names:
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file() or path.resolve() in skip:
                    continue
                scanned += 1
                if file_holds(path, needle):
                    hits.append(str(path))
    return sorted(hits), scanned


CREDENTIAL_ID = 'test'
PLACEHOLDER_SHAPE = 'vault:[A-Za-z0-9_.-]+:' + CREDENTIAL_ID  # re.fullmatch: no anchors to quote


def fetch_script(address, port):
    return ("python3 -c \"import hashlib, os, re, urllib.request; "
            "token = os.environ.get('UKAI_VAULT_TEST', ''); "
            "shown = token if re.fullmatch('%s', token) else '-'; "
            "print('PLACEHOLDER', hashlib.sha256(token.encode()).hexdigest(), len(token), shown); "
            "req = urllib.request.Request('http://%s:%d/echo', headers={'x-test-token': token}); "
            "r = urllib.request.urlopen(req, timeout=20); "
            "print('ECHO', r.status, r.read().decode())\"" % (PLACEHOLDER_SHAPE, address, port))


def placeholder(stdout):
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] == 'PLACEHOLDER' and parts[2].isdigit():
            return {'sha256': parts[1], 'length': int(parts[2]),
                    'value': None if parts[3] == '-' else parts[3]}
    return None


def value_spellings(secret=None):
    """The value as bytes, base64 and hex: none may occur in what the child saw."""
    import base64
    secret = SECRET if secret is None else secret
    return {secret.decode(), base64.b64encode(secret).decode(), secret.hex()}


def placeholder_facts(seen, guest_attempt_id):
    """The child's variable is exactly vault.rs's placeholder for this attempt."""
    seen = seen or {}
    value = seen.get('value')
    expected = f'vault:{guest_attempt_id}:{CREDENTIAL_ID}' if guest_attempt_id else None
    return (isinstance(value, str) and expected is not None and value == expected
            and seen.get('length') == len(value)
            and seen.get('sha256') == hashlib.sha256(value.encode()).hexdigest()
            and not any(spelling in value for spelling in value_spellings()))


def redact(text, address):
    """The Mac's LAN address out of a record (it says where this Mac sits)."""
    return str(text).replace(address, '<mac-address>') if address else str(text)


def judge(observed):
    seen = observed.get('placeholder') or {}
    credentials = observed.get('guest_credentials') or []
    entry = next((c for c in credentials if isinstance(c, dict) and c.get('id') == 'test'), {})
    facts = {
        'run_exit_zero': observed.get('run_exit') == 0,
        'header_injected': observed.get('header') == SECRET.decode(),
        'child_saw_a_placeholder': placeholder_facts(seen, observed.get('guest_attempt_id')),
        'guest_credential_vault_never_staged': entry.get('mode') == 'vault' and entry.get('never_staged') is True,
        'receipt_bound_to_this_attempt': observed.get('receipt_bound') is True,
        'guest_network_proxy': observed.get('guest_network_mode') == 'proxy',
        'settled_exit_zero_tree_empty': (observed.get('phase') == 'settled' and observed.get('exit') == 0
                                         and observed.get('tree_empty') is True),
        'no_value_in_any_export': observed.get('leaks') == [] and observed.get('files_scanned', 0) > 0,
        'no_value_in_client_output': observed.get('client_output_leak') is False,
        'guest_disk_scanned_clean': observed.get('disk_scan') == 'clean' and observed.get('sync_exit') == 0,
        'sync_on_the_vault_attempts_boot': observed.get('same_boot') is True,
    }
    return facts, 'PASS' if all(facts.values()) else 'FAIL'


def agent_attempt(data, profile='agent'):
    """The first attempt of `profile`: the vaulted one is `agent`, the sync on the same boot `tool`."""
    for attempt in sorted((Path(data) / 'attempts').glob('att_*'), key=lambda p: p.stat().st_mtime):
        try:
            record = json.loads((attempt / 'jail.json').read_text())
        except (OSError, ValueError):
            continue
        if (record.get('policy') or {}).get('name') == profile:
            return attempt, record
    return None, None


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return {}


def boot_disk(data):
    """The vault attempt's own boot disk, when the sync attempt ran on that boot.

    (disk path or None, same_boot): both attempts' transport records name
    one serve boot and both bindings one guest kernel boot.
    """
    vault, _ = agent_attempt(data, 'agent')
    sync, _ = agent_attempt(data, 'tool')
    if vault is None or sync is None:
        return None, False
    serve = [read_json(path / 'vm-transport.json').get('boot_id') for path in (vault, sync)]
    guest = [read_json(path / 'evidence' / 'vm-binding.json').get('guest_boot_id') for path in (vault, sync)]
    same = bool(serve[0]) and serve[0] == serve[1] and bool(guest[0]) and guest[0] == guest[1]
    disk = Path(data) / 'vm' / str(serve[0]) / 'image' / 'base.raw'
    return (disk if same and disk.is_file() else None), same


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('home', type=Path)
    parser.add_argument('workspace', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--ukai-jail', help='the ukai-jail under test (default: $UKAI_JAIL_BINARY)')
    args = parser.parse_args(argv)
    jail = harness.required_binary('UKAI_JAIL_BINARY', args.ukai_jail)
    home = args.home.resolve(strict=True)
    workspace = harness.guarded_workspace(args.workspace)
    out = harness.fresh_out_dir(args.out)
    harness.clean_workspace(workspace)

    address = mac_address()
    server = http.server.HTTPServer(('0.0.0.0', 0), Echo)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    config = Path(tempfile.mkdtemp(prefix='vault-cfg-'))
    os.chmod(config, 0o700)
    (config / 'launch').mkdir(mode=0o700)
    source_dir = Path(tempfile.mkdtemp(prefix='vault-src-')).resolve()
    source = source_dir / 'token'
    source.write_bytes(SECRET)
    os.chmod(source, 0o600)
    (config / 'launch' / 'vault-test.toml').write_text(f'''# measurement-only vault profile
name = "vault-test"
jail = "agent"

[credentials.test]
mode = "vault"
source = "{source}"
hosts = ["http://{address}:{port}"]
allow_plaintext = true
header = {{ name = "x-test-token" }}

[network]
allow = ["{address}:{port}"]
''')
    os.chmod(config / 'launch' / 'vault-test.toml', 0o600)

    data = Path(tempfile.mkdtemp(prefix='vault-run-'))
    env = harness.vm_client_environment(UKAI_VM_HOME=home, UKAI_DATA_DIR=data, UKAI_CONFIG_DIR=config)
    observed = {}
    disk_paths = []
    started = time.monotonic()
    try:
        try:
            run = subprocess.run([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'agent',
                                  '--launch', 'vault-test', *harness.vm_wall(40),
                                  '--workspace', str(workspace), '--', '/bin/sh', '-c',
                                  fetch_script(address, port)],
                                 env=env, capture_output=True, text=True, timeout=900)
            observed.update(run_exit=run.returncode, stdout=run.stdout, stderr=run.stderr)
        except subprocess.TimeoutExpired as error:
            observed.update(run_exit=None, stdout=str(error.stdout or ''), stderr='timeout')
        observed['elapsed_s'] = round(time.monotonic() - started, 1)
        server.shutdown()
        server.server_close()
        # The same boot: flush the guest's caches, then read its disk image.
        sync = subprocess.run([str(jail), 'run', '--vm', '--terminal', 'detach', '--profile', 'tool',
                               *harness.vm_wall(20), '--workspace', str(workspace), '--', '/bin/sync'],
                              env=env, capture_output=True, text=True, timeout=300)
        observed['sync_exit'] = sync.returncode
        observed['sync_stderr'] = sync.stderr[-600:]
        disk, observed['same_boot'] = boot_disk(data)
        if disk is not None:
            observed['disk_scan'] = 'value-present' if file_holds(disk, SECRET) else 'clean'
            observed['disk_scanned'] = str(disk.relative_to(data))
        else:
            observed['disk_scan'] = 'not-checked: no disk of the vault attempt\'s boot'
        disk_paths = sorted((data / 'vm').glob('vm-*/image/base.raw'))
    finally:
        # The value's source goes first: a stop that raises or hangs must
        # never leave it behind.
        try:
            source.unlink(missing_ok=True)
            source_dir.rmdir()
        finally:
            try:
                stop = subprocess.run([str(home / 'bin' / 'ukai-vm'), 'stop'], env=env,
                                      capture_output=True, text=True, timeout=60)
                observed['stop_exit'] = stop.returncode
            except (OSError, subprocess.SubprocessError) as error:
                observed['stop_exit'] = None
                observed['stop_error'] = f'{type(error).__name__}: {error}'
    vault_attempt, record = agent_attempt(data)
    if vault_attempt is not None:
        observed['receipt_bound'] = harness.attempt_dir_bound(vault_attempt,
                                                              ['/bin/sh', '-c', fetch_script(address, port)])
        guest_path = vault_attempt / 'evidence/jail.json'
        guest = json.loads(guest_path.read_text()) if guest_path.exists() else {}
        observed.update(phase=record.get('phase'), exit=(record.get('outcome') or {}).get('code'),
                        tree_empty=(record.get('lifetime') or {}).get('tree_empty'),
                        guest_credentials=guest.get('credentials'), guest_attempt_id=guest.get('attempt_id'),
                        guest_network_mode=((guest.get('applied') or {}).get('network') or {}).get('mode'))
    observed['leaks'], observed['files_scanned'] = leak_scan([data, workspace], SECRET, skip=disk_paths)
    output = observed.get('stdout', '') + observed.get('stderr', '')
    observed['client_output_leak'] = any(spelling in output for spelling in value_spellings())
    observed['placeholder'] = placeholder(observed.get('stdout', ''))
    observed['header'] = Echo.received[0].get('x-test-token') if Echo.received else None
    facts, outcome = judge(observed)
    observed['refusals'] = harness.vm_refusals(observed.get('stderr', '') + '\n' + observed.get('sync_stderr', ''))
    if observed['refusals']:
        outcome = 'REFUSED'  # recorded as what it is, never a pass
    verdict = {'schema': 'ukai.vm.vault-consumption/2', 'binary': harness.fingerprint(jail),
               'echo_requests': len(Echo.received),
               'received_header_names': sorted(Echo.received[0]) if Echo.received else [],
               'facts': facts, 'outcome': outcome,
               'observed': {key: (redact(value, address) if key in ('stdout', 'stderr') else value)
                            for key, value in observed.items() if key != 'header'},
               'header_matches_value': facts['header_injected']}
    harness.write_json(out / 'vault-consumption.json', json.loads(redact(json.dumps(verdict), address)))
    print(json.dumps({'facts': facts, 'outcome': outcome}))
    return 0 if outcome == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
