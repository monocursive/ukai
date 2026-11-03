#!/usr/bin/env python3
"""The K109/K111/K112/K113 rows against an INSTALLED ukai-vm package.

K108 (warm reuse) and K110 (fault matrix) run through their own harnesses
(warm_live.py, fault_matrix.py) against the same install; this one covers
the rows that need the CLI or the row's own probes:

  K109  one warm boot on the installed service: a granted write reaches the
        host with its exact bytes, while writes outside the grants (the
        protected .git) and outside the share (/etc, /usr/local/bin, the
        guest's root) are refused and absent;
  K111  one attempt through `ukai-jail run --vm` (the client boots the
        installed service itself): the stored receipt is the guest's Linux
        receipt whose digest the transport record carries, the binding ties
        it to this host attempt, and the summary's transport line carries
        only values lifted from that record;
  K112  the kernel-bound key refuses in every lane: native (as shipped and
        dev-enabled) and this build's installed --vm backend, all with
        `unsupported`, all before any process or boot;
  K113  the summary-naming mechanism those rows rest on, recorded for what
        it is: no VM compatibility record exists yet, so the row itself
        cannot pass — only the mechanism is verified.

Usage: gate_rows.py <installed-root> <workspace> <out> <ukai-jail>
"""
import base64
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fault_matrix import Service, frame, send  # noqa: E402

GUEST_SENTINEL = '[core]\n'


def sh(script):
    return [base64.b64encode(b'/bin/sh').decode(),
            base64.b64encode(b'-c').decode(),
            base64.b64encode(script.encode()).decode()]


def run_attempt(service, name, script, wall=20):
    stream = service.sock()
    ready = frame(stream)
    assert ready['event'] == 'ready', ready
    send(stream, op='prepare', attempt_id=f'row-{name}', profile='tool',
         wall_seconds=wall, argv=sh(script), secrets=[])
    prepared = frame(stream)
    assert prepared['event'] == 'prepared', prepared
    send(stream, op='run')
    stdout = []
    exit_code = None
    while True:
        message = frame(stream)
        event = message['event']
        if event in ('stdout', 'stderr'):
            stdout.append(base64.b64decode(message['data']).decode())
        elif event == 'done':
            exit_code = message['exit_code']
            break
        elif event == 'error':
            exit_code = None
            stdout.append(f"guest error: {message.get('message')}")
            break
    stream.close()
    return {'exit': exit_code, 'stdout': ''.join(stdout)}


def row_k109(home, workspace):
    """Granted writes reach the host; writes outside grants and share don't."""
    git_config = workspace / '.git' / 'config'
    git_config.parent.mkdir(exist_ok=True)
    git_config.write_text(GUEST_SENTINEL)
    for stale in workspace.iterdir():
        if stale.name != '.git':
            shutil.rmtree(stale) if stale.is_dir() else stale.unlink()
    with Service(home, workspace, tempfile.mkdtemp(prefix='row-k109-')) as service:
        granted = run_attempt(
            service, 'granted',
            'printf "granted-bytes\\n" > k109-granted.txt && echo WROTE; '
            'echo forged > .git/config 2>/dev/null && echo GIT_WRITE_ALLOWED '
            '|| echo git_write_refused')
        outside = run_attempt(
            service, 'outside',
            'echo x > /etc/ukai-k109-probe 2>/dev/null && echo ETC_WRITE_ALLOWED '
            '|| echo etc_write_refused; '
            'echo x > /usr/local/bin/ukai-k109-probe 2>/dev/null && echo USR_WRITE_ALLOWED '
            '|| echo usr_write_refused; '
            'echo x > /ukai-k109-root-probe 2>/dev/null && echo ROOT_WRITE_ALLOWED '
            '|| echo root_write_refused')
    on_host = workspace / 'k109-granted.txt'
    row = {
        'granted_write_on_host': on_host.is_file()
        and on_host.read_text() == 'granted-bytes\n',
        'granted_exit': granted['exit'],
        'git_write_refused': 'git_write_refused' in granted['stdout'],
        'git_config_unchanged': git_config.read_text() == GUEST_SENTINEL,
        'etc_write_refused': 'etc_write_refused' in outside['stdout'],
        'usr_write_refused': 'usr_write_refused' in outside['stdout'],
        'root_write_refused': 'root_write_refused' in outside['stdout'],
        'outside_exit': outside['exit'],
        'workspace_listing': sorted(p.name for p in workspace.iterdir()),
    }
    row['outcome'] = 'PASS' if (
        row['granted_write_on_host'] and row['granted_exit'] == 0
        and row['git_write_refused'] and row['git_config_unchanged']
        and row['etc_write_refused'] and row['usr_write_refused']
        and row['root_write_refused']) else 'FAIL'
    return row


def cli_environment(home, data, config=None):
    environment = dict(os.environ)
    environment['PATH'] = f'{home}/bin:/usr/bin:/bin'
    environment['UKAI_VM_HOME'] = str(home)
    environment['UKAI_DATA_DIR'] = str(data)
    if config is not None:
        environment['UKAI_CONFIG_DIR'] = str(config)
    return environment


def row_k111(home, workspace, jail, out):
    """One `run --vm` attempt: receipt digest, binding, transport line."""
    for stale in workspace.iterdir():
        shutil.rmtree(stale) if stale.is_dir() else stale.unlink()
    data = Path(tempfile.mkdtemp(prefix='row-k111-'))
    config = Path(tempfile.mkdtemp(prefix='row-k111-cfg-'))
    os.chmod(config, 0o700)
    started = time.monotonic()
    # script(1) gives the supervisor a real terminal, the only condition
    # under which the summary and its transport line print.
    run = subprocess.run(
        ['script', '-q', '/dev/null', str(jail), 'run', '--vm',
         '--terminal', 'detach', '--profile', 'tool', '--limit', 'wall=20s',
         '--workspace', str(workspace), '--',
         '/bin/sh', '-c', 'printf "row-k111\\n" > k111.txt; echo row-k111-done'],
        env=cli_environment(home, data, config), capture_output=True,
        text=True, timeout=420)
    elapsed = time.monotonic() - started
    # The client leaves the warm service up; stop it through the same
    # install before reading the evidence.
    subprocess.run([str(home / 'bin/ukai-vm'), 'stop'],
                   env=cli_environment(home, data, config),
                   capture_output=True, text=True, timeout=60)
    terminal = run.stdout + run.stderr
    attempts = sorted((data / 'attempts').glob('att_*'),
                      key=lambda p: p.stat().st_mtime)
    record_row = {'run_exit': run.returncode, 'elapsed_s': round(elapsed, 1)}
    if not attempts:
        record_row['outcome'] = 'FAIL'
        record_row['stderr'] = run.stderr[-500:]
        return record_row
    attempt = attempts[-1]
    shutil.copytree(attempt, out / 'k111-attempt', dirs_exist_ok=True)
    guest_path = attempt / 'evidence/jail.json'
    binding_path = attempt / 'evidence/vm-binding.json'
    transport_path = attempt / 'vm-transport.json'
    guest_receipt = json.loads(guest_path.read_text()) if guest_path.exists() else {}
    binding = json.loads(binding_path.read_text()) if binding_path.exists() else {}
    transport = json.loads(transport_path.read_text()) if transport_path.exists() else {}
    guest_digest = (hashlib.sha256(guest_path.read_bytes()).hexdigest()
                    if guest_path.exists() else None)
    stored = json.loads((attempt / 'jail.json').read_text())
    line = re.search(
        r'vm: guest-reported facts in evidence/jail\.json · boot (\S+) '
        r'· image ([0-9a-f]+) · vsock (\d+) · receipt sha256:([0-9a-f]+)',
        terminal)
    record_row.update({
        'phase': stored.get('phase'),
        'exit': stored.get('outcome', {}).get('code'),
        'tree_empty': stored.get('lifetime', {}).get('tree_empty'),
        'granted_write_on_host': (workspace / 'k111.txt').is_file(),
        'guest_receipt_is_linux':
            guest_receipt.get('platform', {}).get('os') == 'linux',
        'digest_matches_record': bool(
            transport.get('guest_receipt_sha256')
            and guest_digest == transport['guest_receipt_sha256']),
        'binding_attempt': binding.get('attempt_id'),
        'attempt_id': attempt.name,
        'binding_matches_attempt': binding.get('attempt_id') == attempt.name,
        'binding_profile': binding.get('profile'),
        'transport_schema': transport.get('schema'),
        'guest_boot_bound': bool(
            binding.get('boot_id') and transport.get('boot_id')
            and binding['boot_id'] == transport['boot_id']),
    })
    if line:
        record_row['transport_line_values_from_record'] = (
            line.group(1) == transport.get('boot_id')
            and line.group(2) == (transport.get('image', {}).get('disk_sha256', ''))[:16]
            and int(line.group(3)) == transport.get('vsock_port')
            and line.group(4) == (transport.get('guest_receipt_sha256', ''))[:16])
    else:
        record_row['transport_line_values_from_record'] = False
        record_row['terminal_tail'] = terminal[-400:]
    record_row['outcome'] = 'PASS' if (
        record_row['phase'] == 'settled'
        and record_row['exit'] == 0
        and record_row['tree_empty'] is True
        and record_row['granted_write_on_host']
        and record_row['guest_receipt_is_linux']
        and record_row['digest_matches_record']
        and record_row['binding_matches_attempt']
        and record_row['binding_profile'] == 'tool'
        and record_row['guest_boot_bound']
        and record_row['transport_line_values_from_record']) else 'FAIL'
    return record_row


def kernel_bound_run(jail, environment, workspace, extra=()):
    data = Path(tempfile.mkdtemp(prefix='row-k112-'))
    config = Path(tempfile.mkdtemp(prefix='row-k112-cfg-'))
    os.chmod(config, 0o700)
    # A real HOME and a private config dir: the state-path checks refuse a
    # homeless run for reasons that have nothing to do with this row.
    environment = dict(environment, HOME=os.environ['HOME'],
                       UKAI_DATA_DIR=str(data), UKAI_CONFIG_DIR=str(config))
    command = [str(jail), 'run', *extra, '--lifetime', 'kernel-bound',
               '--terminal', 'detach', '--workspace', str(workspace),
               '--', '/bin/sh', '-c', 'touch k112-workload-ran']
    started = time.monotonic()
    run = subprocess.run(command, env=environment, capture_output=True,
                         text=True, timeout=300)
    receipt = None
    for jail_json in sorted((data / 'attempts').glob('att_*/jail.json'),
                            key=lambda p: p.stat().st_mtime, reverse=True):
        receipt = json.loads(jail_json.read_text())
        policy = json.loads((jail_json.parent / 'policy.json').read_text())
        receipt['_lifetime_boundary'] = (
            policy.get('snapshot', {}).get('lifetime_boundary'))
        break
    return {
        'exit': run.returncode,
        'elapsed_s': round(time.monotonic() - started, 1),
        'stderr': run.stderr.strip()[-300:],
        'phase': receipt.get('phase') if receipt else None,
        'requirements_name_owner_loss': bool(
            receipt and 'owner_loss_termination' in json.dumps(
                receipt.get('policy', {}).get('requirements', []))),
        'lifetime_boundary': receipt.get('_lifetime_boundary') if receipt else None,
        'workload_ran': Path('/tmp/k112-workload-ran').exists(),
        'boot_attempted': (data / 'vm').exists(),
    }


def row_k112(home, jail, workspace):
    """The kernel-bound key refuses in the native and --vm lanes."""
    Path('/tmp/k112-workload-ran').unlink(missing_ok=True)
    shipped = kernel_bound_run(jail, {'PATH': '/usr/bin:/bin'}, workspace)
    dev = kernel_bound_run(
        jail, {'PATH': '/usr/bin:/bin', 'UKAI_JAIL_MACOS_NATIVE': 'dev'},
        workspace)
    vm = kernel_bound_run(
        jail, cli_environment(home, tempfile.mkdtemp(prefix='row-k112-vm-')),
        workspace, extra=('--vm',))
    row = {'native_shipped': shipped, 'native_dev': dev, 'vm_installed': vm}
    def refused(lane):
        return (lane['exit'] == 125 and lane['phase'] == 'refused'
                and '[unsupported]' in lane['stderr']
                and not lane['workload_ran'])
    row['native_shipped_refused'] = refused(shipped)
    row['native_dev_refused'] = refused(dev)
    row['vm_refused'] = refused(vm) and not vm['boot_attempted']
    row['linux_none_refusal'] = 'ukai-jail/tests/vm_tier.rs::the_kernel_bound_key_is_a_narrowing_none_refuses (portable)'
    row['outcome'] = 'PASS' if (row['native_shipped_refused']
                                and row['native_dev_refused']
                                and row['vm_refused']) else 'FAIL'
    return row


def row_k113(k111_row):
    """The naming mechanism; the row itself needs a VM compatibility record."""
    row = {
        'mechanism_transport_line_verified':
            k111_row.get('transport_line_values_from_record') is True,
        'native_custody_line': (
            'summary.rs renders "verified · native custody, not kernel-bound" '
            'for native receipts (unit-covered); the native tier refuses '
            'every policy in this build, so no native record exists either'),
        'vm_compatibility_record_exists': False,
        'note': ('No VM-tier agent compatibility record exists (J18 §9.4 '
                 'names Claude Code headless in the guest as the record that '
                 'would carry it), so the K113 row cannot pass; this row '
                 'records only that the summary mechanism it will rest on is '
                 'verified live: the transport line carries values lifted '
                 'from vm-transport.json.'),
    }
    row['outcome'] = 'NOT_RUN_NO_COMPATIBILITY_RECORD'
    return row


def main():
    home = Path(sys.argv[1]).resolve()
    workspace = Path(sys.argv[2]).resolve(strict=True)
    out = Path(sys.argv[3]).resolve()
    jail = Path(sys.argv[4]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rows = {}
    rows['K109'] = row_k109(home, workspace)
    (out / 'k109.json').write_text(json.dumps(rows['K109'], indent=2) + '\n')
    rows['K111'] = row_k111(home, workspace, jail, out)
    (out / 'k111.json').write_text(json.dumps(rows['K111'], indent=2) + '\n')
    rows['K112'] = row_k112(home, jail, workspace)
    (out / 'k112.json').write_text(json.dumps(rows['K112'], indent=2) + '\n')
    rows['K113'] = row_k113(rows['K111'])
    (out / 'k113.json').write_text(json.dumps(rows['K113'], indent=2) + '\n')
    summary = {name: row.get('outcome') for name, row in rows.items()}
    (out / 'rows.json').write_text(json.dumps(rows, indent=2) + '\n')
    print(json.dumps(summary))
    return 0


if __name__ == '__main__':
    sys.exit(main())
