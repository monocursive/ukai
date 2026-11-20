#!/usr/bin/env python3
"""Run K27 inside a fresh VM; retain refusal evidence instead of claiming success.

The VM runner provisions distribution prerequisites before this timed workflow.
No operator source, Rust toolchain, or production signing key is used. Since
OpenCode's free tier refuses its own CLI (2026-10-18), the runner may copy one
provider API key into this disposable guest: it is stored with `ukai-jail
credential set`, the copy is deleted, and the agent reaches it only through
the vault, as a placeholder (`--credential-file`).
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tarfile
import time
import tomllib

if not __debug__:
    raise SystemExit('onboarding_guest.py must not run with python -O: its assert statements are its checks')


PROFILES = ['codex', 'claude', 'opencode', 'cursor', 'aider', 'goose', 'gemini',
            'amp', 'cline', 'copilot', 'kilo', 'auggie', 'droid', 'pi']
OPENCODE_ARTIFACTS = {
    'x86_64-unknown-linux-gnu': ('opencode-linux-x64-baseline.tar.gz',
                                 '763af386ef88a8cab18df00fcf055690e5a55e31a7088beabe02307142a6adce'),
    'aarch64-unknown-linux-gnu': ('opencode-linux-arm64.tar.gz',
                                  '568461b7d4d8c19865c97e9a1102e613049c6039d01fe772154de873c1865840'),
}
# The operator profile a provider key runs under: the bundled `opencode`
# profile's hosts plus the provider's, with the key vaulted for that provider
# only. It lives in this guest's config directory and dies with the VM.
VAULT_PROFILE = '''\
# Written by onboarding_guest.py for one disposable VM (K11/K27 with a key).
name = "opencode-vault"
jail = "agent"
home_is_state = true
state_subdirs = ["config/opencode", "data/opencode", "cache/opencode", "state/opencode"]

[environment]
OPENCODE_DISABLE_AUTOUPDATE = "true"
XDG_CONFIG_HOME = { state = "config" }
XDG_DATA_HOME = { state = "data" }
XDG_CACHE_HOME = { state = "cache" }
XDG_STATE_HOME = { state = "state" }

[credentials.anthropic]
mode = "vault"
source = "@config/credentials/anthropic"
env = "ANTHROPIC_API_KEY"
hosts = ["https://api.anthropic.com"]
header = { name = "x-api-key" }

[network]
allow = ["api.anthropic.com", "opencode.ai", "models.opencode.ai", "registry.npmjs.org"]
'''


def verify_build(version, revision, inputs=None, target='x86_64-unknown-linux-gnu'):
    build = version['build']
    if (build['revision'] != revision or build['dirty'] is not False
            or target not in OPENCODE_ARTIFACTS or build['target'] != target
            or build['opt_level'] != '3' or build['debug_assertions'] is not False):
        raise ValueError(f'Expected the named clean optimized {target} build.')
    if inputs is not None and build['inputs'] != inputs:
        raise ValueError('The artifact does not match the expected Jail source inputs.')


def credential_identity(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns'))


def store_credential(binary, path, env):
    """Remove only the exact owned staging file, including command timeout."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as key:
        info = os.fstat(key.fileno())
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid()):
            raise RuntimeError('credential staging file must be owned, regular and private')
        expected = credential_identity(info)
        if credential_identity(path.lstat()) != expected:
            raise RuntimeError('credential staging file identity changed')
        try:
            return subprocess.run([str(binary), 'credential', 'set', 'anthropic'],
                                  env=env, stdin=key, capture_output=True, timeout=60)
        finally:
            if (credential_identity(os.fstat(key.fileno())) != expected
                    or credential_identity(path.lstat()) != expected):
                raise RuntimeError('credential staging file changed; substituted path retained')
            path.unlink()


class Workflow:
    """Record each command's own attempts before evaluating its outcome."""

    def __init__(self, binary, out, env, result, save, *, vendor_attempts=2):
        if type(vendor_attempts) is not int or vendor_attempts not in (1, 2):
            raise ValueError('vendor_attempts must be 1 or 2')
        self.binary, self.out, self.env = binary, out, env
        self.result, self.save = result, save
        self.data = pathlib.Path(env['UKAI_DATA_DIR'])
        self.attempts = {}
        self.vendor_attempts = vendor_attempts

    def attempt_dirs(self):
        root = self.data / 'attempts'
        return {path.name: path for path in root.iterdir()
                if path.is_dir() and not path.is_symlink()} if root.is_dir() else {}

    def vendor_logs(self):
        logs = {}
        # Only diagnostic files: never copy vendor databases, credentials or
        # arbitrary state. Do not follow a vendor-created symlink outside it.
        for root in (self.data / 'state', self.data / 'attempts'):
            if root.is_symlink():
                continue
            for directory, children, files in os.walk(root, followlinks=False):
                children[:] = [name for name in children
                               if not (pathlib.Path(directory) / name).is_symlink()]
                relative = pathlib.Path(directory).relative_to(self.data)
                if 'opencode' not in relative.parts or not {'log', 'logs'}.intersection(relative.parts):
                    continue
                for name in files:
                    path = pathlib.Path(directory) / name
                    if path.is_file() and not path.is_symlink():
                        stat = path.stat()
                        logs[path] = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
        return logs

    def collect(self, name, before, logs_before, row):
        current = self.attempt_dirs()
        new = [current[key] for key in sorted(current.keys() - before.keys())]
        self.attempts[name] = new
        row['attempt_ids'] = [path.name for path in new]
        row['artifacts'] = [f'{name}.stdout', f'{name}.stderr']
        for attempt in new:
            destination = self.out / f'{name}-attempts' / attempt.name
            destination.mkdir(parents=True)
            for filename in ('jail.json', 'trace.ndjson', 'policy.json'):
                source = attempt / filename
                if source.is_file() and not source.is_symlink():
                    shutil.copyfile(source, destination / filename)
                    if len(new) == 1:
                        # Keep the existing names used by receipt consumers,
                        # but never guess between multiple/new-zero attempts.
                        output = f'{name}-{filename}'
                        shutil.copyfile(source, self.out / output)
                        row['artifacts'].append(output)
        if new:
            row['artifacts'].append(f'{name}-attempts')
        changed = []
        for path, identity in self.vendor_logs().items():
            if logs_before.get(path) == identity:
                continue
            relative = path.relative_to(self.data)
            destination = self.out / f'{name}-vendor-logs' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            changed.append(str(relative))
        row['new_or_changed_vendor_logs'] = changed
        if changed:
            row['artifacts'].append(f'{name}-vendor-logs')

    def run(self, name, argv, *, check=True, timeout=300, cwd=None):
        started = time.monotonic()
        jailed = len(argv) > 1 and str(argv[0]) == str(self.binary) and argv[1] in ('run', 'learn')
        before = self.attempt_dirs() if jailed else {}
        logs_before = self.vendor_logs() if jailed else {}
        error = None
        try:
            done = subprocess.run([str(a) for a in argv], env=self.env, stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=timeout, cwd=cwd)
        except subprocess.TimeoutExpired as failure:
            error = failure
            done = subprocess.CompletedProcess(argv, None, failure.stdout or b'', failure.stderr or b'')
        except OSError as failure:
            error = failure
            done = subprocess.CompletedProcess(argv, None, b'', str(failure).encode())
        (self.out / f'{name}.stdout').write_bytes(done.stdout)
        (self.out / f'{name}.stderr').write_bytes(done.stderr)
        row = {'name': name, 'argv': [str(a) for a in argv],
               'seconds': time.monotonic() - started, 'exit': done.returncode}
        if error is not None:
            row['execution_error'] = str(error)
        self.result['rows'].append(row)
        if jailed:
            try:
                self.collect(name, before, logs_before, row)
            except (OSError, ValueError) as failure:
                row['evidence_error'] = str(failure)
                self.save()
                raise
        self.save()
        if error is not None:
            raise error
        if check and done.returncode:
            raise RuntimeError(f'{name} refused with exit {done.returncode}; see {name}.stderr')
        return done

    def receipt(self, name):
        attempts = self.attempts.get(name, [])
        assert len(attempts) == 1, f'{name} created {len(attempts)} attempts; cannot identify its receipt'
        data = json.loads((self.out / f'{name}-jail.json').read_text())
        assert data['phase'] == 'settled', data['phase']
        assert data['containment'] == 'enforced', data['containment']
        assert data['exec_observed'] is True
        assert data['lifetime']['tree_empty'] is True
        assert data['lifetime']['integrity'] == 'verified'
        assert data['outcome']['kind'] == 'exited' and data['outcome']['code'] == 0
        assert data['state_cleanup'] == 'complete'
        return data

    def vendor(self, name, argv, outputs):
        # The default preserves one Bad Request retry; 1 disables it. This
        # bounds CLI launches, not the vendor's internal API requests or cost.
        for attempt in range(self.vendor_attempts):
            before = len(self.result['rows'])
            try:
                done = self.run(name, argv, check=False, timeout=330)
            finally:
                if len(self.result['rows']) > before:
                    row = self.result['rows'][-1]
                    row['vendor_attempt'] = attempt + 1
                    row['vendor_attempt_limit'] = self.vendor_attempts
                    self.save()
            if done.returncode == 0:
                return done
            for path in outputs:
                if path.is_file() and not path.is_symlink():
                    destination = f'{name}-failed-output-{path.name}'
                    shutil.copyfile(path, self.out / destination)
                    row['artifacts'].append(destination)
            self.save()
            if (attempt + 1 >= self.vendor_attempts or b'Bad Request:' not in done.stderr
                    or b'ukai-jail: error' in done.stderr):
                raise RuntimeError(f'{name} failed with exit {done.returncode}; see {name}.stderr')
            label = name + '-provider-failure'
            row['name'] = label
            renamed = []
            for artifact in row['artifacts']:
                destination = label + artifact[len(name):]
                (self.out / artifact).rename(self.out / destination)
                renamed.append(destination)
            row['artifacts'] = renamed
            self.attempts[label] = self.attempts.pop(name)
            for path in outputs:
                if path.exists():
                    path.unlink()
            self.result.setdefault('provider_retries', []).append(label)
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=pathlib.Path, required=True)
    parser.add_argument('--installer', type=pathlib.Path, required=True)
    parser.add_argument('--public-key', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--target', choices=OPENCODE_ARTIFACTS, default='x86_64-unknown-linux-gnu')
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--only', choices=['install', 'onboarding', 'learning'],
                       help='Run just this check in a fresh guest. The default runs both vendor checks.')
    scope.add_argument('--install-only', dest='only', action='store_const', const='install',
                       help=argparse.SUPPRESS)
    parser.add_argument('--inputs', help='Expected Jail build-input SHA256, independently verified.')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--credential-file', type=pathlib.Path,
                        help='An Anthropic API key the runner copied in; deleted once stored.')
    parser.add_argument('--model', default='opencode/big-pickle')
    parser.add_argument('--vendor-attempts', type=int, choices=[1, 2], default=2,
                        help='Maximum CLI invocations per workload; not an API or billing cap.')
    args = parser.parse_args()
    if args.only == 'install' and args.credential_file is not None:
        parser.error('--install-only does not use provider credentials')
    os.umask(0o077)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    home = pathlib.Path.home()
    binary = home / '.local/bin/ukai-jail'
    env = {'HOME': str(home), 'PATH': os.environ['PATH'],
           'UKAI_CONFIG_DIR': str(home / 'ouro-config'),
           'UKAI_DATA_DIR': str(home / 'ouro-data'),
           'XDG_RUNTIME_DIR': os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')}
    result = {'schema': 'ouro.jail.onboarding/1', 'status': 'blocked',
              'expected_revision': args.revision, 'rows': [], 'only': args.only,
              'expected_inputs': args.inputs,
              'vendor_attempts': args.vendor_attempts,
              'max_vendor_invocations': {None: 2, 'install': 0, 'learning': 1, 'onboarding': 1}[args.only] * args.vendor_attempts,
              'timer_scope': 'signed install through first sandboxed OpenCode result; '
                             'includes agent download, excludes VM/dependency bootstrap',
              'publication': 'deferred', 'signing_identity': 'ephemeral test key'}
    workflow_start = None

    def save():
        (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')

    workflow = Workflow(binary, out, env, result, save, vendor_attempts=args.vendor_attempts)
    run, receipt, vendor = workflow.run, workflow.receipt, workflow.vendor

    def distribution_checks():
        result['distribution_checks'] = 'started'
        original = result['binary_sha256']
        bad = home / 'corrupt-artifacts'
        shutil.copytree(args.artifacts, bad)
        archives = list(args.artifacts.glob(f'ukai-jail-*-{args.target}.tar.gz'))
        assert len(archives) == 1, 'expected exactly one versioned native archive'
        archive_name = archives[0].name
        with (bad / archive_name).open('ab') as file:
            file.write(b'CORRUPT-TEST-FIXTURE')
        corrupt = run('corrupt-archive', ['sh', args.installer, '--from-dir', bad,
                       '--public-key', args.public_key, '--upgrade'], check=False)
        assert corrupt.returncode != 0 and b'Checksum verification failed' in corrupt.stderr
        assert hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest() == original
        shutil.copyfile(args.artifacts / archive_name, bad / archive_name)
        (bad / 'SHA256SUMS.minisig').write_text('invalid signature fixture\n')
        signature = run('corrupt-signature', ['sh', args.installer, '--from-dir', bad,
                         '--public-key', args.public_key, '--upgrade'], check=False)
        assert signature.returncode != 0 and b'signature verification failed' in signature.stderr
        assert hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest() == original
        run('upgrade', ['sh', args.installer, '--from-dir', args.artifacts,
                       '--public-key', args.public_key, '--upgrade'])
        result['distribution_checks'] = 'passed'

    save()
    try:
        assert os.getuid() != 0, 'The user workflow must run unprivileged.'
        assert not any(os.isatty(fd) for fd in [0, 1, 2]), 'Run through SSH -T with no TTY.'
        rust = {name: shutil.which(name) for name in ['cargo', 'rustc', 'rustup']}
        result['rust_before'] = rust
        assert not any(rust.values()) and not (home / '.rustup').exists()
        assert not binary.exists(), 'A fresh VM must not have ukai-jail installed.'
        assert not (home / '.opencode').exists(), 'A fresh VM must not have OpenCode installed.'
        result['guest_machine'] = os.uname().machine
        assert args.target == result['guest_machine'] + '-unknown-linux-gnu' and os.uname().sysname == 'Linux'
        run('host', ['sh', '-c', 'uname -a; cat /etc/os-release; '
                    'systemd-detect-virt; id; getconf GNU_LIBC_VERSION; '
                    'bwrap --version; minisign -v; '
                    'cat /proc/sys/kernel/yama/ptrace_scope; '
                    'cat /proc/sys/user/max_user_namespaces; '
                    'cat /proc/sys/kernel/unprivileged_userns_clone; '
                    'cat /proc/self/cgroup; cat /etc/machine-id; '
                    'cat /proc/sys/kernel/random/boot_id'], check=False)
        vm = run('virtualization', ['systemd-detect-virt']).stdout.decode().strip()
        assert vm in ['qemu', 'kvm'], f'Expected a genuine QEMU VM, received {vm!r}.'
        for program in ['bwrap', 'minisign', 'shasum', 'curl', 'git', 'rg']:
            assert shutil.which(program), f'Missing pre-provisioned prerequisite: {program}'
        workflow_start = time.monotonic()
        run('install', ['sh', args.installer, '--from-dir', args.artifacts,
                        '--public-key', args.public_key, '--yes'])
        version = json.loads(run('version', [binary, 'version', '--json']).stdout)
        result['build'] = version
        verify_build(version, args.revision, args.inputs, args.target)
        result['binary_sha256'] = hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()
        workspace = home / 'onboarding-project'
        workspace.mkdir()
        run('git-init', ['git', 'init', '-q', workspace])
        run('true', [binary, 'run', '--workspace', workspace, '--', '/usr/bin/true'])
        receipt('true')
        agent_dir = home / '.opencode/bin'
        agent_dir.mkdir(parents=True)
        archive = home / 'opencode.tar.gz'
        filename, expected_hash = OPENCODE_ARTIFACTS[args.target]
        agent_url = 'https://github.com/anomalyco/opencode/releases/download/v1.18.32/' + filename
        run('opencode-download', ['curl', '--fail', '--silent', '--show-error', '--location',
                                 '--proto', '=https', '--proto-redir', '=https', agent_url,
                                 '-o', archive])
        digest = hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest()
        result['agent_artifact'] = {'url': agent_url, 'sha256': digest}
        assert digest == expected_hash, 'OpenCode artifact checksum mismatch.'
        with tarfile.open(archive) as tar:
            member = next(item for item in tar.getmembers() if pathlib.PurePosixPath(item.name).name == 'opencode')
            assert member.isfile(), 'Agent archive member is not a regular file.'
            with (agent_dir / 'opencode').open('wb') as target:
                shutil.copyfileobj(tar.extractfile(member), target)
        agent = agent_dir / 'opencode'
        agent.chmod(0o755)
        result['vendor_version'] = run('opencode-version', [agent, '--version']).stdout.decode().strip()
        assert result['vendor_version'] == '1.18.32'
        run('ripgrep-version', ['rg', '--version'])
        if args.only == 'install':
            distribution_checks()
            result['status'] = 'install-only-passed'
            return 0
        launch = 'opencode'
        if args.credential_file is not None:
            # Store the provider key the way an operator does, then remove the
            # copy the runner placed here: from now on only the jail's config
            # directory holds it, and the agent sees a placeholder.
            started = time.monotonic()
            store_error = None
            try:
                stored = store_credential(binary, args.credential_file, env)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                store_error = error
                stored = subprocess.CompletedProcess([], None,
                         getattr(error, 'stdout', None) or b'', getattr(error, 'stderr', None) or b'')
            (out / 'credential-set.stdout').write_bytes(stored.stdout)
            (out / 'credential-set.stderr').write_bytes(stored.stderr)
            result['rows'].append({'name': 'credential-set',
                                   'argv': [str(binary), 'credential', 'set', 'anthropic'],
                                   'seconds': time.monotonic() - started,
                                   'exit': stored.returncode,
                                   'runner_copy_removed': not os.path.lexists(args.credential_file),
                                   'execution_error_type': None if store_error is None else type(store_error).__name__,
                                   'prior_error_type': None if store_error is None or store_error.__context__ is None
                                   else type(store_error.__context__).__name__})
            save()
            if store_error is not None:
                raise store_error
            assert stored.returncode == 0, 'credential set refused; see credential-set.stderr'
            launch_dir = home / 'ouro-config/launch'
            launch_dir.mkdir(mode=0o700, exist_ok=True)
            (launch_dir / 'opencode-vault.toml').write_text(VAULT_PROFILE)
            launch = 'opencode-vault'
            result['credential'] = {'provider': 'anthropic', 'mode': 'vault',
                                    'stored_with': 'ukai-jail credential set',
                                    'runner_copy_removed': not args.credential_file.exists()}
        result['agent_launch'] = launch
        result['agent_model'] = args.model
        vaulted = [('anthropic', 'vault', True)] if args.credential_file is not None else []
        # Force the agent's file-search path as well as its write tool. Without
        # rg, OpenCode downloads it from GitHub, outside the starter allowlist.
        (workspace / 'task.txt').write_text('hello\n')
        if args.only != 'learning':
            vendor('opencode', [binary, 'run', '--launch', launch, '--workspace', workspace,
                             '--ro', agent_dir, '--limit', 'wall=300s', '--', agent, 'run',
                             '--print-logs', '--log-level', 'DEBUG', '--model', args.model,
                             'Use your glob tool to find task.txt, read it, then create greeting.txt '
                             'with exactly the same contents. Do not use the network yourself.'], [workspace / 'greeting.txt'])
            data = receipt('opencode')
            assert [(c['id'], c['mode'], c['never_staged']) for c in data['credentials']] == vaulted
            assert (workspace / 'greeting.txt').read_bytes() == b'hello\n'
            shutil.copyfile(workspace / 'greeting.txt', out / 'greeting.txt')
            assert all(row['status'] == 'active' and not row['gaps'] for row in data['coverage'].values())
            assert all(data['coverage'][name]['observed_count'] > 0
                       for name in ['exec', 'fs.write', 'net', 'proxy.net'])
            result['workflow_seconds'] = time.monotonic() - workflow_start
            assert result['workflow_seconds'] < 600, 'The user workflow exceeded ten minutes.'
            result['main_workflow'] = 'passed'
        if args.only != 'onboarding':
            # K11: run the real vendor under learning, with a deliberate exact
            # denied-read fixture. The candidate must cite this run's evidence,
            # retain coverage and propose no parent tree or write grant.
            needed = home / 'learning-needed.txt'
            needed.write_text('learning fixture\n')
            # Only this disposable guest's fixture directory. Vendor consent lets
            # the call reach the jail, whose mount policy still denies the read.
            (workspace / 'opencode.json').write_text(json.dumps({'permission': {
                'bash': 'allow', 'edit': 'allow', 'read': 'allow',
                'external_directory': {str(home) + '/**': 'allow'},
            }}))
            proposal = out / 'opencode-learned.toml'
            vendor('opencode-learn', [binary, 'learn', '--launch', launch, '--workspace', workspace,
                                  '--ro', agent_dir, '--limit', 'wall=300s', '--out', proposal,
                                  '--', agent, 'run', '--print-logs', '--log-level', 'DEBUG', '--model', args.model,
                                  f'Use the bash tool once to run exactly `cat {needed}; '
                                  'cp task.txt learned-greeting.txt`. The cat is expected to fail; still '
                                  'run cp after it. Do not retry, change permissions, or use the network '
                                  'yourself. Reply done only after the command completed.'], [proposal, workspace / 'learned-greeting.txt'])
            learning = receipt('opencode-learn')
            assert [(c['id'], c['mode'], c['never_staged']) for c in learning['credentials']] == vaulted
            assert (workspace / 'learned-greeting.txt').read_bytes() == b'hello\n'
            learned = tomllib.loads(proposal.read_text())
            assert learned['read_only'], 'expected an evidence-supported exact-read subset'
            assert str(home) not in learned['read_only'] and not learned['network_allow']
            assert learned['provenance']['receipt_digest'] == 'sha256:' + hashlib.sha256((out / 'opencode-learn-jail.json').read_bytes()).hexdigest()
            assert json.loads(learned['provenance']['coverage_json']) == learning['coverage']
            assert all(row['status'] == 'active' and not row['gaps'] for row in learning['coverage'].values())
            result['learning_workflow'] = 'passed'
            result['learning_fixture'] = str(needed)
            result['learning_fixture_proposed'] = str(needed) in learned['read_only']
        # From the project, as the guide runs it: doctor treats the current
        # directory as the workspace, and home holds the stored credential.
        for profile in PROFILES:
            run(f'doctor-{profile}', [binary, 'doctor', '--launch', profile, '--json'],
                cwd=workspace)
        distribution_checks()
        result['rust_after'] = {name: shutil.which(name) for name in rust}
        assert not any(result['rust_after'].values())
        result['status'] = 'passed'
    except (AssertionError, KeyError, StopIteration, ValueError, OSError,
            RuntimeError, subprocess.SubprocessError) as error:
        result['blocker'] = str(error) or repr(error)
        if workflow_start is not None and 'workflow_seconds' not in result:
            result['workflow_seconds_to_failure'] = time.monotonic() - workflow_start
        if binary.is_file():
            try:
                run('failure-doctor', [binary, 'doctor', '--launch', 'opencode', '--json'], check=False)
                run('failure-bwrap', ['bwrap', '--unshare-all', '--ro-bind', '/', '/',
                                     '--proc', '/proc', '--dev', '/dev', '/usr/bin/true'], check=False)
                run('failure-security-policy', ['sh', '-c',
                    'cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns; '
                    'sudo -n aa-status; ls /etc/apparmor.d | sort'], check=False)
            except (OSError, subprocess.SubprocessError) as diagnostic:
                result['diagnostic_error'] = str(diagnostic)
        if 'binary_sha256' in result and 'distribution_checks' not in result:
            try:
                distribution_checks()
            except (AssertionError, KeyError, ValueError, OSError,
                    RuntimeError, subprocess.SubprocessError) as distribution:
                result['distribution_error'] = str(distribution) or repr(distribution)
    finally:
        save()
    print(json.dumps({key: result[key] for key in ['status', 'workflow_seconds', 'blocker'] if key in result}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
