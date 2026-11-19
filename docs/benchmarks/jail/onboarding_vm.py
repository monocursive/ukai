#!/usr/bin/env python3
"""Reproduce K27 in a new disposable Linux QEMU VM, without host policy changes.

Supply an official Ubuntu QCOW2 image for the selected target and its independently checked SHA256,
and an optimized GNU/Linux binary built from a clean revision. Distribution
packages are provisioned before the user-workflow timer starts. The guest must
have no Rust. A CPU emulator is suitable for compatibility/onboarding evidence,
not jail performance benchmarks. Linux can use --accelerator kvm. On Apple
Silicon, an ARM guest can use --accelerator hvf with ARM UEFI firmware.
The runner signs only with an ephemeral key and keeps the package private. Since
OpenCode's free tier refuses its own CLI (2026-10-18), --credential-file may
name one private Anthropic API key file: it is copied into the disposable guest
only, vaulted there, and every recorded file is then searched for its bytes;
a hit fails the run (file names only are reported, never the key).
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import time


MAX_KEY_BYTES = 8192
SCAN_MAX_FILES = 8192
SCAN_MAX_BYTES = 256 * 1024 * 1024
TRANSFER_TIMEOUT = 90
RECEIVE_KEY = '''import os, pathlib, sys
value = sys.stdin.buffer.read(8193)
if not 0 < len(value) <= 8192 or value.endswith(b'\\n'):
    raise SystemExit(2)
fd = os.open('provider.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as target:
    target.write(value)
    target.flush()
    os.fsync(target.fileno())
'''


def identity(info):
    return {name: getattr(info, name) for name in
            ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size',
             'st_mtime_ns', 'st_ctime_ns')}


def directory_identity(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('owned temporary path is not a directory')
    return {name: getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_uid')}


def read_credential(path):
    """Keep the exact transferred bytes in memory, never a digest or host copy."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), 'rb') as source:
        before = identity(os.fstat(source.fileno()))
        if (not stat.S_ISREG(before['st_mode']) or stat.S_IMODE(before['st_mode']) != 0o600
                or before['st_uid'] != os.getuid()):
            raise RuntimeError('credential source must be an owned regular mode-0600 file')
        value = source.read(MAX_KEY_BYTES + 1)
        if (identity(os.fstat(source.fileno())) != before
                or identity(path.lstat()) != before):
            raise RuntimeError('credential source changed while reading')
    if not 0 < len(value) <= MAX_KEY_BYTES or value.endswith(b'\n'):
        raise RuntimeError('credential source must contain one bounded key without a trailing newline')
    return value, before


def failure(stage, error):
    # Exception messages can include arbitrary filenames or subprocess output.
    result = {'stage': stage, 'type': type(error).__name__}
    if isinstance(error, subprocess.TimeoutExpired):
        result['timeout_seconds'] = error.timeout
    if isinstance(error, subprocess.CalledProcessError):
        result['returncode'] = error.returncode
    if error.__context__ is not None:
        result['prior_type'] = type(error.__context__).__name__
    return result


def exposure_scan(out, value):
    """Bounded streaming scan of retained regular files; never follow links."""
    scanned, total, visited, hits, pending = 0, 0, 0, [], [out]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > SCAN_MAX_FILES:
                    raise RuntimeError('recorded-file scan entry bound exceeded')
                if entry.is_symlink():
                    raise RuntimeError('recorded-file scan refuses symbolic links')
                if entry.is_dir(follow_symlinks=False):
                    pending.append(pathlib.Path(entry.path))
                    continue
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                with os.fdopen(os.open(entry.path, flags), 'rb') as source:
                    before = identity(os.fstat(source.fileno()))
                    if not stat.S_ISREG(before['st_mode']):
                        raise RuntimeError('recorded-file scan refuses nonregular files')
                    tail, hit = b'', False
                    while chunk := source.read(1024 * 1024):
                        total += len(chunk)
                        if total > SCAN_MAX_BYTES:
                            raise RuntimeError('recorded-file scan byte bound exceeded')
                        combined = tail + chunk
                        hit |= value in combined
                        tail = combined[-(len(value) - 1):] if len(value) > 1 else b''
                    if (identity(os.fstat(source.fileno())) != before
                            or identity(os.lstat(entry.path)) != before):
                        raise RuntimeError('recorded file changed during scan')
                scanned += 1
                relative = os.fsencode(str(pathlib.Path(entry.path).relative_to(out)))
                if hit or value in relative:
                    hits.append('<redacted filename>' if value in relative else os.fsdecode(relative))
    return {'complete': True, 'files_scanned': scanned, 'bytes_scanned': total,
            'files_with_key': sorted(hits)}


def retain_guest_evidence(execute, ssh, options, port, out):
    errors = []
    for stage, argv, destination in (
            ('guest_evidence', ['scp', '-r', '-P', str(port)] + options +
             ['ubuntu@127.0.0.1:onboarding-results', out / 'guest'], None),
            ('bootstrap_evidence', ssh + ['sudo -n cat /var/log/cloud-init-output.log'],
             out / 'bootstrap.log')):
        try:
            with (out / f'{stage}.stderr').open('wb') as errors_output:
                if destination is None:
                    execute(argv, stdout=subprocess.DEVNULL, stderr=errors_output, timeout=TRANSFER_TIMEOUT)
                else:
                    with destination.open('wb') as stream:
                        execute(argv, stdout=stream, stderr=errors_output, timeout=15)
        except (OSError, subprocess.SubprocessError) as error:
            errors.append(failure(stage, error))
    return errors


def run_guest_workflow(execute, ssh, options, port, out, command, metadata):
    with (out / 'workflow.log').open('wb') as workflow:
        try:
            attempt = subprocess.run(ssh + [command], stdin=subprocess.DEVNULL,
                                     stdout=workflow, stderr=subprocess.STDOUT, timeout=1800)
            metadata['guest_exit'] = attempt.returncode
            return attempt
        finally:
            # A timed-out workflow has partial diagnostics only, even if an
            # earlier guest result happens to say passed. Preserve before stop.
            metadata['retention_errors'] = retain_guest_evidence(execute, ssh, options, port, out)


def finalize(metadata, out, vm, temporary, credential_path, held, save):
    """Every independent cleanup/check runs even when an earlier one fails."""
    errors = metadata.setdefault('cleanup_errors', [])
    metadata['vm_destroyed'] = vm is None
    try:
        if vm is not None:
            if vm.poll() is None:
                try:
                    vm.terminate()
                except OSError as error:
                    errors.append(failure('vm_terminate', error))
                try:
                    vm.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait(timeout=15)
            metadata['vm_destroyed'] = vm.poll() is not None
            if not metadata['vm_destroyed']:
                raise RuntimeError('VM termination was not verified')
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        errors.append(failure('vm_teardown', error))
    metadata['temporary_removed'] = temporary is None
    if temporary is not None:
        if metadata['vm_destroyed']:
            try:
                if directory_identity(temporary) != metadata.get('temporary_identity'):
                    raise RuntimeError('owned temporary directory identity changed; retained')
                shutil.rmtree(temporary)
                metadata['temporary_removed'] = not temporary.exists()
            except (OSError, RuntimeError) as error:
                errors.append(failure('temporary_cleanup', error))
        else:
            metadata['temporary_retained'] = str(temporary)
    if credential_path is not None:
        if held is None:
            metadata['credential_exposure'] = {'complete': False, 'reason': 'no validated key was read or staged'}
            metadata['status'] = 'blocked'
        else:
            value, expected = held
            try:
                metadata['credential_source_unchanged'] = identity(credential_path.lstat()) == expected
                if not metadata['credential_source_unchanged']:
                    raise RuntimeError('credential source generation changed')
            except (OSError, RuntimeError) as error:
                metadata['credential_source_unchanged'] = False
                errors.append(failure('credential_source', error))
            try:
                metadata['credential_exposure'] = exposure_scan(out, value)
                if metadata['credential_exposure']['files_with_key']:
                    raise RuntimeError('provider key found in retained evidence')
            except (OSError, RuntimeError) as error:
                metadata.setdefault('credential_exposure', {'complete': False})
                errors.append(failure('credential_exposure', error))
    if errors or not metadata['vm_destroyed'] or not metadata['temporary_removed']:
        metadata['status'] = 'blocked'
        metadata.setdefault('blocker', 'cleanup or credential verification failed; see cleanup_errors')
    try:
        save()
    except OSError as error:
        metadata['status'] = 'blocked'
        metadata['finalization_failure'] = failure('final_record', error)
        metadata.setdefault('blocker', 'the final record could not be persisted')


def guest_arguments(args, trusted_key):
    argv = ['python3', 'onboarding_guest.py', '--artifacts', 'artifacts',
            '--installer', 'install.sh', '--public-key', trusted_key,
            '--revision', args.revision, '--out', 'onboarding-results',
            '--model', args.model, '--vendor-attempts', str(args.vendor_attempts)]
    argv += ['--target', args.target]
    if args.only is not None:
        argv += ['--only', args.only]
    if args.inputs is not None:
        argv += ['--inputs', args.inputs]
    if args.credential_file is not None:
        argv += ['--credential-file', 'provider.key']
    return argv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=pathlib.Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--image-url', required=True)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--inputs', help='Expected Jail build-input SHA256 passed to the guest.')
    parser.add_argument('--release-version', default='0.1.0-rc.1')
    parser.add_argument('--out', type=pathlib.Path, required=True)
    parser.add_argument('--target', choices=['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu'],
                        default='x86_64-unknown-linux-gnu')
    parser.add_argument('--arm-firmware', type=pathlib.Path, help='EDK2 ARM64 UEFI code for QEMU virt.')
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument('--only', choices=['install', 'onboarding', 'learning'],
                       help='Run just this check in a fresh guest. The default runs both vendor checks.')
    scope.add_argument('--install-only', dest='only', action='store_const', const='install',
                       help=argparse.SUPPRESS)
    parser.add_argument('--accelerator', choices=['tcg', 'kvm', 'hvf'], default='tcg')
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--memory-mib', type=int, default=3072)
    parser.add_argument('--boot-timeout', type=int, default=900)
    parser.add_argument('--credential-file', type=pathlib.Path,
                        help='A private (mode 0600) Anthropic API key file, no trailing newline.')
    parser.add_argument('--model', default='opencode/big-pickle')
    parser.add_argument('--vendor-attempts', type=int, choices=[1, 2], default=2,
                        help='Maximum CLI invocations per vendor workload (not an API or billing cap).')
    args = parser.parse_args()
    arm = args.target == 'aarch64-unknown-linux-gnu'
    if arm != (args.arm_firmware is not None):
        parser.error('--arm-firmware is required exactly when using the ARM64 target')
    if args.only == 'install' and args.credential_file is not None:
        parser.error('--install-only does not use provider credentials')
    qemu_system = 'qemu-system-' + args.target.split('-')[0]
    os.umask(0o077)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    metadata = {'schema': 'ouro.jail.onboarding-vm/1', 'status': 'blocked',
                'image_url': args.image_url, 'expected_image_sha256': args.image_sha256,
                'revision': args.revision, 'accelerator': args.accelerator,
                'expected_inputs': args.inputs, 'target': args.target, 'only': args.only,
                'release_version': args.release_version,
                'cpus': args.cpus, 'memory_mib': args.memory_mib,
                'guest_disk_gib': 12, 'fresh_overlay': True,
                'host_policy_changes': [], 'host_uname': list(os.uname()),
                'prerequisites': ['bubblewrap', 'minisign', 'curl', 'ca-certificates',
                                  'perl', 'git', 'python3', 'ripgrep'],
                'private_key_persisted': False, 'production_signing': False,
                'agent_model': args.model,
                'vendor_attempts': args.vendor_attempts,
                'max_vendor_invocations': {None: 2, 'install': 0, 'learning': 1, 'onboarding': 1}[args.only] * args.vendor_attempts,
                'credential': None if args.credential_file is None else {
                    'provider': 'anthropic', 'mode': 'vault',
                    'copied_into': 'the disposable guest only'}}
    vm = None
    temporary = None
    held = None

    def save():
        (out / 'vm.json').write_text(json.dumps(metadata, indent=2) + '\n')

    def execute(argv, **kwargs):
        kwargs.setdefault('timeout', 300)
        if 'input' not in kwargs:
            kwargs.setdefault('stdin', subprocess.DEVNULL)
        return subprocess.run([str(part) for part in argv], check=True,
                              **kwargs)

    save()
    try:
        if args.credential_file is not None:
            held = read_credential(args.credential_file)
            metadata['credential_source_metadata'] = held[1]
        for tool in [qemu_system, 'qemu-img', 'ssh', 'scp', 'ssh-keygen', 'minisign']:
            if not shutil.which(tool):
                raise RuntimeError(f'Missing VM prerequisite: {tool}; no container fallback is valid.')
        iso_tool = 'hdiutil' if os.uname().sysname == 'Darwin' else 'genisoimage'
        if not shutil.which(iso_tool):
            raise RuntimeError(f'Missing NoCloud ISO tool: {iso_tool}.')
        if not re.fullmatch(r'[0-9a-f]{40}', args.revision):
            raise RuntimeError('A full git revision is required for clean-build evidence.')
        digest = hashlib.file_digest(args.image.open('rb'), 'sha256').hexdigest()
        metadata['image_sha256'] = digest
        if digest != args.image_sha256:
            raise RuntimeError('Supplied VM image checksum does not match.')
        metadata['binary_sha256'] = hashlib.file_digest(args.binary.open('rb'), 'sha256').hexdigest()
        metadata['qemu_version'] = execute([qemu_system, '--version'], capture_output=True,
                                          text=True).stdout.strip()
        temporary = pathlib.Path(tempfile.mkdtemp(prefix='ouro-k27-vm-'))
        root = temporary
        metadata['temporary_identity'] = directory_identity(root)
        seed = root / 'seed'
        seed.mkdir()
        key = root / 'guest-key'
        execute(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', key])
        public_key = key.with_suffix('.pub').read_text().strip()
        seed.joinpath('meta-data').write_text('instance-id: ouro-k27-disposable\nlocal-hostname: ouro-k27-fresh\n')
        seed.joinpath('network-config').write_text('version: 2\nethernets:\n  guest:\n    match:\n'
            '      macaddress: "52:54:00:ab:27:01"\n    dhcp4: true\n')
        seed.joinpath('user-data').write_text(
            '#cloud-config\nusers:\n  - name: ubuntu\n    groups: [sudo]\n'
            '    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n'
            '    ssh_authorized_keys:\n      - ' + public_key + '\n'
            'ssh_pwauth: false\npackage_update: true\n'
            'packages: [bubblewrap, minisign, curl, ca-certificates, perl, git, python3, ripgrep]\n'
            'runcmd:\n  - [touch, /home/ubuntu/cloud-ready]\n')
        shutil.copytree(seed, out / 'seed')
        iso = root / 'seed.iso'
        with (out / 'setup.log').open('wb') as setup:
            if iso_tool == 'hdiutil':
                execute(['hdiutil', 'makehybrid', '-o', iso, seed, '-iso', '-joliet',
                         '-default-volume-name', 'cidata'], stdout=setup, stderr=subprocess.STDOUT)
            else:
                execute(['genisoimage', '-output', iso, '-volid', 'cidata', '-joliet', '-rock', seed],
                        stdout=setup, stderr=subprocess.STDOUT)
            disk = root / 'guest.qcow2'
            execute(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b',
                     args.image.resolve(), disk, '12G'], stdout=setup, stderr=subprocess.STDOUT)
            signing_key = root / 'test-signing.key'
            signing_public = root / 'test-signing.pub'
            execute(['minisign', '-G', '-W', '-s', signing_key, '-p', signing_public],
                    stdout=setup, stderr=subprocess.STDOUT)
            trusted_key = signing_public.read_text().splitlines()[1]
            metadata['test_signing_public_key'] = trusted_key
            artifacts = root / 'artifacts'
            script_dir = pathlib.Path(__file__).resolve().parent
            repo = script_dir.parents[2]
            execute(['python3', repo / 'crates/ukai-jail/dist/package.py', '--binary',
                     args.binary.resolve(), '--target', args.target, '--out',
                     artifacts, '--version', args.release_version, '--signing-key', signing_key], stdout=setup, stderr=subprocess.STDOUT)
        (out / 'artifacts').mkdir()
        for filename in ['SHA256SUMS', 'SHA256SUMS.minisig']:
            shutil.copyfile(artifacts / filename, out / 'artifacts' / filename)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        qemu = [qemu_system, '-accel', args.accelerator, '-cpu',
                'max' if args.accelerator == 'tcg' else 'host',
                '-smp', str(args.cpus), '-m', str(args.memory_mib)]
        if arm:
            qemu += ['-machine', 'virt', '-bios', str(args.arm_firmware.resolve()),
                     '-device', 'virtio-scsi-pci,id=scsi0',
                     '-drive', f'if=none,id=seed,format=raw,readonly=on,file={iso}',
                     '-device', 'scsi-cd,drive=seed']
        else:
            qemu += ['-drive', f'file={iso},format=raw,media=cdrom,readonly=on']
        qemu += ['-drive', f'file={disk},if=virtio,format=qcow2',
                 '-netdev', f'user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22',
                 '-device', 'virtio-net-pci,netdev=net0,mac=52:54:00:ab:27:01', '-display', 'none',
                 '-serial', f'file:{out / "console.log"}', '-monitor', 'none']
        metadata['qemu_argv'] = qemu
        save()
        with (out / 'qemu.stderr').open('wb') as errors:
            vm = subprocess.Popen(qemu, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                  stderr=errors)
        known_hosts = root / 'known_hosts'
        options = ['-i', str(key), '-o', f'UserKnownHostsFile={known_hosts}',
                   '-o', 'StrictHostKeyChecking=accept-new', '-o', 'BatchMode=yes',
                   '-o', 'ConnectTimeout=5']
        ssh = ['ssh', '-T', '-p', str(port)] + options + ['ubuntu@127.0.0.1']
        boot_started = time.monotonic()
        while time.monotonic() - boot_started < args.boot_timeout:
            if vm.poll() is not None:
                raise RuntimeError('QEMU stopped before VM readiness; see qemu.stderr.')
            try:
                ready = subprocess.run(ssh + ['test -f /home/ubuntu/cloud-ready'],
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            except subprocess.TimeoutExpired:
                continue
            if ready.returncode == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Fresh VM did not finish prerequisite setup before boot timeout.')
        metadata['bootstrap_seconds'] = time.monotonic() - boot_started
        # Trust learned only from this loopback VM remains pinned for every later call.
        options[options.index('StrictHostKeyChecking=accept-new')] = 'StrictHostKeyChecking=yes'
        ssh = ['ssh', '-T', '-p', str(port)] + options + ['ubuntu@127.0.0.1']
        execute(['scp', '-r', '-P', str(port)] + options +
                [artifacts, repo / 'crates/ukai-jail/dist/install.sh',
                 script_dir / 'onboarding_guest.py', 'ubuntu@127.0.0.1:'])
        if args.credential_file is not None:
            if identity(args.credential_file.lstat()) != held[1]:
                raise RuntimeError('credential source changed before staging')
            # Exact held bytes, not a second pathname read. The only copy is an
            # exclusive mode-0600 guest file; no value enters argv or host disk.
            execute(ssh + ['python3 -c ' + shlex.quote(RECEIVE_KEY)],
                    input=held[0], capture_output=True, timeout=30)
            metadata['credential_staged'] = True
        command = shlex.join(guest_arguments(args, trusted_key))
        attempt = run_guest_workflow(execute, ssh, options, port, out, command, metadata)
        if metadata['retention_errors']:
            raise RuntimeError('guest evidence retrieval was incomplete')
        result = json.loads((out / 'guest/result.json').read_text())
        if type(result) is not dict or result.get('status') not in (('install-only-passed' if args.only == 'install' else 'passed'), 'blocked'):
            raise RuntimeError('guest result has no recognized workflow status')
        metadata['status'] = result['status']
        if result.get('blocker'):
            metadata['blocker'] = 'guest workflow refused; see retained guest/result.json'
        if attempt.returncode != 0:
            metadata['status'] = 'blocked'
            metadata['primary_failure'] = {'stage': 'guest_workflow', 'type': 'NonzeroExit',
                                           'returncode': attempt.returncode}
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        metadata['status'] = 'blocked'
        metadata['primary_failure'] = failure('workflow', error)
        metadata['blocker'] = 'onboarding failed; see primary_failure and retained evidence'
    finally:
        finalize(metadata, out, vm, temporary, args.credential_file, held, save)
    print(json.dumps({key: metadata[key] for key in ['status', 'blocker'] if key in metadata}))
    return 0 if metadata['status'] in ('passed', 'install-only-passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
