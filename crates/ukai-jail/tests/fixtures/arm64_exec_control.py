"""Prove pre-execution rejection for the 64-bit-only Linux conformance case."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


# Debian busybox-static 1:1.37.0-6+b9. Both files execute on the compat-capable
# Pi. A malformed ELF can also return ENOEXEC, so its header alone is insufficient.
FIXTURES = {
    'arm64': '7d93682be37cf6ed46699f6fff546b80bf133cf8ec342c2d04bc23387f78bc34',
    'armhf': '0a58280553462be5d8064f510a8abceef2610fb549d82f52027bcfc9cbdf9d1d',
}
ROOT = Path('/usr/local/lib/ukai-conformance')
SENTINEL = 'ukai-arm64-abi'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def online_cpus():
    result = set()
    for item in Path('/sys/devices/system/cpu/online').read_text().strip().split(','):
        start, _, end = item.partition('-')
        result.update(range(int(start), int(end or start) + 1))
    return result


def verify():
    require(os.uname().machine == 'aarch64', 'requires an AArch64 Linux guest')
    require('Seccomp:\t0' in Path('/proc/self/status').read_text().splitlines(),
            'an inherited filter could be responsible for the rejection')
    cpus = online_cpus()
    require(cpus == os.sched_getaffinity(0), 'need access to every online CPU')
    for arch, digest in FIXTURES.items():
        data = (ROOT / arch / 'busybox').read_bytes()
        require(hashlib.sha256(data).hexdigest() == digest, f'unrecognized {arch} fixture')

    # Linux refuses PER_LINUX32 on this host class. This process is disposable.
    libc = ctypes.CDLL(None, use_errno=True)
    require(libc.personality(8) == -1 and ctypes.get_errno() == errno.EINVAL,
            'kernel did not reject the Linux32 personality with EINVAL')

    for cpu in sorted(cpus):
        os.sched_setaffinity(0, {cpu})
        for arch in FIXTURES:
            program = ROOT / arch / 'busybox'
            args = [str(program), 'echo', SENTINEL]
            try:
                completed = subprocess.run(args, capture_output=True, timeout=5)
            except OSError as exc:
                require(arch == 'armhf' and exc.errno == errno.ENOEXEC,
                        f'{arch} on CPU {cpu} failed with errno {exc.errno}')
            else:
                require(arch == 'arm64' and completed.returncode == 0
                        and completed.stdout == (SENTINEL + '\n').encode(),
                        f'unexpected direct execution result for {arch} on CPU {cpu}')
            with tempfile.NamedTemporaryFile() as trace:
                observed = subprocess.run(
                    ['strace', '-qq', '-e', 'trace=execve', '-o', trace.name, '--', *args],
                    capture_output=True, timeout=5, env={**os.environ, 'LC_ALL': 'C'})
                lines = Path(trace.name).read_text().splitlines()
            require(len(lines) == 1 and lines[0].startswith(f'execve("{program}",'),
                    f'expected exactly one execve of {program} on CPU {cpu}')
            if arch == 'armhf':
                require('= -1 ENOEXEC ' in lines[0] and observed.returncode != 0
                        and not observed.stdout, 'expected rejection before ARM32 execution')
            else:
                require(lines[0].endswith('= 0') and observed.returncode == 0
                        and observed.stdout == (SENTINEL + '\n').encode(),
                        'native execution control failed')
    require(online_cpus() == cpus, 'online CPU set changed during verification')
    print(json.dumps({'arm32_exec': 'ENOEXEC', 'linux32_personality': 'EINVAL',
                      'native_exec': 'succeeded', 'cpus': sorted(cpus)}))


if __name__ == '__main__':
    verify()
