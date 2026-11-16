"""Actual Linux process positive control for the installed exposure sampler.

Only a public canary is used. This is a detector control, not a jail receipt or
an agent compatibility result. Preparation runs it inside the new guest image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import time

import guest_exposure

SCHEMA = 'ukai.vm.sampled-exposure-control/1'
CANARY = b'ukai-public-exposure-control-not-a-secret-2026-11-15'
CHILD = 'import os,time; os.write(1,b"ready\\n"); time.sleep(10)'


def control_source_sha256():
    descriptor = os.open(__file__, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 65536:
            raise ValueError('invalid control source')
        data = stream.read(65537)
        after = os.fstat(stream.fileno())
        stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if len(data) != before.st_size or stamp(before) != stamp(after):
            raise ValueError('control source changed')
    return hashlib.sha256(data).hexdigest()


def detection_facts(sampler, identity):
    """Require actual raw-canary observations of the exact owned child."""
    channels = {hit['channel'] for hit in sampler.hits
                if hit['pid'] == identity[0] and hit['starttime'] == identity[1]
                and hit['identity_stable'] is True and hit['representation'] == 'raw'}
    return {
        'environment_canary_detected': 'environment' in channels,
        'argv_canary_detected': 'argv' in channels,
        'verified_program_environment_read': sampler.program_counts['environment']['readable'] > 0,
        'verified_program_argv_read': sampler.program_counts['argv']['readable'] > 0,
        'only_owned_child_observed': set(sampler.identities) == {identity},
        'sampler_source_unchanged': guest_exposure.source_sha256() == sampler.source_digest,
    }


def run_control():
    report = {'schema': SCHEMA, 'passed': False, 'scope': 'owned-public-canary-process-detector-control',
              'actual_values_retained': False, 'jail_execution_claimed': False,
              'facts': {}, 'sampling': {}, 'errors': []}
    process = sampler = None
    try:
        if not sys.platform.startswith('linux'):
            raise RuntimeError('linux_required')
        report['control_source_sha256'] = control_source_sha256()
        report['sampler_sha256'] = guest_exposure.source_sha256()
        root = Path('/proc')
        boot = (root / 'sys/kernel/random/boot_id').read_text().strip()
        report.update(guest_boot_id=boot, guest_kernel=os.uname().release)
        process = subprocess.Popen([sys.executable, '-I', '-c', CHILD, CANARY.decode()],
                                   env={'LANG': 'C', 'UKAI_PUBLIC_CANARY': CANARY.decode()},
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(5) or os.read(process.stdout.fileno(), 6) != b'ready\n':
                raise RuntimeError('child_not_ready')
        _, start = guest_exposure._stat((root / str(process.pid) / 'stat').read_bytes(), process.pid)
        executable = (root / str(process.pid) / 'exe').stat()
        identity = (process.pid, start)
        # This UID is absent from the prepared guest. The final facts also
        # require that the scanner actually observed only this owned child.
        sampler = guest_exposure.Sampler(root, boot, process.pid, start, 2**32 - 2, [],
                                         (executable.st_dev, executable.st_ino), [CANARY])
        deadline = time.monotonic() + 0.6
        while time.monotonic() < deadline:
            sampler.sample(time.monotonic_ns())
            report['facts'] = detection_facts(sampler, identity)
            if all(report['facts'].values()):
                break
            time.sleep(0.1)
        report['process'] = {'pid': process.pid, 'starttime': start,
                             'executable_dev': executable.st_dev, 'executable_ino': executable.st_ino}
        report['sampling'] = {'ticks': sampler.ticks,
                              'verified_program_reads': {key: dict(value) for key, value in sampler.program_counts.items()},
                              'scan_errors': dict(sampler.errors)}
    except Exception as error:
        # Neither a proc value nor arbitrary exception text is retained.
        report['errors'].append(type(error).__name__)
    finally:
        if sampler is not None:
            sampler.patterns.clear()
            sampler.close()
        reaped = process is None
        if process is not None:
            try:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                reaped = process.poll() is not None
            except (OSError, subprocess.TimeoutExpired):
                reaped = False
            if process.stdout is not None:
                process.stdout.close()
        report['facts']['owned_child_reaped'] = reaped
    report['passed'] = bool(report['facts']) and not report['errors'] and all(report['facts'].values())
    if CANARY in json.dumps(report).encode():
        raise ValueError('control report unexpectedly contains canary text')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    descriptor = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        report = run_control()
        data = (json.dumps(report, sort_keys=True, separators=(',', ':')) + '\n').encode()
        output.write(data)
    print('UKAI_EXPOSURE_CONTROL ' + data.decode().strip(), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
