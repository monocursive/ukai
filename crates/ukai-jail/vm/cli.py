"""The installer's helper (`ukai-vm-install`): the preview's install-time
verbs (expand-image, doctor, version). The operator surface is the Rust
`ukai-vm` warm service that `ukai-jail run --vm` starts."""
import argparse
from array import array
import errno
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import struct
import sys

import run

# The packaged binary cannot read dist/release.json; test_coordinates.py keeps
# this equal to its vm.candidate_version (the version package.py builds; D11),
# not vm.version (what the public installer pins).
VERSION = '0.1.0-preview.2'
IMAGE_BYTES = 6 * 1024**3
_EXPAND_READ_BYTES = 1024 * 1024
_ZERO_BLOCK = bytes(4096)


def installed_image():
    return Path(sys.executable).resolve().parent.parent / 'image'


def _remember_hole(holes, offset, length):
    if holes is None:
        return
    if holes and holes[-2] + holes[-1] == offset:
        holes[-1] += length
    else:
        # At most one range per scanned 4KiB block plus the final partial
        # block: less than 25MiB of numeric offsets for a 6GiB image.
        if len(holes) // 2 >= IMAGE_BYTES // len(_ZERO_BLOCK) + 2:
            raise ValueError('too many sparse image ranges')
        holes.extend((offset, length))


def _write_sparse(output, block, holes):
    # A filesystem block of data must not allocate the surrounding megabyte
    # of zeros. Coalesce each kind of run so dense data still uses one write.
    zeros = block.count(0)
    if zeros == len(block):
        _remember_hole(holes, output.tell(), len(block))
        output.seek(len(block), 1)
        return
    if zeros == 0:
        output.write(block)
        return
    start = 0
    previous_zero = None
    for offset in range(0, len(block), len(_ZERO_BLOCK)):
        part = block[offset:offset + len(_ZERO_BLOCK)]
        zero = part == _ZERO_BLOCK[:len(part)]
        if previous_zero is not None and zero != previous_zero:
            if previous_zero:
                _remember_hole(holes, output.tell(), offset - start)
                output.seek(offset - start, 1)
            else:
                output.write(block[start:offset])
            start = offset
        previous_zero = zero
    if previous_zero:
        _remember_hole(holes, output.tell(), len(block) - start)
        output.seek(len(block) - start, 1)
    else:
        output.write(block[start:])


def _punch_holes(output, holes):
    if not holes:
        return
    # APFS can allocate small skipped gaps when later data is written. Only
    # deallocate after all buffered writes; trim each known-zero range inward
    # to the filesystem block boundaries required by fcntl(2).
    output.flush()
    unit = os.fstatvfs(output.fileno()).f_frsize
    if unit <= 0:
        raise ValueError('invalid filesystem block size')
    for index in range(0, len(holes), 2):
        offset, length = holes[index:index + 2]
        start = ((offset + unit - 1) // unit) * unit
        end = ((offset + length) // unit) * unit
        if start >= end:
            continue
        try:
            # Darwin sys/fcntl.h: F_PUNCHHOLE=99, fpunchhole_t is two
            # unsigned int fields followed by two 64-bit off_t fields.
            fcntl.fcntl(output.fileno(), 99, struct.pack('=IIqq', 0, 0, start, end - start))
        except OSError as error:
            if error.errno in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.ENOSYS):
                return  # The existing seek-based bytes remain valid.
            raise


def expand_image(directory):
    metadata = json.loads((directory / 'image.json').read_text())
    run.optional_program_catalog(directory, metadata)
    destination = directory / 'base.raw'
    digest = hashlib.sha256()
    holes = array('Q') if sys.platform == 'darwin' else None
    total = 0
    created = False
    try:
        output = destination.open('xb')
        created = True
        with output, gzip.open(directory / 'base.raw.gz', 'rb') as source:
            while block := source.read(_EXPAND_READ_BYTES):
                total += len(block)
                if total > IMAGE_BYTES:
                    raise ValueError('image exceeds its declared size')
                digest.update(block)
                _write_sparse(output, block, holes)
            output.truncate(total)
            if total != IMAGE_BYTES or digest.hexdigest() != metadata['disk_sha256']:
                raise ValueError('expanded image checksum mismatch')
            _punch_holes(output, holes)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(prog='ukai-vm', description='Offline Linux Jail preview for Apple Silicon Macs.')
    parser.add_argument('command', choices=['run', 'version', 'doctor', 'expand-image'])
    args, rest = parser.parse_known_args()
    image = installed_image()
    if args.command == 'version':
        value = {'component': 'ukai-vm', 'version': VERSION, 'execution': 'linux-vm', 'native_macos_execution': False}
        print(json.dumps(value) if '--json' in rest else f'Ukai VM {VERSION} (offline Linux on Apple Silicon)')
        return 0
    supported = sys.platform == 'darwin' and platform.machine() == 'arm64' and int(platform.mac_ver()[0].split('.')[0]) >= 27
    if not supported:
        parser.error('this preview is qualified for Apple Silicon and macOS 27 or later')
    if args.command == 'expand-image':
        if rest:
            parser.error('expand-image takes no arguments')
        expand_image(image)
        return 0
    if args.command == 'doctor':
        metadata = json.loads((image / 'image.json').read_text())
        checks = {'virtualization_supported': subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.hv_support'], capture_output=True, text=True).stdout.strip() == '1'}
        for name, key in [('base.raw', 'disk_sha256'), ('seed.iso', 'seed_sha256'), ('vz', 'helper_sha256'), ('custodian', 'custodian_sha256')]:
            checks[name] = (image / name).is_file() and run.digest(image / name) == metadata[key]
        try:
            run.optional_program_catalog(image, metadata)
            checks['guest_program_catalog'] = True
        except (OSError, ValueError):
            checks['guest_program_catalog'] = False
        result = {'schema': 'ukai.vm.install-check/1', 'ready': all(checks.values()), 'checks': checks,
                  'scope': 'package and host prerequisites; a real run still verifies the guest jail'}
        print(json.dumps(result, indent=2))
        return 0 if result['ready'] else 125
    sys.argv = [sys.argv[0], '--image', str(image), *rest]
    return run.main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print(f'ukai-vm: {error}', file=sys.stderr)
        sys.exit(125)
