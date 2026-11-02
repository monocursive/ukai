#!/usr/bin/env python3
"""Build an experimental guest image locally; this is not a release packager."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

SOURCE = Path(__file__).resolve().parent


def load_coordinates():
    """dist/coordinates.py, loaded by path: dist/ also holds a package.py
    that must not shadow this directory's."""
    spec = importlib.util.spec_from_file_location('ukai_release_coordinates',
                                                  SOURCE.parent / 'dist' / 'coordinates.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coordinates = load_coordinates()
IMAGE_URL = 'https://cloud-images.ubuntu.com/minimal/releases/resolute/release-20261009/ubuntu-26.04-minimal-cloudimg-arm64.img'
IMAGE_SHA256 = '4e86a7819b4cc7b4a9c2e719dec3e0a723c4a2788dc3f23f17641cba7f5ca216'
# The guest runs the current public Linux release (dist/release.json), checked
# against the SHA-256 the public installer pins for it.
JAIL_TARGET = 'aarch64-unknown-linux-gnu'
JAIL_URL = coordinates.jail_archive_url(coordinates.JAIL_VERSION, JAIL_TARGET)
JAIL_SHA256 = coordinates.installer_pin(coordinates.JAIL_VERSION, JAIL_TARGET)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fetch(url, path, expected):
    if not path.exists():
        part = path.with_suffix('.part')
        with urllib.request.urlopen(url, timeout=60) as response, part.open('xb') as output:
            while block := response.read(1024 * 1024):
                output.write(block)
        part.rename(path)
    if sha(path) != expected:
        raise ValueError('checksum mismatch: ' + str(path))


def seed(directory, files, commands):
    directory.mkdir()
    config = {'users': [], 'ssh_deletekeys': True, 'ssh_genkeytypes': [],
              'write_files': [{'path': path, 'encoding': 'b64', 'content': base64.b64encode(content).decode(),
                               'permissions': mode} for path, content, mode in files],
              'runcmd': commands}
    (directory / 'user-data').write_text('#cloud-config\n' + json.dumps(config))
    (directory / 'meta-data').write_text('instance-id: ukai-linux-preview\nlocal-hostname: ukai-linux-preview\n')
    (directory / 'network-config').write_text('version: 2\nethernets:\n  uplink:\n    match:\n      driver: virtio_net\n    dhcp4: true\n')
    subprocess.run(['hdiutil', 'makehybrid', '-o', str(directory) + '.iso', str(directory),
                    '-iso', '-joliet', '-default-volume-name', 'cidata'], check=True)




def pinned_from_console(console):
    """The UKAI_PINNED markers the setup script writes to the console, as
    (package=version, ...) rows; the manifest digests exactly these."""
    return [line.split(None, 1)[1] for line in console.splitlines()
            if line.startswith('UKAI_PINNED ') and len(line.split(None, 1)) == 2]


def pinned_digest(rows):
    import hashlib
    return hashlib.sha256('\n'.join(sorted(rows)).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if os.uname().sysname != 'Darwin' or os.uname().machine != 'arm64':
        parser.error('this prototype requires an Apple Silicon Mac')
    os.umask(0o077)
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = root / 'cache'
    cache.mkdir(exist_ok=True)
    fetch(IMAGE_URL, cache / 'ubuntu.img', IMAGE_SHA256)
    fetch(JAIL_URL, cache / 'jail.tar.gz', JAIL_SHA256)
    subprocess.run(['swiftc', '-warnings-as-errors', '-O', str(SOURCE / 'vz.swift'), '-o', str(root / 'vz')], check=True)
    subprocess.run(['clang', '-Wall', '-Wextra', '-Werror', '-O2', str(SOURCE / 'custodian.c'), '-o', str(root / 'custodian')], check=True)
    subprocess.run(['codesign', '--force', '--sign', '-', '--entitlements', str(SOURCE / 'entitlements.plist'), str(root / 'vz')], check=True)
    if (root / 'base.raw').exists():
        raise ValueError('base.raw already exists; use a fresh output directory')
    subprocess.run(['qemu-img', 'convert', '-f', 'qcow2', '-O', 'raw', str(cache / 'ubuntu.img'), str(root / 'base.raw')], check=True)
    # Sparse enlargement, bounded below the host's available disk space.
    with (root / 'base.raw').open('r+b') as disk:
        disk.truncate(6 * 1024**3)
    with tarfile.open(cache / 'jail.tar.gz') as archive:
        binary = archive.extractfile('ukai-jail').read()
    service = b'''[Unit]
Description=Ukai disposable Linux VM controller
After=local-fs.target user@1001.service
Wants=user@1001.service
FailureAction=poweroff-force
[Service]
Type=notify
ExecStart=/usr/bin/python3 /usr/local/lib/ukai-vm/guest.py
WatchdogSec=4
TimeoutStartSec=120
Restart=no
[Install]
WantedBy=multi-user.target
'''
    setup = b'''#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
# Pin what the guest jail's guarantees measure against (apt is not
# snapshot-pinned; the installed set is recorded in the image manifest):
# `bubblewrap` is the containment backend, `dbus-user-session` the session
# bus the Linux jail's tooling expects.
echo UKAI_STEP apt_update >/dev/hvc0
apt-get update
echo UKAI_STEP apt_install >/dev/hvc0
apt-get install -y --no-install-recommends bubblewrap dbus-user-session
echo UKAI_STEP users >/dev/hvc0
mkdir -p /usr/local/share/ukai-vm
dpkg-query -W -f='${Package}=${Version}\n' bubblewrap dbus-user-session > /usr/local/share/ukai-vm/pinned-versions.txt
useradd --create-home --uid 1001 --shell /bin/bash ukai
loginctl enable-linger ukai
systemctl start user@1001.service
systemctl disable ssh.service ssh.socket 2>/dev/null || true
mkdir -p /usr/local/share/ukai-vm
dpkg-query -W > /usr/local/share/ukai-vm/packages.txt
# The console carries the pinned set to the host builder, which records it
# in image.json: the manifest then names what the guarantees measured
# against without mounting the disk.
dpkg-query -W -f='${Package}=${Version}\n' bubblewrap dbus-user-session | while read -r row; do echo "UKAI_PINNED $row" >/dev/hvc0; done
systemctl enable ukai-vm.service
sync
echo UKAI_BOOTSTRAP_DONE > /dev/hvc0
systemctl poweroff
'''
    trace = b'''#!/bin/sh
# The setup trace lands on the console the host captures: a silently
# aborted step (set -e) is otherwise indistinguishable from a hang.
exec >/dev/hvc0 2>&1
sh -x /usr/local/lib/ukai-vm/setup.sh
'''
    seed(root / 'seed', [('/usr/local/bin/ukai-jail', binary, '0755'),
                        ('/usr/local/lib/ukai-vm/guest.py', (SOURCE / 'guest.py').read_bytes(), '0644'),
                        ('/etc/systemd/system/ukai-vm.service', service, '0644'),
                        ('/usr/local/lib/ukai-vm/setup.sh', setup, '0700'),
                        ('/usr/local/lib/ukai-vm/trace.sh', trace, '0700')],
         [['/bin/sh', '/usr/local/lib/ukai-vm/trace.sh']])
    metadata = {'schema': 'ukai.vm.image-build/1', 'status': 'preparing', 'image_url': IMAGE_URL,
                'image_sha256': IMAGE_SHA256, 'jail_url': JAIL_URL, 'jail_archive_sha256': JAIL_SHA256,
                'source_sha256': {name: sha(SOURCE / name) for name in ['guest.py', 'vz.swift', 'custodian.c', 'prepare.py']}}
    (root / 'image.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with (root / 'bootstrap-events.ndjson').open('wb') as events, (root / 'bootstrap-stderr.log').open('wb') as errors:
        vm = subprocess.Popen([str(root / 'vz'), str(root / 'base.raw'), str(root / 'seed.iso'),
                               str(root / 'bootstrap.nvram'), str(root / 'bootstrap-console.log'), 'bootstrap'],
                              stdin=subprocess.PIPE, stdout=events, stderr=errors)
        try:
            code = vm.wait(timeout=900)
        finally:
            if vm.poll() is None:
                vm.terminate()
                try:
                    vm.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    vm.kill()
                    vm.wait(timeout=10)
    console = (root / 'bootstrap-console.log').read_text(errors='replace')
    if code != 0 or 'UKAI_BOOTSTRAP_DONE' not in console:
        raise RuntimeError('guest bootstrap failed; see bootstrap logs')
    pinned = pinned_from_console(console)
    if not pinned:
        raise RuntimeError('guest bootstrap produced no pinned-version markers')
    metadata.update(status='prepared',
                    guest_pinned_versions=sorted(pinned),
                    guest_pinned_digest=pinned_digest(pinned),
                    disk_sha256=sha(root / 'base.raw'), helper_sha256=sha(root / 'vz'),
                    custodian_sha256=sha(root / 'custodian'), seed_sha256=sha(root / 'seed.iso'))
    (root / 'image.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata, indent=2))


if __name__ == '__main__':
    main()
