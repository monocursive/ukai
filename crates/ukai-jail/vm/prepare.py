#!/usr/bin/env python3
"""Build an experimental guest image locally; this is not a release packager."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import urllib.request

SOURCE = Path(__file__).resolve().parent

# An immutable Ubuntu archive snapshot (https://snapshot.ubuntu.com): the
# builder resolves packages against exactly this archive state, so two
# builds see the same versions. The manifest records the pin; a build
# against a different snapshot is a different image.
SNAPSHOT = '20261020T000000Z'
SNAPSHOT_URL = 'https://snapshot.ubuntu.com/ubuntu/' + SNAPSHOT


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


def verify_candidate(directory, dist):
    """Use the release verifier without importing dist/package as vm/package.

    The trust root is this checkout's release.pub, never a key supplied beside
    the candidate or by the caller. This invokes check only, not publication.
    """
    script = '''import json, pathlib, sys
sys.path.insert(0, sys.argv[1])
from publish_release import check
public = pathlib.Path(sys.argv[1], 'release.pub').read_text().splitlines()[1]
plan, names = check(pathlib.Path(sys.argv[2]), public)
print(json.dumps({'plan': plan, 'names': names}))
'''
    result = subprocess.run([sys.executable, '-I', '-c', script, str(dist), str(directory)],
                            check=True, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def stage_candidate(directory, cache, dist=None):
    """Retain and reverify signed local inputs, then select their ARM archive."""
    dist = (dist or SOURCE.parent / 'dist').resolve(strict=True)
    directory = Path(directory).resolve(strict=True)
    public = (dist / 'release.pub').read_bytes()
    verified = verify_candidate(directory, dist)
    retained = cache / 'signed-jail-candidate'
    retained.mkdir(exist_ok=False)
    for name in verified['names']:
        shutil.copyfile(directory / name, retained / name)
    # Check the copied bytes too: a changing input directory cannot put an
    # unverified archive, plan or signature into the seed or saved provenance.
    copied = verify_candidate(retained, dist)
    if copied != verified or (dist / 'release.pub').read_bytes() != public:
        raise ValueError('signed candidate or trusted public key changed while copying')
    plan = copied['plan']
    record = next(record for record in plan['artifacts'] if record['target'] == JAIL_TARGET)
    archive = retained / record['archive']
    destination = cache / 'jail.tar.gz'
    # Existing output is never silently adopted or overwritten.
    with archive.open('rb') as source, destination.open('xb') as output:
        shutil.copyfileobj(source, output)
    if sha(destination) != record['archive_sha256']:
        raise ValueError('selected ARM archive changed while copying')
    (retained / 'trusted-release.pub').write_bytes(public)
    provenance = {
        'kind': 'signed-local-candidate', 'signature_verified': True,
        'verifier': 'publish_release.check', 'trusted_key': 'crates/ukai-jail/dist/release.pub',
        'trusted_key_sha256': hashlib.sha256(public).hexdigest(),
        'target': JAIL_TARGET, 'release': record['release'], 'tag': plan['tag'],
        'source_revision': plan['target_commit'], 'build_inputs': plan['inputs'],
        'archive': record['archive'], 'archive_sha256': record['archive_sha256'],
        'binary_sha256': record['binary_sha256'], 'version': record['version'],
        'retained_directory': 'cache/signed-jail-candidate',
        'verified_assets_sha256': {name: sha(retained / name) for name in copied['names']},
        'publication': 'local input verification only; no publication performed',
    }
    return record['archive_sha256'], provenance


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
    parser.add_argument('--jail-candidate', type=Path,
                        help='use a local signed Linux candidate verified with the checked-in release.pub')
    args = parser.parse_args()
    if os.uname().sysname != 'Darwin' or os.uname().machine != 'arm64':
        parser.error('this prototype requires an Apple Silicon Mac')
    os.umask(0o077)
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=True)
    cache = root / 'cache'
    cache.mkdir(exist_ok=True)
    if args.jail_candidate:
        jail_sha256, jail_candidate = stage_candidate(args.jail_candidate, cache)
        jail_url = None
    else:
        fetch(JAIL_URL, cache / 'jail.tar.gz', JAIL_SHA256)
        jail_sha256, jail_candidate, jail_url = JAIL_SHA256, None, JAIL_URL
    fetch(IMAGE_URL, cache / 'ubuntu.img', IMAGE_SHA256)
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
    setup = f'''#!/bin/sh
set -eu
export DEBIAN_FRONTEND=noninteractive
# Immutable archive pin: every apt operation resolves against the snapshot
# recorded in image.json, never the moving live archive.
printf 'Types: deb\\nURIs: {SNAPSHOT_URL}\\nSuites: resolute resolute-updates resolute-security\\nComponents: main universe\\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\\n' > /etc/apt/sources.list.d/ukai-snapshot.sources
rm -f /etc/apt/sources.list.d/ubuntu.sources
# Install what the guest jail's guarantees measure against, resolved from
# the snapshot above; the installed versions are also recorded in the image
# manifest: `bubblewrap` is the containment backend, `dbus-user-session`
# the session bus the jail's scope request (busctl --user) talks to.
# These leave exactly the user manager, its (sd-pam) helper and the bus
# running as the account; guest.py learns those three from systemd at
# session open (learn_infrastructure) and the attempt stop spares only them.
echo UKAI_STEP apt_update >/dev/hvc0
apt-get update
echo UKAI_STEP apt_install >/dev/hvc0
apt-get install -y --no-install-recommends bubblewrap dbus-user-session
echo UKAI_STEP users >/dev/hvc0
mkdir -p /usr/local/share/ukai-vm
dpkg-query -W -f='${{Package}}=${{Version}}\n' bubblewrap dbus-user-session > /usr/local/share/ukai-vm/pinned-versions.txt
useradd --create-home --uid 1001 --shell /bin/bash ukai
loginctl enable-linger ukai
systemctl start user@1001.service
systemctl disable ssh.service ssh.socket 2>/dev/null || true
mkdir -p /usr/local/share/ukai-vm
dpkg-query -W > /usr/local/share/ukai-vm/packages.txt
# The console carries the pinned set to the host builder, which records it
# in image.json: the manifest then names what the guarantees measured
# against without mounting the disk.
dpkg-query -W -f='${{Package}}=${{Version}}\n' bubblewrap dbus-user-session | while read -r row; do echo "UKAI_PINNED $row" >/dev/hvc0; done
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
                        ('/usr/local/lib/ukai-vm/setup.sh', setup.encode(), '0700'),
                        ('/usr/local/lib/ukai-vm/trace.sh', trace, '0700')],
         [['/bin/sh', '/usr/local/lib/ukai-vm/trace.sh']])
    metadata = {'schema': 'ukai.vm.image-build/1', 'status': 'preparing', 'image_url': IMAGE_URL,
                'image_sha256': IMAGE_SHA256, 'jail_url': jail_url, 'jail_archive_sha256': jail_sha256,
                'apt_snapshot': SNAPSHOT, 'apt_snapshot_url': SNAPSHOT_URL,
                'source_sha256': {name: sha(SOURCE / name) for name in ['guest.py', 'vz.swift', 'custodian.c', 'prepare.py']}}
    if jail_candidate is not None:
        metadata['jail_candidate'] = jail_candidate
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
