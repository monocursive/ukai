#!/usr/bin/env python3
"""Derive bounded guest credential admission from replayed, signed-image evidence.

No capability table is changed. This is guest/service component admission,
not installed-client source-watch, vendor/TLS, or K113 release qualification.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

import claude_vm_row as compatibility
import credential_revocation_measurement as revocation
import harness

SCHEMA = 'ukai.vm.credential-staging-measurement/1'
SHA = re.compile(r'[0-9a-f]{64}')
REVISION = re.compile(r'[0-9a-f]{40}')
FILE_MAX = 64 * 1024 ** 3
IMAGE_KEYS = ('disk_sha256', 'helper_sha256', 'custodian_sha256', 'seed_sha256')
GUEST_CONTRACTS = {'secret_revocation': 'ukai.vm.secret-revocation/1',
                   'journal_export': 'ukai.vm.guest-journal/1'}


class AdmissionError(ValueError):
    pass


def require(held, reason):
    if held is not True:
        raise AdmissionError(reason)


def valid_sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run_tool(argv):
    return subprocess.run([str(value) for value in argv], check=True, capture_output=True,
                          timeout=120, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})


def digest_file(path, cap=FILE_MAX):
    """No-follow regular file, bounded streaming hash, stable identity and size."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap,
                'nonregular, linked or oversized artifact')
        digest, count = hashlib.sha256(), 0
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            require(count <= cap, 'artifact grew past bound')
            digest.update(chunk)
        after = os.fstat(fd)
    stamp = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    require(count == before.st_size and stamp(before) == stamp(after), 'artifact changed while hashing')
    return digest.hexdigest()


def walk_error(error):
    raise error


def tree_files(root):
    """Inventory only regular files/directories; never walk links or devices."""
    found = {}
    require(root.is_dir() and not root.is_symlink(), 'invalid artifact root')
    for parent, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in directories:
            require(not (Path(parent) / name).is_symlink(), 'linked artifact directory')
        for name in files:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            require(len(found) < 8192, 'artifact file count exceeded')
            found[relative] = digest_file(path)
    return found


def developer_requirement(team):
    require(type(team) is str and re.fullmatch(r'[A-Z0-9]{10}', team) is not None, 'invalid expected signing team')
    return ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
            'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
            f'certificate leaf[subject.OU] = "{team}"')


def verify_signature(path, team):
    run_tool(['/usr/bin/codesign', '--verify', '--strict', '-R', '=' + developer_requirement(team), path])


def parse_manifest(raw):
    rows = {}
    for line in raw.decode().splitlines():
        digest, separator, name = line.partition('  ')
        require(bool(separator) and valid_sha(digest) and bool(name)
                and not name.startswith('/') and '\\' not in name
                and all(part not in ('', '.', '..') for part in name.split('/'))
                and '\0' not in name and name not in rows, 'invalid or duplicate package manifest row')
        require(len(rows) < 8192, 'package manifest count exceeded')
        rows[name] = digest
    require(bool(rows), 'empty package manifest')
    return rows


def clean_image(image):
    """Validate build provenance carried inside the authenticated DMG payload."""
    require(type(image) is dict and image.get('schema') == 'ukai.vm.image-build/1'
            and image.get('status') == 'prepared', 'image is not prepared')
    revision = image.get('source_revision')
    require(type(revision) is str and REVISION.fullmatch(revision) is not None, 'image source revision absent')
    version = image.get('ukai_jail_version') or {}
    build = version.get('build') or {}
    require(version.get('component') == 'ukai-jail' and type(version.get('version')) is str
            and bool(version['version']) and build.get('revision') == revision
            and build.get('dirty') is False and build.get('debug_assertions') is False
            and build.get('opt_level') == '3' and build.get('target') == 'aarch64-apple-darwin'
            and type(build.get('inputs')) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', build['inputs']) is not None
            and type(build.get('rustc')) is str and build['rustc'].startswith('rustc 1.98.1 '),
            'host client is not the clean pinned optimized ARM build')
    for key in (*IMAGE_KEYS, 'ukai_vm_sha256', 'ukai_jail_sha256', 'source_archive_sha256',
                'compressed_disk_sha256', 'guest_source_sha256'):
        require(valid_sha(image.get(key)), 'image artifact identity absent: ' + key)
    require((image.get('source_sha256') or {}).get('guest.py') == image['guest_source_sha256'],
            'guest controller source identity disagrees')
    candidate = image.get('jail_candidate') or {}
    guest_build = (candidate.get('version') or {}).get('build') or {}
    require(candidate.get('kind') == 'signed-local-candidate' and candidate.get('signature_verified') is True
            and candidate.get('target') == 'aarch64-unknown-linux-gnu'
            and valid_sha(candidate.get('archive_sha256')) and valid_sha(candidate.get('binary_sha256'))
            and candidate.get('archive_sha256') == image.get('jail_archive_sha256')
            and type(candidate.get('source_revision')) is str
            and REVISION.fullmatch(candidate['source_revision']) is not None
            and guest_build.get('revision') == candidate['source_revision']
            and type(candidate.get('build_inputs')) is str
            and re.fullmatch(r'sha256:[0-9a-f]{64}', candidate['build_inputs']) is not None
            and guest_build.get('inputs') == candidate.get('build_inputs')
            and guest_build.get('dirty') is False and guest_build.get('debug_assertions') is False
            and guest_build.get('opt_level') == '3'
            and guest_build.get('target') == 'aarch64-unknown-linux-gnu'
            and type(guest_build.get('rustc')) is str and guest_build['rustc'].startswith('rustc 1.98.1 '),
            'signed image lacks clean guest candidate provenance')
    return version


def inspect_volume(home, volume, team):
    """Called only after authenticating and mounting the exact signed DMG."""
    raw_manifest = revocation.bounded_file(volume / 'SHA256SUMS', 1024 * 1024)
    manifest = parse_manifest(raw_manifest)
    actual = tree_files(volume)
    # SHA256SUMS is not self-hashed; the containing DMG signature binds it.
    # The rendered installer is also outside the payload manifest.
    require(set(actual) == set(manifest) | {'SHA256SUMS', 'install.sh'},
            'signed volume file set differs from the package contract')
    for name, digest in manifest.items():
        require(actual.get(name) == digest, 'signed payload differs from its manifest: ' + name)
    image_bytes = revocation.bounded_file(volume / 'payload/image/image.json', 1024 * 1024)
    image = compatibility.strict_json(image_bytes)
    expected_version = clean_image(image)
    expected = {name[len('payload/'):]: value for name, value in manifest.items() if name.startswith('payload/')}
    require(expected.get('image/base.raw.gz') == image['compressed_disk_sha256'], 'compressed image is not bound')
    expected.pop('image/base.raw.gz')
    expected['image/base.raw'] = image['disk_sha256']
    require(tree_files(home) == expected, 'installed tree is not the exact signed payload')
    for parent, directories, files in os.walk(home, followlinks=False, onerror=walk_error):
        require(stat.S_IMODE(Path(parent).stat().st_mode) == 0o755, 'installed directory mode differs')
        for name in files:
            relative = (Path(parent) / name).relative_to(home)
            source = volume / 'payload' / relative
            executable = source.exists() and bool(source.stat().st_mode & 0o111)
            mode = 0o755 if executable else 0o644
            require(stat.S_IMODE((Path(parent) / name).stat().st_mode) == mode,
                    'installed file mode differs: ' + relative.as_posix())
    require(manifest.get('preview-source.tar.gz') == image['source_archive_sha256'], 'source archive is not bound')
    binary_hashes = {'bin/ukai-vm': image['ukai_vm_sha256'], 'bin/ukai-jail': image['ukai_jail_sha256'],
                     'image/vz': image['helper_sha256'], 'image/custodian': image['custodian_sha256']}
    for relative, digest in binary_hashes.items():
        require(expected.get(relative) == digest, 'image executable identity disagrees')
        verify_signature(home / relative, team)
    # Execute only these already signature/hash-verified immutable commands.
    version = compatibility.strict_json(run_tool([home / 'bin/ukai-jail', 'version', '--json']).stdout)
    service_version = compatibility.strict_json(run_tool([home / 'bin/ukai-vm', 'version']).stdout)
    require(all(version.get(key) == expected_version.get(key) for key in ('component', 'version', 'build')),
            'installed client build differs from signed provenance')
    require(service_version.get('version') == image.get('preview_version')
            and type(image.get('preview_version')) is str and not image['preview_version'].endswith('-dev'),
            'installed service version differs from signed package')
    require(tree_files(home) == expected, 'installed payload changed during verification')
    return {'image': image, 'image_manifest_sha256': sha(image_bytes), 'manifest_sha256': sha(raw_manifest),
            'team_id': team, 'source_revision': image['source_revision'], 'client_build': version['build'],
            'service_sha256': image['ukai_vm_sha256'], 'client_sha256': image['ukai_jail_sha256']}


def verify_signed_install(home, dmg, team):
    home, dmg = Path(home).resolve(strict=True), Path(dmg).resolve(strict=True)
    digest = digest_file(dmg)
    verify_signature(dmg, team)
    with tempfile.TemporaryDirectory(prefix='ukai-credential-admission-') as temporary:
        # Darwin's default temporary directory is reached through /var,
        # a symlink; anchored evidence readers require the canonical parents.
        mount = Path(temporary).resolve(strict=True) / 'volume'
        mount.mkdir()
        mounted = False
        try:
            run_tool(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', mount, dmg])
            mounted = True
            identity = inspect_volume(home, mount, team)
        finally:
            if mounted:
                run_tool(['/usr/bin/hdiutil', 'detach', mount])
    require(digest_file(dmg) == digest, 'signed DMG changed during verification')
    return dict(identity, dmg_sha256=digest, signing='verified-developer-id',
                notarization='not-established-by-this-measurement')


def derive(replayed, installation):
    """Bind independently recomputed raw facts to authenticated installed bytes."""
    require(replayed.get('outcome') == 'PASS' and bool(replayed.get('facts'))
            and all(value is True for value in replayed['facts'].values())
            and not replayed.get('errors'), 'raw evidence does not replay as PASS')
    record, image = replayed['record'], replayed['image']
    require((record.get('ready') or {}).get('guest_contracts') == GUEST_CONTRACTS,
            'the actual guest did not declare the required credential contracts')
    require(image == installation['image'], 'raw attempt used another image')
    identity = replayed['identity']
    require(identity['binary']['sha256'] == installation['service_sha256']
            and identity['summary_binary']['sha256'] == installation['client_sha256']
            and identity['image_manifest_sha256'] == installation['image_manifest_sha256'],
            'raw attempt did not use these installed binaries/image')
    require(installation.get('signing') == 'verified-developer-id' and valid_sha(installation.get('dmg_sha256')),
            'installation signature verification absent')
    clean_image(image)
    require(valid_sha(replayed.get('inputs_sha256')), 'raw evidence digest absent')
    measured_at, attempt = record.get('started_at'), record.get('attempt_id')
    require(type(measured_at) is str and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', measured_at) is not None,
        'raw measurement time absent or not a UTC instant')
    try:
        datetime.datetime.fromisoformat(measured_at[:-1] + '+00:00')
    except ValueError as error:
        raise AdmissionError('invalid raw measurement time') from error
    require(type(attempt) is str and re.fullmatch(r'k113-raw-[A-Za-z0-9_-]+', attempt) is not None,
            'raw attempt identity absent')
    return {'schema': SCHEMA, 'outcome': 'PASS', 'qualified': False,
            'source_record_sha256': replayed['inputs_sha256'],
            'measurements': {'credential_staging': {'verdict': True, 'measured_at': measured_at,
                'attempt_id': attempt, 'guest_attempt_id': replayed['guest']['attempt_id'],
                'capability': 'credential_staging', 'scope': 'vault-only guest/service component',
                'not_measured': ['normal installed-client host-source watch', 'program-bound credentials',
                                 'credential refresh', 'copied/bound credentials', 'TLS/vendor compatibility',
                                 'K113/release qualification']}},
            'installation': installation, 'recomputed_facts': replayed['facts'],
            'scope': 'Guest admission evidence only; no capability-table change, host-source-watch or release qualification.',
            'compatibility': {'required_image': {key: image[key] for key in IMAGE_KEYS},
                              'required_guest_contracts': GUEST_CONTRACTS,
                              'guest_source_sha256': image['guest_source_sha256'],
                              'older_images_inherit_measurement': False}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('raw', 'installed', 'dmg', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--team-id', required=True)
    args = parser.parse_args(argv)
    out = harness.fresh_out_dir(args.out)
    try:
        replayed = revocation.replay_raw(args.raw)
        # Refuse failed evidence before any mount or installed executable.
        require(replayed.get('outcome') == 'PASS', 'raw replay failed')
        installation = verify_signed_install(args.installed, args.dmg, args.team_id)
        report = derive(replayed, installation)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        report = {'schema': SCHEMA, 'outcome': 'FAIL', 'qualified': False,
                  'error': str(error) if isinstance(error, AdmissionError) else type(error).__name__}
    harness.write_json(out / 'credential-staging.json', report)
    print(json.dumps({'outcome': report['outcome'], 'qualified': False}))
    return 0 if report['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
