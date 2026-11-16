#!/usr/bin/env python3
"""Exercise the actual offline installer without host developer-tool PATH entries.

`summary.json` names the artifact it judged: the volume's manifest and
installer digests (and the DMG's, with --dmg). The `install` case passes only
when both installed commands run, the service reports the package version the
installer names (D8: never a `-dev` build) AND the installed tree is exactly
the manifest's payload: every file with its listed digest, `image/base.raw.gz`
replaced by `image/base.raw` with image.json's `disk_sha256`, nothing extra
and no symlink — AND every installed mode is normalized (directories 0755,
files 0644, or 0755 where the volume's file is executable; never a
world-writable or setuid bit, which the manifest does not cover). The tamper
cases include an unlisted payload file, which the installer must refuse
rather than install. A passed tamper case retains its mutation, output and
postcondition proof before removing only its generated copy of the volume.
Unexpected failures retain their fixture for diagnosis.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

if not __debug__:
    raise SystemExit('check_install.py must not run with python -O: its checks are gates')

SCHEMA = 'ukai.vm.installer-check/3'
CASES = ('install', 'repeat-refused', 'unrelated-refused', 'unrelated-client-refused',
         'manifest-tamper', 'payload-tamper', 'payload-extra')


class CaseFailed(RuntimeError):
    pass


def identity(info):
    return [info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_uid]


def fixture_snapshot(descriptor):
    """Metadata of a small generated volume, anchored to its open directory."""
    entries = {}
    for directory, names, files, current in os.fwalk('.', dir_fd=descriptor, follow_symlinks=False):
        for name in ['.', *names, *files]:
            relative = str(Path(directory) / name)
            info = os.stat(name, dir_fd=current, follow_symlinks=False)
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
                raise CaseFailed('unexpected generated fixture entry')
            entries[relative] = [*identity(info), info.st_mode, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]
            if len(entries) > 4096:
                raise CaseFailed('generated fixture inventory exceeds bound')
    return entries


def capture_fixture(root, name):
    if name not in CASES[-3:]:
        raise CaseFailed('not a generated tamper fixture')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    try:
        child = os.open(name, flags, dir_fd=parent)
        try:
            return {'parent_identity': identity(os.fstat(parent)),
                    'entries': fixture_snapshot(child)}
        finally:
            os.close(child)
    finally:
        os.close(parent)


def remove_owned_fixture(root, name, captured):
    """Remove only a still-identical fixture through its pinned directory FD."""
    if name not in CASES[-3:] or not shutil.rmtree.avoids_symlink_attacks:
        raise CaseFailed('safe generated fixture removal unavailable')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(root, flags)
    try:
        if identity(os.fstat(parent)) != captured['parent_identity']:
            raise CaseFailed('fixture parent changed')
        child = os.open(name, flags, dir_fd=parent)
        try:
            if fixture_snapshot(child) != captured['entries']:
                raise CaseFailed('generated fixture changed')
            # Use the pinned child, not its pathname, for every descendant.
            # A replaced top-level name is checked again before removing it.
            with os.scandir(child) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(entry.name, dir_fd=child)
                    else:
                        os.unlink(entry.name, dir_fd=child)
            if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != captured['entries']['.'][:4]:
                raise CaseFailed('generated fixture name changed')
            os.rmdir(name, dir_fd=parent)
        finally:
            os.close(child)
        if os.path.lexists(root / name):
            raise CaseFailed('generated fixture remains')
    finally:
        os.close(parent)


def persist_fixture_record(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def retire_passed_fixture(results, root, name, captured, artifact, mutation):
    """A proof-write or cleanup failure fails the case and stops the sequence."""
    row = results[-1]
    if row['case'] != name or row['passed'] is not True or row['failed_checks']:
        raise CaseFailed('only a passed expected-negative fixture may be removed')
    check = 'generated-fixture-proof-retained'
    try:
        proof = {'schema': 'ukai.vm.installer-fixture-proof/1', 'case': row.copy(),
                 'artifact': artifact, 'fixture': captured, 'mutation': mutation,
                 'postconditions': {'nothing-installed': True},
                 'stdout_sha256': sha256(root / (name + '.stdout')),
                 'stderr_sha256': sha256(root / (name + '.stderr'))}
        persist_fixture_record(root / (name + '.fixture.json'), proof)
        check = 'generated-fixture-cleanup'
        remove_owned_fixture(root, name, captured)
        persist_fixture_record(root / (name + '.cleanup.json'), {'case': name, 'removed': True})
    except BaseException:
        row['passed'] = False
        row['failed_checks'].append(check)
        raise


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def run_case(results, root, name, argv, environment, expected, message, postconditions=()):
    """Run one installer case and record it as passed only if every check held.

    Postconditions are evaluated before the case is recorded, so the summary
    can never report a case as passed while its after-state was wrong.
    """
    result = subprocess.run(argv, env=environment, capture_output=True, text=True)
    (root / (name + '.stdout')).write_text(result.stdout)
    (root / (name + '.stderr')).write_text(result.stderr)
    checks = {'exit_code': result.returncode == expected, 'message': message in result.stdout + result.stderr}
    errors = []
    for label, check in postconditions:
        try:
            checks[label] = check()
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            checks[label] = False
            errors.append(f'{label}: {error}')
    failed = [label for label, held in checks.items() if held is not True]
    results.append({'case': name, 'exit_code': result.returncode, 'passed': not failed, 'failed_checks': failed})
    if failed:
        raise CaseFailed(f'{name} failed {failed} {errors}: {result.stderr}')


def manifest_payload(volume):
    """{payload-relative path: sha256} as the volume's SHA256SUMS lists them."""
    entries = {}
    for line in (Path(volume) / 'SHA256SUMS').read_text().splitlines():
        digest, separator, name = line.partition('  ')
        if separator and name.startswith('payload/'):
            entries[name[len('payload/'):]] = digest
    return entries


def installed_tree_matches(volume, destination):
    """The installed tree is exactly the manifest's payload (base.raw expanded)."""
    destination = Path(destination)
    expected = manifest_payload(volume)
    if 'image/base.raw.gz' in expected:
        del expected['image/base.raw.gz']
        expected['image/base.raw'] = json.loads((destination / 'image' / 'image.json').read_text())['disk_sha256']
    installed = {}
    for path in destination.rglob('*'):
        if path.is_symlink():
            return False
        if path.is_file():
            installed[str(path.relative_to(destination))] = sha256(path)
    return bool(expected) and installed == expected


def installed_modes_normal(volume, destination):
    """Every installed mode is the normalized one install.sh sets, whatever the volume's."""
    import stat
    destination = Path(destination)
    payload = Path(volume) / 'payload'
    found = False
    for path in [destination, *destination.rglob('*')]:
        mode = stat.S_IMODE(path.lstat().st_mode)
        if path.is_symlink():
            return False
        if path.is_dir():
            if mode != 0o755:
                return False
            continue
        relative = path.relative_to(destination)
        source = payload / relative
        if str(relative) == 'image/base.raw':
            source = payload / 'image' / 'base.raw.gz'
        executable = source.is_file() and bool(stat.S_IMODE(source.stat().st_mode) & 0o111)
        if mode != (0o755 if executable else 0o644):
            return False
        found = True
    return found


def package_version(volume):
    """The version the rendered installer names (`version='…'`, package.py's @VERSION@)."""
    for line in (Path(volume) / 'install.sh').read_text().splitlines():
        if line.startswith("version='") and line.endswith("'"):
            return line[len("version='"):-1]
    raise ValueError('install.sh names no version')


def version_is_the_package(output, expected):
    """`ukai-vm version` prints JSON whose version is exactly the package's."""
    reported = json.loads(output).get('version')
    return isinstance(reported, str) and reported == expected and not reported.endswith('-dev')


def client_is_the_package(output, metadata):
    """The client's immutable build report matches the package's source claim."""
    reported = json.loads(output)
    expected = metadata['ukai_jail_version']
    build = reported.get('build', {})
    return (reported.get('component') == expected.get('component') == 'ukai-jail'
            and reported.get('version') == expected.get('version')
            and build == expected.get('build')
            and build.get('revision') == metadata.get('source_revision')
            and build.get('dirty') is False
            and build.get('target') == 'aarch64-apple-darwin')


def installed_destination(link):
    """The installed version directory the command link names."""
    target = Path(os.readlink(link))
    if target.name != 'ukai-vm' or target.parent.name != 'bin':
        raise ValueError(f'{link} points at {target}, not <version>/bin/ukai-vm')
    return target.parent.parent


def summary(results, artifact=None):
    passed = tuple(r['case'] for r in results) == CASES and all(r['passed'] is True for r in results)
    return {'schema': SCHEMA, 'artifact': artifact, 'results': results,
            'passed': passed and bool(artifact and artifact.get('manifest_sha256'))}


def artifact_identity(volume, dmg=None):
    identity = {'volume': str(volume), 'version': package_version(volume),
                'manifest_sha256': sha256(volume / 'SHA256SUMS'),
                'installer_sha256': sha256(volume / 'install.sh')}
    if dmg is not None:
        identity['dmg'] = Path(dmg).name
        identity['dmg_sha256'] = sha256(dmg)
    return identity


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--volume', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--dmg', type=Path, help='the DMG the volume was mounted from, to bind its digest')
    args = parser.parse_args(argv)
    source = args.volume.resolve()
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    environment = {'HOME': os.environ['HOME'], 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
    results = []
    artifact = artifact_identity(source, args.dmg)

    def invoke(name, volume, prefix, expected, message, postconditions=()):
        run_case(results, root, name, ['/bin/bash', str(volume / 'install.sh'), '--prefix', str(prefix)],
                 environment, expected, message, postconditions)

    try:
        installed = root / 'prefix with spaces'
        link = installed / 'bin' / 'ukai-vm'

        def version_runs():
            version = subprocess.run([str(link), 'version'], env=environment, capture_output=True, text=True)
            (root / 'version.json').write_text(version.stdout)
            return version.returncode == 0 and version_is_the_package(version.stdout, package_version(source))

        def client_runs():
            client = installed / 'bin' / 'ukai-jail'
            destination = installed_destination(link)
            if not client.is_symlink() or Path(os.readlink(client)) != destination / 'bin' / 'ukai-jail':
                return False
            version = subprocess.run([str(client), 'version', '--json'], env=environment,
                                     capture_output=True, text=True)
            (root / 'client-version.json').write_text(version.stdout)
            metadata = json.loads((destination / 'image' / 'image.json').read_text())
            return version.returncode == 0 and client_is_the_package(version.stdout, metadata)

        invoke('install', source, installed, 0, 'Installed ',
               [('installed-command-runs', version_runs),
                ('installed-client-matches-package', client_runs),
                ('installed-tree-is-the-manifest', lambda: installed_tree_matches(source, installed_destination(link))),
                ('installed-modes-normalized', lambda: installed_modes_normal(source, installed_destination(link)))])
        invoke('repeat-refused', source, installed, 2, 'Already installed:')
        unrelated = root / 'unrelated'
        (unrelated / 'bin').mkdir(parents=True)
        marker = unrelated / 'bin' / 'ukai-vm'
        marker.write_text('preserve me')
        invoke('unrelated-refused', source, unrelated, 2, 'unrelated command:',
               [('unrelated-command-preserved', lambda: marker.read_text() == 'preserve me')])
        unrelated_client = root / 'unrelated-client'
        (unrelated_client / 'bin').mkdir(parents=True)
        client_marker = unrelated_client / 'bin' / 'ukai-jail'
        client_marker.write_text('preserve client')
        invoke('unrelated-client-refused', source, unrelated_client, 2, 'unrelated command:',
               [('unrelated-client-preserved', lambda: client_marker.read_text() == 'preserve client'),
                ('no-service-installed', lambda: not os.path.lexists(unrelated_client / 'bin' / 'ukai-vm')
                 and not (unrelated_client / 'share').exists())])
        for case, filename, expected, append in [
                ('manifest-tamper', 'SHA256SUMS', 'manifest checksum mismatch', True),
                ('payload-tamper', 'payload/image/vz', 'Package checksum mismatch', True),
                ('payload-extra', 'payload/bin/unlisted', 'manifest does not list', False)]:
            clone = root / case
            subprocess.run(['/bin/cp', '-cR', str(source), str(clone)], check=True)
            target = clone / filename
            original_sha256 = sha256(target) if append else None
            with target.open('ab' if append else 'xb') as output:
                output.write(b'tampered')
            mutation = {'path': filename, 'operation': 'append' if append else 'exclusive-create',
                        'bytes_hex': b'tampered'.hex(), 'original_sha256': original_sha256,
                        'mutated_sha256': sha256(target)}
            captured = capture_fixture(root, case)
            destination = root / (case + '-prefix')
            invoke(case, clone, destination, 1, expected,
                   [('nothing-installed', lambda destination=destination: not os.path.lexists(destination))])
            retire_passed_fixture(results, root, case, captured, artifact, mutation)
    finally:
        (root / 'summary.json').write_text(json.dumps(summary(results, artifact), indent=2) + '\n')


if __name__ == '__main__':
    main()
