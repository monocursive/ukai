#!/usr/bin/env python3
"""Exercise the actual offline installer without host developer-tool PATH entries.

`summary.json` names the artifact it judged: the volume's manifest and
installer digests (and the DMG's, with --dmg). The `install` case passes only
when the installed command runs and reports exactly the package version the
installer names (D8: never a `-dev` build) AND the installed tree is exactly
the manifest's payload: every file with its listed digest, `image/base.raw.gz`
replaced by `image/base.raw` with image.json's `disk_sha256`, nothing extra
and no symlink. The tamper cases include an unlisted payload file, which the
installer must refuse rather than install.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

if not __debug__:
    raise SystemExit('check_install.py must not run with python -O: its checks are gates')

SCHEMA = 'ukai.vm.installer-check/2'
CASES = ('install', 'repeat-refused', 'unrelated-refused', 'manifest-tamper', 'payload-tamper', 'payload-extra')


class CaseFailed(RuntimeError):
    pass


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

        invoke('install', source, installed, 0, 'Installed ',
               [('installed-command-runs', version_runs),
                ('installed-tree-is-the-manifest', lambda: installed_tree_matches(source, installed_destination(link)))])
        invoke('repeat-refused', source, installed, 2, 'Already installed:')
        unrelated = root / 'unrelated'
        (unrelated / 'bin').mkdir(parents=True)
        marker = unrelated / 'bin' / 'ukai-vm'
        marker.write_text('preserve me')
        invoke('unrelated-refused', source, unrelated, 2, 'unrelated command:',
               [('unrelated-command-preserved', lambda: marker.read_text() == 'preserve me')])
        for case, filename, expected, append in [
                ('manifest-tamper', 'SHA256SUMS', 'manifest checksum mismatch', True),
                ('payload-tamper', 'payload/image/vz', 'Package checksum mismatch', True),
                ('payload-extra', 'payload/bin/unlisted', 'manifest does not list', False)]:
            clone = root / case
            subprocess.run(['/bin/cp', '-cR', str(source), str(clone)], check=True)
            target = clone / filename
            with target.open('ab' if append else 'xb') as output:
                output.write(b'tampered')
            destination = root / (case + '-prefix')
            invoke(case, clone, destination, 1, expected,
                   [('nothing-installed', lambda destination=destination: not os.path.lexists(destination))])
    finally:
        (root / 'summary.json').write_text(json.dumps(summary(results, artifact), indent=2) + '\n')


if __name__ == '__main__':
    main()
