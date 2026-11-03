#!/usr/bin/env python3
"""Build a signed, offline macOS preview DMG from a verified prepared image.

Run in a venv installed with --require-hashes from requirements-build.txt.
Notarization is a separate explicit command so its result is retained.

What ships is built from one committed revision, recorded as
`source_revision`: the build refuses when HEAD's tree differs from the
committed state anywhere under the jail's build inputs (build_provenance.rs's
INPUT_DIR and profiles/inputs.rs) or the archived source paths, builds
`ukai-vm` with `--locked` into an explicit `--target-dir` (copied from there,
never from a default target/), with UKAI_BUILD_REVISION=<HEAD>,
UKAI_BUILD_DIRTY=false (build.rs re-checks the tree) and
UKAI_VM_PACKAGE_VERSION=<release.json vm.candidate_version> (D8/D11), and
refuses a binary whose `version` reports anything else. preview-source.tar.gz
holds the workspace at that revision: enough to rebuild ukai-vm, the VZ
client, the custodian and the installer helper.
"""
import argparse
import ast
import gzip
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

from cli import VERSION
from run import digest

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
RELEASE = REPO / 'crates' / 'ukai-jail' / 'dist' / 'release.json'
# The jail's build inputs, as build_provenance.rs names them: every file
# under INPUT_DIR plus the list in profiles/inputs.rs. build.rs refuses a
# `UKAI_BUILD_DIRTY=false` claim when any of them differs from the revision.
INPUT_DIR = 'crates/ukai-jail/src'
INPUTS_LIST = REPO / 'crates' / 'ukai-jail' / 'profiles' / 'inputs.rs'
# What preview-source.tar.gz carries: the workspace (every crate, the lock
# file, the toolchain pin and cargo config), the VM tooling under crates/,
# and the build inputs outside crates/. Together they build every shipped
# binary: ukai-vm (cargo), vz (swiftc), custodian (clang), ukai-vm-install
# (PyInstaller over vm/cli.py).
SOURCE_PATHS = ('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'LICENSE', '.cargo/config.toml', 'crates')


class SourceError(ValueError):
    pass


def command(*args, env=None):
    subprocess.run([str(arg) for arg in args], check=True, env=env)


def release_coordinates():
    """dist/coordinates.py, loaded by path as prepare.py does (dist/ also holds a package.py)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location('ukai_release_coordinates_for_package',
                                                  RELEASE.with_name('coordinates.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_version(coordinates=None):
    """The version this package builds: VM_CANDIDATE_VERSION, release.json's
    vm.candidate_version (D11).

    `VM_VERSION` (vm.version) is what the public installer pins; the candidate
    is what is packaged. Absent or malformed, the build refuses rather than
    guess, and never falls back to the published version.
    """
    coordinates = release_coordinates() if coordinates is None else coordinates
    value = getattr(coordinates, 'VM_CANDIDATE_VERSION', None)
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', value):
        raise SourceError('dist/coordinates.py names no VM_CANDIDATE_VERSION (release.json '
                          'vm.candidate_version); the package version is never guessed')
    return value


def build_inputs(inputs=INPUTS_LIST):
    """INPUT_DIR plus profiles/inputs.rs's list (a Rust array of string literals)."""
    files = ast.literal_eval(Path(inputs).read_text())
    if not isinstance(files, list) or not files or not all(isinstance(name, str) for name in files):
        raise SourceError(f'{inputs} is not a list of build input paths')
    return [INPUT_DIR, *files]


def git_lines(repo, *args):
    try:
        return subprocess.run(['git', '--no-optional-locks', '-C', str(repo), *args],
                              capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise SourceError(f'git {args[0]} failed: {error}') from error


def head_revision(repo=REPO):
    revision = git_lines(repo, 'rev-parse', 'HEAD').decode().strip()
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise SourceError(f'HEAD is not a full commit: {revision!r}')
    return revision


def require_clean(repo, paths):
    """Refuse any change, staged or not, tracked or untracked, under `paths`."""
    changes = git_lines(repo, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--', *paths)
    if changes:
        listed = sorted({entry[3:].decode(errors='replace') for entry in changes.split(b'\0') if len(entry) > 3})
        raise SourceError('build inputs have uncommitted changes: ' + ', '.join(listed[:20]))


def archive_paths():
    """The pathspecs preview-source.tar.gz archives: SOURCE_PATHS and every build input."""
    return sorted(set(SOURCE_PATHS) | set(build_inputs()))


def listed_sources(repo, paths):
    """The committed files under `paths` (git's index), sorted."""
    return sorted(os.fsdecode(name) for name in git_lines(repo, 'ls-files', '-z', '--', *paths).split(b'\0') if name)


def tree_sources(repo, paths):
    """{repo-relative path: sha256} of every committed file under `paths`, refusing changes."""
    require_clean(repo, paths)
    names = listed_sources(repo, paths)
    if not names:
        raise SourceError('no committed sources found')
    return {name: digest(Path(repo) / name) for name in names}


def committed_sources(directory):
    """List the committed files under `directory`, refusing uncommitted changes to them.

    preview-source.tar.gz claims to be this preview's source, so untracked
    strays (bytecode caches, local outputs) are never included, and an
    edited, staged or deleted tracked file stops the build.
    """
    def git(*args):
        try:
            return subprocess.run(['git', '--no-optional-locks', '-C', str(directory), *args],
                                  capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as error:
            raise SourceError(f'cannot list committed preview sources with git: {error}') from error

    if git('status', '--porcelain=v1', '-z', '--untracked-files=no', '--', '.'):
        raise SourceError('preview sources have uncommitted changes')
    names = sorted(os.fsdecode(name) for name in git('ls-files', '-z', '--', '.').split(b'\0') if name)
    if not names:
        raise SourceError('no committed preview sources found')
    return names


def verify_prepared_sources(recorded, current):
    """Refuse unless the committed sources reproduce every hash prepare.py recorded.

    prepare.py records the sources that built the prepared disk, seed and
    helpers, and the prepared-image fault checks measured those helpers.
    Requiring every one keeps the package, its archived source and that
    evidence on one set of sources.
    """
    if not isinstance(recorded, dict) or 'guest.py' not in recorded:
        raise SourceError('prepared image does not record its guest source')
    changed = sorted(name for name, value in recorded.items() if current.get(name) != value)
    if changed:
        raise SourceError('prepared image was built from other sources: ' + ', '.join(changed))


def write_source_archive(path, directory, sources, prefix='vm/'):
    """Archive under `prefix` exactly the bytes whose SHA-256 `sources` recorded."""
    with tarfile.open(path, 'w:gz') as archive:
        for name, expected in sorted(sources.items()):
            source = directory / name
            info = archive.gettarinfo(source, arcname=prefix + name)
            if not info.isreg():
                raise SourceError('preview source is not a regular file: ' + name)
            data = source.read_bytes()
            if len(data) != info.size or hashlib.sha256(data).hexdigest() != expected:
                raise SourceError('preview source changed while packaging: ' + name)
            archive.addfile(info, io.BytesIO(data))


def package_metadata(metadata, sources, **artifacts):
    """Extend prepared-image provenance without changing what its fields mean.

    `source_sha256` stays the prepare-time hashes of the sources that built
    the image; `package_source_sha256` is every committed vm/ file (the
    preview tooling) at the packaged revision; the whole source archive is
    named by `source_revision` and `source_archive_sha256` in `artifacts`.
    """
    return {**metadata, 'preview_version': VERSION, 'host_minimum': 'macOS 27; Apple Silicon', **artifacts,
            'package_source_sha256': sources, 'guest_source_sha256': metadata['source_sha256']['guest.py']}


def built_version(binary):
    """The version `ukai-vm version` reports (D8: the package version it was built with)."""
    output = subprocess.run([str(binary), 'version'], capture_output=True, text=True, check=True).stdout
    return json.loads(output).get('version')


def build_ukai_vm(target_dir, revision, version, run=command):
    """cargo build --locked into an explicit target dir; returns the built binary.

    UKAI_BUILD_REVISION/UKAI_BUILD_DIRTY=false make build.rs check the tree
    against HEAD itself; UKAI_VM_PACKAGE_VERSION is what `ukai-vm version`
    prints. CARGO_TARGET_DIR is dropped so only `--target-dir` decides where
    the binary comes from.
    """
    environment = {key: value for key, value in os.environ.items() if key != 'CARGO_TARGET_DIR'}
    environment.update(UKAI_BUILD_REVISION=revision, UKAI_BUILD_DIRTY='false',
                       UKAI_VM_PACKAGE_VERSION=version)
    run('cargo', 'build', '--release', '--locked', '--package', 'ukai-jail', '--bin', 'ukai-vm',
        '--manifest-path', REPO / 'Cargo.toml', '--target-dir', target_dir, env=environment)
    return Path(target_dir) / 'release' / 'ukai-vm', {
        'cargo_target_dir': str(target_dir), 'locked': True,
        'environment': {'UKAI_BUILD_REVISION': revision, 'UKAI_BUILD_DIRTY': 'false',
                        'UKAI_VM_PACKAGE_VERSION': version}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--identity', required=True, help='Developer ID Application identity')
    parser.add_argument('--jail-archive', required=True, type=Path)
    parser.add_argument('--target-dir', type=Path,
                        help='cargo target dir to build ukai-vm in (default: a fresh one under --out)')
    args = parser.parse_args()
    prepared = args.image.resolve()
    metadata = json.loads((prepared / 'image.json').read_text())
    try:
        version = candidate_version()
        if version != VERSION:
            raise SourceError(f'cli.VERSION is {VERSION} but release.json vm.candidate_version is {version}')
        revision = head_revision()
        sources = {name: digest(SOURCE / name) for name in committed_sources(SOURCE)}
        verify_prepared_sources(metadata.get('source_sha256'), sources)
        # Every binary the package ships is built from the committed tree:
        # the jail's build inputs (what build.rs checks) and the archived
        # source paths must all match HEAD.
        require_clean(REPO, build_inputs())
        archived = tree_sources(REPO, archive_paths())
    except SourceError as error:
        parser.error(str(error))
    if (metadata['status'] != 'prepared' or digest(prepared / 'base.raw') != metadata['disk_sha256']
            or digest(prepared / 'seed.iso') != metadata['seed_sha256']
            or digest(args.jail_archive) != metadata['jail_archive_sha256']):
        parser.error('prepared disk, seed, or Linux archive does not match provenance')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    volume = out / 'volume'
    payload = volume / 'payload'
    image = payload / 'image'
    binaries = payload / 'bin'
    image.mkdir(parents=True)
    binaries.mkdir()
    command('xcrun', 'swiftc', '-warnings-as-errors', '-O', SOURCE / 'vz.swift', '-o', image / 'vz')
    command('xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-O2', SOURCE / 'custodian.c', '-o', image / 'custodian')
    for name in ('vz', 'custodian'):
        flags = ['--entitlements', SOURCE / 'entitlements.plist'] if name == 'vz' else []
        command('codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', args.identity, *flags, image / name)
        command('codesign', '--verify', '--strict', image / name)
    # The operator surface is the warm service (`ukai-vm serve`, the program
    # `ukai-jail run --vm` starts), built from the committed Rust sources at
    # `revision` into an explicit target dir, and copied from exactly there.
    target_dir = (args.target_dir or out / 'cargo-target').resolve()
    built, build = build_ukai_vm(target_dir, revision, version)
    reported = built_version(built)
    if reported != version:
        parser.error(f'the built ukai-vm reports version {reported!r}, not {version}')
    try:
        if head_revision() != revision:
            raise SourceError('HEAD moved during the build')
        require_clean(REPO, build_inputs())
    except SourceError as error:
        parser.error(str(error))
    shutil.copy2(built, binaries / 'ukai-vm')
    command('codesign', '--force', '--options', 'runtime', '--timestamp',
            '--sign', args.identity, binaries / 'ukai-vm')
    command('codesign', '--verify', '--strict', binaries / 'ukai-vm')
    # The installer helper keeps the preview's install-time verbs
    # (`expand-image`, `doctor`, `version`); only install.sh calls it. A
    # onefile build keeps `bin/` free of a second `_internal` tree beside
    # the service binary.
    command(sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--console',
            '--name', 'ukai-vm-install', '--codesign-identity', args.identity,
            '--distpath', out / 'dist', '--workpath', out / 'work', '--specpath', out,
            SOURCE / 'cli.py')
    shutil.move(out / 'dist' / 'ukai-vm-install', binaries / 'ukai-vm-install')
    shutil.copy2(prepared / 'seed.iso', image / 'seed.iso')
    print('Compressing verified guest image', flush=True)
    with (prepared / 'base.raw').open('rb') as source, (image / 'base.raw.gz').open('wb') as output:
        with gzip.GzipFile(filename='', mode='wb', compresslevel=6, fileobj=output, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed, 1024 * 1024)
    source_archive = volume / 'preview-source.tar.gz'
    write_source_archive(source_archive, REPO, archived, prefix=f'ukai-vm-{VERSION}-source/')
    metadata = package_metadata(metadata, sources, helper_sha256=digest(image / 'vz'),
                                custodian_sha256=digest(image / 'custodian'),
                                ukai_vm_sha256=digest(binaries / 'ukai-vm'),
                                compressed_disk_sha256=digest(image / 'base.raw.gz'),
                                source_revision=revision, source_archive_sha256=digest(source_archive),
                                source_archive_files=len(archived))
    (image / 'image.json').write_text(json.dumps(metadata, indent=2) + '\n')
    notices = payload / 'licenses'
    notices.mkdir()
    shutil.copy2(REPO / 'LICENSE', notices / 'Ukai-LICENSE.txt')
    with tarfile.open(args.jail_archive) as archive:
        for member in archive.getmembers():
            if member.isfile() and member.name.endswith('LICENSES.txt'):
                (notices / 'Linux-Jail-LICENSES.txt').write_bytes(archive.extractfile(member).read())
    # Runtime licenses, including the PyInstaller bootloader exception.
    for package in ('pyinstaller',):
        distribution = importlib.metadata.distribution(package)
        for relative in distribution.files:
            if 'license' in str(relative).lower() and distribution.locate_file(relative).is_file():
                shutil.copy2(distribution.locate_file(relative), notices / (package + '-' + Path(relative).name))
    python_license = Path(sys.base_prefix) / 'lib' / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'LICENSE.txt'
    if not python_license.is_file():
        raise RuntimeError('bundled Python license was not found')
    shutil.copy2(python_license, notices / 'Python-LICENSE.txt')
    shutil.copy2(SOURCE / 'PREVIEW.txt', volume / 'READ-ME.txt')
    files = sorted(path for path in volume.rglob('*') if path.is_file())
    manifest = volume / 'SHA256SUMS'
    manifest.write_text(''.join(f'{digest(path)}  {path.relative_to(volume)}\n' for path in files))
    installer = (SOURCE / 'install.sh.in').read_text().replace('@VERSION@', VERSION).replace('@MANIFEST_SHA256@', digest(manifest))
    (volume / 'install.sh').write_text(installer)
    (volume / 'install.sh').chmod(0o755)
    command('bash', '-n', volume / 'install.sh')
    dmg = out / f'ukai-vm-{VERSION}-macos-arm64.dmg'
    command('hdiutil', 'create', '-quiet', '-fs', 'APFS', '-volname', 'Ukai VM Preview',
            '-srcfolder', volume, '-format', 'UDRO', dmg)
    command('codesign', '--force', '--timestamp', '--sign', args.identity, dmg)
    report = {'schema': 'ukai.vm.package/1', 'version': VERSION, 'dmg': dmg.name,
              'source_revision': revision, 'build': {**build, 'ukai_vm_version': reported},
              'dmg_sha256_before_notarization': digest(dmg), 'manifest_sha256': digest(manifest),
              'installer_sha256': digest(volume / 'install.sh'), 'image': metadata,
              'python_version': sys.version, 'pyinstaller_version': importlib.metadata.version('pyinstaller'),
              'notarization': 'pending', 'published': False}
    (out / 'package.json').write_text(json.dumps(report, indent=2) + '\n')
    print(dmg)


if __name__ == '__main__':
    main()
