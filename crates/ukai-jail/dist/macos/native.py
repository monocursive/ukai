#!/usr/bin/env python3
"""Stage, sign, or validate a native Ukai.app; none of these actions releases it."""
import argparse
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib

BUNDLE_ID = 'com.monocursive.ouroboros.jail'
ENTITLEMENT = 'com.apple.developer.endpoint-security.client'
APP = 'Ukai.app'
EXECUTABLE = 'Contents/MacOS/ukai-jail'
PROVENANCE = 'Contents/Resources/provenance.json'
SCHEMA = 'ukai.macos.package/1'
HERE = Path(__file__).resolve().parent
VERSION = re.compile(r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?')


class Refused(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def execute(argv, **kwargs):
    timeout = kwargs.pop('timeout', 120)
    return subprocess.run([str(arg) for arg in argv], check=True, capture_output=True,
                          timeout=timeout, **kwargs)


def environment():
    # In particular, never enable UKAI_JAIL_MACOS_NATIVE for a version check.
    return {name: os.environ[name] for name in ('HOME', 'PATH', 'TMPDIR') if name in os.environ}


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), f'Not a regular file: {path}')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            return source.read()
    finally:
        os.close(fd)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    path.chmod(0o644)


def bundle_files(app, partial_manifest=None):
    require(app.is_dir() and not app.is_symlink(), f'Not a real app directory: {app}')
    found = {}
    directories = set()
    for directory, children, files in os.walk(app, followlinks=False):
        directories.add(Path(directory).relative_to(app).as_posix())
        for name in children:
            child = Path(directory) / name
            require(not child.is_symlink(), f'Bundle directory is a symlink: {child}')
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(app).as_posix()
            data = read_regular(path)
            mode = stat.S_IMODE(path.stat().st_mode)
            require(mode == (0o755 if relative == EXECUTABLE else 0o644), f'Unsafe bundle mode: {relative}')
            found[relative] = {'sha256': digest(data), 'mode': mode}
        require(stat.S_IMODE(Path(directory).stat().st_mode) == 0o755,
                f'Unsafe bundle directory mode: {directory}')
    allowed_directories = {'.'}
    for relative in found if partial_manifest is None else partial_manifest:
        allowed_directories.update(parent.as_posix() for parent in Path(relative).parents)
    require(directories == allowed_directories if partial_manifest is None else directories <= allowed_directories,
            'Unexpected bundle directory layout')
    return found


def copy_bundle(source, destination, files):
    """Copy only the checked file list, then verify the exact copied bytes."""
    destination.mkdir(mode=0o755)
    for relative, expected in files.items():
        parts = Path(relative).parts
        require(parts and not Path(relative).is_absolute() and all(p not in ('.', '..') for p in parts),
                'Invalid bundle manifest path')
        data = read_regular(source / relative)
        require(digest(data) == expected['sha256'], f'Bundle changed during copy: {relative}')
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        output.chmod(expected['mode'])
    for directory, _, _ in os.walk(destination):
        Path(directory).chmod(0o755)
    require(bundle_files(destination) == files, 'Copied bundle differs from its manifest')


def git(repo, *args):
    return execute(['git', '--no-optional-locks', '-C', repo, *args]).stdout


def commit_inputs(repo, revision):
    """Independently reproduce build_provenance.rs's digest from Git objects."""
    other = ast.literal_eval(git(repo, 'show', f'{revision}:crates/ukai-jail/profiles/inputs.rs').decode())
    listed = git(repo, 'ls-tree', '-rz', '--full-tree', revision, '--', 'crates/ukai-jail/src').split(b'\0')
    paths = list(other)
    for entry in filter(None, listed):
        descriptor, name = entry.split(b'\t', 1)
        require(descriptor.startswith(b'100644 blob ') or descriptor.startswith(b'100755 blob '),
                'Source inputs must be regular Git blobs')
        paths.append(name.decode())
    hasher = hashlib.sha256()
    for name in sorted(paths):
        data = git(repo, 'show', f'{revision}:{name}')
        hasher.update(name.encode() + b'\0' + struct.pack('<Q', len(data)) + data)
    return 'sha256:' + hasher.hexdigest()


def version(binary, run=execute):
    value = json.loads(run([binary, 'version', '--json'], env=environment()).stdout)
    return {key: value[key] for key in ('component', 'version', 'build')}


def check_build(report, revision, inputs, pin):
    build = report.get('build', {})
    require(report.get('component') == 'ukai-jail' and isinstance(report.get('version'), str)
            and build.get('revision') == revision and build.get('dirty') is False
            and build.get('target') == 'aarch64-apple-darwin' and build.get('opt_level') == '3'
            and build.get('debug_assertions') is False and build.get('inputs') == inputs
            and str(build.get('rustc', '')).startswith(f'rustc {pin} '),
            'Expected a clean optimized Apple Silicon artifact from the named source inputs/toolchain')


def info_plist(release, number):
    require(VERSION.fullmatch(release) is not None and 1 <= number <= 9999,
            'Expected a semantic candidate version and build number in 1..9999')
    return {'CFBundleIdentifier': BUNDLE_ID, 'CFBundleExecutable': 'ukai-jail',
            'CFBundleName': 'Ukai', 'CFBundleDisplayName': 'Ukai', 'CFBundlePackageType': 'APPL',
            'CFBundleInfoDictionaryVersion': '6.0', 'CFBundleVersion': str(number),
            'CFBundleShortVersionString': release.split('-')[0], 'UkaiReleaseVersion': release,
            'LSMinimumSystemVersion': '27.0', 'LSBackgroundOnly': True}


def license_notices(repo, revision):
    # Staging alone needs source. Copied native.py/install.py remain standalone;
    # load_package verifies their embedded license bytes through the manifest.
    return execute([sys.executable, repo / 'crates/ukai-jail/dist/notices.py', 'print',
                    '--source', repo, '--revision', revision], env=environment()).stdout


def stage(binary, repo, out, release, number):
    revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', revision), 'Source HEAD is not a full commit')
    require(not git(repo, 'status', '--porcelain', '--untracked-files=all'), 'Source worktree is not clean')
    # Index flags must not hide changes from the clean-source assertion.
    require(all(line.startswith(b'H ') for line in git(repo, 'ls-files', '-v').splitlines()),
            'Source index contains assume-unchanged or skip-worktree entries')
    raw = read_regular(binary)
    require(len(raw) >= 8 and struct.unpack('<II', raw[:8]) == (0xfeedfacf, 0x0100000c),
            'Expected a native arm64 Mach-O executable')
    pin = tomllib.loads(git(repo, 'show', f'{revision}:rust-toolchain.toml').decode())['toolchain']['channel']
    inputs = commit_inputs(repo, revision)
    report = version(binary)
    check_build(report, revision, inputs, pin)
    require(read_regular(binary) == raw, 'Binary changed while its version was checked')
    provenance = {'source_revision': revision, 'build': report, 'toolchain': pin, 'release': release,
                  'build_number': number, 'native_execution': 'disabled-by-default',
                  'qualification': 'none; NC02/K104 and native workflows remain unsupported'}
    plist = info_plist(release, number)
    licenses = license_notices(repo, revision)
    out.mkdir(parents=True, exist_ok=False)
    app = out / APP
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/Resources').mkdir()
    (app / EXECUTABLE).write_bytes(raw)
    (app / EXECUTABLE).chmod(0o755)
    (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(plist))
    (app / 'Contents/Resources/LICENSES.txt').write_bytes(licenses)
    write_json(app / PROVENANCE, provenance)
    for directory, _, files in os.walk(app):
        Path(directory).chmod(0o755)
        for name in files:
            path = Path(directory) / name
            path.chmod(0o755 if path == app / EXECUTABLE else 0o644)
    for name in ('native.py', 'install.py', 'notarize.py', 'README.md'):
        shutil.copyfile(HERE / name, out / name)
    result = {'schema': SCHEMA, 'provenance': provenance, 'signing': 'unsigned',
              'notarization': 'not-submitted', 'qualified': False, 'published': False,
              'files': bundle_files(app)}
    write_json(out / 'package.json', result)
    return result


def load_package(root):
    report = json.loads(read_regular(root / 'package.json'))
    require(report.get('schema') == SCHEMA and report.get('qualified') is False
            and report.get('published') is False, 'Not an unqualified native candidate package')
    app = root / APP
    require(bundle_files(app) == report['files'], 'Bundle does not match package manifest')
    provenance = json.loads(read_regular(app / PROVENANCE))
    require(provenance == report['provenance'], 'Embedded and external provenance differ')
    require(re.fullmatch('[0-9a-f]{40}', provenance['source_revision'])
            and re.fullmatch(r'sha256:[0-9a-f]{64}', provenance['build']['build']['inputs'])
            and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', provenance['toolchain']),
            'Invalid recorded source/toolchain digest')
    check_build(provenance['build'], provenance['source_revision'],
                provenance['build']['build']['inputs'], provenance['toolchain'])
    require(provenance.get('native_execution') == 'disabled-by-default', 'Unexpected native execution claim')
    require(plistlib.loads(read_regular(app / 'Contents/Info.plist')) == info_plist(
        provenance['release'], provenance['build_number']), 'Unexpected bundle identity or layout')
    expected = {EXECUTABLE, PROVENANCE, 'Contents/Info.plist', 'Contents/Resources/LICENSES.txt'}
    if report['signing'] == 'developer-id':
        require(report['notarization'] in ('not-submitted', 'stapled'), 'Unknown notarization state')
        expected |= {'Contents/embedded.provisionprofile', 'Contents/_CodeSignature/CodeResources'}
        if report['notarization'] == 'stapled':
            expected.add('Contents/CodeResources')
    else:
        require(report['signing'] == 'unsigned', 'Unknown signing state')
        require(report['notarization'] == 'not-submitted', 'Unsigned bundle cannot claim notarization')
    require(set(report['files']) == expected, 'Unexpected bundle contents')
    return report


def profile_entitlements(data, now=None):
    """Metadata preflight only. Apple signature/runtime checks are mandatory below."""
    now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    allowed = data.get('Entitlements', {})
    teams = data.get('TeamIdentifier', [])
    require(len(teams) == 1 and re.fullmatch('[A-Z0-9]{10}', teams[0]), 'Invalid profile team')
    team = teams[0]
    require(data.get('ExpirationDate', datetime.datetime.min) > now, 'Expired profile')
    require(data.get('ProvisionsAllDevices') is True, 'A Developer ID distribution profile is required')
    require(allowed.get(ENTITLEMENT) is True, 'Profile does not authorize Endpoint Security')
    require(allowed.get('com.apple.application-identifier') == team + '.' + BUNDLE_ID
            and allowed.get('com.apple.developer.team-identifier') == team, 'Profile app/team mismatch')
    require(not allowed.get('com.apple.security.get-task-allow'), 'Development profile is not a release profile')
    return {ENTITLEMENT: True, 'com.apple.application-identifier': team + '.' + BUNDLE_ID,
            'com.apple.developer.team-identifier': team}


def requirement(team):
    require(re.fullmatch('[A-Z0-9]{10}', team), 'Invalid team')
    return (f'anchor apple generic and identifier "{BUNDLE_ID}" and '
            'certificate 1[field.1.2.840.113635.100.6.2.6] exists and '
            'certificate leaf[field.1.2.840.113635.100.6.1.13] exists and '
            f'certificate leaf[subject.OU] = "{team}"')


def protected_host(run=execute):
    # An ES-entitled launch on a SIP-disabled research VM cannot establish that
    # Apple authorized the profile. This is a bounded prerequisite, not host
    # attestation or protected-host native workload acceptance.
    env = environment()
    env['LC_ALL'] = 'C'
    status = run(['/usr/bin/csrutil', 'status'], env=env).stdout.strip()
    require(status == b'System Integrity Protection status: enabled.',
            'Signing validation requires standard enabled SIP; custom/unknown status is refused')


def verify_signature(app, report, run=execute, distribution=False):
    require(report['signing'] == 'developer-id', 'A Developer ID signed package is required')
    protected_host(run)
    team = report['team']
    run(['/usr/bin/codesign', '--verify', '--strict', '-R', requirement(team), app])
    details = run(['/usr/bin/codesign', '--display', '--verbose=4', app]).stderr.decode()
    require(re.search(r'flags=0x[0-9a-fA-F]+\([^\n)]*runtime', details), 'Hardened runtime is absent')
    claimed = plistlib.loads(run(['/usr/bin/codesign', '--display', '--entitlements', '-', '--xml', app]).stdout)
    decoded = plistlib.loads(run(['/usr/bin/security', 'cms', '-D', '-i', app / 'Contents/embedded.provisionprofile']).stdout)
    expected = profile_entitlements(decoded)
    require(claimed == expected and expected['com.apple.developer.team-identifier'] == team,
            'Signed entitlements differ from the exact approved-profile claim')
    # The OS validates restricted entitlements/provisioning at exec. Merely
    # decoding CMS/plist or trusting an external JSON report is not authority.
    # This runs only `version`; no development gate or workload is enabled.
    require(version(app / EXECUTABLE, run) == report['provenance']['build'],
            'Signed executable failed OS launch/provenance validation')
    if distribution:
        run(['/usr/bin/xcrun', 'stapler', 'validate', app])
        run(['/usr/bin/syspolicy_check', 'distribution', app, '--json'])


def sign(source, out, profile, identity, run=execute):
    report = load_package(source)
    require(report['signing'] == 'unsigned', 'Sign a fresh unsigned stage, never an existing signed candidate')
    require(identity.startswith('Developer ID Application: '), 'A Developer ID Application identity is required')
    raw_profile = read_regular(profile)
    decoded = plistlib.loads(run(['/usr/bin/security', 'cms', '-D', '-i', profile]).stdout)
    entitlements = profile_entitlements(decoded)
    protected_host(run)
    out.mkdir(parents=True, exist_ok=False)
    app = out / APP
    copy_bundle(source / APP, app, report['files'])
    (app / 'Contents/embedded.provisionprofile').write_bytes(raw_profile)
    (app / 'Contents/embedded.provisionprofile').chmod(0o644)
    try:
        with tempfile.TemporaryDirectory(prefix='ukai-sign-') as temporary:
            claim = Path(temporary) / 'entitlements.plist'
            claim.write_bytes(plistlib.dumps(entitlements))
            run(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
                 '--sign', identity, '--entitlements', claim, app])
        report.update(signing='developer-id', team=entitlements['com.apple.developer.team-identifier'],
                      profile_sha256=digest(raw_profile), notarization='not-submitted')
        verify_signature(app, report, run)
        report['files'] = bundle_files(app)
        for name in ('native.py', 'install.py', 'notarize.py', 'README.md'):
            shutil.copyfile(HERE / name, out / name)
        write_json(out / 'package.json', report)
        load_package(out)
    except BaseException:
        # Leave failed bytes for diagnosis, but never a usable package record.
        (out / 'package.json').unlink(missing_ok=True)
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    build = commands.add_parser('stage')
    for name in ('binary', 'source', 'out'):
        build.add_argument('--' + name, type=Path, required=True)
    build.add_argument('--version', required=True)
    build.add_argument('--build-number', type=int, required=True)
    signing = commands.add_parser('sign')
    for name in ('package', 'out', 'profile'):
        signing.add_argument('--' + name, type=Path, required=True)
    signing.add_argument('--identity', required=True)
    validation = commands.add_parser('validate')
    validation.add_argument('--package', type=Path, required=True)
    validation.add_argument('--distribution', action='store_true')
    args = parser.parse_args()
    try:
        if args.action == 'stage':
            report = stage(args.binary, args.source, args.out, args.version, args.build_number)
        elif args.action == 'sign':
            report = sign(args.package, args.out, args.profile, args.identity)
        else:
            report = load_package(args.package)
            if report['signing'] == 'developer-id' or args.distribution:
                verify_signature(args.package / APP, report, distribution=args.distribution)
        print(json.dumps({'signing': report['signing'], 'qualified': False, 'published': False}))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Refused: {error}\n')


if __name__ == '__main__':
    main()
