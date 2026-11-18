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
import stat
import subprocess
import sys
import tarfile
import urllib.request

import guest_program

SOURCE = Path(__file__).resolve().parent

# An immutable Ubuntu archive snapshot (https://snapshot.ubuntu.com): the
# builder resolves packages against exactly this archive state, so two
# builds see the same versions. The manifest records the pin; a build
# against a different snapshot is a different image.
SNAPSHOT = '20261106T000000Z'
SNAPSHOT_URL = 'https://snapshot.ubuntu.com/ubuntu/' + SNAPSHOT
APT_SUITES = ('stonking', 'stonking-updates', 'stonking-security')


def snapshot_sources():
    return (f'Types: deb\nURIs: {SNAPSHOT_URL}\nSuites: {" ".join(APT_SUITES)}\n'
            'Components: main universe\n'
            'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n')


# The guest executes these exact bytes; host tests exercise the same guard on
# small fixtures. This checks the standard source paths, not apt.conf or hooks.
APT_SOURCE_GUARD = '''import hashlib, os, stat, sys

def refuse(code):
    raise ValueError(code)

def verify(root, expected):
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root_fd = os.open(root, directory_flags)
    count = total = 0
    own_seen = False

    def check(parent_fd, name, own=False):
        nonlocal count, total, own_seen
        count += 1
        if count > 64:
            refuse('file_count')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                refuse('file_type')
            if before.st_size > 65536 or total + before.st_size > 1048576:
                refuse('byte_limit')
            data = bytearray()
            while True:
                block = os.read(fd, min(4096, 65537 - len(data)))
                if not block:
                    break
                data.extend(block)
                if len(data) > 65536 or total + len(data) > 1048576:
                    refuse('byte_limit')
            after = os.fstat(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if identity(before) != identity(after) or len(data) != before.st_size:
                refuse('source_changed')
            total += len(data)
            if own:
                if hashlib.sha256(data).hexdigest() != expected:
                    refuse('snapshot_mismatch')
                own_seen = True
            elif any(line.strip(b' \\t\\r') and not line.lstrip(b' \\t\\r').startswith(b'#')
                     for line in data.split(b'\\n')):
                refuse('unexpected_source')
        finally:
            os.close(fd)

    try:
        try:
            os.stat('sources.list', dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            check(root_fd, 'sources.list')
        sources_fd = os.open('sources.list.d', directory_flags, dir_fd=root_fd)
        try:
            with os.scandir(sources_fd) as entries:
                for number, entry in enumerate(entries, 1):
                    if number > 64:
                        refuse('directory_count')
                    if entry.name.endswith(('.list', '.sources')):
                        check(sources_fd, entry.name, entry.name == 'ukai-snapshot.sources')
            if not own_seen:
                refuse('snapshot_missing')
        finally:
            os.close(sources_fd)
    finally:
        os.close(root_fd)

try:
    verify(sys.argv[1], sys.argv[2])
except OSError:
    sys.exit('ukai apt source guard: source_io')
except ValueError as error:
    sys.exit('ukai apt source guard: ' + str(error))
'''


def apt_update_script():
    """Install the pinned stanza and refuse unexpected sources before update."""
    stanza = snapshot_sources()
    digest = hashlib.sha256(stanza.encode()).hexdigest()
    return ("cat > /etc/apt/sources.list.d/ukai-snapshot.sources <<'UKAI_APT_SNAPSHOT'\n"
            + stanza + 'UKAI_APT_SNAPSHOT\n'
            + 'rm -f /etc/apt/sources.list.d/ubuntu.sources\n'
            + f"python3 - /etc/apt {digest} <<'UKAI_APT_SOURCE_GUARD'\n"
            + APT_SOURCE_GUARD + 'UKAI_APT_SOURCE_GUARD\n'
            + 'echo UKAI_STEP apt_update >/dev/hvc0\napt-get update\n')


# Authenticated Stonking package units. Select the single-process user bus
# expected by guest.py; the system bus may continue using dbus-broker.
SESSION_BUS_GUARD = '''import hashlib, os, pathlib, pwd, stat, subprocess, sys

PINS = {
    'dbus.service': 'a3156e86c7a5ea0af164a08d971eb6da110ec740a553cb64e2e2cf2cc2d33059',
    'dbus.socket': 'eb9bcc798c347ea00544ca79f3ca07f3f6bd675235c9d73a42b6dcc9fd16a927',
    'dbus-broker.service': 'eeccf0dc9f8df2252566ca6bb5c3955df594082626f534c8056ee4cea476f19b',
}
ARGV = ['/usr/bin/dbus-daemon', '--session', '--address=systemd:', '--nofork',
        '--nopidfile', '--systemd-activation', '--syslog-only']
PROPERTIES = ['FragmentPath', 'DropInPaths', 'ExecStart', 'MainPID',
              'Type', 'NotifyAccess', 'ActiveState', 'SubState']

def require(condition, code):
    if not condition:
        raise ValueError(code)

def read_small(name, parent=None, cap=16384):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'file_type_or_size')
        data = bytearray()
        while True:
            block = os.read(fd, min(4096, cap + 1 - len(data)))
            if not block:
                return bytes(data)
            data.extend(block)
            require(len(data) <= cap, 'read_limit')
    finally:
        os.close(fd)

def check_units(root=pathlib.Path('/'), allow_broker_alias=False):
    vendor = root / 'usr/lib/systemd/user'
    require(stat.S_ISDIR(vendor.lstat().st_mode), 'unit_directory')
    for name, digest in PINS.items():
        require(hashlib.sha256(read_small(vendor / name, cap=65536)).hexdigest() == digest,
                'vendor_unit_changed')
    for relative in ('etc/systemd/user', 'run/systemd/user',
                     'usr/local/lib/systemd/user', 'usr/lib/systemd/user'):
        directory = root / relative
        if not os.path.lexists(directory):
            continue
        require(stat.S_ISDIR(directory.lstat().st_mode), 'unit_directory')
        for name in (*PINS, 'service', 'socket'):
            require(not os.path.lexists(directory / (name + '.d')), 'unit_dropin')
        if directory == vendor:
            continue
        for name in PINS:
            path = directory / name
            if not os.path.lexists(path):
                continue
            require(allow_broker_alias and relative == 'etc/systemd/user'
                    and name == 'dbus.service' and path.is_symlink()
                    and path.resolve(strict=True) == vendor / 'dbus-broker.service',
                    'unit_override')

def command(argv, account=None):
    options = dict(env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    if account is not None:
        require(account.pw_uid == 1001, 'account_uid')
        options.update(user=account.pw_uid, group=account.pw_gid, extra_groups=[])
        options['env']['XDG_RUNTIME_DIR'] = '/run/user/1001'
    result = subprocess.run(['/usr/bin/systemctl', *argv], stdin=subprocess.DEVNULL,
                            capture_output=True, cwd='/', timeout=30, **options)
    # Accepted-output cap after capture; the trusted bootstrap command has a
    # 30-second deadline, not a claim of a hard pipe-allocation limit.
    require(result.returncode == 0 and len(result.stdout) <= 16384
            and len(result.stderr) <= 16384, 'systemctl_failed')
    return result.stdout.decode('utf-8', errors='strict')

def select():
    check_units(allow_broker_alias=True)
    command(['--global', 'disable', 'dbus-broker.service'])
    check_units()

def properties(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        require(separator and key in PROPERTIES and key not in values, 'unit_properties')
        values[key] = value
    require(set(values) == set(PROPERTIES), 'unit_properties')
    require(values['FragmentPath'] == '/usr/lib/systemd/user/dbus.service'
            and values['DropInPaths'] == '' and values['Type'] == 'notify'
            and values['NotifyAccess'] == 'main' and values['ActiveState'] == 'active'
            and values['SubState'] == 'running', 'effective_unit')
    # systemctl's execution-status suffix varies; require one command and its
    # exact public executable/argv, not a substring match on the daemon name.
    execution = values['ExecStart']
    require(execution.startswith('{ path=' + ARGV[0] + ' ; argv[]=' + ' '.join(ARGV)
                                 + ' ; ignore_errors=no ; ')
            and execution.endswith(' }') and execution.count('{') == 1
            and execution.count('}') == 1, 'effective_exec')
    pid = values['MainPID']
    require(len(pid) <= 10 and pid.isascii() and pid.isdecimal() and 1 < int(pid) < 2**31, 'main_pid')
    return int(pid)

def birth(raw, pid):
    require(raw.startswith(str(pid).encode() + b' ('), 'process_identity')
    fields = raw[raw.rfind(b')') + 1:].split()
    require(len(fields) >= 20 and fields[19].isdigit() and int(fields[19]) > 0,
            'process_identity')
    return int(fields[19])

def verify_process(pid, proc=pathlib.Path('/proc'), confirm=None):
    fd = os.open(proc / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        before = birth(read_small('stat', fd), pid)
        require(os.readlink('exe', dir_fd=fd) == ARGV[0], 'process_executable')
        require(read_small('cmdline', fd) == b'\\0'.join(arg.encode() for arg in ARGV) + b'\\0',
                'process_argv')
        status = read_small('status', fd).splitlines()
        require([line.split()[1:] for line in status if line.startswith(b'Uid:')]
                == [[b'1001'] * 4], 'process_uid')
        require(birth(read_small('stat', fd), pid) == before, 'process_changed')
        if confirm is not None:
            confirm()
            require(birth(read_small('stat', fd), pid) == before, 'process_changed')
    finally:
        os.close(fd)

def verify():
    check_units()
    account = pwd.getpwnam('ukai')
    command(['--user', 'start', 'dbus.service'], account)
    show = ['--user', 'show', 'dbus.service', *['--property=' + key for key in PROPERTIES]]
    pid = properties(command(show, account))
    def confirm():
        require(properties(command(show, account)) == pid, 'main_pid_changed')
    verify_process(pid, confirm=confirm)

if __name__ == '__main__':
    try:
        require(sys.argv[1:] in (['select'], ['verify']), 'phase')
        select() if sys.argv[1] == 'select' else verify()
    except (OSError, subprocess.SubprocessError, UnicodeError, KeyError):
        sys.exit('ukai session bus guard: lookup_failed')
    except ValueError as error:
        sys.exit('ukai session bus guard: ' + str(error))
'''


def session_bus_script(phase):
    if phase not in ('select', 'verify'):
        raise ValueError('session bus guard phase')
    return f"python3 - {phase} <<'UKAI_SESSION_BUS_GUARD'\n" + SESSION_BUS_GUARD + 'UKAI_SESSION_BUS_GUARD\n'


def load_coordinates():
    """dist/coordinates.py, loaded by path: dist/ also holds a package.py
    that must not shadow this directory's."""
    spec = importlib.util.spec_from_file_location('ukai_release_coordinates',
                                                  SOURCE.parent / 'dist' / 'coordinates.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coordinates = load_coordinates()
IMAGE_URL = 'https://cloud-images.ubuntu.com/minimal/releases/stonking/release-20261105/ubuntu-26.10-minimal-cloudimg-arm64.img'
IMAGE_SHA256 = 'bac15af78c37fec8e9474a9a784041c13ddb2603b9095435b7e4269e3faf3064'
# The guest runs the current public Linux release (dist/release.json), checked
# against the SHA-256 the public installer pins for it.
JAIL_TARGET = 'aarch64-unknown-linux-gnu'
JAIL_URL = coordinates.jail_archive_url(coordinates.ARM_PREVIEW_VERSION, JAIL_TARGET)
JAIL_SHA256 = coordinates.installer_pin(coordinates.ARM_PREVIEW_VERSION, JAIL_TARGET)


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


# An explicit opt-in native payload, never a moving installer URL. These are
# metadata pins for the initial image catalog; execution remains catalog-driven.
NATIVE_VERSION = '2.1.311'
NATIVE_SHA256 = '2e2496c9a8065df93acb0fca2d341f59a6b8777649b2e025ab8c9bcd5eef61f3'
NATIVE_SIZE = 293658808
NATIVE_PROFILE_SHA256 = 'e3d804e5557c5829205b5156d636a9fbcdc1e1dcff7d3bebd5b88891bbe17a24'
NATIVE_JAIL_SHA256 = 'c0c1f0e7cecb1fabe9c4ff42f9ae4534e24b16cb9dc0cf5ab21f4d827db6e38f'


def stage_native_program(source, directory, jail_binary):
    """Verify/copy one pinned local ELF; return seed inputs, never execute it."""
    if hashlib.sha256(jail_binary).hexdigest() != NATIVE_JAIL_SHA256:
        raise ValueError('native program requires the pinned signed rc.7 ARM guest jail')
    profile = (SOURCE.parent / 'profiles/launch/claude.toml').read_bytes()
    if hashlib.sha256(profile).hexdigest() != NATIVE_PROFILE_SHA256:
        raise ValueError('native bundled profile differs from the pinned guest jail')
    payload = directory / 'native-program-payload'
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != NATIVE_SIZE:
            raise ValueError('native program input type/link/size')
        guest_program.check_elf(fd, before.st_size, '/lib/ld-linux-aarch64.so.1')
        digest = hashlib.sha256()
        consumed = 0
        with payload.open('xb') as target:
            while data := os.read(fd, 1024 * 1024):
                consumed += len(data)
                if consumed > NATIVE_SIZE:
                    raise ValueError('native program grew while copying')
                target.write(data); digest.update(data)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or digest.hexdigest() != NATIVE_SHA256 or sha(payload) != NATIVE_SHA256:
            raise ValueError('native program input changed or hash mismatch')
    finally:
        os.close(fd)
    root = f'/opt/ukai/programs/claude/{NATIVE_VERSION}'
    entry = {'id': f'claude-{NATIVE_VERSION}-linux-arm64', 'alias': 'claude', 'version': NATIVE_VERSION,
             'format': 'elf64-aarch64', 'executable': root + '/claude', 'install_root': root,
             'program_root': 1, 'argv_prefix': [root + '/claude'],
             'executable_sha256': NATIVE_SHA256, 'executable_size': NATIVE_SIZE,
             'profile_sha256': NATIVE_PROFILE_SHA256, 'guest_jail_sha256': NATIVE_JAIL_SHA256,
             'supported_states': ['attempt'], 'interpreter': '/lib/ld-linux-aarch64.so.1',
             'tree': [{'path': '.', 'kind': 'directory', 'mode': 365, 'uid': 0, 'gid': 0},
                      {'path': 'claude', 'kind': 'file', 'mode': 365, 'uid': 0, 'gid': 0, 'nlink': 1}]}
    data = (json.dumps({'schema': guest_program.CATALOG_SCHEMA, 'entries': [entry]},
                       sort_keys=True, indent=2) + '\n').encode()
    guest_program.parse_catalog(data)
    (directory / guest_program.CATALOG_FILENAME).write_bytes(data)
    return {'catalog': data, 'profile': profile, 'payload': payload, 'entry': entry,
            'sha256': hashlib.sha256(data).hexdigest()}


def native_install_script(native):
    if native is None:
        return ''
    entry = native['entry']
    # The binary is a regular ISO payload, not a ~400MB base64 cloud-init
    # document. Setup mounts the task seed read-only and verifies both copies.
    return f'''echo UKAI_STEP native_program >/dev/hvc0
mkdir -p /mnt/ukai-native-seed
seed_device=
for candidate in /dev/disk/by-label/cidata /dev/disk/by-label/CIDATA; do
    if [ -e "$candidate" ]; then seed_device="$candidate"; break; fi
done
test -n "$seed_device"
mount -t iso9660 -o ro "$seed_device" /mnt/ukai-native-seed
printf '%s  %s\\n' '{entry['executable_sha256']}' /mnt/ukai-native-seed/native-programs/claude | sha256sum -c -
install -d -o 0 -g 0 -m 0555 '{entry['install_root']}'
install -o 0 -g 0 -m 0555 /mnt/ukai-native-seed/native-programs/claude '{entry['executable']}'
printf '%s  %s\\n' '{entry['executable_sha256']}' '{entry['executable']}' | sha256sum -c -
umount /mnt/ukai-native-seed
rmdir /mnt/ukai-native-seed
/usr/bin/python3 -c 'import sys; sys.path.insert(0, "/usr/local/lib/ukai-vm"); import guest_program; guest_program.verify_catalog()'
'''


def seed(directory, files, commands, payloads=None):
    directory.mkdir()
    config = {'users': [], 'ssh_deletekeys': True, 'ssh_genkeytypes': [],
              'write_files': [{'path': path, 'encoding': 'b64', 'content': base64.b64encode(content).decode(),
                               'permissions': mode} for path, content, mode in files],
              'runcmd': commands}
    (directory / 'user-data').write_text('#cloud-config\n' + json.dumps(config))
    (directory / 'meta-data').write_text('instance-id: ukai-linux-preview\nlocal-hostname: ukai-linux-preview\n')
    for name, source in (payloads or {}).items():
        if name != 'native-programs/claude':
            raise ValueError('unexpected native seed payload')
        target = directory / name
        target.parent.mkdir()
        shutil.copyfile(source, target)
        if sha(target) != NATIVE_SHA256:
            raise ValueError('native seed payload changed')
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



def exposure_control_from_console(console, source_hashes):
    """Require one actual installed-sampler detector control, never a claim label."""
    markers = [line[len('UKAI_EXPOSURE_CONTROL '):] for line in console.splitlines()
               if line.startswith('UKAI_EXPOSURE_CONTROL ')]
    if len(markers) != 1 or len(markers[0].encode()) > 65536:
        raise ValueError('missing, duplicate or oversized exposure control marker')
    report = json.loads(markers[0], object_pairs_hook=guest_program._object)
    fields = {'schema', 'passed', 'scope', 'actual_values_retained', 'jail_execution_claimed',
              'facts', 'sampling', 'errors', 'control_source_sha256', 'sampler_sha256',
              'guest_boot_id', 'guest_kernel', 'process'}
    facts = {'environment_canary_detected', 'argv_canary_detected', 'verified_program_environment_read',
             'verified_program_argv_read', 'only_owned_child_observed', 'sampler_source_unchanged',
             'owned_child_reaped'}
    if (type(report) is not dict or set(report) != fields
            or report['schema'] != 'ukai.vm.sampled-exposure-control/1'
            or report['scope'] != 'owned-public-canary-process-detector-control'
            or report['passed'] is not True or report['actual_values_retained'] is not False
            or report['jail_execution_claimed'] is not False or report['errors'] != []
            or report['sampler_sha256'] != source_hashes['guest_exposure.py']
            or report['control_source_sha256'] != source_hashes['guest_exposure_control.py']
            or type(report['facts']) is not dict or set(report['facts']) != facts
            or any(value is not True for value in report['facts'].values())):
        raise ValueError('exposure control facts or source identity differ')
    for name in ('guest_boot_id', 'guest_kernel'):
        value = report[name]
        if type(value) is not str or not 1 <= len(value) <= 128 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-' for c in value):
            raise ValueError('exposure control guest identity invalid')
    process = report['process']
    if (type(process) is not dict or set(process) != {'pid', 'starttime', 'executable_dev', 'executable_ino'}
            or any(type(value) is not int or value < (0 if key == 'executable_dev' else 1) or value >= 2**64 for key, value in process.items())):
        raise ValueError('exposure control process identity invalid')
    sample = report['sampling']
    if (type(sample) is not dict or set(sample) != {'ticks', 'verified_program_reads', 'scan_errors'}
            or type(sample['ticks']) is not int or not 1 <= sample['ticks'] <= 1000
            or type(sample['verified_program_reads']) is not dict
            or set(sample['verified_program_reads']) != {'environment', 'argv'}):
        raise ValueError('exposure control sampling invalid')
    # Import the same pure scanner schema; no proc access occurs while parsing.
    import guest_exposure
    for row in sample['verified_program_reads'].values():
        if (type(row) is not dict or set(row) != set(guest_exposure.READ_STATES)
                or any(type(value) is not int or not 0 <= value < 2**64 for value in row.values())
                or row['readable'] < 1):
            raise ValueError('exposure control lacks readable program samples')
    if (type(sample['scan_errors']) is not dict or set(sample['scan_errors']) - guest_exposure.SCAN_ERROR_CODES
            or any(type(value) is not int or not 1 <= value < 2**64 for value in sample['scan_errors'].values())):
        raise ValueError('exposure control scan error counts invalid')
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--jail-candidate', type=Path,
                        help='use a local signed Linux candidate verified with the checked-in release.pub')
    parser.add_argument('--native-claude', type=Path,
                        help='opt in to the pinned local Claude ELF catalog (requires the pinned signed rc.7 ARM guest jail)')
    args = parser.parse_args()
    if args.native_claude is not None and args.jail_candidate is None:
        parser.error('--native-claude requires --jail-candidate')
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
    native = stage_native_program(args.native_claude, root, binary) if args.native_claude else None
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
# Install what the guest jail's guarantees measure against, resolved from
# the snapshot above; the installed versions are also recorded in the image
# manifest: `bubblewrap` is the containment backend; `dbus-user-session`
# and the explicitly selected `dbus-daemon` supply the session bus.
# These leave exactly the user manager, its (sd-pam) helper and the bus
# running as the account; guest.py learns those three from systemd at
# session open (learn_infrastructure) and the attempt stop spares only them.
{apt_update_script()}echo UKAI_STEP apt_install >/dev/hvc0
apt-get install -y --no-install-recommends bubblewrap dbus-user-session dbus-daemon
{session_bus_script('select')}echo UKAI_STEP users >/dev/hvc0
mkdir -p /usr/local/share/ukai-vm
dpkg-query -W -f='${{Package}}=${{Version}}\n' bubblewrap dbus-user-session dbus-daemon > /usr/local/share/ukai-vm/pinned-versions.txt
useradd --create-home --uid 1001 --shell /bin/bash ukai
loginctl enable-linger ukai
systemctl start user@1001.service
{session_bus_script('verify')}systemctl disable ssh.service ssh.socket 2>/dev/null || true
mkdir -p /usr/local/share/ukai-vm
dpkg-query -W > /usr/local/share/ukai-vm/packages.txt
# The console carries the pinned set to the host builder, which records it
# in image.json: the manifest then names what the guarantees measured
# against without mounting the disk.
dpkg-query -W -f='${{Package}}=${{Version}}\n' bubblewrap dbus-user-session dbus-daemon | while read -r row; do echo "UKAI_PINNED $row" >/dev/hvc0; done
{native_install_script(native)}{('python3 /usr/local/lib/ukai-vm/guest_exposure_control.py --out /usr/local/share/ukai-vm/exposure-control.json' + chr(10)) if native else ''}systemctl enable ukai-vm.service
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
    extra_files = []
    if native is not None:
        extra_files = [(str(guest_program.CATALOG_PATH), native['catalog'], '0644'),
                       (str(guest_program.PROFILE_DIRECTORY / 'claude.toml'), native['profile'], '0644')]
    seed(root / 'seed', [('/usr/local/bin/ukai-jail', binary, '0755'),
                        ('/usr/local/lib/ukai-vm/guest_program.py', (SOURCE / 'guest_program.py').read_bytes(), '0644'),
                        ('/usr/local/lib/ukai-vm/guest_exposure.py', (SOURCE / 'guest_exposure.py').read_bytes(), '0644'),
                        ('/usr/local/lib/ukai-vm/guest_exposure_control.py', (SOURCE / 'guest_exposure_control.py').read_bytes(), '0644'),
                        ('/usr/local/lib/ukai-vm/guest.py', (SOURCE / 'guest.py').read_bytes(), '0644'),
                        ('/etc/systemd/system/ukai-vm.service', service, '0644'),
                        ('/usr/local/lib/ukai-vm/setup.sh', setup.encode(), '0700'),
                        ('/usr/local/lib/ukai-vm/trace.sh', trace, '0700'), *extra_files],
         [['/bin/sh', '/usr/local/lib/ukai-vm/trace.sh']],
         {'native-programs/claude': native['payload']} if native else None)
    metadata = {'schema': 'ukai.vm.image-build/1', 'status': 'preparing', 'image_url': IMAGE_URL,
                'image_sha256': IMAGE_SHA256, 'jail_url': jail_url, 'jail_archive_sha256': jail_sha256,
                'apt_snapshot': SNAPSHOT, 'apt_snapshot_url': SNAPSHOT_URL,
                'source_sha256': {name: sha(SOURCE / name) for name in ['guest.py', 'guest_program.py', 'guest_exposure.py', 'guest_exposure_control.py', 'vz.swift', 'custodian.c', 'prepare.py']}}
    if jail_candidate is not None:
        metadata['jail_candidate'] = jail_candidate
    if native is not None:
        metadata['guest_program_catalog_sha256'] = native['sha256']
        metadata['guest_program_inputs'] = {key: native['entry'][key] for key in
            ('id', 'version', 'executable_sha256', 'executable_size', 'profile_sha256', 'guest_jail_sha256')}
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
    if native is not None:
        control = exposure_control_from_console(console, metadata['source_sha256'])
        control_bytes = (json.dumps(control, sort_keys=True, separators=(',', ':')) + '\n').encode()
        with (root / 'guest-exposure-control.json').open('xb') as output:
            output.write(control_bytes)
        metadata['guest_exposure_control'] = control
        metadata['guest_exposure_control_sha256'] = hashlib.sha256(control_bytes).hexdigest()
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
