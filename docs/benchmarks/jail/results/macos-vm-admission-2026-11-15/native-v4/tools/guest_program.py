"""Bounded image catalogs and guest-only native program verification.

The catalog describes a root-owned immutable tree, not a held executable.
The Linux jail still resolves --from-path and pins/rechecks its executable.
Filesystem-root/owner parameters are unit-test seams; the controller always
uses / and uid/gid zero. No request or environment selects those parameters.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import time
import tomllib

CONTRACT = 'ukai.vm.guest-native-launch/1'
CATALOG_SCHEMA = 'ukai.vm.guest-program-catalog/1'
CATALOG_FILENAME = 'guest-program-catalog.json'
CATALOG_PATH = Path('/usr/local/share/ukai-vm') / CATALOG_FILENAME
PROFILE_DIRECTORY = Path('/usr/local/share/ukai-vm/guest-program-profiles')
JAIL_PATH = Path('/usr/local/bin/ukai-jail')
NATIVE_CONFIG = Path('/run/ukai-vm/native-config')
MAX_CATALOG_BYTES = 65536
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 16
VERIFY_SECONDS = 20
NAME = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')
SHA = re.compile(r'[0-9a-f]{64}\Z')
ENTRY_FIELDS = {'id', 'alias', 'version', 'format', 'executable', 'install_root',
                'program_root', 'argv_prefix', 'executable_sha256', 'executable_size',
                'profile_sha256', 'guest_jail_sha256', 'supported_states', 'interpreter', 'tree'}
INTENT_FIELDS = {'schema', 'catalog_sha256', 'entry_id', 'launch_name', 'profile_sha256',
                 'state', 'selected_credential_id', 'argv_suffix', 'request_argv_digest',
                 'resolved_argv_digest', 'expected_policy_digest'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def _text(value, regex):
    return type(value) is str and regex.fullmatch(value) is not None


def parse_catalog(data):
    """Pure strict parser shared by the host packager and guest controller."""
    require(type(data) is bytes and 0 < len(data) <= MAX_CATALOG_BYTES, 'catalog byte limit')
    value = json.loads(data.decode('utf-8'), object_pairs_hook=_object,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('JSON constant')))
    require(type(value) is dict and set(value) == {'schema', 'entries'}, 'catalog fields')
    require(value['schema'] == CATALOG_SCHEMA, 'catalog schema')
    entries = value['entries']
    require(type(entries) is list and 1 <= len(entries) <= MAX_ENTRIES, 'catalog entry count')
    ids, aliases, roots = set(), set(), set()
    for entry in entries:
        require(type(entry) is dict and set(entry) == ENTRY_FIELDS, 'catalog entry fields')
        for name in ('id', 'version'):
            require(_text(entry[name], VERSION if name == 'version' else IDENTIFIER)
                    and entry[name] not in ('.', '..'), 'catalog identifier')
        require(_text(entry['alias'], NAME), 'catalog alias')
        require(entry['id'] not in ids and entry['alias'] not in aliases, 'duplicate catalog entry')
        ids.add(entry['id']); aliases.add(entry['alias'])
        root = f"/opt/ukai/programs/{entry['alias']}/{entry['version']}"
        exe = root + '/' + entry['alias']
        require(entry['install_root'] == root and entry['executable'] == exe and root not in roots,
                'catalog install path')
        roots.add(root)
        require(entry['format'] == 'elf64-aarch64' and type(entry['program_root']) is int
                and entry['program_root'] == 1 and entry['argv_prefix'] == [exe], 'catalog program shape')
        require(type(entry['executable_size']) is int and 64 <= entry['executable_size'] <= MAX_EXECUTABLE_BYTES,
                'catalog executable size')
        require(entry['supported_states'] == ['attempt'] and entry['interpreter'] == '/lib/ld-linux-aarch64.so.1',
                'catalog state or loader')
        for field in ('executable_sha256', 'profile_sha256', 'guest_jail_sha256'):
            require(_text(entry[field], SHA), 'catalog hash')
        tree = entry['tree']
        expected = [{'path': '.', 'kind': 'directory', 'mode': 365, 'uid': 0, 'gid': 0},
                    {'path': entry['alias'], 'kind': 'file', 'mode': 365, 'uid': 0, 'gid': 0, 'nlink': 1}]
        require(type(tree) is list and len(tree) == 2 and all(type(row) is dict for row in tree), 'catalog tree')
        require(tree == expected and all(type(row[k]) is int for row in tree
                                        for k in ('mode', 'uid', 'gid'))
                and type(tree[1]['nlink']) is int, 'catalog exact tree')
    return value


def argv_digest(argv):
    data = b'ukai.jail.argv/1\0' + struct.pack('>Q', len(argv))
    data += b''.join(struct.pack('>Q', len(word)) + word for word in argv)
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def decode_argv(encoded):
    require(type(encoded) is list and len(encoded) <= 4096, 'native argv shape')
    result = []
    total = 0
    for value in encoded:
        require(type(value) is str, 'native argv type')
        word = base64.b64decode(value, validate=True)
        require(base64.b64encode(word).decode() == value and b'\0' not in word, 'native argv encoding')
        total += len(word)
        require(total <= 1024 * 1024, 'native argv byte limit')
        result.append(word)
    return result


def validate_intent(intent, encoded_argv, verified):
    require(type(intent) is dict and set(intent) == INTENT_FIELDS, 'native intent fields')
    require(intent['schema'] == CONTRACT and intent['state'] == 'attempt', 'native intent contract/state')
    require(intent['catalog_sha256'] == verified['sha256'], 'native catalog mismatch')
    entry = next((e for e in verified['catalog']['entries'] if e['id'] == intent['entry_id']), None)
    require(entry is not None, 'native entry missing')
    require(intent['launch_name'] == entry['alias'] and intent['profile_sha256'] == entry['profile_sha256'],
            'native profile mismatch')
    require(intent['selected_credential_id'] in verified['credentials'][entry['id']], 'native credential selection')
    suffix = decode_argv(intent['argv_suffix'])
    argv = decode_argv(encoded_argv)
    require(argv == [entry['executable'].encode(), *suffix], 'native resolved argv mismatch')
    require(intent['request_argv_digest'] == argv_digest([entry['alias'].encode(), *suffix])
            and intent['resolved_argv_digest'] == argv_digest(argv), 'native argv digest mismatch')
    digest = intent['expected_policy_digest']
    require(type(digest) is str and digest.startswith('sha256:') and _text(digest[7:], SHA),
            'native policy digest')
    return entry, suffix


def native_binding(intent, entry, policy_digest):
    require(policy_digest == intent['expected_policy_digest'], 'native receipt policy mismatch')
    return {'catalog_sha256': intent['catalog_sha256'], 'entry_id': entry['id'],
            'profile_sha256': entry['profile_sha256'], 'executable_sha256': entry['executable_sha256'],
            'selected_credential_id': intent['selected_credential_id'], 'state': 'attempt',
            'request_argv_digest': intent['request_argv_digest'],
            'resolved_argv_digest': intent['resolved_argv_digest'], 'policy_digest': policy_digest}


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _safe(info, uid, gid, directory=False, exact_mode=None):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == uid and info.st_gid == gid and not info.st_mode & 0o7022,
            'native owner/mode/type')
    if not directory:
        require(info.st_nlink == 1, 'native file hardlink')
    if exact_mode is not None:
        require(stat.S_IMODE(info.st_mode) == exact_mode, 'native exact mode')


def _open(path, root, uid, gid, directory=False):
    path = PurePosixPath(path)
    require(path.is_absolute() and '..' not in path.parts, 'native absolute path')
    current = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _safe(os.fstat(current), uid, gid, True)
        for index, part in enumerate(path.parts[1:]):
            is_dir = index < len(path.parts) - 2 or directory
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if is_dir else 0)
            child = os.open(part, flags, dir_fd=current)
            os.close(current); current = child
            _safe(os.fstat(current), uid, gid, is_dir)
        return current
    except BaseException:
        os.close(current)
        raise


def _read(path, limit, root, uid, gid):
    fd = _open(path, root, uid, gid)
    try:
        before = os.fstat(fd)
        require(before.st_size <= limit, 'native metadata byte limit')
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(chunk)
            require(len(data) <= limit, 'native metadata byte limit')
        require(len(data) == before.st_size and _identity(before) == _identity(os.fstat(fd)),
                'native metadata changed')
        return bytes(data)
    finally:
        os.close(fd)


def check_elf(fd, size, interpreter):
    """Check the pinned native ELF header/table without executing it."""
    header = os.pread(fd, 64, 0)
    require(len(header) == 64 and header[:7] == b'\x7fELF\x02\x01\x01'
            and struct.unpack_from('<HH', header, 16)[0] in (2, 3)
            and struct.unpack_from('<H', header, 18)[0] == 183, 'native ELF header')
    offset = struct.unpack_from('<Q', header, 32)[0]
    width, count = struct.unpack_from('<HH', header, 54)
    require(width == 56 and 0 < count <= 128 and offset + width * count <= size,
            'native ELF program table')
    table = os.pread(fd, width * count, offset)
    loaders = []
    for index in range(count):
        kind, _, start, _, _, length, _, _ = struct.unpack_from('<IIQQQQQQ', table, index * width)
        if kind == 3:
            require(1 <= length <= 4096 and start + length <= size, 'native ELF loader range')
            loaders.append(os.pread(fd, length, start))
    require(loaders == [interpreter.encode() + b'\0'], 'native ELF loader mismatch')


def _hash_file(path, expected, size, root, uid, gid, pulse, exact_mode=None, elf=None):
    fd = _open(path, root, uid, gid)
    try:
        before = os.fstat(fd)
        _safe(before, uid, gid, exact_mode=exact_mode)
        require(before.st_size <= MAX_EXECUTABLE_BYTES and (size is None or before.st_size == size),
                'native executable size mismatch')
        if elf is not None:
            check_elf(fd, before.st_size, elf)
        digest = hashlib.sha256(); consumed = 0
        while chunk := os.read(fd, 1024 * 1024):
            consumed += len(chunk); require(consumed <= MAX_EXECUTABLE_BYTES, 'native executable byte limit')
            digest.update(chunk); pulse()
        require(consumed == before.st_size and digest.hexdigest() == expected
                and _identity(before) == _identity(os.fstat(fd)), 'native executable changed or hash mismatch')
        # A fresh anchored walk must still reach the same object after hashing.
        again = _open(path, root, uid, gid)
        try:
            require(_identity(before) == _identity(os.fstat(again)), 'native executable replaced')
        finally:
            os.close(again)
    finally:
        os.close(fd)


def profile_credentials(data, alias):
    profile = tomllib.loads(data.decode('utf-8'))
    require(profile.get('name') == alias and profile.get('jail') == 'agent', 'native profile identity')
    selected = profile.get('credentials_one_of')
    declarations = profile.get('credentials')
    require(type(selected) is list and selected and all(_text(x, NAME) for x in selected)
            and len(selected) == len(set(selected)) and type(declarations) is dict
            and set(declarations) == set(selected), 'native profile credential declarations')
    for key in selected:
        declaration = declarations[key]
        require(type(declaration) is dict and declaration.get('mode') == 'vault'
                and declaration.get('source') == '@config/credentials/' + key
                and declaration.get('binaries') == ['@program'] and 'refresh' not in declaration,
                'native profile credential shape')
    return selected


def verify_catalog(catalog_path=CATALOG_PATH, *, filesystem_root=Path('/'), owner_uid=0, owner_gid=0,
                   notify=lambda: None):
    """Verify all bytes before Session and again before staging/release.

    Missing catalog alone means a legacy image. Every malformed/present but
    inaccessible catalog is a refusal, including a dangling symlink.
    """
    root = Path(filesystem_root)
    try:
        root.joinpath(*PurePosixPath(catalog_path).parts[1:]).lstat()
    except FileNotFoundError:
        return None
    started = time.monotonic()
    def pulse():
        require(time.monotonic() - started < VERIFY_SECONDS, 'native verification deadline')
        notify()
    data = _read(catalog_path, MAX_CATALOG_BYTES, root, owner_uid, owner_gid)
    catalog = parse_catalog(data)
    credentials = {}
    for entry in catalog['entries']:
        pulse()
        fd = _open(entry['install_root'], root, owner_uid, owner_gid, True)
        try:
            before = os.fstat(fd); _safe(before, owner_uid, owner_gid, True, 0o555)
            require(os.listdir(fd) == [entry['alias']], 'native installation inventory')
            _hash_file(entry['executable'], entry['executable_sha256'], entry['executable_size'],
                       root, owner_uid, owner_gid, pulse, 0o555, entry['interpreter'])
            require(_identity(before) == _identity(os.fstat(fd)), 'native install root changed')
        finally:
            os.close(fd)
        profile = _read(PROFILE_DIRECTORY / (entry['alias'] + '.toml'), MAX_CATALOG_BYTES,
                        root, owner_uid, owner_gid)
        require(hashlib.sha256(profile).hexdigest() == entry['profile_sha256'], 'native profile hash')
        credentials[entry['id']] = profile_credentials(profile, entry['alias'])
        _hash_file(JAIL_PATH, entry['guest_jail_sha256'], None, root, owner_uid, owner_gid, pulse)
    require(_read(catalog_path, MAX_CATALOG_BYTES, root, owner_uid, owner_gid) == data, 'native catalog changed')
    return {'catalog': catalog, 'sha256': hashlib.sha256(data).hexdigest(), 'credentials': credentials}
