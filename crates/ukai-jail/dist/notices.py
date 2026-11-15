#!/usr/bin/env python3
"""Generate or verify checked-in attribution; this is not a legal-compliance verdict."""
import argparse
import hashlib
from html import unescape
from html.parser import HTMLParser
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[3]
BASE = 'crates/ukai-jail/dist/'
BUNDLE = BASE + 'THIRD_PARTY_NOTICES.txt'
INVENTORY = BASE + 'third-party-notices.json'
TARGETS = ('aarch64-apple-darwin', 'aarch64-unknown-linux-gnu', 'x86_64-unknown-linux-gnu')
INPUTS = ('LICENSE', 'Cargo.lock', 'Cargo.toml', 'rust-toolchain.toml', 'crates/ukai-jail/Cargo.toml',
          'crates/ukai-records/Cargo.toml', 'crates/ukai-jail/data/uts46_unicode17_tables.rs',
          BASE + 'release.json', BASE + 'WEBPKI_ROOTS_LICENSE', BASE + 'UNICODE_LICENSE', BASE + 'notices.py')
SCHEMA = 'ukai.jail.third-party-notices/1'
NOTICE = re.compile(r'^(?:licen[cs]e|copying|copyright|notice|authors)(?:$|[-_.])', re.I)
LEGAL = re.compile(rb'copyright|permission (?:is hereby granted|to use)|licensed under|SPDX-License-Identifier', re.I)
COMMENTS = re.compile(rb'/\*.*?\*/|(?:^[ \t]*(?://|\#(?=[ \t])|@)[^\n]*(?:\n|$))+', re.M | re.S)
HEADER = (b'Ukai Jail third-party attribution\n\n'
          b'Generated from the locked normal dependency closure for the listed Linux and macOS targets.\n'
          b'Normal proc-macro dependencies and upstream cross-platform notices are retained conservatively.\n'
          b'These notices do not change Ukai\'s project license or certify legal compliance.\n\n')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def run(argv, root):
    env = {key: os.environ[key] for key in ('HOME', 'PATH', 'USER', 'LOGNAME', 'TMPDIR', 'RUSTUP_HOME', 'CARGO_HOME') if key in os.environ}
    return subprocess.check_output(argv, cwd=root, env=env, timeout=120)


def read_source(root, revision=None):
    if revision is None:
        return lambda path: (root / path).read_bytes()
    require(re.fullmatch('[0-9a-f]{40}', revision), 'Expected a full source revision')
    return lambda path: run(['git', 'show', f'{revision}:{path}'], root)


def checked(read):
    inventory = json.loads(read(INVENTORY))
    require(inventory.get('schema') == SCHEMA and inventory.get('targets') == list(TARGETS),
            'Invalid notice inventory schema or target matrix')
    require(set(json.loads(read(BASE + 'release.json'))['jail']['elf_machine_by_target']) ==
            {target for target in TARGETS if target.endswith('-unknown-linux-gnu')}, 'Notice target matrix differs from release targets')
    require(set(inventory['inputs_sha256']) == set(INPUTS), 'Incomplete notice input guard')
    for path in INPUTS:
        require(digest(read(path)) == inventory['inputs_sha256'][path],
                f'Stale third-party notices: {path}; regenerate and review before packaging')
    data = read(BUNDLE)
    require(digest(data) == inventory['bundle_sha256'], 'Third-party notice bundle changed')
    locked = {(p['name'], p['version']): p for p in tomllib.loads(read('Cargo.lock').decode())['package']}
    seen = set()
    for package in inventory['packages']:
        key = (package['name'], package['version'])
        require(key not in seen and key in locked, 'Duplicate or unlocked notice package')
        seen.add(key)
        require(package['checksum'] == locked[key].get('checksum') and package['source'] == locked[key].get('source'),
                'Notice package does not match Cargo.lock')
        require(package['targets'] and package['targets'] == sorted(set(package['targets']))
                and set(package['targets']) <= set(TARGETS), 'Invalid package target set')
    require(inventory['documents'], 'No attribution documents')
    represented = set()
    cursor = len(HEADER)
    require(data.startswith(HEADER), 'Invalid notice bundle header')
    for document in inventory['documents']:
        offset, length = document['offset'], document['length']
        require(type(offset) is int and type(length) is int and offset >= 0 and length > 0
                and offset + length <= len(data), 'Invalid notice document span')
        require(digest(data[offset:offset + length]) == document['sha256'], 'Notice document bytes changed')
        prefix = f"\n=== {document['component']}: {document['label']} ===\n".encode()
        require(offset == cursor + len(prefix) and data[cursor:offset] == prefix
                and data[offset + length:offset + length + 1] == b'\n', 'Incomplete or reordered notice inventory')
        cursor = offset + length + 1
        represented.add(document['component'])
    require(cursor == len(data), 'Unindexed notice content')
    require(represented == {f'{name}@{version}' for name, version in seen}
            | {'rust-standard-library', 'unicode-uts46-data'}, 'Package or runtime attribution inventory is incomplete')
    require(inventory['rust_standard_library']['release'] ==
            tomllib.loads(read('rust-toolchain.toml').decode())['toolchain']['channel'], 'Rust notice release mismatch')
    return read('LICENSE') + b'\n\n' + data


class LibraryText(HTMLParser):
    """Keep all body text and preserve every upstream preformatted notice."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.body = False
        self.pre = False
        self.parts = []
        self.preformatted = []
        self.current = []

    def handle_starttag(self, tag, attrs):
        if tag == 'body':
            self.body = True
        if not self.body:
            return
        if tag == 'pre':
            self.pre = True
            self.current = []
        if tag in ('h1', 'h2', 'h3', 'p', 'pre', 'li', 'summary', 'br'):
            self.parts.append('\n')
        if tag == 'a':
            href = dict(attrs).get('href', '')
            if href.startswith(('https://', 'http://')):
                self.parts.append('[' + href + '] ')

    def handle_endtag(self, tag):
        if tag == 'pre':
            self.preformatted.append(''.join(self.current))
            self.pre = False
        if tag in ('h1', 'h2', 'h3', 'p', 'pre', 'li', 'summary'):
            self.parts.append('\n')
        if tag == 'body':
            self.body = False

    def handle_data(self, data):
        if self.body:
            self.parts.append(data if self.pre else re.sub(r'\s+', ' ', data))
            if self.pre:
                self.current.append(data)

    def text(self):
        value = ''.join(self.parts)
        require(self.preformatted and all(notice in value for notice in self.preformatted),
                'Rust library notice conversion lost preformatted text')
        return value.encode() + b'\n'


def crate_documents(raw, name, version, license_file=None):
    documents = {}
    prefix = f'{name}-{version}/'
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive.getmembers():
            require(member.name.startswith(prefix), 'Crate archive has an unexpected root')
            relative = member.name[len(prefix):]
            require(not PurePosixPath(relative).is_absolute() and '..' not in PurePosixPath(relative).parts,
                    'Unsafe crate archive path')
            if not member.isfile():
                continue
            if NOTICE.match(PurePosixPath(relative).name) or relative == license_file:
                documents[relative] = archive.extractfile(member).read()
            # ring's LICENSE expressly delegates to per-source headers. Include
            # these conservatively across architectures, including generated asm.
            if name == 'ring' and PurePosixPath(relative).suffix.lower() in ('.rs', '.c', '.h', '.inl', '.s', '.pl', '.asm', '.inc'):
                contents = archive.extractfile(member).read()
                for index, match in enumerate(COMMENTS.finditer(contents)):
                    if LEGAL.search(match[0]):
                        documents[f'{relative} [legal comment {index + 1}]'] = match[0]
    require(documents and any(NOTICE.match(PurePosixPath(p).name) for p in documents),
            f'No upstream license documents for {name}@{version}')
    for path, content in documents.items():
        require(content.strip(), f'Empty upstream notice: {name}/{path}')
        content.decode('utf-8')
    return documents


def generate(root):
    read = read_source(root)
    pin = tomllib.loads(read('rust-toolchain.toml').decode())['toolchain']['channel']
    require(re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', pin), 'Expected an exact Rust release pin')
    locked = {(p['name'], p['version']): p for p in tomllib.loads(read('Cargo.lock').decode())['package']}
    selected = {}
    metadata = json.loads(run(['cargo', '+' + pin, 'metadata', '--locked', '--offline', '--format-version', '1'], root))
    packages = {(p['name'], p['version']): p for p in metadata['packages']}
    for target in TARGETS:
        tree = run(['cargo', '+' + pin, 'tree', '--locked', '--offline', '-p', 'ukai-jail',
                    '--target', target, '--edges', 'normal', '--prefix', 'none', '--format', '{p}'], root).decode()
        for line in tree.splitlines():
            match = re.match(r'^([^ ]+) v([^ ]+)(?: |$)', line)
            require(match is not None, 'Unrecognized Cargo dependency tree row')
            key = (match[1], match[2])
            if packages[key]['source'] is None:
                require(key[0] in ('ukai-jail', 'ukai-records') and packages[key]['license'] == 'MIT'
                        and Path(packages[key]['manifest_path']).resolve() ==
                        (root / 'crates' / key[0] / 'Cargo.toml').resolve(), 'Unexpected local runtime dependency')
                continue
            selected.setdefault(key, []).append(target)
    cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
    rows = []
    documents = []
    output = bytearray(HEADER)

    def append(component, label, content, sources):
        output.extend(f'\n=== {component}: {label} ===\n'.encode())
        offset = len(output)
        output.extend(content)
        documents.append({'component': component, 'label': label, 'sources': sources, 'offset': offset,
                          'length': len(content), 'sha256': digest(content)})
        output.extend(b'\n')

    for (name, version), targets in sorted(selected.items()):
        package = packages[name, version]
        lock = locked[name, version]
        require(lock['source'] == 'registry+https://github.com/rust-lang/crates.io-index', 'Unreviewed dependency source')
        verified_archive = None
        for path in sorted((cargo_home / 'registry/cache').glob(f'*/{name}-{version}.crate')):
            raw = path.read_bytes()
            if digest(raw) == lock['checksum']:
                verified_archive = raw
                break
        require(verified_archive is not None,
                f'Missing checksum-verified cached crate: {name}@{version}; cargo fetch --locked first')
        license_file = package.get('license_file')
        if license_file:
            license_file = Path(license_file).relative_to(Path(package['manifest_path']).parent).as_posix()
        notices = crate_documents(verified_archive, name, version, license_file)
        if name == 'webpki-roots':
            require(notices['LICENSE'] == read(BASE + 'WEBPKI_ROOTS_LICENSE'), 'Reviewed CA license differs from locked crate')
        grouped = {}
        for path, content in sorted(notices.items()):
            grouped.setdefault(content, []).append(path)
        component = name + '@' + version
        for content, paths in grouped.items():
            append(component, '; '.join(paths), content, paths)
        rows.append({'name': name, 'version': version, 'license': package['license'],
                     'source': lock['source'], 'checksum': lock['checksum'], 'targets': sorted(set(targets))})

    tables = read('crates/ukai-jail/data/uts46_unicode17_tables.rs')
    header = tables.split(b'\n\n', 1)[0] + b'\n'
    append('unicode-uts46-data', 'Unicode 17.0.0 / UTS 46 revision 35 source attribution', header,
           ['crates/ukai-jail/data/uts46_unicode17_tables.rs [generated header]'])
    append('unicode-uts46-data', 'Unicode License v3', read(BASE + 'UNICODE_LICENSE'),
           ['https://www.unicode.org/license.txt', BASE + 'UNICODE_LICENSE'])

    rustc = run(['rustc', '+' + pin, '-Vv'], root).decode()
    require(f'release: {pin}\n' in rustc, 'Installed Rust does not match the pin')
    sysroot = Path(run(['rustc', '+' + pin, '--print', 'sysroot'], root).decode().strip())
    library = sysroot / 'share/doc/rust/COPYRIGHT-library.html'
    html = library.read_bytes()
    parser = LibraryText()
    parser.feed(html.decode())
    text = parser.text()
    append('rust-standard-library', f'Rust {pin} COPYRIGHT-library.html, readable body text', text,
           ['share/doc/rust/COPYRIGHT-library.html'])
    # In-tree source entries name standard licenses separately from the full
    # notices bundled for out-of-tree dependencies. Retain their shipped texts.
    expressions = ' '.join(unescape(value) for value in re.findall(r'<p><b>License:</b> (.*?)</p>', html.decode()))
    rust_licenses = {}
    for path in sorted((library.parent / 'licenses').glob('*.txt')):
        if path.stem in expressions:
            content = path.read_bytes()
            append('rust-standard-library', 'licenses/' + path.name, content, ['share/doc/rust/licenses/' + path.name])
            rust_licenses[path.name] = digest(content)
    require({'MIT.txt', 'Apache-2.0.txt'} <= set(rust_licenses), 'Missing Rust standard license texts')
    inventory = {'schema': SCHEMA, 'targets': list(TARGETS), 'packages': rows, 'documents': documents,
                 'inputs_sha256': {path: digest(read(path)) for path in INPUTS}, 'bundle_sha256': digest(output),
                 'rust_standard_library': {'release': pin, 'copyright_html_sha256': digest(html),
                    'readable_text_sha256': digest(text), 'preformatted_notices_preserved': len(parser.preformatted),
                    'standard_license_sha256': rust_licenses,
                    'scope': 'Upstream cross-platform library inventory and available notices retained as provided; named components are not all linked into the three shipped targets, and this is not a claim of full license-text coverage for unshipped components.'},
                 'selection': 'Union of normal cargo-tree dependencies for three shipped targets; includes proc-macro normal edges, excludes dev/build-only edges. Upstream notices conservatively retain cross-platform content.'}
    return bytes(output), json.dumps(inventory, indent=2, sort_keys=True).encode() + b'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('generate', 'check', 'print'))
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--revision')
    parser.add_argument('--check', action='store_true', help='Regenerate in memory and compare exact checked-in bytes')
    args = parser.parse_args()
    try:
        if args.command == 'generate':
            require(args.revision is None, 'Regeneration reads the current locked source tree')
            bundle, inventory = generate(args.source)
            if args.check:
                require((args.source / BUNDLE).read_bytes() == bundle and (args.source / INVENTORY).read_bytes() == inventory,
                        'Generated notice closure or bytes differ; regenerate and review')
            else:
                (args.source / BUNDLE).write_bytes(bundle)
                (args.source / INVENTORY).write_bytes(inventory)
        else:
            notices = checked(read_source(args.source, args.revision))
            if args.command == 'print':
                sys.stdout.buffer.write(notices)
            else:
                print('Notice input hashes, package inventory and bundled document bytes match.')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, f'Refused: {error}\n')


if __name__ == '__main__':
    main()
