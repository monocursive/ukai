#!/usr/bin/env python3
"""Package an explicit allowlist of credential-free lab sources, never evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
FILES = ['reader_lab.py', 'arena.py', 'collector.py', 'common.py', 'evidence.py',
         'm1/__init__.py', 'm1/runtime.py', 'm1/prepare.py', 'm1/scoring.py', 'm1/adapters.py',
         'experiments/__init__.py', 'experiments/boundary_suite.py']
TREES = ['experiments/boundary-suite-v1', 'm1/scenarios/local-postinstall', 'm1/agents']
VERIFY = '''#!/usr/bin/env python3
"""Verify package bytes only; no network or lab execution."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent
manifest=json.loads((root/'manifest.json').read_text())
errors=[]
for name,wanted in manifest['files'].items():
    p=root/name
    if Path(name).is_absolute() or '..' in Path(name).parts or p.is_symlink() or not p.is_file():
        errors.append(name+': missing or unsafe')
    elif hashlib.sha256(p.read_bytes()).hexdigest()!=wanted:
        errors.append(name+': checksum mismatch')
print(json.dumps({'files_checked':len(manifest['files']),'errors':errors,
                  'scope':'package integrity only; no experiment executed'},indent=2))
raise SystemExit(bool(errors))
'''


def package(out):
    sources = [ROOT / name for name in FILES]
    for name in TREES:
        sources += [p for p in (ROOT / name).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    payload = {'source/' + str(p.relative_to(ROOT)): p.read_bytes() for p in sorted(sources)}
    payload['README.md'] = (ROOT / 'READER-LAB.md').read_bytes()
    payload['LICENSE'] = (ROOT.parent / 'LICENSE').read_bytes()
    payload['verify.py'] = VERIFY.encode()
    payload['manifest.json'] = (json.dumps({'schema': 'arena.reader-lab.package/1',
        'edition': '2026-11-01', 'experiment': 'boundary-suite-v1',
        'files': {name: hashlib.sha256(data).hexdigest() for name, data in sorted(payload.items())}},
        indent=2) + '\n').encode()
    with zipfile.ZipFile(out, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(payload.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    out.with_suffix(out.suffix + '.sha256').write_text(digest + '  ' + out.name + '\n')
    return {'archive': str(out), 'files': len(payload), 'sha256': digest, 'bytes': out.stat().st_size}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    print(json.dumps(package(parser.parse_args().out), indent=2))
