"""Verify export integrity with Python's standard library; no network."""
import hashlib
from pathlib import Path
root=Path(__file__).resolve().parent
listed=set()
for line in (root/'SHA256SUMS').read_text().splitlines():
    expected,name=line.split('  ',1)
    p=root/name
    assert name not in listed and p.resolve().is_relative_to(root) and not p.is_symlink()
    listed.add(name)
    assert hashlib.sha256(p.read_bytes()).hexdigest()==expected, name
actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.name!='SHA256SUMS' and '__pycache__' not in p.parts}
assert actual==listed, (actual-listed,listed-actual)
print(f'{len(listed)} export files verified.')
