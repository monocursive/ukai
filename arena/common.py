"""Small file helpers shared by the M0 runner and evidence reader."""
import datetime as dt
import hashlib
import json
import os
import stat
from pathlib import Path


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(65536), b""):
            h.update(b)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def read(path):
    return json.loads(Path(path).read_text())


def regular_bytes(path, limit=1024 * 1024):
    """Do not follow a candidate symlink, block on a FIFO, or read unbounded files."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit or st.st_nlink != 1:
            raise ValueError("expected a bounded, singly linked regular file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(limit + 1)
        if len(data) > limit:
            raise ValueError("file grew beyond capture limit")
        return data
    finally:
        os.close(fd)


def manifest(root):
    root = Path(root)
    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()
                   and p.name != "SHA256SUMS")
    (root / "SHA256SUMS").write_text("".join(
        f"{sha(p)}  {p.relative_to(root).as_posix()}\n" for p in files))


def verify(root):
    root = Path(root).resolve()
    failures = []
    listed = set()
    for line in (root / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        p = root / name
        if name in listed or not p.resolve().is_relative_to(root) or p.is_symlink():
            failures.append(name)
            continue
        listed.add(name)
        if not p.is_file() or sha(p) != expected:
            failures.append(name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
              if p.is_file() and p.name != "SHA256SUMS"}
    failures.extend(sorted(actual - listed))
    return failures
