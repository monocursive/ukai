#!/usr/bin/env python3
"""Offline canonical SQLite source-tree build through the actual native jail."""
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import sys
import traceback
import zipfile

from macos_j16_spike_guest import Trial, command, guard, save

guard()
resource.setrlimit(resource.RLIMIT_NPROC, (2000, resource.getrlimit(resource.RLIMIT_NPROC)[1]))
assert resource.getrlimit(resource.RLIMIT_NPROC)[0] == 2000
root = Path(sys.argv[1]).resolve()
archive = root / "src/ukai-spike-sqlite-src-3530200.zip"
source = root / "src/sqlite-src-3530200"
if not source.exists():
    with zipfile.ZipFile(archive) as z:
        assert all(not Path(n).is_absolute() and ".." not in Path(n).parts for n in z.namelist())
        z.extractall(root / "src")
        for entry in z.infolist():
            mode = (entry.external_attr >> 16) & 0o777
            if mode:
                (root / "src" / entry.filename).chmod(mode)

t = Trial(root, "k93-sqlite-full-repository-explicit-temp")
try:
    temporary = t.ws / ".build-tmp"
    temporary.mkdir(mode=0o700)
    developer = command(["xcode-select", "-p"])["stdout"].strip()
    compiler = command(["xcrun", "--find", "clang"])["stdout"].strip()
    sdk = command(["xcrun", "--show-sdk-path"])["stdout"].strip()
    script = "set -e\n" + shlex.join(["/bin/sh", str(source / "configure"), "--disable-tcl", "--disable-readline"])
    script += "\n/usr/bin/make -j4 sqlite3 libsqlite3.a sqldiff\n./sqlite3 :memory: 'select sqlite_version();' > built-version.txt\n"
    files = [p for p in source.rglob("*") if p.is_file()]
    t.result["build"] = {"project": "SQLite canonical source tree", "version_define": (source / "VERSION").read_text().strip(),
                         "source_revision": (source / "manifest.uuid").read_text().strip(),
                         "source_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                         "source_files": len(files), "source_bytes": sum(p.stat().st_size for p in files),
                         "parallel_jobs": 4, "script": script, "compiler": command([compiler, "--version"]), "sdk": sdk}
    t.launch([root / "src/spike-fixture", "command", t.ws / "births.jsonl", "/usr/bin/env",
              "PATH=/usr/bin:/bin:/usr/sbin:/sbin:" + developer + "/usr/bin",
              "TMPDIR=" + str(temporary), "TMP=" + str(temporary), "TEMP=" + str(temporary),
              "SDKROOT=" + sdk, "CFLAGS=-O2 -isysroot " + sdk,
              "CPPFLAGS=-isysroot " + sdk,
              "DEVELOPER_DIR=" + developer, "CC=" + compiler, "CC_FOR_BUILD=" + compiler,
              "/bin/sh", "-c", script], wall="240s", extra_ro=[developer])
    t.finish(timeout=300)
    outputs = {p.name: {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
               for p in (t.ws / name for name in ("sqlite3", "libsqlite3.a", "sqldiff")) if p.is_file()}
    t.result["build"]["outputs"] = outputs
    version = t.ws / "built-version.txt"
    t.result["build"]["built_version"] = version.read_text().strip() if version.exists() else None
    r = t.result.get("receipt") or {}
    custody = r.get("lifetime", {}).get("native", {}).get("details", {}).get("custodians", {})
    t.result["ordinary_build_custody_loss_free"] = all(custody.get(c, {}).get("stream") == "contiguous" for c in ("supervisor", "guardian"))
    t.result["ordinary_build_observation_loss_free"] = all(r.get("coverage", {}).get(c, {}).get("status") == "active" for c in ("exec", "fs.write"))
    if (t.result["exit"] != 0 or len(outputs) != 3 or t.result["build"]["built_version"] != "3.53.2"
            or not t.result["ordinary_build_custody_loss_free"] or not t.result["ordinary_build_observation_loss_free"]):
        t.result["outcome"] = "FAIL"
except Exception as error:
    t.result.update(outcome="FAIL", harness_error=repr(error), traceback=traceback.format_exc())
    if t.proc:
        t.result["before_emergency_cleanup"] = t.snapshots()
        t.artifacts()
finally:
    t.cleanup()
save(root / "results/k93-full-repository-explicit-temp.json", {"outcome": t.result["outcome"], "trials": [t.result],
     "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
print(json.dumps({"name": t.result["name"], "outcome": t.result["outcome"], "exit": t.result.get("exit")}))
