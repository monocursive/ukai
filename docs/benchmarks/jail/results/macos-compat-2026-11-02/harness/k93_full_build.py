#!/usr/bin/env python3
"""Full SQLite source-tree build with the measured explicit /var/tmp grant.

2026-11-02 diagnosis: Apple's tclsh8.5 creates its exec error-capture files
without honoring TMPDIR (measured on the host: a capture succeeds with an
unwritable TMPDIR), stat-ing the system P_tmpdir /private/var/tmp; under
the profile that stat is denied (EPERM, surfaced as "not owner") and no
write is ever attempted. The member TMPDIR already points at the granted
scratch root, so this is tool behavior, not a product gap. The grant here
is the operator's explicit per-attempt choice (--rw /private/var/tmp),
recorded in the receipt's profile parameters - never a silent broadening.
"""
import hashlib
import json
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

t = Trial(root, "k93-sqlite-full-var-tmp-grant")
try:
    developer = command(["xcode-select", "-p"])["stdout"].strip()
    compiler = command(["xcrun", "--find", "clang"])["stdout"].strip()
    sdk = command(["xcrun", "--show-sdk-path"])["stdout"].strip()
    script = "set -e\n" + shlex.join(["/bin/sh", str(source / "configure"),
                                      "--disable-tcl", "--disable-readline"])
    script += ("\n/usr/bin/make -j4 sqlite3 libsqlite3.a sqldiff\n"
               "./sqlite3 :memory: 'select sqlite_version();' > built-version.txt\n")
    t.result["build"] = {
        "project": "SQLite canonical source tree",
        "version_define": (source / "VERSION").read_text().strip(),
        "source_revision": (source / "manifest.uuid").read_text().strip(),
        "source_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "parallel_jobs": 4, "script": script,
        "compiler": command([compiler, "--version"]), "sdk": sdk,
        "explicit_grants": ["/private/var/tmp (--rw)", "workspace exec root (--ro, interim §13.3 step 4)"]}
    t.launch([root / "src/spike-fixture", "command", t.ws / "births.jsonl", "/usr/bin/env",
              "PATH=/usr/bin:/bin:/usr/sbin:/sbin:" + developer + "/usr/bin",
              "SDKROOT=" + sdk, "CFLAGS=-O2 -isysroot " + sdk,
              "CPPFLAGS=-isysroot " + sdk,
              "DEVELOPER_DIR=" + developer, "CC=" + compiler, "CC_FOR_BUILD=" + compiler,
              "/bin/sh", "-c", script], wall="240s",
              # The measured explicit grants of this attempt, both
              # receipt-recorded: /private/var/tmp for Apple tclsh8.5's
              # TMPDIR-ignoring exec error files, and the workspace as an
              # exec root (writable stays writable: the later read-write
              # entry wins) for the build's generated helpers (lemon,
              # mkkeywordhash, jimsh) - the interim shape of jail-macos
              # §13.3 step 4's workspace-helper review, pending the
              # per-helper digest design.
              extra_ro=[developer, t.ws], extra_rw=["/private/var/tmp"])
    t.finish(timeout=300)
    outputs = {p.name: {"bytes": p.stat().st_size,
                        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
               for p in (t.ws / name for name in ("sqlite3", "libsqlite3.a", "sqldiff"))
               if p.is_file()}
    t.result["build"]["outputs"] = outputs
    version = t.ws / "built-version.txt"
    t.result["build"]["built_version"] = version.read_text().strip() if version.exists() else None
    r = t.result.get("receipt") or {}
    details = r.get("lifetime", {}).get("native", {}).get("details", {})
    custody = details.get("custodians", {})
    t.result["receipt_read_write"] = (r.get("applied", {}).get("filesystem", {})
                                      or details.get("profile_parameters", {})
                                      or {}).get("read_write")
    t.result["ordinary_build_custody_loss_free"] = all(
        custody.get(c, {}).get("stream") == "contiguous" for c in ("supervisor", "guardian"))
    t.result["ordinary_build_observation_loss_free"] = all(
        r.get("coverage", {}).get(c, {}).get("status") == "active" for c in ("exec", "fs.write"))
    if (t.result.get("exit") != 0 or len(outputs) != 3
            or t.result["build"]["built_version"] != "3.53.2"
            or not t.result["ordinary_build_custody_loss_free"]
            or not t.result["ordinary_build_observation_loss_free"]):
        t.result["outcome"] = "FAIL"
    else:
        t.result["outcome"] = "PASS"
except Exception as error:
    t.result.update(outcome="FAIL", harness_error=repr(error), traceback=traceback.format_exc())
    if t.proc:
        t.result["before_emergency_cleanup"] = t.snapshots()
        t.artifacts()
finally:
    t.cleanup()
save(root / "results/k93-full-var-tmp.json",
     {"outcome": t.result["outcome"], "trials": [t.result],
      "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
print(json.dumps({"name": t.result["name"], "outcome": t.result["outcome"],
                  "exit": t.result.get("exit")}))
