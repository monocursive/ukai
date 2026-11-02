#!/usr/bin/env python3
"""Guest-only J16/J17 trials. Results precede emergency cleanup.

The independent process oracle is macos_native.snapshot: a birth identity,
not PID existence, and zombies are not live processes. No product source is
modified. Every destructive signal is confined to the disposable VM.
"""
import argparse
import base64
import ctypes
import datetime
import hashlib
import json
import math
import os
import resource
from pathlib import Path
import shlex
import signal
import statistics
import subprocess
import time
import traceback

from macos_native import json_lines, signal_token, snapshot

LABEL = ("Measured in a SIP-disabled development VM with an ad-hoc entitlement; "
         "not a protected Mac, not release evidence (K104).")


def continuous_ns():
    class Timebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    lib.mach_continuous_time.restype = ctypes.c_uint64
    base = Timebase()
    assert lib.mach_timebase_info(ctypes.byref(base)) == 0
    return lib.mach_continuous_time() * base.numer // base.denom


def command(argv, timeout=30, **kw):
    start = time.monotonic()
    try:
        p = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=timeout, **kw)
        return {"argv": list(map(str, argv)), "exit": p.returncode, "stdout": p.stdout,
                "stderr": p.stderr, "elapsed_ms": (time.monotonic()-start)*1000}
    except subprocess.TimeoutExpired as e:
        return {"argv": list(map(str, argv)), "timeout": timeout,
                "stdout": (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else e.stdout,
                "stderr": (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else e.stderr,
                "elapsed_ms": (time.monotonic()-start)*1000}


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def save(path, data):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, indent=2) + "\n")
    temp.replace(path)


def rows(path):
    return json_lines(path.read_text(errors="replace")) if path.exists() else []


def guard():
    assert command(["sysctl", "-n", "kern.hv_vmm_present"])["stdout"].strip() == "1"
    assert command(["csrutil", "status"])["stdout"].strip() == "System Integrity Protection status: disabled."
    assert command(["networksetup", "-getnetworkserviceenabled", "Ethernet"])["stdout"].strip() == "Disabled"


class Trial:
    def __init__(self, root, name):
        self.root = root
        self.dir = root / "trials" / name
        self.dir.mkdir(mode=0o700)
        for part in ("workspace", "config", "data", "tmp"):
            (self.dir / part).mkdir(mode=0o700)
        self.ws = self.dir / "workspace"
        self.exe = root / "Ukai.app/Contents/MacOS/ukai-jail"
        self.fixture = root / "src/native-fixture"
        self.env = {"HOME": str(Path.home()), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "TMPDIR": str(self.dir / "tmp"), "LANG": "en_US.UTF-8",
                    "UKAI_JAIL_MACOS_NATIVE": "dev", "UKAI_CONFIG_DIR": str(self.dir / "config"),
                    "UKAI_DATA_DIR": str(self.dir / "data")}
        self.result = {"name": name, "label": LABEL, "workspace": str(self.ws),
                       "env": self.env, "actions": [], "outcome": "PENDING"}
        self.proc = None
        self.guardian = None
        self.custodian_births = {}
        self.handles = []

    def invoke(self, *args, timeout=30):
        return command([self.exe, *args], timeout, env=self.env, cwd=self.ws)

    def discover_guardian(self):
        text = command(["ps", "-axo", "pid=,ppid=,comm="])["stdout"]
        for line in text.splitlines():
            parts = line.split(None, 2)
            if len(parts) == 3 and int(parts[1]) == self.proc.pid and parts[2].endswith("ukai-jail"):
                return int(parts[0])
        return None

    def launch(self, target, wall="3s", observe="on", evidence="best-effort", extra_ro=()):
        stdout = (self.dir / "stdout.txt").open("w")
        stderr = (self.dir / "stderr.txt").open("w")
        trace = (self.dir / "trace.jsonl").open("w")
        control = (self.dir / "control.jsonl").open("w")
        self.handles = [stdout, stderr, trace, control]
        argv = [str(self.exe), "run", "--profile", "tool", "--workspace", str(self.ws),
                "--ro", str(self.root / "src"), "--limit", "wall=" + wall,
                "--terminal", "detach", "--observe", observe, "--evidence", evidence,
                "--receipt", str(self.dir / "receipt.json"), "--trace-fd", str(trace.fileno()),
                "--control-fd", str(control.fileno())]
        for path in extra_ro:
            argv += ["--ro", str(path)]
        argv += ["--", *map(str, target)]
        self.result["argv"] = argv
        self.result["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.start = time.monotonic()
        self.proc = subprocess.Popen(argv, env=self.env, cwd=self.ws, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, pass_fds=(trace.fileno(), control.fileno()))
        self.result["supervisor_pid"] = self.proc.pid
        self.custodian_births[self.proc.pid] = json.loads(command([self.fixture, "info", self.proc.pid])["stdout"])

    def ready(self, timeout=35):
        until = time.monotonic()+timeout
        while time.monotonic()<until:
            if self.guardian is None:
                self.guardian = self.discover_guardian()
                if self.guardian:
                    self.custodian_births[self.guardian] = json.loads(command([self.fixture, "info", self.guardian])["stdout"])
                    (self.ws / "targets.sh").write_text(
                        "export OURO_RESEARCH_GUARDIAN_PID=" + str(self.guardian) + "\n" +
                        "export OURO_RESEARCH_WARD_PID=" + str(self.proc.pid) + "\n")
                    self.result["guardian_pid"] = self.guardian
            values = rows(self.dir / "stdout.txt") + rows(self.ws / "births.jsonl")
            if any(v.get("ready") for v in values):
                self.result["ready_ms"] = (time.monotonic()-self.start)*1000
                return True
            if self.proc.poll() is not None:
                self.result["readiness_failure"] = "supervisor exited before fixture ready"
                return False
            time.sleep(.025)
        self.result["readiness_failure"] = "fixture not ready within timebox"
        return False

    def signal(self, pid, sig):
        row = {"pid": pid, "signal": sig, "since_start_ms": (time.monotonic()-self.start)*1000,
               "continuous_ns": continuous_ns()}
        try:
            os.kill(pid, sig)
            row["sent"] = True
        except ProcessLookupError:
            row["sent"] = False
        self.result["actions"].append(row)

    def known(self):
        all_rows = rows(self.dir / "stdout.txt") + rows(self.ws / "births.jsonl")
        known = {}
        for row in all_rows:
            if "audit_token" in row and row.get("unique_bytes") == 56:
                known[(row["pid"], row["uniqueid"])] = row
        self.result["fixture_records"] = all_rows
        return list(known.values())

    def snapshots(self):
        known = self.known()
        before = time.monotonic()
        snapshots = [{"birth": row, "snapshot": snapshot(self.fixture, row)} for row in known]
        return {"started_since_launch_ms": (before-self.start)*1000,
                "duration_ms": (time.monotonic()-before)*1000, "identities": snapshots,
                "empty": not any(row["snapshot"]["alive"] for row in snapshots) if known else None}

    def artifacts(self):
        self.result["receipt"] = read_json(self.dir / "receipt.json")
        paths = [p for p in (self.dir / "data").rglob("*") if p.is_file()]
        self.result["files"] = {str(p.relative_to(self.dir)): p.read_text(errors="replace")
                                for p in paths if p.stat().st_size < 8_000_000}
        self.result["binary_files_base64"] = {str(p.relative_to(self.dir)): base64.b64encode(p.read_bytes()).decode()
                                              for p in paths if p.name == "launch-block"}
        self.result["large_files"] = [str(p) for p in paths if p.stat().st_size >= 8_000_000]
        for key, path in (("stdout", "stdout.txt"), ("stderr", "stderr.txt"),
                          ("trace", "trace.jsonl"), ("control", "control.jsonl")):
            file = self.dir / path
            self.result[key] = file.read_text(errors="replace") if file.exists() else ""
        self.result["guardian_records"] = [read_json(p) for p in (self.dir / "data").rglob("guardian*.json")]

    def finish(self, timeout=15, snapshot_tree=True):
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.result["supervisor_timeout"] = timeout
        self.result["exit"] = self.proc.poll()
        self.result["elapsed_ms"] = (time.monotonic()-self.start)*1000
        if snapshot_tree:
            self.result["before_emergency_cleanup"] = self.snapshots()
        self.result["custodians_before_emergency_cleanup"] = {
            str(pid): snapshot(self.fixture, birth) for pid, birth in self.custodian_births.items()
        }
        self.artifacts()
        r = self.result["receipt"] or {}
        lifetime = r.get("lifetime", {})
        self.result["tree_empty"] = lifetime.get("tree_empty")
        self.result["phase"] = r.get("phase")
        independent = self.result.get("before_emergency_cleanup", {}).get("empty")
        self.result["false_tree_empty"] = lifetime.get("tree_empty") is True and independent is False
        self.result["outcome"] = "PASS" if r.get("phase") == "settled" and lifetime.get("tree_empty") is True and (
            not snapshot_tree or independent is True) else "FAIL"
        return self.result

    def cleanup(self):
        # This always follows the retained pre-cleanup oracle and artifacts.
        if self.proc is None:
            return
        cleanup = []
        for row in self.known():
            now = snapshot(self.fixture, row)
            if now["alive"]:
                current = dict(row)
                current["audit_token"] = list(row["audit_token"])
                current["audit_token"][7] = now["pidversion"] & 0xffffffff
                cleanup.append({"birth": row, "signal": signal_token(current, signal.SIGKILL)})
        for pid in (self.guardian, self.proc.pid):
            if pid:
                try:
                    birth = self.custodian_births.get(pid)
                    if birth and snapshot(self.fixture, birth)["alive"]:
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
        for handle in self.handles:
            handle.close()
        self.result["emergency_cleanup"] = cleanup
        self.result["after_emergency_cleanup"] = self.snapshots()


def tree_target(t):
    script = ("while [ ! -f targets.sh ]; do /bin/sleep 0.02; done; . ./targets.sh; exec " +
              shlex.quote(str(t.fixture)) + " tree-spawn " + shlex.quote(str(t.ws)))
    return ["/bin/sh", "-c", script]


def simple(root, name, target):
    t = Trial(root, name)
    try:
        t.launch(target, wall="10s", evidence="strict")
        t.finish(snapshot_tree=False)
        r = t.result.get("receipt") or {}
        obs = r.get("observer", {})
        coverage = r.get("coverage", {})
        t.result["observation_checks"] = {
            "attached": obs.get("attached") is True,
            "closed_set": obs.get("set") == "macos-closed-v1",
            "exec_active": coverage.get("exec", {}).get("status") == "active",
            "write_active": coverage.get("fs.write", {}).get("status") == "active",
            "exec_count": isinstance(coverage.get("exec", {}).get("observed_count"), int),
            "write_count": isinstance(coverage.get("fs.write", {}).get("observed_count"), int),
            "deny_unsupported": coverage.get("fs.deny", {}).get("status") == "unsupported",
            "net_unsupported": coverage.get("net", {}).get("status") == "unsupported",
        }
        if not all(t.result["observation_checks"].values()):
            t.result["outcome"] = "FAIL"
        if "mutations" in name:
            actions = {event.get("fields", {}).get("action") for event in json_lines(t.result.get("trace", ""))
                       if event.get("source") == "audit" and event.get("fields", {}).get("path", {}).get("kind") == "workspace_relative"}
            t.result["expected_mutations"] = {action: action in actions for action in
                ("created", "modified", "renamed", "hard_link_created", "metadata_changed", "unlinked")}
            if not all(t.result["expected_mutations"].values()):
                t.result["outcome"] = "FAIL"
    finally:
        t.cleanup()
    return t.result


def lifecycle(root, name, mode, stress=None):
    t = Trial(root, name)
    try:
        wall = "3s" if mode in ("wall", "supervisor_stop", "guardian_stop") else "12s"
        target = tree_target(t) if stress is None else [root / "src/spike-fixture", stress, t.ws / "births.jsonl"]
        t.launch(target, wall=wall)
        if t.ready():
            if stress:
                time.sleep(.4)
                t.result["guest_uid_processes_before_stop"] = command(["sh", "-c", 'ps -axo uid= | awk -v uid="$(id -u)" \'$1==uid {n++} END {print n}\''])
            started = time.monotonic()
            if mode in ("int", "term", "supervisor_kill", "supervisor_stop"):
                t.signal(t.proc.pid, {"int": signal.SIGINT, "term": signal.SIGTERM,
                                     "supervisor_kill": signal.SIGKILL, "supervisor_stop": signal.SIGSTOP}[mode])
            elif mode in ("guardian_kill", "guardian_stop"):
                t.signal(t.guardian, signal.SIGKILL if mode == "guardian_kill" else signal.SIGSTOP)
                if "tail" in name:
                    time.sleep(7)
                    t.result["before_guardian_tail"] = t.snapshots()
            elif mode == "target_exit":
                root_row = next(r for r in t.known() if r["role"] == "root")
                t.result["target_exit_signal"] = signal_token(root_row, signal.SIGTERM)
            elif mode in ("killall", "both_killall"):
                t.result["killall"] = command(["killall", "-9" if mode == "both_killall" else "-TERM", "ukai-jail"])
            elif mode == "both_serial":
                # Freeze both first so the two KILLs test simultaneous loss,
                # not a scheduling race in which the survivor drains first.
                t.signal(t.proc.pid, signal.SIGSTOP)
                t.signal(t.guardian, signal.SIGSTOP)
                t.signal(t.proc.pid, signal.SIGKILL)
                t.signal(t.guardian, signal.SIGKILL)
            if mode in ("supervisor_kill", "supervisor_stop"):
                if "timing" in name:
                    samples = []
                    until = time.monotonic() + 9
                    while time.monotonic() < until:
                        sample = t.snapshots()
                        samples.append({"since_fault_ms": (time.monotonic()-started)*1000,
                                        "empty": sample["empty"]})
                        if sample["empty"] is True:
                            break
                        time.sleep(.05)
                    t.result["empty_poll_samples"] = samples
                    t.result["first_empty_after_fault_ms"] = samples[-1]["since_fault_ms"] if samples[-1]["empty"] else None
                    time.sleep(.2)
                else:
                    time.sleep(7 if mode == "supervisor_kill" else 9)
                t.result["before_gc"] = t.snapshots()
                t.artifacts()
                t.result["guardian_records_before_gc"] = t.result["guardian_records"]
                t.result["gc"] = t.invoke("gc", "--json")
                if mode == "supervisor_stop":
                    t.signal(t.proc.pid, signal.SIGCONT)
            elif mode.startswith("both_"):
                time.sleep(.1)
                t.result["survivors_after_loss"] = t.snapshots()
                t.artifacts()
                t.result["receipt_after_loss"] = t.result["receipt"]
                t.result["next_run"] = t.invoke("run", "--profile", "tool", "--workspace", t.ws,
                                                 "--limit", "wall=3s", "--", "/usr/bin/true", timeout=20)
                t.result["gc"] = t.invoke("gc", "--json")
                t.result["after_gc"] = t.snapshots()
                r = t.result["receipt_after_loss"] or {}
                if r.get("attempt_id"):
                    t.result["abandon"] = t.invoke("gc", "--json", "--abandon", r["attempt_id"])
            t.result["stop_requested_since_launch_ms"] = (started-t.start)*1000
            t.result["stop_to_wait_start_ms"] = (time.monotonic()-started)*1000
        t.finish(timeout=75 if "tail" in name else 15)
        if t.result.get("readiness_failure"):
            t.result["outcome"] = "BLOCKED"
            t.result["blocked_reason"] = "Requested fixture never became ready; lifecycle fault was not injected"
        if "ready_ms" in t.result:
            t.result["stop_to_snapshot_ms"] = t.result["before_emergency_cleanup"]["started_since_launch_ms"] - t.result["stop_requested_since_launch_ms"]
        if mode in ("guardian_kill", "guardian_stop") and not t.result.get("readiness_failure"):
            code = "custodian_lost" if mode == "guardian_kill" else "custodian_stalled"
            r = t.result.get("receipt") or {}
            t.result["expected_custodian_error_present"] = any(e.get("code") == code for e in r.get("errors", []))
            if not t.result["expected_custodian_error_present"]:
                t.result["outcome"] = "FAIL"
        if mode == "supervisor_kill" and not t.result.get("readiness_failure"):
            drained = any(r and r.get("drained") for r in t.result.get("guardian_records_before_gc", []))
            gc_verified = "gc_custody_verified" in json.dumps(t.result.get("gc"))
            t.result["outcome"] = "PASS" if t.result.get("before_gc", {}).get("empty") and drained and gc_verified else "FAIL"
        if mode == "supervisor_stop" and not t.result.get("readiness_failure"):
            entries = json.loads(t.result["gc"]["stdout"]).get("entries", [])
            t.result["gc_retained_live_supervisor"] = any(entry.get("action") == "retained" and "live supervisor" in entry.get("reason", "") for entry in entries)
            if not t.result.get("before_gc", {}).get("empty") or not t.result["gc_retained_live_supervisor"]:
                t.result["outcome"] = "FAIL"
        if stress and not t.result.get("readiness_failure"):
            r = t.result.get("receipt") or {}
            lifetime = r.get("lifetime", {})
            t.result["honest_unknown"] = lifetime.get("tree_empty") is None and r.get("phase") != "settled" and lifetime.get("integrity") == "lost"
            if t.result["honest_unknown"] and not t.result["false_tree_empty"]:
                t.result["outcome"] = "PASS"
        if mode.startswith("both_") and not t.result.get("readiness_failure"):
            r = t.result.get("receipt_after_loss") or {}
            t.result["residual_checks"] = {
                "never_settled": r.get("phase") not in (None, "settled"),
                "survivors_recorded": bool(t.result.get("survivors_after_loss", {}).get("identities")),
                "gc_target_attempted": "gc_killed_target" in json.dumps(t.result.get("gc")),
                "abandon_recorded": "gc_abandoned" in json.dumps(t.result.get("abandon")),
                "next_run_warned": "ended unverified" in json.dumps(t.result.get("next_run")),
                "lease_unmeasured": "Native vendor staging refuses before acquiring a J14 lease on this build",
            }
            t.result["outcome"] = "BLOCKED" if all(v is True for v in t.result["residual_checks"].values() if isinstance(v, bool)) else "FAIL"
    except Exception as e:
        t.result["harness_error"] = repr(e)
        t.result["traceback"] = traceback.format_exc()
        t.result["outcome"] = "FAIL"
        if t.proc:
            t.result["before_emergency_cleanup"] = t.snapshots()
            t.artifacts()
    finally:
        t.cleanup()
    return t.result


def heavy_build(root, name="k93-sqlite-build"):
    """Four parallel SQLite 3.53.2 amalgamation configurations, entirely offline."""
    t = Trial(root, name)
    try:
        source = root / "src/sqlite3.c"
        if not source.exists():
            t.result.update(outcome="BLOCKED", blocked_reason="No staged offline SQLite amalgamation")
            return t.result
        sdk = Path(command(["xcrun", "--show-sdk-path"])["stdout"].strip())
        clang = Path(command(["xcrun", "--find", "clang"])["stdout"].strip())
        ar = Path(command(["xcrun", "--find", "ar"])["stdout"].strip())
        make_path = Path(command(["xcrun", "--find", "make"])["stdout"].strip())
        wrapper = [root/"src/spike-fixture", "command", t.ws/"births.jsonl"]
        def wrapped(args):
            return shlex.join([str(v) for v in [*wrapper, *args]])
        variants = {"base": [], "fts5": ["-DSQLITE_ENABLE_FTS5"],
                    "rtree": ["-DSQLITE_ENABLE_RTREE"], "debug": ["-DSQLITE_DEBUG"]}
        make = "SHELL := /bin/bash\n.PHONY: all\nall: " + " ".join("lib"+v+".a" for v in variants) + "\n"
        for name, flags in variants.items():
            make += name+".o:\n\t"+wrapped([clang,"-O2","-isysroot",sdk,"-c",source,"-o",name+".o",*flags])+"\n"
            make += "lib"+name+".a: "+name+".o\n\t"+wrapped([ar,"rcs","lib"+name+".a",name+".o"])+"\n"
        (t.ws/"Makefile").write_text(make)
        version = next(line for line in (root/"src/sqlite3.h").read_text().splitlines() if line.startswith("#define SQLITE_VERSION "))
        t.result["build"] = {"project": "SQLite", "version_define": version, "parallel_jobs": 4,
            "source_lines": len(source.read_bytes().splitlines()), "source_bytes": source.stat().st_size,
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "makefile": make,
            "compiler": command([clang,"--version"]), "sdk": str(sdk)}
        developer = Path(command(["xcode-select", "-p"])["stdout"].strip())
        # Apple's make consults xcode-select even when invoked by absolute path.
        # Explicitly select and grant the offline toolchain for this workload.
        t.result["build"]["developer_dir"] = str(developer)
        t.launch([*wrapper, "/usr/bin/env", "DEVELOPER_DIR="+str(developer), make_path, "-j4", "all"],
                 wall="240s", extra_ro=[developer])
        t.finish(timeout=300)
        t.result["build"]["outputs"] = {p.name: {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                                            for p in t.ws.glob("*.a")}
        if t.result["exit"] != 0 or len(t.result["build"]["outputs"]) != 4:
            t.result["outcome"] = "FAIL"
        coverage = (t.result.get("receipt") or {}).get("coverage", {})
        t.result["ordinary_build_observation_loss_free"] = all(coverage.get(c, {}).get("status") == "active" for c in ("exec", "fs.write"))
        if not t.result["ordinary_build_observation_loss_free"]:
            t.result["outcome"] = "FAIL"
    except Exception as error:
        t.result["outcome"] = "FAIL"; t.result["harness_error"] = repr(error)
        if t.proc:
            t.result["before_emergency_cleanup"] = t.snapshots(); t.artifacts()
    finally:
        t.cleanup()
    return t.result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--scenario", required=True)
    p.add_argument("--trials", type=int, default=5)
    p.add_argument("--maxproc", type=int, default=2000)
    a = p.parse_args()
    guard()
    limits_before = resource.getrlimit(resource.RLIMIT_NPROC)
    assert a.maxproc <= limits_before[1], "requested guest maxproc exceeds inherited hard limit"
    resource.setrlimit(resource.RLIMIT_NPROC, (a.maxproc, limits_before[1]))
    limits_after = resource.getrlimit(resource.RLIMIT_NPROC)
    assert limits_after[0] == a.maxproc, ("guest kernel clamped maxproc", limits_after)
    root = a.root.resolve()
    os.umask(0o077)
    result = {"label": LABEL, "scenario": a.scenario, "trials": [], "outcome": "PENDING",
              "guest_nproc_before": limits_before, "guest_nproc_after": limits_after,
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    path = root / "results" / (a.scenario + ".json")
    def append(row):
        result["trials"].append(row)
        save(path, result)
    if a.scenario == "doctor":
        t = Trial(root, "doctor")
        result["doctor"] = t.invoke("doctor", "--json", "--profile", "tool", "--workspace", t.ws)
        result["version"] = t.invoke("version", "--json")
        result["outcome"] = "PASS" if result["doctor"].get("exit") == 0 else "FAIL"
    elif a.scenario in ("smoke", "smoke-chmod-change"):
        append(simple(root, a.scenario + "-true", ["/usr/bin/true"]))
        append(simple(root, a.scenario + "-mutations", ["/bin/sh", "-c",
            "set -e; printf test > original; mv original renamed; ln renamed linked; chmod 640 linked; rm linked"]))
    elif a.scenario in ("k87", "k87-wall-repeat"):
        for mode in (("wall",) if a.scenario == "k87-wall-repeat" else ("wall", "int", "term", "target_exit")):
            for i in range(a.trials):
                append(lifecycle(root, f"{a.scenario}-{mode}-{i:02d}", mode))
    elif a.scenario in ("k88", "k89", "k95", "k89-tail", "k88-timing"):
        modes = {"k88": ("supervisor_kill", "supervisor_stop", "killall"),
                 "k89": ("guardian_kill", "guardian_stop"),
                 "k95": ("both_serial", "both_killall"),
                 "k89-tail": ("guardian_stop",),
                 "k88-timing": ("supervisor_kill", "supervisor_stop")}[a.scenario]
        for mode in modes:
            append(lifecycle(root, a.scenario + "-" + mode, mode))
    elif a.scenario in ("k92", "k93"):
        modes = ("parallel", "continue", "orphan", "chain", "exec") if a.scenario == "k92" else ("storm", "signal")
        for mode in modes:
            for i in range(a.trials):
                append(lifecycle(root, f"{a.scenario}-{mode}-{i:02d}", "term", stress=mode))
        values = [t["stop_to_snapshot_ms"] for t in result["trials"] if "stop_to_snapshot_ms" in t]
        if values:
            result["timings"] = {"definition": "operator stop after readiness to start of independent snapshots",
                                 "n": len(values), "p50_ms": statistics.median(values),
                                 "p95_ms": sorted(values)[math.ceil(.95*len(values))-1]}
        else:
            result["timings"] = {"n": 0, "p50_ms": None, "p95_ms": None,
                                 "reason": "No workload became ready; startup refusal time is not stop time"}
        if a.scenario == "k93":
            build = heavy_build(root)
            append(build)
            result["heavy_build"] = {"outcome": build["outcome"], "project": "SQLite", "trial": build["name"]}
    elif a.scenario == "k93-build-repeat":
        append(heavy_build(root, "k93-sqlite-build-explicit-toolchain"))
    elif a.scenario == "k90-deputy-repeat":
        from macos_j16_spike_matrix import kickstart_repeat
        for custodian in ("supervisor", "guardian"):
            append(kickstart_repeat(root, custodian))
    elif a.scenario == "k90":
        from macos_j16_spike_matrix import matrix
        for custodian in ("supervisor", "guardian"):
            append(matrix(root, custodian))
    else:
        raise ValueError("scenario not implemented: " + a.scenario)
    if result["trials"]:
        outcomes = [t["outcome"] for t in result["trials"]]
        result["counts"] = {s: outcomes.count(s) for s in ("PASS", "FAIL", "BLOCKED")}
        result["outcome"] = "FAIL" if "FAIL" in outcomes else "BLOCKED" if "BLOCKED" in outcomes else "PASS"
    save(path, result)
    print(json.dumps({"scenario": a.scenario, "outcome": result["outcome"], "trials": len(result["trials"])}))


if __name__ == "__main__":
    main()
