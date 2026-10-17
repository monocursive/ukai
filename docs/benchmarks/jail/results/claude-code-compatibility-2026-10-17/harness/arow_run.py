#!/usr/bin/env python3
"""One run of a command under ukai-jail for the Claude Code A-row record.

usage: arow_run.py --out DIR [--protected FILE]... [--wall S]
                   [--revoke FILE --revoke-after S] -- ARGV...

The command runs in the current directory with stdin /dev/null, stdout to
DIR/stdout, and stderr on a pseudo-terminal whose bytes go to
DIR/terminal.txt: ukai-jail prints its pre-exec line, the end-of-run summary
and the receipt line only when stderr is a terminal (J13 §4.1).

Exposure sampler, as the credential benchmarks' (credentials/2026-10-12
harness/vault_agents.py): every 100 ms, the environment and argv of every
descendant process, and every regular file of at most 1 MiB in the working
directory and in each attempt directory created after the start, are
searched for each protected value (environments are also tallied, readable
and unreadable, by process name); afterwards stdout and the terminal bytes
are too. The values are read into memory only; they are never printed or
written, and DIR/exposure.json records only where one was found.

--revoke FILE deletes FILE S seconds after the new attempt's journal records
its `exec_confirmed` lifecycle note (run 5: the source deleted mid-run).
"""
import argparse
import datetime
import json
import os
import pty
import signal
import subprocess
import threading
import time
from pathlib import Path


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def data_dir():
    if os.environ.get("UKAI_DATA_DIR"):
        return Path(os.environ["UKAI_DATA_DIR"])
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local/share")
    return Path(base) / "ukai"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--protected", action="append", default=[], type=Path)
    parser.add_argument("--wall", type=float, default=900)
    parser.add_argument("--revoke", type=Path)
    parser.add_argument("--revoke-after", type=float, default=15)
    parser.add_argument("argv", nargs="+")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)

    values = []
    for path in args.protected:
        value = path.read_bytes().rstrip(b"\n")
        if len(value) < 20:
            raise SystemExit("a protected value is shorter than 20 bytes; refusing to search for it")
        values.append(value)

    attempts = data_dir() / "attempts"
    before = set(p.name for p in attempts.iterdir()) if attempts.is_dir() else set()
    proof = {"schema": "sampled-credential-exposure/1", "period_ms": 100,
             "protected_values": len(values), "snapshots": 0,
             "readable_process_environments": 0, "unreadable_process_environments": 0,
             "files_checked": 0, "environments_by_name": {}, "hits": [],
             "actual_values_retained": False,
             "limit": "Periodic readable environment/argv and regular-file checks, "
                      "not arbitrary process memory or exhaustive history."}
    revocation = {}

    def check(where, data):
        if any(v in data for v in values) and where not in proof["hits"]:
            proof["hits"].append(where)

    master, slave = pty.openpty()
    stdout = open(args.out / "stdout", "wb")
    started_at, started = now(), time.monotonic()
    process = subprocess.Popen(args.argv, stdin=subprocess.DEVNULL, stdout=stdout,
                               stderr=slave, start_new_session=True)
    os.close(slave)
    stop = threading.Event()
    terminal = bytearray()

    def read_terminal():
        while True:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            terminal.extend(chunk)

    def new_attempts():
        if not attempts.is_dir():
            return []
        return [p for p in attempts.iterdir() if p.name not in before]

    def exec_confirmed(attempt):
        trace = attempt / "trace.ndjson"
        try:
            for line in trace.read_text(errors="replace").splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                fields = event.get("fields") or {}
                if event.get("operation") == "note" and fields.get("transition") == "exec_confirmed":
                    return True
        except OSError:
            pass
        return False

    def observe():
        while not stop.is_set():
            proof["snapshots"] += 1
            parents = {}
            for stat in Path("/proc").glob("[0-9]*/stat"):
                try:
                    parents[int(stat.parent.name)] = int(stat.read_text().rsplit(")", 1)[1].split()[1])
                except (OSError, ValueError, IndexError):
                    continue
            descendants = {process.pid}
            while True:
                grown = {pid for pid, parent in parents.items() if parent in descendants}
                if grown <= descendants:
                    break
                descendants |= grown
            for pid in descendants:
                try:
                    name = (Path("/proc") / str(pid) / "comm").read_text().strip()
                except OSError:
                    name = "?"
                tally = proof["environments_by_name"].setdefault(name, [0, 0])
                try:
                    check("process-environment", (Path("/proc") / str(pid) / "environ").read_bytes())
                    check("process-argv", (Path("/proc") / str(pid) / "cmdline").read_bytes())
                    proof["readable_process_environments"] += 1
                    tally[0] += 1
                except OSError:
                    proof["unreadable_process_environments"] += 1
                    tally[1] += 1
            fresh = new_attempts()
            for location in [Path.cwd()] + fresh:
                for path in location.rglob("*"):
                    try:
                        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
                            continue
                        check("file:" + ("workspace" if location == Path.cwd() else "attempt"),
                              path.read_bytes())
                        proof["files_checked"] += 1
                    except OSError:
                        continue
            if args.revoke and "deleted_at" not in revocation:
                if "exec_confirmed_seen" not in revocation and any(exec_confirmed(a) for a in fresh):
                    revocation["exec_confirmed_seen"] = time.monotonic()
                seen = revocation.get("exec_confirmed_seen")
                if seen is not None and time.monotonic() - seen >= args.revoke_after:
                    args.revoke.unlink()
                    revocation["deleted_at"] = now()
                    revocation["deleted_after_start_s"] = round(time.monotonic() - started, 3)
                    revocation["deleted_after_exec_confirmed_seen_s"] = round(time.monotonic() - seen, 3)
            stop.wait(0.1)

    reader = threading.Thread(target=read_terminal, daemon=True)
    watcher = threading.Thread(target=observe, daemon=True)
    reader.start()
    watcher.start()
    timed_out = False
    try:
        code = process.wait(timeout=args.wall)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            code = process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
    elapsed = time.monotonic() - started
    stop.set()
    watcher.join(timeout=10)
    reader.join(timeout=5)
    os.close(master)
    stdout.close()
    (args.out / "terminal.txt").write_bytes(bytes(terminal))
    check("raw-stdout", (args.out / "stdout").read_bytes())
    check("raw-terminal", bytes(terminal))
    (args.out / "exposure.json").write_text(json.dumps(proof, indent=1) + "\n")
    result = {"argv": args.argv, "cwd": str(Path.cwd()), "started_at": started_at,
              "ended_at": now(), "elapsed_s": round(elapsed, 3), "exit": code,
              "timed_out": timed_out, "new_attempts": sorted(p.name for p in new_attempts())}
    if args.revoke:
        result["revocation"] = {"file_deleted": "deleted_at" in revocation,
                                **{k: v for k, v in revocation.items() if k != "exec_confirmed_seen"}}
    (args.out / "exit.json").write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: result[k] for k in ("exit", "elapsed_s", "timed_out", "new_attempts")}))


if __name__ == "__main__":
    main()
