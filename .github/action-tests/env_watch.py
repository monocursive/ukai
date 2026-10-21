#!/usr/bin/env python3
"""Samples the environment of every running ukai-jail process during the
self-test (K78: the variable a `credentials` line names is absent from
ukai-jail's own environment). Every 20 ms it reads /proc/PID/environ of each
process started as EXE (its argv[0]); the supervisor makes itself non-dumpable
before it releases the command (crates/ukai-jail/src/supervisor/attempt.rs),
so after that point its environment is unreadable and is counted as such.
The value is read from this process's own environment into memory and never
written: OUT records only counts and where a name or value was found.

usage: env_watch.py --exe PATH --name VAR --out OUT.json --stop FILE
It stops when FILE exists.
"""
import argparse
import json
import os
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--stop", required=True)
    args = parser.parse_args()
    value = os.environ[args.name].encode()
    name = args.name.encode() + b"="
    exe = args.exe.encode()
    seen = {}
    summary = {"schema": "ukai-selftest-env-watch/1", "name": args.name, "processes": 0,
               "readable_snapshots": 0, "unreadable_snapshots": 0, "by_verb": {}, "name_found": [],
               "value_found": [], "limit": "20 ms sampling of /proc/PID/environ; a process "
               "non-dumpable at the time of a sample cannot be read"}
    while not os.path.exists(args.stop):
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                # cmdline stays readable when the process is not dumpable
                with open(f"/proc/{pid}/cmdline", "rb") as handle:
                    words = handle.read().split(b"\0")
            except OSError:
                continue
            if words[0] != exe:
                continue
            verb = " ".join(w.decode(errors="replace") for w in words[1:3] if w)
            if pid not in seen:
                seen[pid] = verb
                summary["processes"] += 1
            tally = summary["by_verb"].setdefault(verb, {"readable": 0, "unreadable": 0})
            try:
                with open(f"/proc/{pid}/environ", "rb") as handle:
                    environ = handle.read()
            except OSError:
                summary["unreadable_snapshots"] += 1
                tally["unreadable"] += 1
                continue
            summary["readable_snapshots"] += 1
            tally["readable"] += 1
            entries = environ.split(b"\0")
            if any(entry.startswith(name) for entry in entries) and verb not in summary["name_found"]:
                summary["name_found"].append(verb)
            if value in environ and verb not in summary["value_found"]:
                summary["value_found"].append(verb)
        time.sleep(0.02)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
