#!/usr/bin/env python3
"""Record the environment the agent process holds inside the jail.

usage: arow_envprobe.py --out FILE --comm NAME --protected FILE -- ARGV...

Runs ARGV (stdin /dev/null, output discarded) and, while it runs, reads
/proc/PID/environ of the first descendant whose comm is NAME. Writes the
variable names, and the values of those that hold a vault placeholder
(`vault:` prefix), to FILE as JSON; every other value is omitted. A value is
written only if it starts with `vault:` and contains no protected value, so
the real credential can never be written even if it were present.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--comm", required=True)
    parser.add_argument("--protected", action="append", default=[], type=Path)
    parser.add_argument("argv", nargs="+")
    args = parser.parse_args()
    values = [p.read_bytes().rstrip(b"\n") for p in args.protected]
    process = subprocess.Popen(args.argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    record = None
    while record is None and process.poll() is None:
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
        for pid in sorted(descendants):
            try:
                if (Path("/proc") / str(pid) / "comm").read_text().strip() != args.comm:
                    continue
                raw = (Path("/proc") / str(pid) / "environ").read_bytes()
            except OSError:
                continue
            names, placeholders = [], {}
            for entry in raw.split(b"\0"):
                if not entry:
                    continue
                name, _, value = entry.partition(b"=")
                names.append(name.decode(errors="replace"))
                if value.startswith(b"vault:") and not any(v in value for v in values):
                    placeholders[name.decode()] = value.decode(errors="replace")
            record = {"comm": args.comm, "names": sorted(names), "vault_placeholders": placeholders,
                      "protected_value_present": any(v in raw for v in values)}
            break
        time.sleep(0.05)
    code = process.wait()
    args.out.write_text(json.dumps({"exit": code, "agent_environment": record}, indent=1) + "\n")
    print(json.dumps({"exit": code, "found": record is not None}))


if __name__ == "__main__":
    main()
