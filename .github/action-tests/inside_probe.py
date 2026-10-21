#!/usr/bin/env python3
"""Runs inside the jail during the self-test (K80) and records what a jailed
process can see and reach on a GitHub-hosted runner. It only records; the
verdicts are selftest.py's, outside. Standard library and the image's curl
and unshare only.

usage: inside_probe.py --paths PATHS.json --out OUT.json
PATHS.json maps names to host paths the runner has (RUNNER_TEMP, the
file-command directory, ...), written by the job before the run.
"""
import argparse
import json
import os
import socket
import subprocess


def curl(*args):
    try:
        done = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", *args],
                              capture_output=True, text=True, timeout=30)
        return {"rc": done.returncode, "http": done.stdout.strip(), "error": done.stderr.strip()[-200:]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"rc": None, "error": repr(error)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--paths", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    with open(args.paths, encoding="utf-8") as handle:
        paths = json.load(handle)
    result = {"env_names": sorted(os.environ), "paths": {}}
    for name, path in paths.items():
        result["paths"][name] = {"path": path, "exists": os.path.lexists(path)}
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect("/var/run/docker.sock")
        result["docker_socket"] = "connected"
        sock.close()
    except OSError as error:
        result["docker_socket"] = f"{type(error).__name__} errno {error.errno}"
    result["allowed_host"] = curl("https://api.github.com/zen")
    result["off_allowlist"] = curl("https://example.com/")
    metadata = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    result["metadata_via_proxy"] = curl("-H", "Metadata: true", metadata)
    result["metadata_direct"] = curl("--noproxy", "*", "-H", "Metadata: true", metadata)
    try:
        nested = subprocess.run(["unshare", "--user", "--map-root-user", "/bin/true"],
                                capture_output=True, text=True, timeout=10)
        result["nested_user_namespace"] = {"rc": nested.returncode, "error": nested.stderr.strip()[-200:]}
    except (OSError, subprocess.TimeoutExpired) as error:
        result["nested_user_namespace"] = {"rc": None, "error": repr(error)}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=1, sort_keys=True)


if __name__ == "__main__":
    main()
