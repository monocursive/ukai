#!/usr/bin/env python3
"""A stand-in for ukai-jail in test_action_scripts.py: it logs each call
(argv, environment names, a digest of stdin, whether stdin is /dev/null) as
one JSON line to $STUB_LOG and answers the verbs the action's scripts use.
It never runs anything and proves nothing about the real binary."""
import hashlib
import json
import os
import sys
from pathlib import Path


def stdin_is_devnull():
    try:
        mine, null = os.fstat(0), os.stat("/dev/null")
    except OSError:
        return False
    return (mine.st_rdev, mine.st_ino) == (null.st_rdev, null.st_ino)


argv = sys.argv[1:]
record = {"argv": argv, "env_names": sorted(os.environ), "stdin_devnull": stdin_is_devnull()}
config = Path(os.environ["UKAI_CONFIG_DIR"])
data = Path(os.environ["UKAI_DATA_DIR"])
status = 0
if argv[:2] == ["credential", "set"]:
    value = sys.stdin.buffer.read()
    record["stdin_sha256"] = hashlib.sha256(value).hexdigest()
    (config / "credentials").mkdir(parents=True, exist_ok=True)
    (config / "credentials" / argv[-1]).write_bytes(value)
elif argv[:2] == ["credential", "rm"]:
    (config / "credentials" / argv[-1]).unlink()
elif argv[:1] == ["version"]:
    print(json.dumps({"build": {"revision": "stub"}}))
elif argv[:1] == ["doctor"]:
    ready = os.environ.get("STUB_DOCTOR_READY", "true") == "true"
    print(json.dumps({"ready": ready, "requirements": ["tree_termination"],
                      "capabilities": [{"name": "tree_termination",
                                        "status": "available" if ready else "unavailable",
                                        "reason_code": "ok" if ready else "bwrap_too_old"}]}))
    status = 0 if ready else 125
elif argv[:1] == ["run"]:
    attempt = data / "attempts" / "att_stub"
    attempt.mkdir(parents=True, exist_ok=True)
    (attempt / "jail.json").write_text('{"attempt_id": "att_stub"}\n')
    (attempt / "policy.json").write_text('{"digest": "sha256:stub"}\n')
    (attempt / "trace.ndjson").write_text(os.environ.get("STUB_TRACE", '{"note": "stub"}') + "\n")
    print(os.environ.get("STUB_RUN_STDOUT", "stub run"))
    status = int(os.environ.get("STUB_RUN_EXIT", "0"))
elif argv[:2] == ["tail", "--summary"]:
    if "--json" in argv:
        print(Path(os.environ["STUB_SUMMARY_JSON"]).read_text(), end="")
    else:
        print(os.environ.get("STUB_SUMMARY_TEXT", "ukai-jail: settled · exited 0"))
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(record) + "\n")
sys.exit(status)
