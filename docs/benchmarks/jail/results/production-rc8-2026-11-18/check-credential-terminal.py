"""Verify the repaired x86_64 binary's credential prompt on a disposable Linux PTY."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import tempfile
import termios
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_terminal(binary, environment, config, setup_error):
    master, slave = pty.openpty()
    child = None
    try:
        child = subprocess.Popen(
            [binary, "credential", "set", "fixture"],
            env=environment, stdin=slave, stdout=slave, stderr=slave,
        )
        if setup_error:
            require(child.wait(timeout=5) == 1, "terminal setup error must refuse without input")
            output = drain(master)
            require(b"paste the value" not in output, "prompted before securing the input")
            require(not (config / "credentials/fixture").exists(), "stored a credential on refusal")
            return "refused before prompting or receiving input; no stored file"

        deadline = time.monotonic() + 5
        output = bytearray()
        while b"Ctrl-D" not in output:
            ready, _, _ = select.select([master], [], [], max(0, deadline - time.monotonic()))
            require(ready, "timed out waiting for the credential prompt")
            output.extend(os.read(master, 8192))
        require(termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL) == 0,
                "echo is still on at the credential prompt")
        marker = b"synthetic-test-value"
        os.write(master, marker + b"\n\x04")
        require(child.wait(timeout=5) == 0, "ordinary terminal input failed")
        output.extend(drain(master))
        stored = config / "credentials/fixture"
        require(marker not in output, "the terminal echoed the fixture")
        require(stored.read_bytes() == marker and stored.stat().st_mode & 0o777 == 0o600,
                "wrong stored bytes or permissions")
        require(termios.tcgetattr(slave)[3] & termios.ECHO, "terminal echo was not restored")
        return "echo off at prompt, value stored privately, no echo, terminal restored"
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)
        os.close(slave)


def drain(fd):
    output = bytearray()
    while select.select([fd], [], [], 0)[0]:
        output.extend(os.read(fd, 8192))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    build = json.loads(subprocess.check_output([binary, "version", "--json"]))["build"]
    require(build["revision"] == args.revision and build["dirty"] is False
            and build["opt_level"] == "3" and build["target"] == "x86_64-unknown-linux-gnu",
            "expected a clean optimized x86_64 Linux binary at the specified revision")
    with binary.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    result = {"binary_sha256": digest, "build": build, "kernel": os.uname().release}
    with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
        root = Path(temporary)
        config = root / "config"
        env = {"HOME": str(root), "UKAI_CONFIG_DIR": str(config),
               "UKAI_DATA_DIR": str(root / "data"), "PATH": "/usr/bin:/bin"}
        source = root / "terminal_stub.c"
        shim = root / "terminal_stub.so"
        source.write_text(
            "#include <errno.h>\n#include <termios.h>\n"
            "int tcsetattr(int fd, int act, const struct termios *settings) "
            "{ errno = EIO; return -1; }\n"
        )
        subprocess.run(["cc", "-shared", "-fPIC", "-o", shim, source], check=True)
        result["terminal_setup_io_error"] = check_terminal(
            binary, {**env, "LD_PRELOAD": str(shim)}, config, setup_error=True,
        )
        result["ordinary_terminal"] = check_terminal(binary, env, config, setup_error=False)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
