#!/usr/bin/env python3
"""Build only the allowlisted inputs inside the isolated development guest."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def command(*args, check=True):
    p = subprocess.run(args, text=True, capture_output=True, timeout=120)
    row = {"argv": args, "exit": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    if check and p.returncode:
        raise RuntimeError(row)
    return row


def main():
    if not __debug__:
        raise SystemExit("Assertions are isolation checks; do not use python -O")
    root = Path(sys.argv[1]).resolve()
    assert command("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present")["stdout"].strip() == "1"
    assert command("/usr/bin/csrutil", "status")["stdout"].strip() == "System Integrity Protection status: disabled."
    assert command("/usr/sbin/networksetup", "-getnetworkserviceenabled", "Ethernet")["stdout"].strip() == "Disabled"
    routes = {family: command("/usr/sbin/netstat", "-rn", "-f", family)
              for family in ("inet", "inet6")}
    assert all(not re.search(r"(?m)^default\s", row["stdout"]) for row in routes.values()), "Guest must have no default route"
    interface = command("/sbin/ifconfig", "en0")
    assert "status: inactive" in interface["stdout"]
    mounts = command("/sbin/mount")
    assert "virtiofs" not in mounts["stdout"].lower(), "Host directory shares are forbidden"
    assert os.getuid() != 0, "Only setup of guest limits/network uses guest sudo"
    os.umask(0o077)
    (root / "trials").mkdir(mode=0o700, exist_ok=True)
    (root / "results").mkdir(mode=0o700, exist_ok=True)
    assert not any((root / "trials").iterdir()), "Never reconfigure a guest that already ran trials"
    hashes = json.loads((root / "inputs.json").read_text())
    for name, expected in hashes.items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
    record = {"vm": command("/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"),
              "os": command("/usr/bin/sw_vers"), "sip": command("/usr/bin/csrutil", "status"),
              "network": command("/usr/sbin/networksetup", "-getnetworkserviceenabled", "Ethernet"),
              "routes": routes, "interface": interface, "mounts": mounts, "uid": os.getuid(),
              "sdk": command("/usr/bin/xcrun", "--show-sdk-version"), "builds": [],
              "approved_entitlement": False, "release_evidence": False}
    builds = [
        ("macos_native.c", "native-fixture", ["-fblocks", "-lEndpointSecurity"]),
        ("macos_j16_spike_fixture.c", "spike-fixture", ["-pthread"]),
        ("macos_j16_spike_attack.c", "live-attack", ["-framework", "CoreServices"]),
        ("defense_probe.c", "defense-probe", []),
    ]
    for source, target, flags in builds:
        record["builds"].append(command("/usr/bin/xcrun", "clang", "-O1", "-Wall", "-Wextra",
            "-Wno-deprecated-declarations", *flags, str(root / "src" / source), "-o", str(root / "src" / target)))
    app = root / "Ukai.app"
    record["signing"] = command("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements",
                                str(root / "entitlements.plist"), str(app))
    record["signature"] = command("/usr/bin/codesign", "-dv", "--entitlements", ":-", str(app))
    record["artifacts"] = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in ["Ukai.app/Contents/MacOS/ukai-jail", *["src/" + b[1] for b in builds]]}
    (root / "results" / "guest-setup.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"setup": "PASS", "uid": os.getuid(), "sdk": record["sdk"]["stdout"].strip(),
                      "approved_entitlement": False, "release_evidence": False}))


if __name__ == "__main__":
    main()
