#!/usr/bin/env python3
"""Record final isolation, artifact hashes and test-owned process/job cleanup."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import sys

from macos_j16_spike_guest import command, guard, save

guard()
root = Path(sys.argv[1]).resolve()
processes = command(["/bin/ps", "-axo", "pid=,ppid=,stat=,args="])
assert processes["exit"] == 0
owned = [line for line in processes["stdout"].splitlines()
         if str(root) in line and "record_guest_state.py" not in line]
jobs = command(["/bin/launchctl", "list"])
assert jobs["exit"] == 0
owned_jobs = [line for line in jobs["stdout"].splitlines()
              if "com.ukai.validation." in line or "com.ukai.spike." in line]
paths = [p for p in (root / "src").iterdir() if p.is_file()]
paths += [root / "Ukai.app/Contents/MacOS/ukai-jail", root / "Ukai.app/Contents/Info.plist",
          root / "entitlements.plist"]
result = {
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "outcome": "PASS" if not owned and not owned_jobs else "FAIL",
    "remaining_test_owned_processes": owned, "remaining_test_owned_jobs": owned_jobs,
    "uid": os.getuid(), "rlimit_nproc": resource.getrlimit(resource.RLIMIT_NPROC),
    "guest_settings": command(["/usr/sbin/sysctl", "kern.hv_vmm_present", "kern.maxproc", "kern.maxprocperuid", "hw.model"]),
    "guest_sip": command(["/usr/bin/csrutil", "status"]),
    "ethernet": command(["/usr/sbin/networksetup", "-getnetworkserviceenabled", "Ethernet"]),
    "en0": command(["/sbin/ifconfig", "en0"]),
    "ipv4_routes": command(["/usr/sbin/netstat", "-rn", "-f", "inet"]),
    "ipv6_routes": command(["/usr/sbin/netstat", "-rn", "-f", "inet6"]),
    "mounts": command(["/sbin/mount"]),
    "version": command([root / "Ukai.app/Contents/MacOS/ukai-jail", "version", "--json"]),
    "codesign": command(["/usr/bin/codesign", "-dv", "--verbose=4", root / "Ukai.app"]),
    "files": {str(p.relative_to(root)): {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
              for p in paths},
}
save(root / "results/final-guest-state.json", result)
print(json.dumps({k: result[k] for k in ("outcome", "remaining_test_owned_processes", "remaining_test_owned_jobs")}))
