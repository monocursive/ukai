"""Frozen TIME-case program: sleeps `duration` seconds with exactly one child.

Without enforcement the process tree stays active for the full duration;
the parent exits with the child's status after both have slept.
"""
import subprocess
import sys
import time

duration = float(sys.argv[1])
child = subprocess.Popen(["/usr/bin/sleep", str(duration)])
time.sleep(duration)
raise SystemExit(child.wait())
