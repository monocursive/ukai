"""Frozen CHILD-case parent program: runs its fixed argv as exactly one child.

The child inherits this process's stdio so its output reaches the capture
files. The exit status is the child's own status.
"""
import subprocess
import sys

raise SystemExit(subprocess.run(sys.argv[1:], timeout=15).returncode)
