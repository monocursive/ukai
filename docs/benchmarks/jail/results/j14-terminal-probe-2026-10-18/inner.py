"""Runs inside bwrap on a pty. Prints what the terminal relationship allows.

argv[1]: "plain" (stay in the inherited process group) or "ownpgrp"
(setpgid(0,0) first, then take the foreground with SIGTTOU ignored).
"""
import errno
import fcntl
import os
import signal
import struct
import sys
import termios
import time

mode = sys.argv[1]


def report(name, fn):
    try:
        value = fn()
        print(f"{name}: ok {value if value is not None else ''}".rstrip())
    except OSError as e:
        print(f"{name}: {errno.errorcode.get(e.errno, e.errno)}")


print(f"mode: {mode}")
print(f"isatty0: {os.isatty(0)}")
report("apparmor label", lambda: open("/proc/self/attr/current").read().strip())
report("ttyname0", lambda: os.ttyname(0))
report("tty rdev", lambda: divmod(os.fstat(0).st_rdev, 256))
report("getsid", lambda: os.getsid(0))
report("getpgrp", lambda: os.getpgrp())
report("tcgetpgrp", lambda: os.tcgetpgrp(0))
report("open /dev/tty", lambda: os.close(os.open("/dev/tty", os.O_RDWR)))
report("TIOCSTI", lambda: fcntl.ioctl(0, termios.TIOCSTI, b"#"))
# TIOCLINUX subcode 6 = TIOCL_GETFGCONSOLE; only a VT implements it.
report("TIOCLINUX", lambda: fcntl.ioctl(0, 0x541C, bytes([6]) + bytes(31)))

if mode == "ownpgrp":
    signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    report("setpgid(0,0)", lambda: os.setpgid(0, 0))
    report("tcsetpgrp(own)", lambda: os.tcsetpgrp(0, os.getpgrp()))
    report("tcgetpgrp after", lambda: os.tcgetpgrp(0))
    signal.signal(signal.SIGTTOU, signal.SIG_DFL)

# Does a resize made outside reach us? The outer side changes the window
# size about 1 s after start.
got = []
signal.signal(signal.SIGWINCH, lambda *_: got.append(time.monotonic()))
deadline = time.monotonic() + 3
while not got and time.monotonic() < deadline:
    time.sleep(0.05)
rows, cols, _, _ = struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, bytes(8)))
print(f"SIGWINCH received: {bool(got)}; size now {rows}x{cols}")

# Signal our whole process group with SIGURG (default action: ignore).
# The outer shell traps it and prints when it arrives there.
report("kill(0, SIGURG)", lambda: os.kill(0, signal.SIGURG))
time.sleep(0.3)
