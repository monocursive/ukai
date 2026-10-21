"""K62 probe (jail-interactive-sessions.md §6.3): run as the next command of
the same command line as the jail (`ukai-jail claude …; rc=$?; python3 -I k62.py`),
so the shell itself reads nothing in between. Switches the terminal (stdin) to
non-canonical, no-echo, reads whatever is pending for WINDOW seconds, restores
the settings, and prints one line: K62-RESULT {"pending": N, "bytes": "<escaped>"}.
The marker is built at run time so the typed command line never contains it."""
import json
import os
import select
import sys
import termios
import time

WINDOW = float(sys.argv[1]) if len(sys.argv) > 1 else 1.0
fd = 0
started = time.monotonic()
old = termios.tcgetattr(fd)
new = termios.tcgetattr(fd)
new[3] &= ~(termios.ICANON | termios.ECHO)
new[6][termios.VMIN] = 0
new[6][termios.VTIME] = 0
got = b""
try:
    termios.tcsetattr(fd, termios.TCSANOW, new)
    end = time.monotonic() + WINDOW
    while True:
        left = end - time.monotonic()
        if left <= 0:
            break
        ready, _, _ = select.select([fd], [], [], left)
        if ready:
            chunk = os.read(fd, 4096)
            if chunk:
                got += chunk
finally:
    termios.tcsetattr(fd, termios.TCSANOW, old)
marker = "K62-" + "RESULT"
print(marker, json.dumps({"pending": len(got), "bytes": got.decode("latin-1"),
                          "window_s": WINDOW, "probe_s": round(time.monotonic() - started, 3)}),
      flush=True)
