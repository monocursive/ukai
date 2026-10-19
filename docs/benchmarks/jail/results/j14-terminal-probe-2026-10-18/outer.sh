#!/bin/sh
# Runs as the session leader of a fresh pty (under `script`). For each
# variant: resize the pty from outside after 1 s, run inner.py in bwrap,
# and report whether its kill(0, SIGURG) reached this shell.
here=$(cd "$(dirname "$0")" && pwd)
T=$(tty)
echo "outer: tty $T, sid $(ps -o sid= -p $$), pgrp $(ps -o pgid= -p $$)"
trap 'echo "outer: SIGURG reached the shell outside the namespace"' URG
NS="--unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts --unshare-cgroup --die-with-parent"
FS="--ro-bind / / --proc /proc --dev /dev"
reclaim() {
  python3 -c 'import os,signal; signal.signal(signal.SIGTTOU, signal.SIG_IGN); os.tcsetpgrp(0, os.getpgrp())'
}
for variant in "new-session plain" "attached plain" "attached ownpgrp"; do
  set -- $variant
  echo "=== $1 / $2"
  stty -F "$T" rows 24 cols 80
  (sleep 1; stty -F "$T" rows 40 cols 123) &
  if [ "$1" = new-session ]; then
    bwrap $NS --new-session $FS -- python3 "$here/inner.py" "$2"
  else
    bwrap $NS $FS -- python3 "$here/inner.py" "$2"
  fi
  echo "bwrap exit $?"
  wait
  reclaim
  sleep 0.2
done
