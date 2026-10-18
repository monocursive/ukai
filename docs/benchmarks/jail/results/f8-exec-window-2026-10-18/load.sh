#!/bin/bash
# Runs a command beside the same load as run.sh: 8 busy shells and 2 exec
# loops on the 4-vCPU reference host.
set -u
hogs=()
for _ in 1 2 3 4 5 6 7 8; do bash -c 'while :; do :; done' & hogs+=($!); done
for _ in 1 2; do bash -c 'while :; do /bin/true; done' & hogs+=($!); done
sleep 2
echo "runnable/total tasks before: $(cut -d' ' -f4 /proc/loadavg)"
"$@"
for pid in "${hogs[@]}"; do kill "$pid"; done
wait 2>/dev/null
