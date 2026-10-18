#!/bin/bash
# The F8 pin test in a loop, idle or beside a CPU and exec load.
#   run.sh BIN RUNS LABEL [load]
# Load: 8 busy shells and 2 exec loops on the 4-vCPU reference host, started
# before the first run and killed after the last.
set -u
bin=$1; runs=$2; label=$3; load=${4:-}
name=vault::origin::linux_tests::a_process_execd_with_a_loader_environment_is_refused_at_the_pin
hogs=()
if [ "$load" = load ]; then
  for _ in 1 2 3 4 5 6 7 8; do bash -c 'while :; do :; done' & hogs+=($!); done
  for _ in 1 2; do bash -c 'while :; do /bin/true; done' & hogs+=($!); done
  sleep 2
fi
fail=0; names=(); runq=
for i in $(seq 1 "$runs"); do
  [ "$i" -eq $(( (runs + 1) / 2 )) ] && runq=$(cut -d' ' -f4 /proc/loadavg)
  out=$("$bin" --exact "$name" --test-threads=1 2>&1) || {
    fail=$((fail+1))
    names+=("$(printf '%s\n' "$out" | grep -A1 'panicked at' | tail -1)")
  }
done
for pid in "${hogs[@]}"; do kill "$pid"; done
wait 2>/dev/null
echo "$label: $fail/$runs failed (runnable/total tasks at mid-run: $runq)"
[ "$fail" -gt 0 ] && printf '%s\n' "${names[@]}" | sort | uniq -c
exit 0
