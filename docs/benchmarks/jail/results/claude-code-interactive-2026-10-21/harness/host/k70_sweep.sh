#!/bin/bash
# K70 (jail-interactive-sessions.md §6.3): the token's value is absent from the
# receipts, journals, workspaces, the harness transcripts and the state.
# Fixed-string search, file names only; the token file is read by grep alone.
# usage: k70_sweep.sh D   (prints a JSON-ish report on stdout)
D=$1
T=$HOME/.config/ukai/credentials/claude-oauth
echo "date_utc $(date -u +%FT%TZ)"
for p in "$D/runs" "$D/data/attempts" "$D/data/state" "$D/evidence" "$D"/ws-*; do
  n=$(find "$p" -type f | wc -l)
  hits=$(grep -rlF -f "$T" -- "$p"); rc=$?
  echo "search $p files=$n exit=$rc hits=[${hits//$'\n'/,}]"
done
# Positive control: the vaulted copy must be found (proves the search works).
hits=$(grep -rlF -f "$T" -- "$D/config"); rc=$?
echo "control $D/config exit=$rc hits=[${hits//$'\n'/,}]"
