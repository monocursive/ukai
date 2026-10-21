#!/bin/bash
# End-to-end driver for the interactive Claude Code A-row
# (docs/specs/jail-interactive-sessions.md §6.3). Runs on the operator's
# machine (here: the Mac), drives the reference host over SSH.
#
# usage: driver.sh OUT [REPS] [JAIL_ON_HOST] [ROOT_NAME] [WS_SUFFIX] [FIRST_LAUNCH]
#   OUT           local output directory (created)
#   REPS          run (7)'s repetitions of run (2) (default 10)
#   JAIL_ON_HOST  the ukai-jail binary on the host to copy into ROOT/bin
#                 (phase 2: the release binary; default the pilot's build)
#   ROOT_NAME     the private directory under the host's $HOME (default arow-int-pilot);
#                 it holds the vaulted copy of the token under config/: remove it after
#   WS_SUFFIX     workspaces ROOT/ws-A<sfx>, ROOT/ws-B<sfx> (default none)
#   FIRST_LAUNCH  as-written (default: the bundled profile, which allows platform.claude.com
#                 since spec §8 item 30) | both | workaround (the pilot's --allow-host variants)
# Needs: uv, ssh key ~/.ssh/ouroboros_vps, the repository at $REPO (summary_check.py,
# the slug fixture). Nothing here prints or copies the token.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?usage: driver.sh OUT [REPS] [JAIL_ON_HOST] [ROOT_NAME] [WS_SUFFIX] [FIRST_LAUNCH]}
REPS=${2:-10}
SRC=${3:-'$HOME/land4-live/src/target/release/ukai-jail'}
ROOT_NAME=${4:-arow-int-pilot}
SFX=${5:-}
FIRST=${6:-as-written}
REPO=${REPO:-$HOME/code/ouroboros}
H="$HERE/hostssh"
SCP=(scp -q -i "$HOME/.ssh/ouroboros_vps" -o BatchMode=yes)
HOSTADDR=${AROW_HOST:-ubuntu@37.59.114.70}

mkdir -p "$OUT"
# 1. The host-side harness: collector, K62 probe, K70 sweep, setup, the
#    repository's summary_check.py and the slug fixture.
mkdir -p "$HERE/host/fixture"
cp "$REPO/docs/specs/jail-v1/summary_check.py" "$HERE/host/summary_check.py"
cp "$REPO/docs/benchmarks/jail/results/claude-code-demo-2026-10-19/fixture/slug.py" \
   "$REPO/docs/benchmarks/jail/results/claude-code-demo-2026-10-19/fixture/test_slug.py" "$HERE/host/fixture/"
"$H" "umask 077; mkdir -p ~/$ROOT_NAME/harness"
"${SCP[@]}" -r "$HERE"/host/* "$HOSTADDR:$ROOT_NAME/harness/"
shasum -a 256 "$HERE"/host/*.py "$HERE"/host/*.sh "$HERE"/*.py "$HERE"/driver.sh > "$OUT/harness.sha256"

# 2. Host setup: private config/data, the vaulted credential, workspaces A and B,
#    host facts, explain, doctor.
"$H" "bash ~/$ROOT_NAME/harness/host_setup.sh ~/$ROOT_NAME $SRC $SFX"

# 3. The runs, in order: 1, 2, 7 (repeats 2), 3, 4, 5, 6, 8.
cd "$HERE"
uv run --with pexpect --with pyte python3 arow_int.py --out "$OUT" --reps "$REPS" \
  --root "\$HOME/$ROOT_NAME" --ws-suffix "$SFX" --first-launch "$FIRST" 2>&1 | tee -a "$OUT/driver.log"

# 4. K70: the token search over runs (with the transcripts), attempts, state,
#    workspaces, plus the positive control on config/.
"$H" "bash ~/$ROOT_NAME/harness/k70_sweep.sh ~/$ROOT_NAME" > "$OUT/k70-sweep.txt"
cat "$OUT/k70-sweep.txt"

# 5. Host evidence (searched first), then the report.
if "$H" "grep -rlF -f ~/.config/ukai/credentials/claude-oauth ~/$ROOT_NAME/evidence"; then
  echo "token found in host evidence: not fetched" >&2
else
  mkdir -p "$OUT/host-evidence"
  "${SCP[@]}" -r "$HOSTADDR:$ROOT_NAME/evidence/." "$OUT/host-evidence/"
fi
python3 "$HERE/report.py" "$OUT" > "$OUT/report.md"
echo "report: $OUT/report.md"
