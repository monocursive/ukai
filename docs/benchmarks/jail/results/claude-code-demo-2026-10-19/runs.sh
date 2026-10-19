#!/bin/sh
# The commands of this record, in the order they ran on 2026-10-19 (UTC) on
# the reference host, as the account `ubuntu`, over SSH. Kept as
# documentation. The harness is the Claude Code A-row's, byte for byte:
# ../claude-code-compatibility-2026-10-17/harness/arow_run.py and arow_check.py,
# with ../../../../specs/jail-v1/summary_check.py (SHA-256 in the record).
# In the scratch directory, evidence/ held the files at this directory's top level.
set -u
D=$HOME/cc-plain-demo-20261019
T=$HOME/.config/ukai/credentials/claude-oauth   # read by `credential set` and the harness only

# Install the public release into a private prefix, with private state.
mkdir -m 0700 $D $D/bin $D/config $D/data $D/evidence
curl --proto "=https" --tlsv1.2 -fsSL -o $D/install.sh https://ukai.sh/install.sh
bash $D/install.sh --bin-dir $D/bin 2>&1 | tee $D/evidence/install.txt
export UKAI_CONFIG_DIR=$D/config UKAI_DATA_DIR=$D/data
$D/bin/ukai-jail credential set claude-oauth < $T > $D/evidence/credential-set.out 2>&1

# The demo repository: fixture/ committed as one commit.
export PATH=$D/bin:$HOME/.local/bin:$PATH        # this ukai-jail, then the native claude
mkdir $D/slug && cp $D/fixture/* $D/slug/ && cd $D/slug
git init -q && git add . && git -c user.name=demo -c user.email=demo@localhost commit -qm "slug: initial"
sha256sum README.md slug.py test_slug.py > $D/evidence/fixture.sha256
python3 -m unittest > $D/evidence/unittest-before.txt 2>&1; echo "exit $?" >> $D/evidence/unittest-before.txt
rm -rf __pycache__
ukai-jail explain --launch claude --from-path > $D/evidence/explain.txt 2>&1
ukai-jail doctor --launch claude --from-path > $D/evidence/doctor.txt 2>&1

date -u +%FT%TZ > $D/evidence/r1-started-utc.txt
# r1: the run. stdout to runs/r1/stdout, stderr on a pseudo-terminal (runs/r1/terminal.txt).
python3 -I $D/arow_run.py --out $D/runs/r1 --protected $T --wall 540 -- \
  ukai-jail claude -p "fix the failing test" --dangerously-skip-permissions

# Afterwards, in this order.
R=$D/runs/r1
ps -eo pid,ppid,user,etimes,args | grep -E "2\.1\.302|cc-plain-demo" | grep -v grep > $R/process-survey.txt
python3 -I $D/arow_check.py $R ukai-jail $D/summary_check.py --workspace $D/slug \
  --install-root $HOME/.local/share/claude/versions
{ git status --short; echo; git diff; } > $R/git-after.txt
sha256sum test_slug.py README.md slug.py > $R/sha256-after.txt
python3 -m unittest > $R/unittest-after.txt 2>&1; echo "exit $?" >> $R/unittest-after.txt
ukai-jail tail --attempt att_01e92cd2-e93f-4048-873f-89524fb5fb10 > $R/tail.txt 2>&1

# host.txt: build, install and host facts, collected after r1 by a separate
# command (uname, sysctl, sha256sum, `ukai-jail version`, stat); its
# `~/.local/bin/claude` line was then rewritten by a script to show the link
# and its target, because the first command printed only the target.

# The token search: file names only (token-exposure-check.txt has the output).
for p in $D/runs $D/evidence $D/slug $D/fixture $D/data $D/bin; do grep -rlF -f $T $p; echo "$p: exit $?"; done
grep -rlF -f $T $D/config   # positive control: finds the stored copy, credentials/claude-oauth

# Cleanup: rm -rf $D (the attempt directory was inside it, in $D/data).
