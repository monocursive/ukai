#!/bin/sh
# The commands of this record, in the order they ran on 2026-10-17 (UTC) on
# the reference host, as the account `ubuntu`. Kept as documentation: each
# block was typed as shown (over SSH), with D=$HOME/cc-arow-20261017.
# The harness files are in harness/; host.txt has the build and installs.
set -u
D=$HOME/cc-arow-20261017
J=$D/bin/ukai-jail
S=$D/src/docs/specs/jail-v1/summary_check.py
T=$HOME/.config/ukai/credentials/claude-oauth   # read only by the harness, into memory
IR=$HOME/.local/share/claude/versions
FIXTURE="Create a file named greeting.txt containing the single word hello."
CHECK="python3 -I $D/arow_check.py"
RUN="python3 -I $D/arow_run.py"
export PATH=$HOME/.local/bin:$PATH              # the native claude first

# explain and doctor, from a fresh git repository
mkdir -p $D/ws-a01 && cd $D/ws-a01 && git init -q
$J explain --launch claude --from-path > $D/evidence/explain.txt 2>&1        # claude/ here
$J explain --launch claude --from-path --json > $D/evidence/explain.json
$J doctor --launch claude --from-path > $D/evidence/doctor.txt 2>&1

# §6.3 (1), the A01 fixture exactly as §6.3 writes it: r01
$RUN --out $D/runs/r01-a01 --protected $T --wall 900 -- $J claude -p "$FIXTURE"
# the same with a permission flag and JSON output, same repository: r02
$RUN --out $D/runs/r02-a01 --protected $T --wall 900 -- \
  $J claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json
$CHECK $D/runs/r02-a01 $J $S --workspace $D/ws-a01 --expect greeting.txt=hello --install-root $IR

# §6.3 (2), a real small task in the same repository: r03
# (slug.py and test_slug.py committed first; their text is in runs/r03-task/outcome.txt's diff)
$RUN --out $D/runs/r03-task --protected $T --wall 900 -- \
  $J claude -p "The tests in test_slug.py fail. Fix the bug in slug.py so that python3 -m unittest passes, without changing test_slug.py, and run the tests to confirm." \
  --dangerously-skip-permissions --output-format json
$CHECK $D/runs/r03-task $J $S --workspace $D/ws-a01 --expect greeting.txt=hello --install-root $IR

# §6.3 (3), the API-key variant: not run (runs/api-key-not-run.txt)
ls -la $HOME/.config/ukai/credentials/anthropic

# §6.3 (4), no source: an empty private config directory: r04
mkdir -m 0700 $D/cfg-empty
mkdir -p $D/ws-nosrc && cd $D/ws-nosrc && git init -q
UKAI_CONFIG_DIR=$D/cfg-empty $RUN --out $D/runs/r04-no-source --protected $T --wall 300 -- \
  $J claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json
UKAI_CONFIG_DIR=$D/cfg-empty $J claude -p x > pipe.stdout 2> pipe.stderr < /dev/null   # stderr not a terminal

# §6.3 (5), the source deleted mid-run: a copy in a separate config directory: r05
mkdir -m 0700 $D/cfg-revoke $D/cfg-revoke/credentials
cp $T $D/cfg-revoke/credentials/claude-oauth && chmod 0600 $D/cfg-revoke/credentials/claude-oauth
mkdir -p $D/ws-revoke && cd $D/ws-revoke && git init -q
UKAI_CONFIG_DIR=$D/cfg-revoke $RUN --out $D/runs/r05-revoke --protected $T --wall 900 \
  --revoke $D/cfg-revoke/credentials/claude-oauth --revoke-after 15 -- \
  $J claude -p "Write a detailed essay of about 3000 words on the history of lighthouses. Print the essay as your reply; do not create any files." \
  --dangerously-skip-permissions --output-format json
rmdir $D/cfg-revoke/credentials $D/cfg-revoke

# §6.3 (6), ten repetitions of (1), each in a fresh git repository: r06-rep01..10
for n in 01 02 03 04 05 06 07 08 09 10; do
  ws=$D/ws-rep$n; mkdir -p $ws
  (cd $ws && git init -q && $RUN --out $D/runs/r06-rep$n --protected $T --wall 900 -- \
     $J claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json > /dev/null
   $CHECK $D/runs/r06-rep$n $J $S --workspace $ws --expect greeting.txt=hello --install-root $IR)
done

# extra: the sampler with its per-process tally (r07), and the agent's environment (r08)
mkdir -p $D/ws-probe && cd $D/ws-probe && git init -q
$RUN --out $D/runs/r07-sampler-probe --protected $T --wall 900 -- \
  $J claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json
mkdir -p $D/ws-envprobe && cd $D/ws-envprobe && git init -q
python3 -I $D/arow_envprobe.py --out $D/runs/r08-env-probe/agent-environment.json --comm 2.1.302 --protected $T -- \
  $J claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json

# OpenCode A01 under the alias (o01, then o02 in a second fresh repository)
export PATH=$HOME/.opencode/bin:$HOME/.local/bin:$PATH
mkdir -p $D/ws-oc01 && cd $D/ws-oc01 && git init -q
$RUN --out $D/runs/o01-a01 --protected $T --wall 900 -- $J opencode run "$FIXTURE"
$CHECK $D/runs/o01-a01 $J $S --workspace $D/ws-oc01 --expect greeting.txt=hello --install-root $HOME/.opencode/bin \
  --credential none --hosts opencode.ai:443,models.opencode.ai:443,registry.npmjs.org:443
# direct controls without the jail, throwaway XDG directories (controls/), each in a fresh
# repository: 1.19.0 as installed (below), and 1.19.3 from the npm package, the same command
# with $O/package/bin first on PATH and as the program, in $D/direct-oc2:
#   O=$D/oc-1.19.3; curl -fsS -o $O/pkg.tgz https://registry.npmjs.org/opencode-linux-x64/-/opencode-linux-x64-1.19.3.tgz
#   test "sha512-$(openssl dgst -sha512 -binary $O/pkg.tgz | base64 -w0)" = <dist.integrity of opencode-linux-x64@1.19.3>
#   tar -C $O -xzf $O/pkg.tgz --no-same-owner
X=$D/direct-oc; mkdir -p $X/ws $X/config $X/data $X/cache $X/state $X/home; cd $X/ws && git init -q
env -i PATH=$HOME/.opencode/bin:/usr/local/bin:/usr/bin:/bin HOME=$X/home XDG_CONFIG_HOME=$X/config \
  XDG_DATA_HOME=$X/data XDG_CACHE_HOME=$X/cache XDG_STATE_HOME=$X/state LANG=C.UTF-8 TERM=dumb \
  timeout 300 $HOME/.opencode/bin/opencode run "$FIXTURE" > $X/stdout 2> $X/stderr < /dev/null
mkdir -p $D/ws-oc02 && cd $D/ws-oc02 && git init -q
$RUN --out $D/runs/o02-a01 --protected $T --wall 900 -- $J opencode run "$FIXTURE"

# afterwards: arow_check.py rerun over every run (r01 without the file expectation,
# see runs/r01-a01/outcome.txt), and the exposure search, which prints file names only
grep -rlF -f $T $D/runs $D/ws-* $D/direct-oc $D/direct-oc2 $D/evidence $HOME/.local/share/ukai/attempts/<each attempt of this record>
