#!/bin/sh
# The commands of this record, in the order they ran on 2026-10-21 (UTC). Kept as
# documentation. The operator's machine (a Mac with uv) drove the reference host
# over SSH (key-based, `ubuntu`); the harness files are in harness/, byte for byte
# (harness.sha256 has their digests as run).
set -u
REPO=<a checkout of j14-review-fixes at 79200cfda>   # summary_check.py and the slug fixture
K=$HOME/.ssh/ouroboros_vps; HOST=ubuntu@<the reference host>
D='~/arow-int-final'                                 # the private directory on the host

# 0. The jail binary: the operator's clean build of 79200cfda (UKAI_BUILD_REVISION set,
#    UKAI_BUILD_DIRTY=false, Rust 1.98.1, cargo build --locked --release -p ukai-jail),
#    left at ~/rc4-build/ukai-jail with version.json and ukai-jail.sha256 beside it
#    (host-evidence/build-version.json, build-ukai-jail.sha256). Not built by this record.

# 1-5. Everything else is one command (harness/driver.sh). In order, it:
#   - copies harness/host/* and $REPO/docs/specs/jail-v1/summary_check.py to $D/harness;
#   - runs harness/host/host_setup.sh $D '$HOME/rc4-build/ukai-jail' on the host:
#       umask 077; mkdir $D/{bin,config,data,harness,runs,evidence}  (config, data 0700)
#       cp ~/rc4-build/ukai-jail $D/bin/ukai-jail; copies version.json, ukai-jail.sha256
#       UKAI_CONFIG_DIR=$D/config UKAI_DATA_DIR=$D/data PATH=$D/bin:~/.local/bin:$PATH
#       ukai-jail credential set claude-oauth < ~/.config/ukai/credentials/claude-oauth
#       workspaces $D/ws-A (README + the slug fixture) and $D/ws-B (README), one commit each
#       host.txt (uname, sysctl, bwrap, both binaries' SHA-256, claude --version), explain, doctor
#   - runs harness/arow_int.py: §6.3 runs 1, 2, 7 (ten repetitions of 2), 3, 4, 5, 6, 8, each
#     in a fresh `ssh -tt` login shell (bash, job control on) on a local pty of 120x40,
#     TERM=xterm-256color, rendered by pyte; every launch is typed as one line:
#         <command>; rc=$?; python3 -I $D/harness/k62.py; echo "ARROW-DONE rc=$rc"
#     and after each attempt harness/host/arow_int_collect.py runs on the host (archive,
#     tail --summary, state list/show, the state's files, summary_check.py, the checks,
#     the token search), whose directory is fetched back only when that search found nothing;
#   - runs harness/host/k70_sweep.sh $D (the token search over runs, attempts, state,
#     evidence and workspaces, with the positive control on config/);
#   - fetches $D/evidence after searching it, and writes report.md.
REPO=$REPO ./driver.sh <out> 10 '$HOME/rc4-build/ukai-jail' arow-int-final '' as-written

# The commands typed into the terminals, run by run (arow_int.py; the prompts are its constants):
#  r01  ukai-jail claude                       onboarding answered, shift+tab to manual mode,
#                                              FIXTURE, permission answered `1`, /exit
#  r02  ukai-jail claude --resume               picker: run 1's session, ASK_RESUME, /exit
#       ukai-jail claude --continue             ASK_CONTINUE, /exit
#  r07  the two launches of r02, ten times
#  r03  ukai-jail claude (in B)                 onboarding, /resume (+ ctrl+a), esc, /exit
#  r04  ukai-jail claude                        LONG_PROMPT; resize to 100x32 while generating;
#                                              ^C while generating; ctrl+g (editor), ^X;
#                                              ^Z; fg; SIGHUP to the local ssh (a window close)
#  r05  ukai-jail claude                        /login, method 1, FAKE_CODE; retry;
#                                              FAKE_CODE#<state from the URL>; esc; /exit
#  r06  rm -f greeting.txt; ukai-jail claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json
#       rm -f greeting.txt; true | ukai-jail claude -p "$FIXTURE" --dangerously-skip-permissions --output-format json
#  r08  t1: ukai-jail claude (holds the state)
#       t2 (a second ssh connection): ukai-jail claude; onboarding; ASK_FALLBACK; /exit
#       t1: /resume inside the session, esc, /exit; then ukai-jail claude --resume,
#           pick run 1's session, /exit

# Afterwards, on the host: the staged results directory was copied there and searched
# (grep -rlF -f ~/.config/ukai/credentials/claude-oauth, file names only) before commit,
# then $D was removed: rm -rf ~/arow-int-final.
