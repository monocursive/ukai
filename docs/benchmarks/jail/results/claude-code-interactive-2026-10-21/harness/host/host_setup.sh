#!/bin/bash
# Host-side setup for the interactive Claude Code A-row (jail-interactive-sessions.md §6.3).
# Runs on the reference host as `ubuntu`. Idempotent for the directories; refuses to
# recreate a workspace or overwrite the binary unless asked.
#
# usage: host_setup.sh D JAIL_SOURCE [WS_SUFFIX]
#   D            the record's private directory (e.g. ~/arow-int-pilot)
#   JAIL_SOURCE  the ukai-jail binary to copy into D/bin (the release binary in phase 2)
#   WS_SUFFIX    workspaces are D/ws-A<suffix> and D/ws-B<suffix> (default none)
# The harness/ files (summary_check.py, arow_int_*.py) are copied in by the local driver.
set -euo pipefail
D=$1
SRC=$2
SFX=${3:-}
T=$HOME/.config/ukai/credentials/claude-oauth     # used only by `credential set` and grep -lF
umask 077
mkdir -p "$D" "$D/bin" "$D/config" "$D/data" "$D/harness" "$D/runs" "$D/evidence"
chmod 0700 "$D" "$D/config" "$D/data"
if [ ! -x "$D/bin/ukai-jail" ]; then
  cp "$SRC" "$D/bin/ukai-jail.tmp" && chmod 0755 "$D/bin/ukai-jail.tmp" && mv "$D/bin/ukai-jail.tmp" "$D/bin/ukai-jail"
fi
export UKAI_CONFIG_DIR=$D/config UKAI_DATA_DIR=$D/data
export PATH=$D/bin:$HOME/.local/bin:$PATH
if [ ! -f "$D/config/credentials/claude-oauth" ]; then
  ukai-jail credential set claude-oauth < "$T" > "$D/evidence/credential-set.out" 2>&1
fi
# The fixture repositories: A (the A01 fixture task runs here; README + the slug fixture),
# B (README only). Each one commit.
for ws in A B; do
  W=$D/ws-$ws$SFX
  [ -d "$W" ] && continue
  mkdir -p "$W" && cd "$W" && git init -q
  printf '# Workspace %s\n\nA fixture repository for the interactive Claude Code record.\n' "$ws$SFX" > README.md
  if [ "$ws" = A ]; then
    cp "$D/harness/fixture/slug.py" "$D/harness/fixture/test_slug.py" .
  fi
  git add . && git -c user.name=arow -c user.email=arow@localhost commit -qm "fixture: initial"
done
# Build facts left next to the source binary (the operator's clean build), copied as they are.
B=$(dirname "$SRC")
[ -f "$B/version.json" ] && cp "$B/version.json" "$D/evidence/build-version.json"
[ -f "$B/ukai-jail.sha256" ] && cp "$B/ukai-jail.sha256" "$D/evidence/build-ukai-jail.sha256"
# Host facts (no secret): binary digests, versions, sysctls.
{
  echo "date_utc: $(date -u +%FT%TZ)"
  echo "uname: $(uname -srvmo)"
  echo "os: $(. /etc/os-release; echo "$PRETTY_NAME")"
  echo "apparmor_restrict_unprivileged_userns: $(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null)"
  echo "bwrap: $(bwrap --version 2>&1)"
  echo "jail_sha256: $(sha256sum "$D/bin/ukai-jail" | cut -d' ' -f1)"
  echo "jail_source: $SRC"
  echo "jail_source_sha256: $(sha256sum "$SRC" | cut -d' ' -f1)"
  echo "claude_link: $(ls -l "$HOME/.local/bin/claude" | sed 's/.* -> //')"
  echo "claude_resolved: $(readlink -f "$HOME/.local/bin/claude")"
  echo "claude_sha256: $(sha256sum "$(readlink -f "$HOME/.local/bin/claude")" | cut -d' ' -f1)"
  echo "claude_version: $(cd /tmp && timeout 20 "$HOME/.local/bin/claude" --version 2>&1 | head -1)"
  echo "credential_source: $(stat -c '%a %s bytes, %h link(s), mtime %y' "$T")"
  echo "vaulted_copy: $(stat -c '%a %s bytes' "$D/config/credentials/claude-oauth")"
  echo "jail_version:"; ukai-jail version --json
} > "$D/evidence/host.txt" 2>&1
cd "$D/ws-A$SFX"
ukai-jail explain --launch claude --from-path > "$D/evidence/explain.txt" 2>&1 || true
ukai-jail doctor --launch claude --from-path > "$D/evidence/doctor.txt" 2>&1 || true
ukai-jail state list > "$D/evidence/state-list-before.txt" 2>&1 || true
echo "setup done: $D"
