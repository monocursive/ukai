#!/usr/bin/env bash
# The runner check (J15 §3.2): validate the inputs and refuse, with a
# one-line reason, before any host change and any credential.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

# --- the inputs (§3.1) ------------------------------------------------------
launch=${UKAI_ACTION_LAUNCH:-}
profile=${UKAI_ACTION_PROFILE:-}
if [ -n "$launch" ] && [ -n "$profile" ]; then
    fail "set \`launch\` or \`profile\`, not both"
elif [ -n "$launch" ]; then
    mode=launch
    [[ "$launch" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "launch: \`$launch\` is not a launch profile name"
    [ -z "${UKAI_ACTION_RUN:-}" ] || fail "\`run\` belongs to profile mode; launch mode takes \`args\`"
elif [ -n "$profile" ]; then
    mode=profile
    case "$profile" in
        tool|build|agent) ;;
        none) fail "profile: \`none\` runs uncontained and is refused" ;;
        *) fail "profile: \`$profile\` is not tool, build or agent" ;;
    esac
    [ -n "${UKAI_ACTION_RUN:-}" ] || fail "profile mode needs a \`run\` script"
    [ -z "${UKAI_ACTION_ARGS:-}" ] || fail "\`args\` belongs to launch mode; profile mode takes \`run\`"
else
    fail "set \`launch\` (a launch profile) or \`profile\` (tool, build or agent)"
fi
words=()
split_words words "${UKAI_ACTION_LIMITS:-}"
for word in ${words[@]+"${words[@]}"}; do
    [[ "$word" == ?*=?* ]] || fail "limits: \`$word\` is not KEY=VALUE"
done
parse_credentials
fail_on=${UKAI_ACTION_FAIL_ON:-}
split_words words "${fail_on//,/ }"
for word in ${words[@]+"${words[@]}"}; do
    case "$word" in unsettled|survivors|gaps) ;; *) fail "fail-on: \`$word\` is not unsettled, survivors or gaps" ;; esac
done
for name in PR_COMMENT ALLOW_CHECKOUT_TOKEN; do
    value_name=UKAI_ACTION_$name
    case "${!value_name:-false}" in
        true|false) ;;
        *) fail "$(printf '%s' "$name" | tr 'A-Z_' 'a-z-'): expected true or false" ;;
    esac
done
artifact_name=${UKAI_ACTION_ARTIFACT_NAME:-}
[ -n "$artifact_name" ] || fail "artifact-name must not be empty"
case "$artifact_name" in
    *[\":\<\>\|\*\?\\/]*|*$'\n'*|*$'\r'*) fail "artifact-name: \`$artifact_name\` holds a character artifacts refuse" ;;
esac
[ -n "${UKAI_ACTION_VERSION:-}" ] || fail "version must not be empty"

# --- the runner (§3.2 items 1 to 5) ----------------------------------------
# Nothing is created until every check has passed; the facts wait here.
facts=("ukai-jail action setup facts (docs/specs/jail-ci-action.md §3)" "runner check:")
fact() { facts+=("$*"); }

# 1. Linux on x86_64 or ARM64
case "${RUNNER_OS:-}:${RUNNER_ARCH:-}" in
    Linux:X64|Linux:ARM64) ;;
    *) fail "runner check: needs RUNNER_OS Linux and RUNNER_ARCH X64 or ARM64, found ${RUNNER_OS:-unset} ${RUNNER_ARCH:-unset}; nothing was changed" ;;
esac
fact "  runner: $RUNNER_OS $RUNNER_ARCH, RUNNER_ENVIRONMENT=${RUNNER_ENVIRONMENT:-unset}, image ${ImageOS:-unknown} ${ImageVersion:-unknown}"

# 2. not root: the jail refuses EUID 0
euid=$(id -u)
[ "$euid" != 0 ] || fail "runner check: this step runs as root (EUID 0), which ukai-jail refuses; nothing was changed"
fact "  euid: $euid"

# 3. Ubuntu 24.04 or later, glibc 2.39 or later
os_field() { awk -F= -v key="$1" '$1 == key { value = $2; gsub(/^"|"$/, "", value); print value; exit }' /etc/os-release 2>/dev/null; }
os_id=$(os_field ID)
os_version=$(os_field VERSION_ID)
if [ "$os_id" != ubuntu ] || ! version_at_least "$os_version" 24.04; then
    fail "runner check: needs Ubuntu 24.04 or later, found ${os_id:-unknown} ${os_version:-unknown} (ukai-jail needs glibc 2.39); nothing was changed"
fi
glibc=$(ldd --version 2>/dev/null | awk 'NR == 1 {print $NF}')
version_at_least "${glibc:-0}" 2.39 ||
    fail "runner check: needs glibc 2.39 or later, \`ldd --version\` reports ${glibc:-nothing}; nothing was changed"
fact "  os: $(os_field PRETTY_NAME) (ID=$os_id VERSION_ID=$os_version), glibc $glibc, kernel $(uname -r)"

# 4. never pull_request_target (§4.6)
[ "${GITHUB_EVENT_NAME:-}" != pull_request_target ] ||
    fail "runner check: the pull_request_target event is refused: it hands the base repository's secrets to a workflow that may check out a fork's code; use pull_request; nothing was changed"
fact "  event: ${GITHUB_EVENT_NAME:-unset}"

# 5. a git work tree without the checkout's persisted token (§4.2)
workspace=${UKAI_ACTION_WORKSPACE:-}
[ -n "$workspace" ] || workspace=${GITHUB_WORKSPACE:?}
case "$workspace" in /*) ;; *) workspace=$GITHUB_WORKSPACE/$workspace ;; esac
[ -d "$workspace" ] || fail "runner check: the workspace \`$workspace\` is not a directory; nothing was changed"
workspace=$(cd -P -- "$workspace" && pwd)
inside=$(git -C "$workspace" rev-parse --is-inside-work-tree 2>/dev/null || true)
[ "$inside" = true ] || fail "runner check: the workspace $workspace is not a git work tree; nothing was changed"
# --name-only: the header's value is the token itself, never read here
headers=$(git -C "$workspace" config --name-only --get-regexp '^http\..*\.extraheader$' 2>/dev/null || true)
token_note=
if [ -n "$headers" ]; then
    if [ "${UKAI_ACTION_ALLOW_CHECKOUT_TOKEN:-false}" != true ]; then
        fail "runner check: the workspace's git config holds $(printf '%s' "$headers" | head -1), the checkout's persisted token, which the agent could read; set persist-credentials: false on actions/checkout (or allow-checkout-token: true); nothing was changed"
    fi
    token_note="the checkout token was readable inside the workspace (allow-checkout-token: true)"
    fact "  workspace: $workspace (git work tree; checkout token PRESENT and allowed: $(printf '%s' "$headers" | tr '\n' ' '))"
else
    fact "  workspace: $workspace (git work tree; no checkout token in its git config)"
fi

mkdir -p "$UKAI_ROOT"
chmod 0700 "$UKAI_ROOT"
dir=$(mktemp -d "$UKAI_ROOT/report.XXXXXX")
export UKAI_ACTION_DIR=$dir
printf '%s\n' "${facts[@]}" > "$dir/setup.txt"
: > "$dir/facts.env"
set_fact mode "$mode"
set_fact workspace "$workspace"
set_fact token_note "$token_note"
set_fact environment "${RUNNER_ENVIRONMENT:-unset}"
set_output dir "$dir"
note "runner check passed: $mode mode, workspace $workspace"
