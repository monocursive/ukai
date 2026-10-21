# shellcheck shell=bash disable=SC2034 # its names are used by the scripts that source it
# Shared by the action's step scripts (docs/specs/jail-ci-action.md, J15).
# Inputs arrive as UKAI_ACTION_* environment variables set by action.yml;
# nothing here splices, sources or evaluates their text.

set -euo pipefail
umask 077
export LC_ALL=C

: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"
UKAI_ROOT=$RUNNER_TEMP/ukai
UKAI_BIN=$UKAI_ROOT/bin/ukai-jail
export UKAI_CONFIG_DIR=$UKAI_ROOT/config
export UKAI_DATA_DIR=$UKAI_ROOT/data
ACTION_DIR=${GITHUB_ACTION_PATH:?GITHUB_ACTION_PATH must be set}
FACTS_PY=$ACTION_DIR/scripts/facts.py

# §3.3 item 2: bubblewrap 0.11.1 from its release tarball, pinned by digest.
BWRAP_VERSION=0.11.1
BWRAP_URL=https://github.com/containers/bubblewrap/releases/download/v0.11.1/bubblewrap-0.11.1.tar.xz
BWRAP_SHA256=c1b7455a1283b1295879a46d5f001dfd088c0bb0f238abb5e128b3583a246f71
BWRAP_TARGET=/usr/local/bin/bwrap
# §3.3 item 3: the one profile the action may load, and the sysctl it reads.
APPARMOR_PROFILE=ukai-jail-action-bwrap
APPARMOR_SYSCTL=kernel.apparmor_restrict_unprivileged_userns
APPARMOR_SYSCTL_FILE=/proc/sys/kernel/apparmor_restrict_unprivileged_userns

# Workflow-command data escaping, so a message built from an input or a
# file name stays one line and cannot start a command of its own.
escape_data() {
    local text=$1
    text=${text//'%'/%25}
    text=${text//$'\r'/%0D}
    text=${text//$'\n'/%0A}
    printf '%s' "$text"
}

note() { printf 'ukai-jail action: %s\n' "$(escape_data "$*")"; }

fail() {
    printf '::error title=ukai-jail action::%s\n' "$(escape_data "$*")"
    exit 1
}

warn() { printf '::warning title=ukai-jail action::%s\n' "$(escape_data "$*")"; }

set_output() { printf '%s=%s\n' "$1" "$2" >> "${GITHUB_OUTPUT:?}"; }

# The report directory check.sh created for this invocation.
report_dir() {
    local dir=${UKAI_ACTION_DIR:-}
    [ -n "$dir" ] && [ -d "$dir" ] || fail "internal: the report directory is missing"
    printf '%s' "$dir"
}

# One line of setup facts (§3.3, `setup.txt` in the artifact).
fact() { printf '%s\n' "$*" >> "$(report_dir)/setup.txt"; }

# key=value facts the later steps read back; values are this action's own.
set_fact() { printf '%s=%s\n' "$1" "$2" >> "$(report_dir)/facts.env"; }

get_fact() {
    local file
    file="$(report_dir)/facts.env"
    [ -f "$file" ] || return 0
    awk -v key="$1" 'index($0, key "=") == 1 { value = substr($0, length(key) + 2) } END { printf "%s", value }' "$file"
}

sha256_of() { sha256sum -- "$1" | awk '{print $1}'; }

# The sysctl as the kernel reports it, or `absent`.
read_sysctl() {
    local value
    if value=$(cat "$APPARMOR_SYSCTL_FILE" 2>/dev/null); then
        printf '%s' "$value"
    else
        printf 'absent'
    fi
}

# Split an input on whitespace into the named array, with no globbing.
split_words() {
    local -n into=$1
    into=()
    local IFS=$' \t\n'
    read -r -d '' -a into < <(printf '%s\0' "$2") || true
}

# `credentials` (§3.1): ID=ENVVAR words. Both halves are checked before the
# variable is ever read: `${!name}` evaluates an array subscript, so an
# unchecked name such as `A[$(cmd)]` would run a command.
CREDENTIAL_IDS=()
CREDENTIAL_VARS=()
parse_credentials() {
    local words=() word id var
    CREDENTIAL_IDS=()
    CREDENTIAL_VARS=()
    split_words words "${UKAI_ACTION_CREDENTIALS:-}"
    for word in ${words[@]+"${words[@]}"}; do
        [[ "$word" == *=* ]] || fail "credentials: \`$word\` is not ID=ENVVAR"
        id=${word%%=*}
        var=${word#*=}
        [[ "$id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] ||
            fail "credentials: \`$word\`: the id must be letters, digits, '.', '_' or '-'"
        [[ "$var" =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] ||
            fail "credentials: \`$word\`: ENVVAR must be an environment variable name"
        # Removed from ukai-jail's environment below, so never one it needs.
        case "$var" in
            UKAI_*|PATH|HOME) fail "credentials: \`$word\`: $var cannot hold a credential here" ;;
        esac
        case " ${CREDENTIAL_IDS[*]-} " in
            *" $id "*) fail "credentials: the id \`$id\` appears twice" ;;
        esac
        CREDENTIAL_IDS+=("$id")
        CREDENTIAL_VARS+=("$var")
    done
}

# Run ukai-jail with every variable named in `credentials` removed from its
# environment (§3.4): no value reaches even the supervisor after
# `credential set`.
jail() {
    parse_credentials
    (
        for var in ${CREDENTIAL_VARS[@]+"${CREDENTIAL_VARS[@]}"}; do
            unset -v "$var"
        done
        exec "$UKAI_BIN" "$@"
    )
}

# The first absolute PATH entry holding an executable `bwrap`, as ukai-jail
# resolves its backend (operating.md, Install); empty and relative entries
# are never searched.
first_bwrap() {
    local entry IFS=:
    for entry in ${PATH-}; do
        case "$entry" in /*) ;; *) continue ;; esac
        if [ -f "$entry/bwrap" ] && [ -x "$entry/bwrap" ]; then
            printf '%s' "$entry/bwrap"
            return 0
        fi
    done
    return 1
}

# The version `bwrap --version` reports (`bubblewrap 0.11.1`), or empty.
bwrap_version_of() {
    "$1" --version 2>/dev/null | awk 'NR == 1 && $1 == "bubblewrap" {print $2}'
}

# True when version $1 is at least $2 (numeric x.y.z).
version_at_least() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (a !~ /^[0-9]+(\.[0-9]+)*$/) exit 1
        na = split(a, x, "."); nb = split(b, y, ".")
        for (i = 1; i <= 3; i++) {
            p = (i <= na) ? x[i] + 0 : 0; q = (i <= nb) ? y[i] + 0 : 0
            if (p > q) exit 0
            if (p < q) exit 1
        }
        exit 0
    }'
}

random_token() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
