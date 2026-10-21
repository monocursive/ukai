#!/usr/bin/env bash
# Credentials (J15 §3.3 item 5): each `ID=ENVVAR` value goes from the step's
# environment into the vault with `ukai-jail credential set ID`, on stdin.
# The value is never printed, never an argument and never in ukai-jail's
# environment; it is masked in the job log before anything else is done
# with it.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

parse_credentials
dir=$(report_dir)
: > "$dir/credential-ids"
index=0
for id in ${CREDENTIAL_IDS[@]+"${CREDENTIAL_IDS[@]}"}; do
    var=${CREDENTIAL_VARS[$index]}
    index=$((index + 1))
    line="credentials word $index ($id=$var)"
    # parse_credentials checked $var's shape, so this reads one variable
    value=${!var-}
    value=${value%$'\n'}
    if [ -z "$value" ]; then
        fail "$line: \$$var is empty or unset (a pull request from a fork gets no secrets); nothing of it was stored"
    fi
    # credential set takes 1 to 8192 printable ASCII bytes (operating.md);
    # a line break would also split the mask below, so refuse first
    if [ "${#value}" -gt 8192 ] || [[ "$value" == *[^[:print:]]* ]]; then
        fail "$line: \$$var is not 1 to 8192 printable ASCII bytes (a line break or control character); nothing of it was stored"
    fi
    printf '::add-mask::%s\n' "$value"
    printf '%s' "$value" | jail credential set --force "$id" > /dev/null ||
        fail "$line: \`ukai-jail credential set $id\` refused the value"
    unset -v value
    printf '%s\n' "$id" >> "$dir/credential-ids"
    fact "credential $id: from \$$var, stored with \`ukai-jail credential set $id\` (stdin), masked in the log"
done
[ "$index" -gt 0 ] || fact "credentials: none"
