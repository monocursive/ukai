#!/usr/bin/env bash
# The run (J15 §3.4). Launch mode is exactly `ukai-jail NAME ARG...` plus the
# requested options; profile mode runs `run` as one argv element of
# `/bin/bash -e -c`. Inputs become argv elements here, never shell text.
# This step records ukai-jail's exit status and always succeeds; the verdict
# step fails the action with it, after the report.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

dir=$(report_dir)
workspace=$(get_fact workspace)
options=(--workspace "$workspace")
words=()
split_words words "${UKAI_ACTION_ALLOW_HOSTS:-}"
for word in ${words[@]+"${words[@]}"}; do options+=("--allow-host=$word"); done
split_words words "${UKAI_ACTION_LIMITS:-}"
for word in ${words[@]+"${words[@]}"}; do options+=("--limit=$word"); done

if [ "$(get_fact mode)" = launch ]; then
    # `args`: one argument per line; a final newline ends the last line
    arguments=()
    if [ -n "${UKAI_ACTION_ARGS:-}" ]; then
        mapfile -t arguments < <(printf '%s' "$UKAI_ACTION_ARGS")
    fi
    command=(run --launch "$UKAI_ACTION_LAUNCH" --from-path "${options[@]}" -- ${arguments[@]+"${arguments[@]}"})
else
    command=(run --profile "$UKAI_ACTION_PROFILE" "${options[@]}" -- /bin/bash -e -c "$UKAI_ACTION_RUN")
fi

attempts() {
    local entry
    for entry in "$UKAI_DATA_DIR"/attempts/*/; do
        [ -d "$entry" ] || continue
        entry=${entry%/}
        printf '%s\n' "${entry##*/}"
    done | sort
}
attempts > "$dir/attempts-before"
cd "$workspace"
note "ukai-jail ${command[0]} ${command[1]} ${command[2]} … (stdin /dev/null); the agent's output follows, with workflow commands off"
# The agent's output is the agent's: no line of it may act as a workflow
# command (set an output, add a mask, open a group) until the token returns.
token=$(random_token)
printf '::stop-commands::%s\n' "$token"
status=0
jail "${command[@]}" < /dev/null || status=$?
printf '::%s::\n' "$token"
attempts > "$dir/attempts-after"
attempt=$(comm -13 "$dir/attempts-before" "$dir/attempts-after" | tail -1)
printf '%s' "$attempt" > "$dir/attempt-id"
printf '%s' "$status" > "$dir/exit-code"
set_output exit-code "$status"
note "ukai-jail exited $status${attempt:+, attempt $attempt}"
