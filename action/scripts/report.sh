#!/usr/bin/env bash
# The report (J15 §3.5 items 1 to 3): `tail --summary` into the job summary
# with the host-setup line, the artifact's files, and the exposure check that
# must pass before anything is uploaded or written to the job page.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

dir=$(report_dir)
artifact=$dir/artifact
rm -rf "$artifact"
mkdir -p "$artifact"
attempt=$(cat "$dir/attempt-id" 2>/dev/null || true)
status=$(cat "$dir/exit-code" 2>/dev/null || true)

# Both sysctl readings (§3.5 item 2): before setup, and now.
after=$(read_sysctl)
fact "apparmor: $APPARMOR_SYSCTL=$after at report"
set_fact sysctl_after "$after"

# --- 1. the summary ----------------------------------------------------------
summary_ok=false
if [ -n "$attempt" ]; then
    source_dir=$UKAI_DATA_DIR/attempts/$attempt
    for file in jail.json policy.json trace.ndjson; do
        [ ! -f "$source_dir/$file" ] || cp -- "$source_dir/$file" "$artifact/$file"
    done
    if jail tail --summary --attempt "$attempt" > "$artifact/summary.txt" &&
        jail tail --summary --attempt "$attempt" --json > "$artifact/summary.json"; then
        summary_ok=true
    else
        warn "\`ukai-jail tail --summary\` could not read attempt $attempt"
        rm -f "$artifact/summary.txt" "$artifact/summary.json"
    fi
fi
[ ! -f "$dir/doctor.json" ] || cp -- "$dir/doctor.json" "$artifact/doctor.json"

# --- the host-setup line (§3.3, §3.5 item 1) --------------------------------
before=$(get_fact sysctl_before)
if [ "$(get_fact environment)" = github-hosted ]; then
    parts=()
    if [ "$(get_fact bwrap_built)" = true ]; then
        parts+=("bubblewrap $BWRAP_VERSION built from its release tarball (sha256:${BWRAP_SHA256:0:8}…) at $BWRAP_TARGET")
    elif [ -n "$(get_fact bwrap_path)" ]; then
        parts+=("bubblewrap $(get_fact bwrap_version) at $(get_fact bwrap_path), already present, nothing built")
    fi
    if [ "$(get_fact profile_loaded)" = true ]; then
        parts+=("AppArmor profile $APPARMOR_PROFILE allows user namespaces for that binary only")
    elif [ -n "$(get_fact profile_reason)" ]; then
        parts+=("no AppArmor profile loaded ($(get_fact profile_reason))")
    fi
    if [ "$before" = "$after" ]; then
        parts+=("$APPARMOR_SYSCTL stays $after")
    else
        parts+=("$APPARMOR_SYSCTL read $before before setup and $after now")
    fi
    host_line="host setup (this runner only): $(printf '%s · ' "${parts[@]}")"
    host_line=${host_line% · }
else
    host_line="host setup: none (RUNNER_ENVIRONMENT=$(get_fact environment); the runner is used as found)"
fi
token_note=$(get_fact token_note)
[ -z "$token_note" ] || host_line="$host_line · $token_note"
fact "$host_line"
cp -- "$dir/setup.txt" "$artifact/setup.txt"

# A fence longer than any run of backticks in the text, so no file name in a
# summary line can end the code block.
fence_for() {
    local longest
    longest=$(grep -o '`*' "$1" 2>/dev/null | awk '{ if (length($0) > n) n = length($0) } END { print n + 0 }')
    [ "$longest" -ge 3 ] || longest=2
    printf '%*s' "$((longest + 1))" '' | tr ' ' '`'
}

if [ "$(get_fact mode)" = launch ]; then what="launch $UKAI_ACTION_LAUNCH"; else what="profile $UKAI_ACTION_PROFILE"; fi
summary_md=$dir/summary.md
{
    printf '### ukai-jail (%s)\n\n' "$what"
    if [ "$summary_ok" = true ]; then
        fence=$(fence_for "$artifact/summary.txt")
        printf '%stext\n' "$fence"
        cat "$artifact/summary.txt"
        printf '%s\n\n' "$fence"
    elif [ -n "$status" ]; then
        printf 'ukai-jail exited %s and recorded no readable attempt; its message is in the step log.\n\n' "$status"
    else
        # shellcheck disable=SC2016 # Markdown backticks, not an expansion
        printf 'ukai-jail did not run: the setup or doctor step failed; `setup.txt` and `doctor.json` in the artifact say why.\n\n'
    fi
    printf '%s\n' "$host_line"
} > "$summary_md"

comment_md=
if [ "${UKAI_ACTION_PR_COMMENT:-false}" = true ]; then
    comment_md=$dir/comment.md
    marker="ukai-jail-action:${GITHUB_WORKFLOW:-}:${GITHUB_JOB:-}:$UKAI_ACTION_ARTIFACT_NAME"
    marker=$(printf '%s' "$marker" | tr -c 'A-Za-z0-9._ /:-' '_')
    printf '%s' "$marker" > "$dir/comment-marker"
    {
        printf '<!-- %s -->\n' "$marker"
        cat "$summary_md"
        printf '\n[Workflow run](%s/%s/actions/runs/%s)' "${GITHUB_SERVER_URL:-https://github.com}" "${GITHUB_REPOSITORY:-}" "${GITHUB_RUN_ID:-}"
    } > "$comment_md"
fi

# --- 3. the exposure check (must) --------------------------------------------
# Every file that leaves the runner is searched for each stored credential's
# value as a fixed string; the value is read by grep from the vault file
# itself and never enters this script.
hits=()
checked=0
while IFS= read -r id; do
    [ -n "$id" ] || continue
    vault=$UKAI_CONFIG_DIR/credentials/$id
    [ -s "$vault" ] || continue
    checked=$((checked + 1))
    found=$(grep -rlF -f "$vault" -- "$artifact" "$summary_md" ${comment_md:+"$comment_md"}) && rc=0 || rc=$?
    if [ "$rc" -gt 1 ]; then
        hits+=("(the search for credential $id failed)")
    elif [ "$rc" -eq 0 ]; then
        while IFS= read -r path; do hits+=("${path#"$dir"/} (credential $id)"); done <<< "$found"
    fi
done < <(cat "$dir/credential-ids" 2>/dev/null || true)

if [ "${#hits[@]}" -gt 0 ]; then
    rm -rf "$artifact"
    {
        printf '### ukai-jail (%s): exposure check FAILED, nothing uploaded\n\n' "$what"
        printf 'A stored credential value was found in:\n\n'
        printf -- '- %s\n' "${hits[@]}"
    } >> "${GITHUB_STEP_SUMMARY:?}"
    set_output upload false
    fail "exposure check: a stored credential value is in $(printf '%s; ' "${hits[@]}")nothing was uploaded or posted"
fi
note "exposure check: $checked stored credential(s) searched for in every artifact file and the summary; none found"

cat "$summary_md" >> "${GITHUB_STEP_SUMMARY:?}"
settled=false
if [ "$summary_ok" = true ]; then
    settled=$(python3 -I "$FACTS_PY" summary "$artifact/summary.json" "" | awk -F= '$1 == "settled" {print $2}')
    set_output summary-json "$artifact/summary.json"
fi
[ ! -f "$artifact/jail.json" ] || set_output receipt "$artifact/jail.json"
set_output attempt-id "$attempt"
set_output settled "$settled"
set_output artifact-dir "$artifact"
set_output upload true
