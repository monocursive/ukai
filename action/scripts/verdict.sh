#!/usr/bin/env bash
# Exit status (J15 §3.6): the step fails with ukai-jail's own status (the
# command's, or 125 for a refusal before exec), and, whatever that status,
# for each `fail-on` condition that holds. It runs after every report step.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

dir=$(report_dir)
status=$(cat "$dir/exit-code" 2>/dev/null || echo 1)
fail_on=${UKAI_ACTION_FAIL_ON:-}
reasons=()
while IFS= read -r line; do
    case "$line" in fail=*) reasons+=("${line#fail=}") ;; esac
done < <(python3 -I "$FACTS_PY" summary "$dir/artifact/summary.json" "${fail_on//,/ }")
for reason in ${reasons[@]+"${reasons[@]}"}; do
    printf '::error title=ukai-jail action (fail-on)::%s\n' "$(escape_data "$reason")"
done
if [ "$status" != 0 ]; then
    printf '::error title=ukai-jail action::ukai-jail exited %s\n' "$status"
    exit "$status"
fi
[ "${#reasons[@]}" -eq 0 ] || exit 1
note "ukai-jail exited 0; fail-on (${fail_on:-nothing}) found nothing to fail"
