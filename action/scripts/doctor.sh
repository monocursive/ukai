#!/usr/bin/env bash
# doctor (J15 §3.3 item 4): the requested plan must be ready on this runner,
# or the step fails with what is unavailable. Its JSON goes to the artifact.
# It runs after the credentials are stored: `doctor --launch` counts a
# launch profile whose credential is missing as not ready.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

dir=$(report_dir)
workspace=$(get_fact workspace)
cd "$workspace"
if [ "$(get_fact mode)" = launch ]; then
    plan=(--launch "$UKAI_ACTION_LAUNCH" --from-path)
else
    plan=(--profile "$UKAI_ACTION_PROFILE")
fi
status=0
jail doctor "${plan[@]}" --workspace "$workspace" --json < /dev/null > "$dir/doctor.json" || status=$?
if ready=$(python3 -I "$FACTS_PY" doctor "$dir/doctor.json"); then
    fact "doctor: ready for ${plan[*]} (doctor.json)"
    note "doctor: ready for ${plan[*]}"
    exit 0
fi
fact "doctor: NOT ready for ${plan[*]} (exit $status):"
printf '%s\n' "$ready" | sed 's/^/  /' >> "$dir/setup.txt"
printf '%s\n' "$ready" | while IFS= read -r line; do note "doctor: $line"; done
if [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    fail "doctor is not ready for ${plan[*]} on this self-hosted runner, and the action changes nothing there; see the host notes at https://ukai.sh/guide/ and \`ukai-jail doctor\`"
fi
fail "doctor is not ready for ${plan[*]} (exit $status); the reasons are above and in doctor.json"
