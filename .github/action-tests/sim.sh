#!/usr/bin/env bash
# Runs the action's step scripts directly, in the order action.yml runs them,
# with whatever environment the caller set: the self-test's simulated runner
# shapes (a root step, pull_request_target, a self-hosted runner), which a
# `uses:` step on a hosted runner cannot take on, since GitHub sets
# GITHUB_* and RUNNER_* itself and runs no step as root.
# usage: sim.sh STEP...   (check setup credentials doctor run ...)
# Prints `sim: completed` or `sim: stopped at STEP` and exits 0 or 1.
set -uo pipefail
GITHUB_ACTION_PATH=$(cd "$(dirname "$0")/../../action" && pwd)
GITHUB_OUTPUT=$(mktemp)
GITHUB_STEP_SUMMARY=$(mktemp)
export GITHUB_ACTION_PATH GITHUB_OUTPUT GITHUB_STEP_SUMMARY
for step in "$@"; do
    if ! bash "$GITHUB_ACTION_PATH/scripts/$step.sh"; then
        echo "sim: stopped at $step"
        exit 1
    fi
    if [ "$step" = check ]; then
        UKAI_ACTION_DIR=$(awk -F= '$1 == "dir" { value = $2 } END { print value }' "$GITHUB_OUTPUT")
        export UKAI_ACTION_DIR
    fi
done
echo "sim: completed"
