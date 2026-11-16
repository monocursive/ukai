#!/usr/bin/env bash
# After the upload (J15 §3.5 items 4 and 5): the artifact's link in the job
# summary, and with `pr-comment: true` one pull-request comment, found by its
# hidden marker and updated in place, on a same-repository pull_request only.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

dir=$(report_dir)
url=${UKAI_ACTION_ARTIFACT_URL:-}
if [ -n "$url" ]; then
    # shellcheck disable=SC2016 # Markdown backticks, not an expansion
    printf '\nArtifact `%s` (receipt, policy, journal, summary JSON, doctor JSON, setup.txt): %s\n' \
        "$UKAI_ACTION_ARTIFACT_NAME" "$url" >> "${GITHUB_STEP_SUMMARY:?}"
fi

[ "${UKAI_ACTION_PR_COMMENT:-false}" = true ] || exit 0
comment=$dir/comment.md
[ -f "$comment" ] || fail "pr-comment: the report wrote no comment (it did not pass the exposure check)"
if [ "${GITHUB_EVENT_NAME:-}" != pull_request ]; then
    note "pr-comment: nothing posted on a ${GITHUB_EVENT_NAME:-unknown} event; only pull_request posts"
    exit 0
fi
pr=
same=false
while IFS='=' read -r key value; do
    case "$key" in pr) pr=$value ;; same_repository) same=$value ;; esac
done < <(python3 -I "$FACTS_PY" event "${GITHUB_EVENT_PATH:?}")
if [ -z "$pr" ] || [ "$same" != true ]; then
    note "pr-comment: nothing posted: the pull request's head is not in ${GITHUB_REPOSITORY:-this repository} (a fork's token cannot comment)"
    exit 0
fi
command -v gh > /dev/null 2>&1 || fail "pr-comment: the gh CLI is not on this runner"
# shellcheck disable=SC2016 # Markdown backticks, not an expansion
[ -z "$url" ] || printf ' · [artifact `%s`](%s)' "$UKAI_ACTION_ARTIFACT_NAME" "$url" >> "$comment"
printf '\n' >> "$comment"
marker=$(cat "$dir/comment-marker")
repository=${GITHUB_REPOSITORY:?}
gh api --paginate --slurp "repos/$repository/issues/$pr/comments" > "$dir/comments.json" ||
    fail "pr-comment: cannot list the comments of pull request $pr (the job needs pull-requests: write)"
existing=$(python3 -I "$FACTS_PY" find-comment "$dir/comments.json" "$marker")
python3 -I "$FACTS_PY" comment-body "$comment" > "$dir/comment-request.json"
if [ -n "$existing" ]; then
    gh api --method PATCH "repos/$repository/issues/comments/$existing" --input "$dir/comment-request.json" > /dev/null ||
        fail "pr-comment: cannot update comment $existing on pull request $pr"
    note "pr-comment: updated comment $existing on pull request $pr"
else
    gh api --method POST "repos/$repository/issues/$pr/comments" --input "$dir/comment-request.json" > /dev/null ||
        fail "pr-comment: cannot comment on pull request $pr (the job needs pull-requests: write)"
    note "pr-comment: posted on pull request $pr"
fi
