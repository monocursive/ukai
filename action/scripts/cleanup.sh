#!/usr/bin/env bash
# The last report step (J15 §3.5 item 6): the credential files this
# invocation stored under $RUNNER_TEMP/ukai/config are removed.
# shellcheck source=action/scripts/lib.sh
source "${GITHUB_ACTION_PATH:?}/scripts/lib.sh"

dir=$(report_dir)
removed=0
while IFS= read -r id; do
    [ -n "$id" ] || continue
    vault=$UKAI_CONFIG_DIR/credentials/$id
    [ -e "$vault" ] || continue
    jail credential rm "$id" > /dev/null 2>&1 || rm -f -- "$vault"
    [ ! -e "$vault" ] || fail "cleanup: could not remove the stored credential $id"
    removed=$((removed + 1))
done < <(cat "$dir/credential-ids" 2>/dev/null || true)
note "cleanup: removed $removed stored credential(s)"
