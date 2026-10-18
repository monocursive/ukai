#!/usr/bin/env bash
# The demo run, from inside the repository, as a developer runs it.
set -u
export PATH="$HOME/.local/bin:$HOME/cc-demo-20261018/prefix/bin:$PATH"
cd "$HOME/cc-demo-20261018/ws/shipit"
ukai-jail claude -p "The tests in test_slug.py fail. Fix the bug in slug.py so that python3 -m unittest passes, without changing test_slug.py, and run the tests to confirm." --dangerously-skip-permissions
status=$?
echo "UKAI_EXIT_STATUS=$status (printed by the capture script)"
exit 0
