#!/usr/bin/env python3
"""K85's inputs: shell metacharacters, quotes, `;`, newlines and `${{ }}`
text for the action's `args` (launch mode, with the fake `claude`, a copy of
bash) and `run` (profile mode). It writes them as the step outputs `args`
and `run`, so the workflow passes them to the action as an issue title
would be (`${{ steps.hostile.outputs.args }}`), and writes the expected
argv and script text for selftest.py. Each marker file names a command that
would create it if any shell outside the jail evaluated the text.

usage: hostile.py --markers DIR --expected DIR   (appends to $GITHUB_OUTPUT)
"""
import argparse
import json
import os
import secrets
from pathlib import Path

EXPRESSION = "$" + "{{ github.token }}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--markers", required=True)
    parser.add_argument("--expected", required=True, type=Path)
    args = parser.parse_args()
    mark = f"{args.markers}/ukai-k85"
    # the fake claude is bash: `-c SCRIPT $0 ARG...`, recording its argv
    script = 'printf "%s\\0" "$0" "$@" > argv.bin; env > env.txt; sleep 3'
    argv = [
        "fake-claude",
        f"$(touch {mark}-args-dollar)",
        f"`touch {mark}-args-backtick`",
        "it's \"quoted\" \\ and $HOME",
        f"a;touch {mark}-args-semicolon",
        EXPRESSION,
        "--allow-host=evil.example",
        "",
        "  spaces around  ",
    ]
    run = "\n".join([
        'printf "%s" "$BASH_EXECUTION_STRING" > .ukai-selftest/run-text.txt',
        f': "$(touch {mark}-run-dollar)" "`touch {mark}-run-backtick`"',
        f": 'single;quote' \"double \\\"quote\\\"\" ; : '{EXPRESSION}'",
        "python3 -I .github/action-tests/inside_probe.py --paths .ukai-selftest/paths.json"
        " --out .ukai-selftest/inside.json",
    ])
    lines = ["-c", script, *argv]
    args.expected.mkdir(parents=True, exist_ok=True)
    (args.expected / "expected-argv.json").write_text(json.dumps(argv))
    (args.expected / "expected-args.json").write_text(json.dumps(lines))
    (args.expected / "expected-run.txt").write_text(run)
    (args.expected / "markers.json").write_text(json.dumps(
        [f"{mark}-{name}" for name in ("args-dollar", "args-backtick", "args-semicolon",
                                       "run-dollar", "run-backtick")]))
    delimiter = "UKAI_" + secrets.token_hex(16)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"args<<{delimiter}\n" + "\n".join(lines) + f"\n{delimiter}\n")
        output.write(f"run<<{delimiter}\n{run}\n{delimiter}\n")


if __name__ == "__main__":
    main()
