# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml==6.0.2"]
# ///
"""Static checks of the action's source (docs/specs/jail-ci-action.md).

Run from the repository root: uv run .github/action-tests/check_action.py

- No `run:` in action.yml holds a `${{ }}` expression: every input reaches
  the scripts as an environment variable (§2, §4.5; K85's static half).
- Every action that action.yml and the action workflows use is pinned by a
  full commit SHA (§4.7), or is the action itself in place (`./action`).
- The AppArmor profile file is byte for byte the text §3.3 gives.
- The scripts pin the bubblewrap digest §3.3 gives.
- action.yml's default `version` is the release the root installer pins and
  installs by default (§3.1).
"""
import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = ROOT / "docs/specs/jail-ci-action.md"
ACTION = ROOT / "action"
WORKFLOWS = [ROOT / ".github/workflows/action-selftest.yml", ROOT / ".github/workflows/action-arow.yml"]
PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
BWRAP_SHA256 = "c1b7455a1283b1295879a46d5f001dfd088c0bb0f238abb5e128b3583a246f71"

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


def uses_of(document):
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            if "uses" in step:
                yield step["uses"]


action = yaml.safe_load((ACTION / "action.yml").read_text())
steps = action["runs"]["steps"]
for step in steps:
    if "run" in step:
        check("${{" not in step["run"], f"action.yml step {step.get('id')}: `run:` holds an expression")
    if "uses" in step:
        check(PINNED.match(step["uses"]) is not None,
              f"action.yml step {step.get('id')}: `{step['uses']}` is not pinned by commit SHA")
for name, workflow in ((w.name, yaml.safe_load(w.read_text())) for w in WORKFLOWS if w.exists()):
    for uses in uses_of(workflow):
        check(uses == "./action" or PINNED.match(uses) is not None,
              f"{name}: `{uses}` is not pinned by commit SHA")
check(all(w.exists() for w in WORKFLOWS), "an action workflow is missing")

# §3.3's profile, the first code block after "load, with `sudo apparmor_parser -r`"
spec = SPEC.read_text()
block = re.search(r"apparmor_parser -r`, exactly.*?```\n(.*?)\n *```", spec, re.S)
check(block is not None, "the spec's AppArmor profile block was not found")
if block:
    expected = "\n".join(line[3:] if line.startswith("   ") else line
                         for line in block.group(1).splitlines()) + "\n"
    check((ACTION / "ukai-jail-action-bwrap").read_text() == expected,
          "action/ukai-jail-action-bwrap differs from the profile text in §3.3")
check(f"`{BWRAP_SHA256}`" in spec, "the spec no longer gives the bubblewrap digest")
check(f"BWRAP_SHA256={BWRAP_SHA256}" in (ACTION / "scripts/lib.sh").read_text(),
      "lib.sh does not pin the bubblewrap digest of §3.3")

installer = (ROOT / "install.sh").read_text()
default = re.search(r"^    version=(\S+)$", installer, re.M)
check(default is not None, "install.sh has no default version line")
if default:
    version = action["inputs"]["version"]["default"]
    check(str(version) == default.group(1),
          f"action.yml's default version {version} is not install.sh's {default.group(1)}")
    for target in ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"):
        check(f"{version}:{target})" in installer, f"install.sh pins no {version} for {target}")

for failure in failures:
    print(f"check_action: {failure}")
if failures:
    sys.exit(1)
print("check_action: ok")
