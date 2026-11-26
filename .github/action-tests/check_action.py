# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml==6.0.2"]
# ///
"""Static checks of the action's source (docs/specs/jail-ci-action.md).

Run from the repository root: uv run .github/action-tests/check_action.py

- No `run:` in action.yml holds a `${{ }}` expression: every input reaches
  the scripts as an environment variable (§2, §4.5; K85's static half).
- Every action that action.yml and the action workflows use is pinned by a
  full commit SHA (§4.7), or is the action itself: in place (`./action`), or
  at the release tag the workflow's UKAI_ACTION_TAG names (K86).
- The AppArmor profile file is byte for byte the text §3.3 gives.
- The scripts pin the bubblewrap digest §3.3 gives.
- action.yml's default `version` is the release the root installer pins for every
  target it ships and installs by default (§3.1), and the action workflows
  install that same release on both images.
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
RELEASE_TAG = re.compile(r"^monocursive/ukai/action@(ukai-jail-action-v[0-9][0-9A-Za-z.\-+]*)$")
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
    for job_name, job in (workflow.get("jobs") or {}).items():
        version = (job.get("env") or {}).get("UKAI_ACTION_VERSION")
        if version is not None:
            check(str(version) == str(action["inputs"]["version"]["default"]),
                  f"{name} job {job_name}: simulator version {version} differs from action.yml")
    # `uses:` takes no expression, so the release-tag job names its tag twice; the tag is
    # the action's release of some jail release, and the workflow's env names the same one.
    tag = (workflow.get("env") or {}).get("UKAI_ACTION_TAG")
    for uses in uses_of(workflow):
        at_tag = RELEASE_TAG.match(uses)
        check(uses == "./action" or PINNED.match(uses) is not None or (at_tag and tag == at_tag.group(1)),
              f"{name}: `{uses}` is not pinned by commit SHA, nor the action at UKAI_ACTION_TAG ({tag})")
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
    sys.path.insert(0, str(ROOT / 'crates/ukai-jail/dist'))
    from coordinates import release_targets
    # The default release ships one archive for each target it is qualified on (§3.1),
    # and the workflows install that same release on both images.
    for target in release_targets(str(version)):
        check(f"{version}:{target})" in installer, f"installer lacks {version} for {target}")
    for workflow in WORKFLOWS:
        env = yaml.safe_load(workflow.read_text())["env"]
        check(env.get("UKAI_ACTION_VERSION") == version, f"{workflow.name}: wrong release")
        check("ARM_PREVIEW_VERSION" not in env, f"{workflow.name}: still selects a separate ARM64 preview")
        if "UKAI_ACTION_TAG" in env:
            check(RELEASE_TAG.fullmatch(f"monocursive/ukai/action@{env['UKAI_ACTION_TAG']}") is not None,
                  f"{workflow.name}: UKAI_ACTION_TAG is not an action release tag")

for failure in failures:
    print(f"check_action: {failure}")
if failures:
    sys.exit(1)
print("check_action: ok")
