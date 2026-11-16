# Ukai Jail for GitHub Actions

Run a coding agent, or any script, inside [Ukai Jail](https://ukai.sh) on a
GitHub-hosted Ubuntu 24.04 runner. The agent can write only the workspace,
reach only the hosts you allow, and never holds your API key: the key stays
in the jail's vault and the agent gets a placeholder. When the run ends, the
jail's end-of-run summary goes to the job page and its receipt, policy and
event journal become an artifact.

Specification: [jail-ci-action.md](https://github.com/monocursive/ukai/blob/dev/docs/specs/jail-ci-action.md).
Version 1 is a developer preview, like the jail it installs.

## Launch mode: an agent with its launch profile

```yaml
permissions:
  contents: read
jobs:
  agent:
    runs-on: ubuntu-24.04          # or ubuntu-24.04-arm
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false   # required, see below
      - name: Install Claude Code
        run: curl -fsSL https://claude.ai/install.sh | bash
      - uses: monocursive/ukai/action@<commit SHA>   # ukai-jail-action-vX; see "Pin it" below
        with:
          launch: claude
          args: |
            -p
            The tests in test_slug.py fail. Fix the bug in slug.py and run them.
            --dangerously-skip-permissions
          credentials: anthropic=ANTHROPIC_API_KEY
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

`launch` names a launch profile, as `ukai-jail NAME` takes it; the step runs
exactly what `ukai-jail NAME ARG...` runs, plus `allow-hosts` and `limits`.
The program is found on the step's `PATH`, so install the agent first.
`args` holds the program's arguments, **one per line**: each line is one
argument, passed with no shell, so quotes and `$(…)` are literal. A blank
line is an empty argument. The bundled `claude` profile takes a Claude
Console API key as `anthropic` or a `claude setup-token` value as
`claude-oauth`.

## Profile mode: a script under an execution profile

```yaml
      - uses: monocursive/ukai/action@<sha>   # ukai-jail-action-vX
        with:
          profile: agent             # tool, build or agent; none is refused
          allow-hosts: |
            pypi.org
            files.pythonhosted.org
          run: |
            python3 -m pip install --user -r requirements.txt
            python3 -m pytest
```

`run` is one script, run inside the jail as `/bin/bash -e -c "$run"`.
`tool` and `build` have no network; `agent` reaches the `allow-hosts`
through the jail's proxy.

## Inputs and outputs

| Input | Meaning | Default |
| --- | --- | --- |
| `launch` | A launch profile name. Exclusive with `profile`. | |
| `args` | Launch mode: the program's arguments, one per line. | |
| `profile` | `tool`, `build` or `agent`. Exclusive with `launch`. | |
| `run` | Profile mode: the script. | |
| `allow-hosts` | Hosts to allow, one per line or space-separated. | none |
| `limits` | `KEY=VALUE` limits (`wall=30m`, `mem=4GiB`), one per line or space-separated. | the profile's |
| `credentials` | `ID=ENVVAR` lines: store `$ENVVAR`'s value as the vault credential `ID`. | none |
| `workspace` | A git work tree; relative to `$GITHUB_WORKSPACE`. | `$GITHUB_WORKSPACE` |
| `version` | The ukai-jail release; the installer beside the action must pin it. | the release of this action's tag |
| `fail-on` | Also fail the step when: `unsettled`, `survivors`, `gaps`. | `unsettled,survivors` |
| `pr-comment` | Post or update one comment on a same-repository pull request. | `false` |
| `artifact-name` | The artifact's name. Unique per workflow run: set it per job in a matrix. | `ukai-jail-receipt` |
| `allow-checkout-token` | Run although the workspace holds the checkout's token. | `false` |

Outputs: `exit-code`, `attempt-id`, `settled` (`true`/`false`),
`summary-json` (the path of `tail --summary --json`'s output) and `receipt`
(the path of the copied `jail.json`).

The step fails with ukai-jail's exit status: the command's own, or 125 when
the jail refused before running it. `fail-on` adds conditions: `unsettled`
(the receipt is not settled), `survivors` (processes could not be verified
gone) and `gaps` (an evidence class was not active or had gaps). Under
`tool` and `build`, which have no proxy, the `proxy.net` class is never
active, so `gaps` fails every such run; use it with `agent` and launch
profiles. The report steps run either way.

## Credentials

Each `ID=ENVVAR` line stores the value of `$ENVVAR` with `ukai-jail
credential set ID`, on stdin. Put the value in the step's `env:` from a
secret, as above. The action masks it in the log, removes `ENVVAR` from the
environment ukai-jail runs in, and deletes the stored file when the job's
action step ends. Inside, the agent sees only a placeholder; the jail's
proxy puts the real value in the request headers for the hosts the launch
profile names. An empty variable fails the step and names the line, never
the value.

Before anything is uploaded or posted, every artifact file, the job summary
and the comment are searched for each stored value. A hit fails the step,
uploads nothing and names the file.

## `persist-credentials: false`

`actions/checkout` stores the job's `GITHUB_TOKEN` in the workspace's
`.git/config` unless told not to. The workspace is the agent's, so it could
read that token. The action refuses such a workspace. Set
`persist-credentials: false`; if a later step needs to push, give it a token
there. `allow-checkout-token: true` runs anyway and the summary says the
token was readable inside.

## Forks and pull_request_target

A `pull_request` from a fork gets no secrets, so a `credentials` line names
an empty variable and the step fails, saying so. The comment is posted only
on a `pull_request` whose head is in the same repository; on a fork's pull
request, on other events, or without `pr-comment: true`, nothing is posted.
For the comment, grant `pull-requests: write`.

`pull_request_target` is refused: it runs with the base repository's
secrets on a workflow that often checks out the fork's code.

## What the agent writes is untrusted

The jail bounds what the agent can do during the run. Whatever it wrote to
the workspace is still there for the job's later steps: treat it as
untrusted input (run its tests in the jail too, with profile mode), and do
not run a copy of this action from inside the agent's workspace.

## What the host-setup line means

GitHub-hosted 24.04 runners need two changes before the jail can run
contained, both measured
([runner spike](https://github.com/monocursive/ukai/blob/dev/docs/benchmarks/jail/github-runners-2026-10-21.md)),
and the action makes them only there:

- **bubblewrap 0.11.1**, built on the runner from its release tarball,
  verified by SHA-256 (`c1b7455a…`), installed as `/usr/local/bin/bwrap`.
  The image's bubblewrap is 0.9.0, older than the 0.10.0 the jail needs.
  This adds about half a minute per job.
- **One AppArmor profile**, `ukai-jail-action-bwrap`, that lets that one
  binary create user namespaces, loaded only when
  `kernel.apparmor_restrict_unprivileged_userns` reads 1. The restriction
  stays on for every other program; the sysctl is never written.

The summary ends with a line that says exactly what was done:

```text
host setup (this runner only): bubblewrap 0.11.1 built from its release tarball (sha256:c1b7455a…) at /usr/local/bin/bwrap · AppArmor profile ukai-jail-action-bwrap allows user namespaces for that binary only · kernel.apparmor_restrict_unprivileged_userns stays 1
```

`setup.txt` in the artifact has the details: the runner check, both
digests, the profile's text and the sysctl before setup and at the end.
On a self-hosted runner the action changes nothing: it installs ukai-jail
into the job's temporary directory and runs only if `ukai-jail doctor` is
already ready there.

## Pin it by commit SHA

A tag can be moved; a commit cannot. Reference the action by the commit the
release tag names, and keep the tag in a comment:

```yaml
      - uses: monocursive/ukai/action@<40-character commit SHA>  # ukai-jail-action-vX
```

Each release `ukai-jail-vX` gets one commit on this repository's `action`
branch, tagged `ukai-jail-action-vX`, that holds only `action/` and that
release's installer, so the download stays small; `version` defaults to
release X. No release of the action is tagged yet: the first comes with the
next jail release. The installer checks
the release archive against the SHA-256 it pins, and the action pins
bubblewrap by digest and every action it uses by commit SHA.

## Large repositories

Before a run the jail scans the workspace for the paths it protects (`.git`,
`.ukai`), and it refuses a workspace with more than 100,000 directory
entries rather than claim a partial scan (`missing_capability`: "protected
scan reached its 100000-entry limit"). A large repository's full checkout
can exceed that; this repository's does. Check out only what the run needs
(`sparse-checkout:` on `actions/checkout`) or point `workspace` at a
smaller work tree.

## Runners

`ubuntu-24.04` and `ubuntu-24.04-arm`, and any later GitHub-hosted Ubuntu
the runner check accepts. `ubuntu-22.04` (glibc 2.35), Windows, macOS, a
root step and other CI systems are refused or out of scope.
