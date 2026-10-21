# Jail proposal: receipts in CI, a GitHub Action (J15)

Status: design proposal, 2026-10-21. The operator settled its five
decisions the same day (§9): four as recommended, and for the fifth chose a
Console API key over the recommended dedicated setup token, with the
recommended approval gate. Decision 3 was then amended after a measurement
(§7): the action is released on a slim orphan ref. Nothing is
implemented. It was written against `dev` at `fbd86aa73`, after Ukai Jail
0.1.0-rc.4
(`ukai-jail-v0.1.0-rc.4`, `eb9b67b18`). It follows the
[GitHub-hosted runner spike](../benchmarks/jail/github-runners-2026-10-21.md),
which is its evidence base, and the adoption ranking that put a CI receipt
after the one-word launch (J12), the end-of-run summary (J13) and
interactive sessions (J14). The milestone name J15 and the row numbers
K76–K86 are provisional and follow that sequence.

Each claim says where it comes from:

- **measured**: a run whose evidence is in this repository;
- **by reading**: GitHub, bubblewrap, AppArmor or vendor documentation or
  source, not run;
- **inferred**: argued from those, not observed.

Normative words follow jail-v2. **must** is a release gate. **initial** is a
tunable default that must be recorded. **candidate** is unproved until the
named measurement passes.

Teams run coding agents headless in CI, where a pull request or an issue is
the agent's input and the repository's secrets sit next to it. This
proposal puts the jail there: one step that runs the agent contained, keeps
its credential in the vault, and leaves the run's receipt on the job page
(illustrative, not a recorded run):

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@<sha>
    with:
      persist-credentials: false
  - uses: monocursive/ukai/action@ukai-jail-action-v0.1.0-rc.5
    with:
      launch: claude
      args: |
        -p
        The tests in test_slug.py fail. Fix the bug in slug.py and run them.
        --dangerously-skip-permissions
      credentials: claude-oauth=CLAUDE_CODE_OAUTH_TOKEN
    env:
      CLAUDE_CODE_OAUTH_TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}
```

```text
ukai-jail: settled · exited 0 · 41.2s exec→settled · survivors: none (verified)
ukai-jail: workspace: 3 paths opened for writing, 2 in renames
ukai-jail: network: allowed api.anthropic.com:443 (9)
ukai-jail: credential claude-oauth: vault, never staged · used on 9 proxy results · 0 credential refusals
ukai-jail: evidence: 6/6 classes active, no gaps · reads and file contents are not observed
host setup (this runner only): bubblewrap 0.11.1 built from its release tarball (sha256:c1b7455a…) at /usr/local/bin/bwrap · AppArmor profile ukai-jail-action-bwrap allows user namespaces for that binary only · kernel.apparmor_restrict_unprivileged_userns stays 1
```

## 1. Scope

In scope:

- A composite action whose source is `action/` on `dev` (`action/action.yml`,
  its scripts and `action/README.md`), released on the slim orphan branch
  `action` and referenced as `monocursive/ukai/action@ukai-jail-action-vX`
  (decision 3 as amended, §9).
- GitHub-hosted `ubuntu-24.04` and `ubuntu-24.04-arm` runners, and any later
  GitHub-hosted Ubuntu image the runner check (§3.2) accepts.
- Two modes: a launch profile with its arguments (`launch:` + `args:`), and
  a script under an execution profile (`profile:` + `run:`).
- Credentials from the workflow's environment into the vault.
- The report: the summary in the job summary, the receipt, policy and
  journal as an artifact, and an opt-in pull-request comment.

Out of scope, each its own later work:

- Self-hosted runners beyond refusing cleanly: the action makes no host
  change there, and runs only when `doctor` is already ready (§3.2).
- Other CI systems, Windows and macOS runners, `ubuntu-22.04` (glibc 2.35;
  the installer refuses, measured).
- A Marketplace listing (it needs `action.yml` at a repository's root).
- A prebuilt bubblewrap, caching the build, and the `pull_request_target`
  event (refused, §4.6).

## 2. Invariants kept

- **The jail binary configures no host.** jail-v1 §3 holds unchanged for
  `ukai-jail`. The action is a separate component that prepares a disposable
  GitHub-hosted runner it owns, with the two changes §3.3 names, and says so
  in its output. On a self-hosted runner it changes nothing.
- **No credential value enters the sandbox.** Values go from the workflow's
  environment into the vault with `credential set`, never into the child's
  environment, argv or files; the agent holds the attempt's placeholders
  (jail-v1 §12, J12 §3.5).
- **Nothing claims more than the receipt.** The job summary's jail lines are
  `tail --summary` verbatim (K52's equality holds there too); the action adds
  only its host-setup line and links.
- **Everything fetched is pinned.** `ukai-jail` through the hash-pinned
  installer at the action's own ref; bubblewrap by the SHA-256 of its release
  tarball; every third-party action the action uses by commit SHA.
- **No workflow input is interpreted by a shell.** The action's steps read
  inputs from environment variables, never from `${{ }}` text spliced into
  script source (§4.5).

## 3. The action

### 3.1 Inputs and outputs

| Input | Meaning | Default |
| --- | --- | --- |
| `launch` | A launch profile name, as `ukai-jail NAME` takes it. Exclusive with `profile`. | — |
| `args` | Launch mode: the program's arguments, one per line, passed as argv elements with no shell. | empty |
| `profile` | An execution profile: `tool`, `build` or `agent`. Exclusive with `launch`; `none` refuses. | — |
| `run` | Profile mode: a script, run inside the jail as one argv element of `/bin/bash -e -c`. | — |
| `allow-hosts` | Hosts to allow, one per line or space-separated (`--allow-host`). | none |
| `limits` | `KEY=VALUE` lines (`--limit`). | the profile's |
| `credentials` | `ID=ENVVAR` lines: store the value of `$ENVVAR` as credential `ID`. | none |
| `workspace` | The workspace. Must be a git work tree. | `$GITHUB_WORKSPACE` |
| `version` | The `ukai-jail` release to install; must be pinned in the installer at the action's ref. | the release that ref names |
| `fail-on` | Besides the command's own failure, what fails the step: `unsettled`, `survivors`, `gaps`. | `unsettled,survivors` |
| `pr-comment` | Post or update one comment with the summary on a same-repository pull request. | `false` |
| `artifact-name` | The artifact's name. | `ukai-jail-receipt` |

Outputs: `exit-code` (what `ukai-jail` exited with), `attempt-id`,
`settled` (`true`/`false`), `summary-json` (the path of `tail --summary
--json`'s output) and `receipt` (the path of the copied `jail.json`).

### 3.2 The runner check

Before any change and any credential, the action refuses (step failure, a
one-line reason, no host change) unless:

1. `RUNNER_OS` is `Linux` and `RUNNER_ARCH` is `X64` or `ARM64`;
2. the runner is not running the step as root (the jail refuses EUID 0);
3. `/etc/os-release` names Ubuntu 24.04 or later and `ldd --version` reports
   glibc 2.39 or later (the installer checks the second again);
4. the event is not `pull_request_target` (§4.6);
5. the workspace is a git work tree whose `git config --get-regexp
   '^http\..*\.extraheader$'` is empty (§4.2), unless
   `allow-checkout-token: true` is set, which the summary then names.

`RUNNER_ENVIRONMENT` decides what follows. `github-hosted`: §3.3's setup.
Anything else (self-hosted): no setup at all; `doctor` must already be
ready for the requested profile, and otherwise the step fails with doctor's
reasons and the guide's host notes.

### 3.3 Setup on a GitHub-hosted runner

1. **ukai-jail.** Run the installer from the action's own ref
   (`$GITHUB_ACTION_PATH/../install.sh`: the release commit on the `action`
   branch carries a byte-for-byte copy of the root installer of `ukai-jail-vX`)
   with `--version` and `--bin-dir $RUNNER_TEMP/ukai/bin`. Config and data
   go to `$RUNNER_TEMP/ukai/config` and `$RUNNER_TEMP/ukai/data`
   (`UKAI_CONFIG_DIR`, `UKAI_DATA_DIR`), mode 0700.
2. **bubblewrap 0.11.1.** When the first `bwrap` on `PATH` is older than
   0.10.0 or absent (stock 24.04 has none; apt's is 0.9.0, measured):
   install `meson ninja-build libcap-dev pkg-config gcc` from the image's
   apt sources, download `bubblewrap-0.11.1.tar.xz`, refuse unless its
   SHA-256 is `c1b7455a1283b1295879a46d5f001dfd088c0bb0f238abb5e128b3583a246f71`,
   build it with `-Dman=disabled -Dselinux=disabled -Dtests=false
   -Dbash_completion=disabled -Dzsh_completion=disabled`, and install it to
   `/usr/local/bin/bwrap` with `sudo` (GitHub-hosted runners grant
   passwordless sudo, by reading). The version, the tarball digest and the
   installed binary's SHA-256 go to the setup facts.
3. **AppArmor.** Only when
   `kernel.apparmor_restrict_unprivileged_userns` reads `1` (it does on both
   24.04 images, measured): load, with `sudo apparmor_parser -r`, exactly
   this profile from the action's tree:

   ```
   abi <abi/4.0>,
   include <tunables/global>
   profile ukai-jail-action-bwrap /usr/local/bin/bwrap flags=(unconfined) {
     userns,
   }
   ```

   It is the spike's variant 3 under its final name. The sysctl is never
   written, before or after; the restriction stays in force for every other
   program. When the sysctl reads `0` or AppArmor is absent, nothing is
   loaded and the setup facts say why.
4. **doctor.** `ukai-jail doctor --json` for the requested profile (`--profile
   P`, or `--launch NAME --from-path` from the workspace) must report
   `ready: true`, or the step fails with its unavailable capabilities. It is
   kept for the artifact.
5. **Credentials.** For each `ID=ENVVAR`, the value of `$ENVVAR` must be
   non-empty (an empty one fails the step and names the line, not the
   value); it is registered with `::add-mask::` when it did not come from a
   secret, then written to `ukai-jail credential set ID` on stdin.

Measured cost: the spike's whole job, including the apt build dependencies,
the bubblewrap build and four rounds of checks, took 22 to 31 seconds per
image.

### 3.4 The run

- Launch mode: `ukai-jail run --launch NAME --from-path --workspace W
  [--allow-host H]... [--limit K=V]... -- ARG...`, which is exactly what
  `ukai-jail NAME ARG...` runs (J12 §3.1) plus the requested options.
- Profile mode: `ukai-jail run --profile P --workspace W [--allow-host H]...
  [--limit K=V]... -- /bin/bash -e -c "$RUN"`, with `RUN` passed from the
  environment as one argv element.
- stdin is `/dev/null`, so terminal mode never attaches (J14 §3.2) and the
  `agent` wall is its detached 2 h unless `limits` say otherwise.
- The environment `ukai-jail` itself runs in is the step's minus every
  `ENVVAR` named in `credentials`, so no value reaches even the supervisor's
  environment after `credential set`. The child's environment is the jail's
  allowlist (jail-v1 §12, J14 §6.3: `PATH`, `LANG`, `TERM`, `TZ` and the
  profile's variables), so the runner's `GITHUB_*` and `ACTIONS_*` variables
  are not passed (by reading; K80 measures it).
- stdout and stderr stream to the job log as they come.
- A launch profile with `state = "persistent"` (the bundled `claude`) keeps
  its state in `$RUNNER_TEMP/ukai/data`, which ends with the job: every CI
  run is a first launch.

### 3.5 The report

Run with `if: always()` after the run step, in this order:

1. `ukai-jail tail --summary` and `--summary --json` for the attempt. The
   text goes into `$GITHUB_STEP_SUMMARY` as a code block, followed by the
   host-setup line (§3.3) and a link to the artifact; the JSON path becomes
   the `summary-json` output.
2. The artifact: the attempt's `jail.json`, `policy.json` and
   `trace.ndjson`, the summary JSON, the doctor JSON and `setup.txt` (the
   runner check, the bubblewrap facts, the AppArmor profile text and both
   sysctl readings). Nothing from the config directory.
3. **The exposure check (must).** Before upload, every artifact file is
   searched for each stored credential's value as a fixed string. A hit
   fails the step, uploads nothing, and names the file, never the value.
   This is the benchmarks' exposure check, applied to every run.
4. The artifact is uploaded with `actions/upload-artifact`, pinned by commit
   SHA.
5. With `pr-comment: true`, on a `pull_request` event whose head repository
   is the base repository: one comment, found by a hidden marker and updated
   in place, holding the summary lines and links to the run and the
   artifact, posted with the job's `GITHUB_TOKEN` through `gh api` (the
   workflow must grant `pull-requests: write`). On any other event it does
   nothing and says so.
6. The credential files under `$RUNNER_TEMP/ukai/config` are removed.

### 3.6 Exit status

The step's result is `ukai-jail`'s exit status: the command's own status, or
125 for a refusal before exec. The step also fails, whatever that status,
for each condition `fail-on` names: `unsettled` (the receipt's phase is not
`settled`), `survivors` (survivors not verified none), `gaps` (an evidence
class not active or with gaps). The report steps run either way.

## 4. Threats the action adds, and what it does about each

### 4.1 Hostile input steering the agent

A pull request's diff, an issue's text or a repository file can carry
instructions to the agent. The jail bounds what any instruction can do: the
workspace is the only writable tree, the network is the allowlist, and
credentials are placeholders (measured for Claude Code in the launch demo of
18 October). The action changes none of that. Later steps of the same job
see what the agent wrote to the workspace and must treat it as untrusted;
the README says so.

### 4.2 The checkout's token in the workspace

`actions/checkout` stores the job's `GITHUB_TOKEN` in the work tree's
`.git/config` as an `http.<url>.extraheader` unless `persist-credentials:
false` is set (by reading). The workspace is the agent's, so the agent could
read that token. The runner check (§3.2 item 5) refuses such a workspace
unless the operator opts in, and the summary then says the token was
readable inside.

### 4.3 What the runner exposes to a jailed process

- **Files.** `$RUNNER_TEMP`, the runner's file-command files
  (`$GITHUB_ENV`, `$GITHUB_OUTPUT`, `$GITHUB_PATH`, `$GITHUB_STEP_SUMMARY`)
  and the rest of `/home/runner` are not granted, so a jailed process can
  neither read them nor write the files that set later steps' environment
  and outputs (inferred from the contained profiles' grants; K80 measures
  it).
- **The Docker socket.** The runner account is in the `docker` group (by
  reading), and a connection to `/var/run/docker.sock` would be root on the
  runner. `/var/run` is a link to `/run`, and the host's `/run` is never
  granted to a contained run (jail-v1 §6.4 refuses it as a grant by its
  path), so the socket should not exist inside (inferred); K80 must show a
  connection attempt fail inside.
- **The network.** Only the allowlist, through the proxy; the runner's
  metadata endpoints are not reachable inside (inferred; K80 checks one).

### 4.4 The AppArmor profile

The profile lets any process on the runner create a user namespace through
`/usr/local/bin/bwrap`, the property Ubuntu's own `bwrap-userns-restrict`
grants `/usr/bin/bwrap` from 24.10 on (by reading the reference host's copy).
On a single-job disposable runner the only such processes are the job's own
(inferred). Inside the jail, `tool` and `build` refuse `unshare` and
namespace creation in their baselines; `agent` permits the nested setup an
inner sandbox needs, within the outer authority (jail-v1 §9.2). With the
profile loaded, `doctor` reported `nested_user_namespace` available on both
images (measured), unlike the reference host: an agent's own sandbox can
nest there, which K80 records rather than assumes away.

### 4.5 Workflow injection

Expression text such as `${{ github.event.issue.title }}` placed in a
workflow's `run:` is a known injection route (by reading GitHub's security
guidance). The action never splices an input into script source: each input
reaches its steps as an environment variable, `args` become argv elements,
and `run` becomes one argv element. K85 passes shell metacharacters through
every input.

### 4.6 Forks and `pull_request_target`

A `pull_request` from a fork gets no secrets (by reading): a `credentials`
line then names an empty variable and fails as §3.3 item 5 says, which the
README explains. `pull_request_target` runs with the base repository's
secrets on a workflow that often checks out the fork's code, the classic
way to hand an untrusted change both; the action refuses that event in this
version (§3.2 item 4).

### 4.7 Supply chain

The action's ref pins `ukai-jail` (the installer's SHA-256 pins), bubblewrap
(the tarball digest) and every action it uses (commit SHAs). The apt build
dependencies come from the image's signed Ubuntu archive. Users should
reference the action by commit SHA as well as by tag; the README shows
both.

## 5. Contract changes, row by row

| Where | Change | Kind |
| --- | --- | --- |
| `action/` on `dev` | New: `action.yml`, the setup, run and report scripts, the AppArmor profile file, `README.md`. Not a jail build input. Tested in place (`uses: ./action`). | New component |
| The orphan branch `action` | New: one commit per jail release holding only `action/` and the root `install.sh` of that release, tagged `ukai-jail-action-vX`. Never merged anywhere; nothing else lives there. | Release artifact |
| [jail-v1](jail-v1.md) §3, "no host configuration" | Clarified: holds for `ukai-jail`; the action is a separate component that, on a GitHub-hosted runner only, makes §3.3's two disclosed changes, and on any other host makes none. | Clarification |
| [operating.md](jail-v1/operating.md), [guide](../guide.md) | A "CI: GitHub Actions" section: the two modes, credentials, the checkout token, forks, what the summary's host-setup line means. | Guide |
| [agent-compatibility.md](jail-v1/agent-compatibility.md) | A GitHub-hosted runner row, after §6.2's record. | Support record |
| [RELEASING.md](../RELEASING.md) | After a jail release is published and the root installer rolled out: copy `action/` and that `install.sh` from the rollout commit to a new commit on the `action` branch, tag it `ukai-jail-action-vX` (annotated, naming the jail tag and the rollout commit), push both, and run the action self-test (K86) against that tag. | Procedure |
| `.github/workflows/` | An action self-test workflow on both 24.04 images, for changes to `action/` and the installer and at release tags. | CI |
| The receipt, summary and schemas | None. The action reads `tail --summary` and the receipt as they are. | None |

## 6. Tests and the record required before "supported"

### 6.1 Rows

| Row | Claim |
| --- | --- |
| K76 | Runner check: each refusal of §3.2 fires before any host change or credential (an `ubuntu-22.04` job, a root step, a `pull_request_target` event, a workspace with a checkout extraheader), and a self-hosted-shaped environment (`RUNNER_ENVIRONMENT` not `github-hosted`) makes no change and refuses unless `doctor` is ready. |
| K77 | Setup: a tarball whose digest differs refuses before building; the profile is loaded only when the sysctl reads `1`; the sysctl reads the same before and after the job; the host-setup line and `setup.txt` match what was done. |
| K78 | Credentials: the value appears in no artifact file (the exposure check, with a positive control) and in no job log line unmasked; the named variable is absent from `ukai-jail`'s own environment; an empty variable fails naming its line only. |
| K79 | Report: the job summary's jail lines equal `tail --summary`; the artifact holds the receipt, policy, journal, summary JSON, doctor JSON and `setup.txt`; `summary_check.py` recomputes the summary from the artifact alone. |
| K80 | Inside, measured on both images: the child's environment has no `GITHUB_*`, `ACTIONS_*` or credential variable; `$RUNNER_TEMP` and the file-command files are absent; a connection to `/var/run/docker.sock` fails; a request to a host off the allowlist (and to the runner's metadata address) is denied and journaled; under `agent`, whether a nested user namespace can be created is recorded. |
| K81 | Exit status: a failing command fails the step with its status; a refusal fails with 125 and its message; each `fail-on` condition fails the step; the report steps run in every case. |
| K82 | PR comment: posted once and updated in place on a same-repository pull request with `pr-comment: true`; nothing on a fork's pull request, on other events or without the flag. |
| K83 | Both modes: launch mode's argv equals `ukai-jail NAME ARG...`'s (identical policy and argv digests, K33's method); profile mode runs `run` under the named profile. |
| K84 | Both images: every row above passes on `ubuntu-24.04` and `ubuntu-24.04-arm`; the image versions are recorded; `ubuntu-latest`'s resolution at test time is recorded, not assumed. |
| K85 | Injection: inputs holding `$(…)`, backticks, quotes, `;`, newlines and `${{ }}` text reach the jailed program as literal argv or script text and are never evaluated by the action's own steps. |
| K86 | Self-test at a release tag: `uses: monocursive/ukai/action@ukai-jail-action-vX` installs exactly release X (version, revision and inputs match `ukai-jail-vX`'s `release.json`); the tagged commit holds only `action/` and `install.sh`, and its `install.sh` equals the root installer of X's rollout byte for byte; its "Set up job" fetch stays slim (recorded, as in §7). |

### 6.2 The compatibility record (A-row)

One real agent run on GitHub-hosted runners makes the action supported for
that combination: Claude Code from the native installer, `launch: claude`,
the A01 fixture task and one real small task, on both images, with the
bundled profile's `anthropic` credential (a Console API key, sent as
`x-api-key`) from the approval-gated environment secret of decision 5. It is
also the first recorded run of that credential path, which the 2026-10-17
headless row left unrun.
Pass conditions as for the 2026-10-17 headless row (settled, six classes
active, tree empty, one credential never staged), plus K78's exposure check
over the job logs as GitHub stores them and over the artifact, and the
summary posted to the job page.

## 7. Costs

- Setup: 22 to 31 seconds per job on the spike's images, including the
  bubblewrap build (measured).
- **The action's download (measured, a consequence of decision 3).** A job
  that uses `monocursive/ukai/action@<ref>` makes GitHub fetch the whole
  repository at that ref before any step runs. Run
  [39659918505](https://github.com/monocursive/ukai/actions/runs/39659918505)
  timed it, three jobs per image and ref
  ([timings](../benchmarks/jail/results/github-action-fetch-2026-10-21/timings.txt)):
  the same one-step action on a ref holding this repository's full tree
  (`dev` at `fbd86aa73` plus the action) put **1.9 GB** on each runner and
  its "Set up job" took **56 to 69 s**; on an orphan ref holding only
  `action/action.yml` it was **24 KB** and **0 to 1 s**, on both images. A
  `git archive` of the rc.4 tree is 253 MB compressed, mostly
  `docs/benchmarks`. Decision 3 was amended for it (§9): the action is
  released on a slim ref.
- The run itself costs what the jail costs on any host (K17's records); the
  runner's two or four CPUs are the only difference.

## 8. Open questions

1. *(Settled 2026-10-21: decision 3 amended, §9.)* A separate repository
   remains the route to a Marketplace listing, if one is wanted.
2. *(Settled 2026-10-21, decision 5.)*
3. **Caching the bubblewrap build** with `actions/cache`, keyed by the
   tarball digest and the image version.
4. **`ubuntu-latest` drift.** A later image with bubblewrap 0.10.0 or newer,
   or with Ubuntu's `bwrap-userns-restrict` profile, would need less setup;
   §3.3 already skips what is not needed, and K84 records what it found.

## 9. Decisions (settled 2026-10-21)

The operator settled all four as recommended:

1. **The runner change.** On a GitHub-hosted runner whose
   `kernel.apparmor_restrict_unprivileged_userns` is `1`, the action loads
   one AppArmor profile that allows user namespaces for its own
   `/usr/local/bin/bwrap` only, and discloses it in the job summary and the
   artifact. It never writes the sysctl. On any other runner it changes
   nothing.
2. **bubblewrap.** Built on every run from the pinned 0.11.1 release tarball,
   verified by SHA-256. No prebuilt bubblewrap is distributed.
3. **Where it lives** (amended the same day). In this repository and
   versioned with the jail, released on a slim ref: its source is `action/`
   on `dev`; each jail release `ukai-jail-vX` adds one commit holding only
   `action/` and that release's root installer to the orphan branch
   `action`, tagged `ukai-jail-action-vX`, so `uses:
   monocursive/ukai/action@ukai-jail-action-vX` installs release X. The
   tag name is its own because the jail tags name full-tree commits. As
   first decided, the action was referenced at the jail tag itself; the
   operator amended that after §7's measurement (about a minute and 1.9 GB
   of fetch per job from the full tree, under a second and 24 KB from a
   slim ref).
4. **Version 1's scope.** Launch profiles and profile-mode scripts, the job
   summary and the artifact; the pull-request comment is opt-in; forks get
   no secrets; `pull_request_target` is refused.
5. **The A-row's credential** (§6.2, settled the same day). An Anthropic
   Console API key, stored by the operator as the secret `ANTHROPIC_API_KEY`
   of a GitHub Environment `ukai-arow` in this repository, with the operator
   as required reviewer and deployments limited to `dev`: every job that
   reads it waits for the operator's approval. The A-row workflow is run by
   hand (`workflow_dispatch`) from `dev`.
