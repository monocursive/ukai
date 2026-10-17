# Claude Code compatibility record — 17 October 2026

This is the record that
[jail-launch-and-summary.md §6.3](../../specs/jail-launch-and-summary.md#63-the-claude-code-compatibility-record-a-row)
requires before `ukai-jail claude` can be called supported, and the OpenCode
A01 rerun under the alias that §6.3's last paragraph requires. It marks one
combination supported: Claude Code 2.1.302 from the native installer, run
headless as `ukai-jail claude -p "…" --dangerously-skip-permissions`, with the
bundled `claude` profile unchanged and a `claude setup-token` value through the
vault, under `agent` on the reference host, at `ukai-jail` revision `56f9fb15`.
Nothing else is claimed: not the API-key fallback (not run), not Claude Code's
default permission mode (its own write was refused), not interactive sessions,
npm installs, other versions or hosts.

The OpenCode rerun did not pass. The jail settled cleanly, but OpenCode Zen's
free tier refused the request, and the same command without the jail is
refused identically. OpenCode's rows are not extended to the alias.

## Where and what

From [host.txt](results/claude-code-compatibility-2026-10-17/host.txt):

| Fact | Value |
| --- | --- |
| Host | The reference host: Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic, x86_64 (KVM), account `ubuntu`, lingering on |
| Host settings | Stock: `kernel.apparmor_restrict_unprivileged_userns = 1` (`doctor`: `restriction_on`). The setup-token spike ran with it at 0 ([correction](../README.md#corrections)) |
| Backend | bubblewrap 0.11.1, ptrace observer |
| Source | `git clone --depth 1 --branch dev` of the public repository, `HEAD` `56f9fb15197ffadf401b8f2bb70162adb938b88b` ("the vault reads the exec-time environment of a connection's process (review F8)"). A sparse checkout left out `docs/benchmarks/` (not a build input) to save disk; `git status` was clean |
| Build | `UKAI_BUILD_REVISION=$(git rev-parse HEAD) UKAI_BUILD_DIRTY=false cargo +1.98.1 build --locked --release -p ukai-jail`, 0 warnings. `version --json`: revision `56f9fb15…`, `dirty: false`, opt-level 3, inputs `sha256:7b1a95a9b6a2acb7e81ddcdec49ef784220902f4c8392d3879aab2d5c6eadfe1` |
| Jail binary | `sha256:5115e497d92b3b8c55a00f4a46bc4b20627dd5cdf0e1b4552adfeb966bf54b09` |
| Claude Code | 2.1.302, installed by the native installer (`install.sh` `sha256:3a68d340…`, default target, which installed `latest`) as `ubuntu`; `~/.local/bin/claude` links to `~/.local/share/claude/versions/2.1.302`, an x86_64 ELF, `sha256:60d7eb7f12fbb28a52533fe8be5884097403562aa02dc73991a021c7067e29a5`, unchanged at the end of the record. Loader `/lib64/ld-linux-x86-64.so.2`, system libraries only, no `DT_RPATH` or `DT_RUNPATH` |
| `PATH` | `~/.local/bin` first, so `command -v claude` resolved the native install. The npm install at `/usr/bin/claude` (2.1.295, the spike's) is second on `PATH` and was not used |
| Profile | The bundled `claude` profile; no operator file in `~/.config/ukai/launch/` |
| Credential | `~/.config/ukai/credentials/claude-oauth`, mode 0600, 108 bytes, one link, written 2026-10-16 and unchanged; its value was never printed. No `anthropic` source exists |
| State | Default config and data directories, except runs (4) and (5), which used private `UKAI_CONFIG_DIR`s |

`explain --launch claude --from-path` and `doctor`
([explain](results/claude-code-compatibility-2026-10-17/claude/explain.txt),
[doctor](results/claude-code-compatibility-2026-10-17/claude/doctor.txt))
resolved `claude` to the native executable (`format=elf`) and derived one
read-only root, `~/.local/share/claude/versions` (`by=program_resolution`).
`doctor` reported `ready true`, `claude-oauth` available, `anthropic`
`source_missing`, and the launch `experimental` (`no_recorded_run`): the binary
never claims support; this record does.

## What ran

Each run started in a git repository from the operator's shell.
[arow_run.py](results/claude-code-compatibility-2026-10-17/harness/arow_run.py)
gave the jail's stderr a pseudo-terminal, so the pre-exec line, the summary
and the receipt line printed as they do for a person, and sampled for the
token while the run lasted, as the credential benchmarks' exposure sampler
does: every 100 ms, the environment and argv of every descendant process, and
every file of at most 1 MiB in the workspace and the attempt directory.
[arow_check.py](results/claude-code-compatibility-2026-10-17/harness/arow_check.py)
then archived the receipt, policy and journal, printed
`ukai-jail tail --summary` and `--json`, compared them with the terminal, ran
the repository's independent recomputation
([summary_check.py](../../specs/jail-v1/summary_check.py)) on the archived
copy, and evaluated the receipt. [runs.sh](results/claude-code-compatibility-2026-10-17/runs.sh)
lists every command in order.

| Run | §6.3 | Command (in the workspace) | Result |
| --- | --- | --- | --- |
| [r01](results/claude-code-compatibility-2026-10-17/runs/r01-a01/) | (1) as written | `ukai-jail claude -p "Create a file named greeting.txt containing the single word hello."` | **Failed (by the agent):** the jail met every condition, but Claude Code refused its own write: "The write … was blocked because permission wasn't granted" |
| [r02](results/claude-code-compatibility-2026-10-17/runs/r02-a01/) | (1) | the same `-p` plus `--dangerously-skip-permissions --output-format json` | **Passed** |
| [r03](results/claude-code-compatibility-2026-10-17/runs/r03-task/) | (2) | in the same repository: `-p "The tests in test_slug.py fail. Fix the bug in slug.py so that python3 -m unittest passes, without changing test_slug.py, and run the tests to confirm."`, same flags | **Passed** |
| — | (3) | the API-key variant | **Not run:** no Console key at `<config-dir>/credentials/anthropic` ([note](results/claude-code-compatibility-2026-10-17/runs/api-key-not-run.txt)) |
| [r04](results/claude-code-compatibility-2026-10-17/runs/r04-no-source/) | (4) | the fixture with `UKAI_CONFIG_DIR` an empty private directory | **Passed** |
| [r05](results/claude-code-compatibility-2026-10-17/runs/r05-revoke/) | (5) | a long streamed answer, with a copy of the token in a private config directory deleted mid-run | **Passed** |
| [r06-rep01 … rep10](results/claude-code-compatibility-2026-10-17/runs/) | (6) | r02's command, each in a fresh repository | **10/10 passed** |
| [r07](results/claude-code-compatibility-2026-10-17/runs/r07-sampler-probe/), [r08](results/claude-code-compatibility-2026-10-17/runs/r08-env-probe/) | extra | r02's command, to tally the sampled processes (r07) and record the agent's environment names (r08) | Passed |

The flags after the fixture are Claude Code's, not the jail's: they change
neither the policy nor its digest, only the argv. They match the
[setup-token spike](claude-setup-token-spike-2026-10-16.md) and the
[credential benchmark](../credentials/2026-10-12/README.md), minus `--model`
and `--max-turns`; the subscription's default model was `claude-sonnet-5-5` in
every run that printed JSON.

## Results

### (1), (2) and the repetitions: the pass conditions

Every condition below held in r02, r03, the ten repetitions, r07 and r08 (from
each run's `check.json`):

| §6.3 pass condition | Evidence |
| --- | --- |
| The file contains `hello` | `greeting.txt` is `hello\n` in r02, every repetition, r07 and r08. In r03, `slug.py` gained `.lower()`, `python3 -m unittest` passed 3 tests, `test_slug.py` kept its SHA-256 ([outcome](results/claude-code-compatibility-2026-10-17/runs/r03-task/outcome.txt)); Claude Code took 5 turns |
| Settled, exit 0, no error | `phase: settled`, `outcome` `exited` 0, `errors: []`; Claude Code `is_error: false` |
| Six classes active without gaps | All six `active`, no class gaps. r02: `exec` 22, `fs.write` 126, `fs.deny` 1, `net` 8, `limits` 0, `proxy.net` 4; r03: 49, 178, 1, 19, 0, 5 |
| `tree_empty` true, `state_cleanup` complete | Every run |
| Exactly one credential, never staged | `credentials` lists only `claude-oauth`, `mode: vault`, `never_staged: true`, no digest; the journal's credential note is `loaded` |
| The summary shows the use count | `credential claude-oauth: vault, never staged · used on 4 proxy results · 0 credential refusals` (5 in r03), equal to the number of proxy results whose `fields.credentials` carries the id |
| `policy.grants` lists the derived root and nothing unexpected | Exactly two grants: `read_only` `~/.local/share/claude/versions` `by: program_resolution`, and the profile's `allow_host` `api.anthropic.com:443` |
| The summary reproduces from the archived receipt and journal (K52) | In every run, `tail --summary` printed the terminal's lines byte for byte, `--json`'s `text` fields equal them, and `summary_check.py` recomputed every line, fact and number from the archived copies (on the reference host and again from this directory) |
| The token is absent | See [Exposure](#exposure) |

Wall times, measured around `ukai-jail`: r02 3.73 s, r03 6.94 s; the ten
repetitions median 3.79 s, range 3.48–49.30 s. Repetition 10's last request
spent 46.7 s in the proxy, and Claude Code's own API time for the run was
48.4 s, so the time was upstream, not the jail's. As in the spike, there is no
direct baseline for these runs, so they support no overhead figure. Every run
used 4 proxy results (5 in r03), all to `api.anthropic.com:443`, allowed and
relayed, none denied.

The summary's evidence line reads `6/6 classes active` without `no gaps`
whenever Claude Code wrote a file: the receipt then carries one observer gap
per write, `path_claim_unverified` with no classes. The code documents it as
bookkeeping: the tracer could not corroborate an `openat` path against the
returned descriptor, so it kept the event and marked its path incomplete. It
counts no loss and degrades no class. r01 and r05, which wrote nothing, print
`no gaps`.

### (1) as written: Claude Code refuses its own write

With `-p` alone, Claude Code ran in its default permission mode, which
refuses a file write it cannot prompt for. It printed the refusal and exited
0, and the jail's receipt is as clean as r02's (settled, six classes active,
4 proxy results, one credential used on all 4). The A01 condition "the file
contains `hello`" failed for a vendor reason; r01's
[outcome note](results/claude-code-compatibility-2026-10-17/runs/r01-a01/outcome.txt)
explains why its `check.json` carries no file check. A headless
`ukai-jail claude` user needs Claude Code's own permission flags. This record
covers `--dangerously-skip-permissions`, under which the jail is the only
boundary; `--permission-mode acceptEdits` and allow-lists were not run.

### (4) No source

`ukai-jail claude` with an empty private `UKAI_CONFIG_DIR` exited 125 after
35 ms, before anything was prepared (no attempt directory), with one line,
the same on a terminal and on a pipe
([terminal](results/claude-code-compatibility-2026-10-17/runs/r04-no-source/terminal.txt),
[pipe](results/claude-code-compatibility-2026-10-17/runs/r04-no-source/pipe.stderr)):

```text
ukai-jail: error credential_unavailable at resolving [configuration]: launch profile `claude` needs one of its credentials, and none is present: `claude-oauth` (run `claude setup-token` on this host, then `ukai-jail credential set claude-oauth`); `anthropic` (put a Claude Console API key in it: `ukai-jail credential set anthropic`) (key: launch.credentials_one_of)
```

### (5) The source deleted mid-run

A copy of the token in a private config directory (0700, the file 0600, one
link, byte-identical by `cmp`) was the source. The harness deleted it 15.04 s
after it saw the attempt's `exec_confirmed` note, while Claude Code was
streaming an essay
([exit.json](results/claude-code-compatibility-2026-10-17/runs/r05-revoke/exit.json),
[journal](results/claude-code-compatibility-2026-10-17/runs/r05-revoke/attempt/trace.ndjson)):

- **Revocation recorded.** The journal's credential note `revoked`
  (generation 3) is at 15.208 s on the attempt's clock. The deletion fell
  between 15.130 s and 15.174 s on that clock, so the vault revoked within
  34–78 ms, inside its documented 100 ms poll.
- **The stream interrupted.** The streaming request's proxy result ended
  0.2 ms after the note, after 14.46 s with 12,900 bytes of the response
  relayed, with `end: credential_revoked`. Claude Code reported
  `API Error: Connection dropped (ECONNRESET)` (`is_error: true`).
- **Nothing after it was substituted.** Claude Code retried ten times over
  the next 142 s. Each was refused `credential_revoked`, carried no
  credential, and sent nothing upstream (0 bytes).
- **The attempt settled.** Exit 1 (Claude Code's), six classes active with no
  gaps, `tree_empty`, cleanup complete. The summary reads
  `allowed api.anthropic.com:443 (3) · denied api.anthropic.com:443 (10)` and
  `used on 3 proxy results · revoked · 10 credential refusals`, and it
  reproduces from the archive like the others.

### (6) Ten repetitions

All ten passed every condition (table above;
[console log](results/claude-code-compatibility-2026-10-17/runs/r06-reps-check.log)).
None stalled. Repetition 10 was slow upstream, as described above.

### Exposure

The token's value was searched for as a fixed string (`grep -rlF -f` on its
source file, printing file names only). It is in none of the 19 run
directories, which hold the receipts, policies, journals, summaries, Claude
Code's stdout and the terminal bytes. It is in none of the workspaces, none of
the 18 attempt directories (receipt, policy, journal, jail state, CA), the
direct controls, or the 220 committed files of the results directory and the
four documents this record changes. The
harness's sampler, across its 18 runs (every run but r08), took 2,374 snapshots: 9,403 readable
process environments and argv, 4,702 unreadable ones, and 83,085 file checks.
It found 0 hits. r07's per-process tally shows what that covers: Claude Code's
process (`comm` `2.1.302`) had a readable environment in all 31 of its
snapshots, as did `bwrap`. The unreadable ones were jail-side processes
(`ukai-jail`, `jail`). r08 recorded the agent's environment
([agent-environment.json](results/claude-code-compatibility-2026-10-17/runs/r08-env-probe/agent-environment.json)):
19 variable names, no `HOME`, no `ANTHROPIC_API_KEY`, and
`CLAUDE_CODE_OAUTH_TOKEN=vault:att_cf174e17-…:claude-oauth`. As in the
benchmarks, this is bounded sampling, not proof of absence from arbitrary
memory.

## The vendor facts (§6.3)

| §6.3 question | Answer for Claude Code 2.1.302, native | Evidence |
| --- | --- | --- |
| Which header carries `CLAUDE_CODE_OAUTH_TOKEN`? | `Authorization: Bearer <token>`, as the spike measured for 2.1.295 | The bundled profile declares only that header; the vault refuses a placeholder anywhere else (`CredentialPlacementDenied`), and every request was substituted and answered |
| Does the client check the token's shape? | No | The agent held `vault:att_…:claude-oauth` (r08) and sent its requests |
| Which hosts does a first run contact? | Only `api.anthropic.com:443` (with the profile's `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`) | No proxy denial in any run but r05's revoked retries; `platform.claude.com` was never asked for |
| Is `home_is_state` needed? | No, for `-p` | `HOME` is unset in the child (r08). Every run recorded exactly one `fs.deny`: a `mkdir` of `/home/ubuntu/.local/state` (the home from `/etc/passwd`), a path digest outside the known roots that matches that path's SHA-256. Claude Code carried on without it |
| Does a request come from another executable? | No | No `credential_process_denied` in any run. Claude Code ran `git` (and in r03 a shell, `env`, `python3`, `cat` and `tail`) and re-executed itself (`2.1.302`, 3 times per run, the pinned file in the install root); every substituted request came from the pinned executable |
| Which §3.3 interpreter case applied? | ELF, no expansion | `explain`: `format=elf`; the receipt's first `proc.exec` is the launcher's `execveat` of the pinned descriptor (`empty_path`) |

Also measured: the native install root, `~/.local/share/claude/versions`, is
outside the runtime roots, so `--from-path` adds a real read-only grant here.
On the spike's npm layout the grant duplicated `/usr`.

## OpenCode under the alias

OpenCode 1.19.0, already installed at `~/.opencode/bin` (not 1.18.32, the
version of the existing rows), ran as
`ukai-jail opencode run "Create a file named greeting.txt containing the single word hello."`
in a fresh git repository, twice (o01, o02), with the bundled `opencode`
profile and no credential (OpenCode Zen's free model `big-pickle`).

- **The jail:** settled, six classes active without gaps, `tree_empty`,
  cleanup complete, no credential. The derived grant is `~/.opencode/bin`
  `by: program_resolution`, replacing the old rows' `--ro ~/.opencode/bin`.
  There was one proxy result each to `opencode.ai`, `models.opencode.ai` and
  `registry.npmjs.org`, nothing denied, and the summaries reproduce from the
  archive.
- **The agent:** OpenCode printed
  `Error: OpenCode's free tier can only be used from within OpenCode. Download it at https://opencode.ai and keep building.`
  and exited 1; no `greeting.txt`.
- **The cause is the vendor's, not the jail's.** The same command without the
  jail ([controls](results/claude-code-compatibility-2026-10-17/controls/)),
  with throwaway XDG directories, printed the same refusal for 1.19.0 and for
  1.19.3, the latest release (the npm package `opencode-linux-x64`, its
  `dist.integrity` checked, run from a private directory and deleted after).
  Whether the free tier now refuses this client, this host or its address is
  not established.

So the A01 pass condition failed, and the OpenCode 1.18.32 rows are not
extended to the alias. A rerun needs a working free model or a credential
through the profile.

## What this record found

- **`-p` alone does not complete a write task**: Claude Code's default
  permission mode refuses the write (r01). The bundled profile's comment,
  the guide's example and operating.md describe `ukai-jail claude -p "…"`
  without the flag that made every passing run work.
- **The workspace line does not name Claude Code's own writes.** Each file
  Claude Code created or edited is an `fs.create` with path
  `unavailable`/`path_truncated` (the downgraded claim above), so r02 prints
  `workspace: 0 paths opened for writing · 85 results with unnamed paths`
  although it wrote `greeting.txt`. Most of the unnamed results are Claude
  Code's writes to its vendor state (`/run/ukai/state`, `.claude.json` and its
  lock), which the audit records as digests outside the known roots. The
  summary is right by its rules and never overclaims. For this agent, though,
  it cannot show which workspace files changed: only `python3`'s
  `__pycache__` writes in r03 were named.
- **The refused `mkdir ~/.local/state`** is harmless here but appears as
  `1 refused write` in every summary.
- **The bundled profile's header comment** still says no Claude Code build
  has a recorded run. The profile is a build input, so this record leaves it
  as is.

## Not established

The API-key fallback (`anthropic`, run (3)) and `credentials_one_of`
choosing between two present sources. Claude Code's default and `acceptEdits`
permission modes as a passing combination. Interactive sessions (J14). The npm
install and every other Claude Code version. Hosts other than the reference
host, including the Raspberry Pi. Token expiry. Runs without
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`. Larger tasks than (2). Reliability
beyond twelve passing fixture runs and one task.
