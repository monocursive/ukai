# Claude Code home-page demo — 19 October 2026

The home page at [ukai.sh](https://ukai.sh/) shows one `ukai-jail claude` run:
the command, Claude Code's answer and the jail's end-of-run summary. This
record holds that run's complete output, receipt, policy and journal, so
every line on the page can be checked against what the binaries produced.

It is one demonstration run of the combination the
[Claude Code compatibility record](claude-code-compatibility-2026-10-17.md)
marks supported (Claude Code 2.1.302 from the native installer, headless,
`--dangerously-skip-permissions`, a setup token through the vault, the bundled
`claude` profile, the reference host), this time with the public
`0.1.0-rc.3` release. It is not a benchmark, a repetition count or a
conformance claim.

The task is ordinary on purpose: a three-file repository with one failing
test, and the prompt `fix the failing test`. Nothing in the repository asks
for anything outside the boundary.

**Result:** Claude Code fixed the bug, the tests pass, and the jail settled
with every process verified gone, one host reached (`api.anthropic.com`), the
credential never staged, and all six evidence classes active without gaps.

## Where and what

From [host.txt](results/claude-code-demo-2026-10-19/host.txt) and
[install.txt](results/claude-code-demo-2026-10-19/install.txt):

| Fact | Value |
| --- | --- |
| Host | The reference host: Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic, x86_64 (KVM), account `ubuntu`, no sudo |
| Host settings | Stock: `kernel.apparmor_restrict_unprivileged_userns = 1` (`doctor`: `restriction_on`) |
| Backend | bubblewrap 0.11.1, ptrace observer |
| Installer | `https://ukai.sh/install.sh`, `sha256:0e1dd4fe…647bea`, byte-identical to this repository's `install.sh` (default `0.1.0-rc.3`), run with `--bin-dir` into a private scratch directory |
| Jail binary | `Installed release 0.1.0-rc.3`; `sha256:cbd87e7a2431676c639f4cfd36b3d1a0c1ec70cbb25b698b7956f6802246e953`, the published x86_64 binary ([release record](release-preview-2026-10-18.md#website-and-public-installation)); revision `f95f2d39…`, `dirty false`, inputs `sha256:32e294a3…` |
| State | `UKAI_CONFIG_DIR` and `UKAI_DATA_DIR` set, for every `ukai-jail` command after the install, to private (0700) directories created empty for this record |
| Credential | The host's `claude setup-token` value, stored in the private config directory with `ukai-jail credential set claude-oauth < <source file>` ([output](results/claude-code-demo-2026-10-19/credential-set.out)): mode 0600, 108 bytes, byte-identical to the source by `cmp`. Its value was never printed |
| Claude Code | 2.1.302, native installer: `~/.local/bin/claude` links to `~/.local/share/claude/versions/2.1.302`, `sha256:60d7eb7f…e29a5`, the A-row's executable |
| `PATH` | The private `bin` directory, then `~/.local/bin`, so the command was literally `ukai-jail claude …` and `claude` resolved to the native install |
| Profile | The bundled `claude` profile; no operator file |

`ukai-jail explain --launch claude --from-path` and `doctor`, run in the
repository just before
([explain](results/claude-code-demo-2026-10-19/explain.txt),
[doctor](results/claude-code-demo-2026-10-19/doctor.txt)), resolved `claude`
to the native executable (`format=elf`), derived one read-only grant,
`~/.local/share/claude/versions` (`by=program_resolution`), and reported
`ready true` with `claude-oauth` available and `anthropic` `source_missing`.
`doctor` still says `launch claude experimental reason=no_recorded_run`: the
binary never claims support, as in the A-row.

## The repository

[fixture/](results/claude-code-demo-2026-10-19/fixture/) holds the three
files exactly as committed
([SHA-256](results/claude-code-demo-2026-10-19/fixture.sha256)): a README,
`slug.py` and `test_slug.py`. `slugify` keeps only the letters of each word
(`[a-z]+`), so `test_numbers` expects `top-10-tips` and gets `top-tips`.
Before the run, outside the jail, `python3 -m unittest` ran 3 tests with 1
failure, exit 1
([unittest-before.txt](results/claude-code-demo-2026-10-19/unittest-before.txt)).
The files were copied into a new directory and committed as one commit; the
jail's workspace is that git repository.

## What ran

[runs.sh](results/claude-code-demo-2026-10-19/runs.sh) lists every command in
order, and [SHA256SUMS](results/claude-code-demo-2026-10-19/SHA256SUMS) every
file of the results directory. The run used the A-row's harness unchanged (`arow_run.py`
`sha256:4de7294f…`, `arow_check.py` `sha256:e8980a9e…`, and the repository's
[summary_check.py](../../specs/jail-v1/summary_check.py) `sha256:14339b41…`,
each byte-identical to the committed file): stdout went to a file, stderr to
a pseudo-terminal so the jail printed its terminal lines, and an exposure
sampler searched every 100 ms for the token (see [Exposure](#exposure)).

```sh
cd slug
ukai-jail claude -p "fix the failing test" --dangerously-skip-permissions
```

The run started at 07:12:53 UTC and took 18.9 s around `ukai-jail`
([exit.json](results/claude-code-demo-2026-10-19/runs/r1/exit.json)); exit 0.

## The output

Claude Code's answer, its whole stdout
([stdout](results/claude-code-demo-2026-10-19/runs/r1/stdout)):

```text
I fixed the failing test, `test_numbers`. `slugify` in `slug.py` used the regex `[a-z]+`, which dropped digits, so "Top 10 Tips" came out as `top-tips`. I changed it to `[a-z0-9]+`. I didn't run the suite before the change, so I didn't see the original failure. I spotted the cause from the code and the test. All 3 tests pass now under `python3 -m unittest`.
```

The jail's stderr on the terminal
([terminal.txt](results/claude-code-demo-2026-10-19/runs/r1/terminal.txt),
raw bytes): the pre-exec line, then the summary and the receipt line.

```text
ukai-jail: claude = /home/ubuntu/.local/share/claude/versions/2.1.302 (read-only: /home/ubuntu/.local/share/claude/versions)
```

`ukai-jail tail --summary --attempt att_01e92cd2-e93f-4048-873f-89524fb5fb10`,
run afterwards
([tail-summary.txt](results/claude-code-demo-2026-10-19/runs/r1/tail-summary.txt)),
printed:

```text
ukai-jail: settled · exited 0 · 18.7s exec→settled · survivors: none (verified)
ukai-jail: workspace: 4 paths opened for writing, 6 in renames · 1 refused write
ukai-jail: network: allowed api.anthropic.com:443 (7)
ukai-jail: credential claude-oauth: vault, never staged · used on 7 proxy results · 0 credential refusals
ukai-jail: evidence: 6/6 classes active, no gaps · reads and file contents are not observed
ukai-jail: receipt /home/ubuntu/cc-plain-demo-20261019/data/attempts/att_01e92cd2-e93f-4048-873f-89524fb5fb10/jail.json
```

These six lines are the ones the terminal showed at the end of the run, byte
for byte, apart from the terminal's carriage returns and one escape sequence:
Claude Code wrote `ESC [ ? 2 5 h` (show the cursor) to stderr as it exited,
so it sits at the start of the first summary line in `terminal.txt`.
The `text` fields of `--json` equal the first five
([tail-summary.json](results/claude-code-demo-2026-10-19/runs/r1/tail-summary.json),
which carries the receipt as `receipt_digest`),
and the repository's independent recomputation rebuilt every line, fact and
number from the archived receipt and journal, on the reference host and again
from this directory: `every line, fact and number recomputed (complete
journal, 337 frames)`
([summary-check.txt](results/claude-code-demo-2026-10-19/runs/r1/summary-check.txt)).
Every condition [arow_check.py](results/claude-code-compatibility-2026-10-17/harness/arow_check.py)
evaluates held ([check.json](results/claude-code-demo-2026-10-19/runs/r1/check.json)).

## Results

### The task

Done. `git diff` after the run
([git-after.txt](results/claude-code-demo-2026-10-19/runs/r1/git-after.txt))
is one changed line in `slug.py`, `[a-z]+` → `[a-z0-9]+`, plus an untracked
`__pycache__/` from the tests Claude Code ran. `test_slug.py` and the README
kept their SHA-256
([sha256-after.txt](results/claude-code-demo-2026-10-19/runs/r1/sha256-after.txt)).
Run again by the operator outside the jail, `python3 -m unittest` passed all 3
tests, exit 0
([unittest-after.txt](results/claude-code-demo-2026-10-19/runs/r1/unittest-after.txt)).
The journal records two `python3` executions inside the run. As its answer
says, Claude Code did not run the tests before its change.

### No process survived

The receipt ([jail.json](results/claude-code-demo-2026-10-19/runs/r1/attempt/jail.json))
is `phase: settled`, `outcome` `exited` 0, `errors: []`, `lifetime.tree_empty:
true` with `integrity: verified` (scope `attempt_tree`, at 07:13:12 UTC), and
`state_cleanup: complete`. The summary's `survivors: none (verified)` is that
field. Right after the run, a process listing of the host had no process whose
command line contained `2.1.302` or the scratch directory's name
([process-survey.txt](results/claude-code-demo-2026-10-19/runs/r1/process-survey.txt)
is empty).

### One host, through the proxy

`applied.network` is `mode: proxy` with one allowed host, `api.anthropic.com:443`,
TLS only; the policy has exactly two grants, that host (the profile's) and the
derived read-only install root. The journal has 7 proxy results, all to
`api.anthropic.com:443`, allowed and relayed. Nothing was denied: the summary
prints no `denied` part. The `net` class's 29 events are the 7 connections to
the proxy's in-jail listener, `127.0.0.1:3128`, and 22 Unix-socket `connect`s
that returned `ENOENT` (`mediator_reason: path_absent`) to a path outside the
known roots, kept as the digest `sha256:5779d679…`, which is the SHA-256 of
`/var/run/nscd/socket`, glibc's name-service cache socket. No other
destination appears in the journal.

### The credential was never staged

The receipt lists one credential, `claude-oauth`, `mode: vault`,
`never_staged: true`, with no digest (`digest_unavailable_reason:
never_staged`). The journal's only credential note is `loaded`. Each of the 7
proxy results carries the credential's id (the summary's `used on 7 proxy
results`), and none was refused. The child's copy is the vault's placeholder
under `CLAUDE_CODE_OAUTH_TOKEN` (`explain`: `launch credential claude-oauth
mode=vault dest=.vault-claude-oauth source=omitted`); this run did not record
the placeholder's value, which the A-row's
[r08](results/claude-code-compatibility-2026-10-17/runs/r08-env-probe/agent-environment.json)
did for the same build of Claude Code. The token itself is in no recorded file
and in no sampled process environment (next section).

### The workspace line

`tail-summary.json` names the seven workspace paths behind `4 paths opened
for writing, 6 in renames`: `slug.py` and the temporary file Claude Code
wrote it through (`slug.py.tmp.2.16c482771fd6`), and `python3`'s
`__pycache__` directory with its two `.pyc` files and their temporaries. No
path was left unnamed (`unnamed: 0`), and no observer gap was recorded
(`path_claims_unverified: 0`): with this release, the summary names Claude
Code's own write, which the A-row's earlier build could not
([workspace-line record](claude-code-workspace-line-2026-10-17.md)).

The one refused write is the `mkdir` Claude Code makes at start-up, as in
every A-row run: the journal records an `fs.deny` of `mkdir` on a path outside
the known roots, kept as the digest `sha256:4251803132e6…`, which is the
SHA-256 of `/home/ubuntu/.local/state` (`printf %s /home/ubuntu/.local/state |
sha256sum`). The home directory is not mounted; Claude Code carried on
without it.

### Evidence

All six classes `active` with no gaps: `exec` 71, `fs.write` 222, `fs.deny` 1,
`net` 29, `limits` 0, `proxy.net` 7 observed. The `wall` (7,200 s) and
`pids` (512) limits were applied and not hit. The journal's 38 `proc.exec`
results ([tail.txt](results/claude-code-demo-2026-10-19/runs/r1/tail.txt))
are the launcher's start of the pinned executable, Claude Code re-executing
itself (3), `bash` (6), `git` (10), `python3` (2) and core utilities
(`cat`, `tail`, `head`, `ls`, `env`), all successful, and four that returned
`ENOENT`, each an attempt to execute `zsh` (which the host does not have)
from a new process, before the first `bash` started. Three
are named relative to the system roots (`bin/zsh`, `local/bin/zsh` and
`zsh`, as the journal writes them); the fourth is outside the known roots,
kept as the digest `sha256:4e61fcfb…`, which is the SHA-256 of
`/opt/homebrew/bin/zsh`.

### Exposure

The token's value was searched for as a fixed string with `grep -rlF -f` on
its source file, which prints file names only
([token-exposure-check.txt](results/claude-code-demo-2026-10-19/token-exposure-check.txt)).
It is in no file of the run directory, the workspace (including `.git`), the
fixture, the private data directory (the attempt's receipt, policy, journal,
jail state and CA) or the install directory. The same search over the private
config directory found the stored copy, `credentials/claude-oauth`, and
nothing else, which shows the search matches. Every file of the commit that
adds this record (the results directory, this document, the benchmarks README
and the home page source) was searched the same way on the reference host
before the commit, with no match
([token-exposure-committed.txt](results/claude-code-demo-2026-10-19/token-exposure-committed.txt)).

The harness's sampler took 168 snapshots during the run: 669 readable process
environments and argv, 334 unreadable ones, and 8,127 file checks, with 0
hits ([exposure.json](results/claude-code-demo-2026-10-19/runs/r1/exposure.json)).
Claude Code's process (`comm` `2.1.302`) had a readable environment in all 167
snapshots it appeared in; the unreadable ones were the jail's own processes.
As in the A-row, this is bounded sampling, not proof of absence from
arbitrary memory.

## What the page shows

The home page's terminal is, in this order: the command as typed, the
pre-exec line from `terminal.txt`, Claude Code's answer from `stdout`, and the
six lines of `tail-summary.txt`. Each is verbatim; nothing is trimmed. stdout
and stderr were captured separately, so the page interleaves them in the
order they were produced: the pre-exec line is printed before Claude Code
starts, its answer before it exits, and the summary after the jail settles.
The side notes restate the evidence above: the workspace paths, the one host,
the credential fields and the verified process tree.

## Not established

Anything beyond this one run: no repetition, no other task, repository,
Claude Code version, host or permission mode (the A-row covers ten
repetitions and its other cases). No refusal was exercised: the run asked for
nothing outside the boundary except the start-up `mkdir`. The 18.7 s is one
wall time with no baseline, not a performance figure. Reads and file contents
are not observed, so the summary does not show what Claude Code read.

## Reproduce

On a Linux host where `ukai-jail doctor --launch claude --from-path` reports
ready, with a setup token stored (`ukai-jail credential set claude-oauth`),
copy [fixture/](results/claude-code-demo-2026-10-19/fixture/) into a new
directory, commit it, then:

```sh
ukai-jail claude -p "fix the failing test" --dangerously-skip-permissions
ukai-jail tail --summary
```

Claude Code's answer, attempt ids, times and counts differ on every run.
