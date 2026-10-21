# Interactive Claude Code compatibility record — 21 October 2026

This is the record that
[jail-interactive-sessions.md §6.3](../../specs/jail-interactive-sessions.md#63-the-interactive-claude-code-compatibility-record-a-row)
requires before interactive `ukai-jail claude` can be called supported.

It marks one combination supported:

- Claude Code 2.1.302 from the native installer.
- Run as interactive `ukai-jail claude`, and as `-p` from an interactive shell (attached, or with stdin a pipe).
- The bundled `claude` profile, unchanged and persistent (it allows `platform.claude.com` since §8 item 30).
- A `claude setup-token` value through the vault.
- `agent` on the reference host, at `ukai-jail` revision `79200cfda`.
- A pseudo-terminal reached over SSH and driven by this record's harness, which emulates an xterm-like terminal.

Nothing else is claimed: no other terminal emulator, no other version, no npm install, no other host, no API key, no real `/login`.

All 31 attempts passed every pass condition of §6.3. The hangup of run (4) is an exception: a hung-up terminal cannot be restored. Its receipt says so (`restored` false for the four restore steps, `after_tree_death` true), and §6.3's condition was amended the same day to expect it.

The same day, the whole driver ran again on the release build, `cccf5db30`, and passed identically (see [Confirmation on the release build](#confirmation-on-the-release-build)). This record is the full evidence; that pass is its confirmation.

## Where and what

From [host.txt](results/claude-code-interactive-2026-10-21/host-evidence/host.txt) and the build files beside it:

| Fact | Value |
| --- | --- |
| Host | The reference host: Ubuntu 26.04.1 LTS, Linux 7.0.0-31-generic, x86_64 (KVM), account `ubuntu` |
| Host settings | Stock: `kernel.apparmor_restrict_unprivileged_userns = 1` |
| Backend | bubblewrap 0.11.1, ptrace observer |
| Source and build | The operator's clean build of `79200cfda548c2f6f0125b4355881f63910b284b` (branch `j14-review-fixes`, the candidate for rc.4): `UKAI_BUILD_REVISION` set, `UKAI_BUILD_DIRTY=false`, Rust 1.98.1, `cargo build --locked --release -p ukai-jail`. Not built by this record. `version --json` ([build-version.json](results/claude-code-interactive-2026-10-21/host-evidence/build-version.json)): revision `79200cfda…`, `dirty: false`, opt-level 3, inputs `sha256:95dac7f9fd0bcde675007dc9e38c6f15c5c1856632c5884a0c4972e4fc3af4ca` |
| Jail binary | `sha256:9ba9da31df1ce378fe824c2f4dd471a3e09cc35533fccc2a5ac4152ae133778b` ([build-ukai-jail.sha256](results/claude-code-interactive-2026-10-21/host-evidence/build-ukai-jail.sha256)), copied unchanged into the record's private directory |
| Claude Code | 2.1.302, native installer. `~/.local/bin/claude` links to `~/.local/share/claude/versions/2.1.302`, `sha256:60d7eb7f12fbb28a52533fe8be5884097403562aa02dc73991a021c7067e29a5`. This is the same file as the [headless record](claude-code-compatibility-2026-10-17.md)'s |
| `PATH` | The record's `bin/` first, then `~/.local/bin`, so `claude` resolved to the native install |
| Profile | The bundled `claude` profile, no operator file. `state = "persistent"`, `state_discard = [".credentials.json"]`, `[network] allow = ["api.anthropic.com", "platform.claude.com"]`. Every receipt lists exactly three grants: `allow_host` `api.anthropic.com:443` and `platform.claude.com:443` (`by: operator`, the profile layer), and the derived `read_only` `~/.local/share/claude/versions` (`by: program_resolution`) |
| Credential | `~/.config/ukai/credentials/claude-oauth`: mode 0600, 108 bytes, one link, written 2026-10-16. Stored with `ukai-jail credential set claude-oauth` into a private config directory (0700). Its value was never printed |
| State | Private `UKAI_CONFIG_DIR` and `UKAI_DATA_DIR` under `~/arow-int-final` (0700). That directory was removed after the record |
| Workspaces | Two fresh git repositories, one commit each. A holds a README plus the slug fixture of the [19 October demo](claude-code-demo-2026-10-19.md). B holds a README. Both started with no state |

`doctor` ([doctor.txt](results/claude-code-interactive-2026-10-21/host-evidence/doctor.txt)) reported `ready true`, the launch `experimental` (`no_recorded_run`) and `interactive_sessions unrecorded`. The binary never claims support; this record does, as the headless one did.

## The harness

The operator's machine (a Mac with `uv`) ran [harness/driver.sh](results/claude-code-interactive-2026-10-21/harness/driver.sh). [runs.sh](results/claude-code-interactive-2026-10-21/runs.sh) lists what it ran. [harness.sha256](results/claude-code-interactive-2026-10-21/harness.sha256) holds the digests of the files as they ran; `host/summary_check.py` is the repository's own [summary_check.py](../../specs/jail-v1/summary_check.py) at `79200cfda`.

- **The terminal.** [ttyharness.py](results/claude-code-interactive-2026-10-21/harness/ttyharness.py):
  - **Connection.** A local pseudo-terminal of 120x40 runs `ssh -tt -F /dev/null` (key-based) into the host's login bash. Job control was on (`$-` = `himBHs`). The environment had `TERM=xterm-256color` and `LANG=C.UTF-8`, and no `TZ`, `COLORTERM` or `LC_*`.
  - **Recording.** Every byte in both directions goes to an ndjson transcript with timestamps. The `x` field holds the bytes as latin-1, so the recording is reversible. The transcript also records:
    - the terminal's own answers;
    - resizes, waits and screen snapshots.
  - **Rendering.** pyte renders the screen, with xterm's alternate screen added.
  - **Queries answered.** The emulated terminal answers DA1, cursor position (CPR), DSR 5, OSC 10/11, DECRQM and the XTWINOPS size reports.
  - **Queries left unanswered.** XTVERSION, the kitty keyboard query and OSC 7501, as a terminal without those features would.
  - **Resize and hangup.** A resize is `setwinsize` on the local pty, which ssh forwards. A hangup is `SIGHUP` to the local ssh, as closing a terminal window does.
- **The runs.** [arow_int.py](results/claude-code-interactive-2026-10-21/harness/arow_int.py) recognises Claude Code 2.1.302's screens: the onboarding steps, the permission dialog, generation (the footer's `esc to interrupt`), the idle input box, the `/resume` picker and the login screens.
  - Each run uses a fresh SSH connection; run (8) uses two.
  - Every launch is typed as one command line: `<command>; rc=$?; python3 -I k62.py; echo "ARROW-DONE rc=$rc"`.
  - [k62.py](results/claude-code-interactive-2026-10-21/harness/host/k62.py) switches the terminal to non-canonical, no-echo mode. It reads whatever is pending for one second and prints the count and the bytes. The shell reads nothing in between, since it is still executing that line.
- **The checks.** [arow_int_collect.py](results/claude-code-interactive-2026-10-21/harness/host/arow_int_collect.py) runs on the host after each attempt. It:
  - archives the receipt, policy snapshot and journal;
  - saves `ukai-jail tail --summary` (text and `--json`), `state list` (text and `--json`), `state show claude --workspace …`, and a listing of the state's `vendor/` directory (names, modes, sizes);
  - runs `summary_check.py` on the archive;
  - evaluates the conditions;
  - searches for the token: `grep -rlF -f`, file names only, over the run's directory (with the transcripts), the attempt directory, the workspace and the state.

  Only a run directory whose search came back empty was copied off the host. The driver then compared the summary the terminal showed with `tail --summary`, and the pre-exec lines with §3.7 and §4.6–§4.7.
- **Order and timing.** Runs (1), (2), (7), (3), (4), (5), (6), (8), on 2026-10-21 from 09:50 to 10:01 UTC. Run (7) repeats run (2) right after it, so that run (1)'s session stays the one the picker lists.

The prompts were small and ordinary:

- the A01 fixture, "Create a file named greeting.txt containing the single word hello.";
- two one-sentence questions about the conversation;
- a 1,500-word essay to keep generation going during run (4);
- "What is 17 times 3?" in run (8).

## What ran

| Run | §6.3 | Command and what the harness did | Result |
| --- | --- | --- | --- |
| [r01](results/claude-code-interactive-2026-10-21/runs/r01-first-launch/) | (1) | `ukai-jail claude` in A, empty state. Onboarding: theme (Enter), security notes (Enter), folder trust (its default is "No, exit"; the harness chose "Yes, I trust this folder"). No login step. The footer read `auto mode on`, 2.1.302's default, so one shift+tab switched to `manual mode`. Then the A01 fixture; "Do you want to create greeting.txt?" answered `1`; `/exit` | **Passed.** `greeting.txt` is `hello`; generation 1, `new_state` |
| [r02](results/claude-code-interactive-2026-10-21/runs/r02-resume-continue/) | (2) | `ukai-jail claude --resume`: the picker listed one entry, "Greeting.txt file creation" (run (1)'s session), selected with Enter. The history showed run (1)'s prompt; one question; `/exit`. Then `ukai-jail claude --continue`: no picker, the previous question in view, one question, `/exit` | **Passed.** No onboarding. Both launches continued run (1)'s session (`391a2c6b…`, the id Claude Code prints at exit), and the answers named `greeting.txt` and the previous question. Generations 2 and 3 |
| [r03](results/claude-code-interactive-2026-10-21/runs/r03-workspace-b/) | (3) | `ukai-jail claude` in B: onboarding again, since B's state is new. `/resume` inside the session: "No conversations found in this project.", and none with Ctrl+A ("all projects"). Esc; `/exit` | **Passed.** Run (1)'s session is not listed. B's generation 1 |
| [r04](results/claude-code-interactive-2026-10-21/runs/r04-signals-hangup/) | (4) | `ukai-jail claude` in A, then the essay prompt. While generating: resize to 100x32, then `^C`. Then Ctrl+G (external editor) and `^X`, `^Z`, `fg`, and the hangup | **Passed, with the hangup exception** (below). Generation 24 |
| [r05](results/claude-code-interactive-2026-10-21/runs/r05-login/) | (5), as amended by §8 item 30 | `/login`, method 1 (Claude account). At the code prompt `fake-code-for-ukai-record`, then a retry with `fake-code-for-ukai-record#<the state shown in the login URL>`. Esc; `/exit` | **Passed.** Both failed visibly (below). No `.credentials.json` in the state after release; `discarded: 0`. Generation 25 |
| [r06](results/claude-code-interactive-2026-10-21/runs/r06-headless/) | (6) | `rm -f greeting.txt; ukai-jail claude -p "<A01>" --dangerously-skip-permissions --output-format json` from the interactive shell (attached). Then the same after `true \|` (stdin a pipe: detached) | **Passed, both.** `greeting.txt` is `hello`; Claude Code reported `is_error: false` in 2 turns. Generations 26 and 27 |
| [r07-rep01 … rep10](results/claude-code-interactive-2026-10-21/runs/) | (7) | Run (2)'s two launches, ten times | **20/20 passed.** Each picker listed exactly run (1)'s session; every launch continued `391a2c6b…`; no onboarding; generations 4–23 |
| [r08](results/claude-code-interactive-2026-10-21/runs/r08-concurrent/) | (8) | Terminal 1: `ukai-jail claude` in A, held open. Terminal 2 (a second SSH connection): `ukai-jail claude` in A. Onboarding (throwaway state is empty), "What is 17 times 3?", `/exit`. Back in terminal 1: `/resume` inside the session, Esc, `/exit`. Then `ukai-jail claude --resume`: picked run (1)'s session, `/exit` | **Passed** (below). Generations 28 and 29 |

### Run (4) in detail

From [run.json](results/claude-code-interactive-2026-10-21/runs/r04-signals-hangup/run.json) and its screens:

- **Resize during generation.** The input box's rule went from 120 to 100 columns while the footer still read `esc to interrupt`: the interface reflowed.
- **`^C` during generation.** Claude Code showed `⎿ Interrupted · What should Claude do instead?` and went back to its prompt. The attempt continued: no shell marker, receipt still `enforced`.
- **External editor (Ctrl+G).** nano opened (no `$EDITOR` is set in the jail). The host's process table ([editor-ps.txt](results/claude-code-interactive-2026-10-21/runs/r04-signals-hangup/editor-ps.txt)) shows nano in Claude Code's own process group, which is the terminal's foreground group (`pgid = tpgid`). After `^X`, nano was gone and the draft was back in Claude Code's input. The `TIOCSPGRP` filter of §8 item 22 did not affect it.
- **`^Z`.** Claude Code handles it itself: it printed "Claude Code has been suspended. Run `fg` to bring Claude Code back." and a note that ctrl+z now suspends, then stopped. Then:
  - bash printed `[1]+  Stopped  ukai-jail claude`, and the receipt counts `stops: 1`;
  - the journal has `terminal_stopped`, and later `terminal_continued`;
  - the relay wrote `ESC [ 0 m ESC [ ? 25 h` before the shell's line (§8 item 24);
  - bash went on with the rest of the command line at the stop (`rc=148`), so the K62 probe also ran there: 0 bytes pending.
- **`fg`.** The interface came back, redrawn at 100 columns.
- **Hangup.** `SIGHUP` to the local ssh. The receipt was settled 0.4 s later. The outcome is `signaled 9 (operator_signal)`: bash forwarded `SIGHUP` to the job, the supervisor took it as a stop request and killed the tree. Then:
  - tree death was verified (`survivors: none (verified)`, `integrity: verified`, `tree_empty: true`);
  - the state was released at generation 24, chained, with `matches_release: true`;
  - `applied.terminal` is `{"stops": 1, "restored": {"foreground": false, "termios": false, "input_flushed": false, "reset_written": false, "after_tree_death": true}}`.

  The summary's cleanup line reads `terminal not restored (foreground, termios, input): run reset`. Nothing could restore a terminal whose session is gone; that is the exception §6.3 now names.

### Run (5) in detail

- **The plain fake code.** `fake-code-for-ukai-record` got `OAuth error: Invalid code. Please make sure the full code was copied` from Claude Code itself. Nothing reached the network.
- **The code in the shape `code#state`.** It got `OAuth error: Request failed with status code 400`. The journal ([trace](results/claude-code-interactive-2026-10-21/runs/r05-login/A/attempt/trace.ndjson.gz)) has one proxy result to `platform.claude.com:443`, at the second the code was submitted. It was allowed, relayed and ended `upstream_closed`, with 553 bytes up and 955 down, and **no credential** (the vault substitutes only for `api.anthropic.com`).
- **Before the code.** The login screen warned that `CLAUDE_CODE_OAUTH_TOKEN is set in your environment` and that the session would switch to new credentials after logging in.
- **After release.** The state holds no `.credentials.json` ([state-files.txt](results/claude-code-interactive-2026-10-21/runs/r05-login/A/state-files.txt)); `discarded` is 0 because none was ever written.

### Run (8) in detail

- **Before exec.** Terminal 2's pre-exec line: `state: claude for this workspace is held by att_5c54adf5-c077-41b9-8bbe-f302786f229a · this session uses throwaway state and will not be kept`. `att_5c54adf5…` is terminal 1's attempt.
- **The fallback attempt** ([t2-fallback](results/claude-code-interactive-2026-10-21/runs/r08-concurrent/t2-fallback/)):
  - `vendor_state` is `{kind: attempt_fallback, reason: held, held_by: att_5c54adf5…}` and `state_cleanup` is `complete`;
  - its summary says `state: NOT kept · this session used throwaway state because att_5c54adf5… held the persistent state for this workspace`;
  - its onboarding repeated, as an empty state's does, and it reached `platform.claude.com` for the preflight (below).
- **Nothing of its session is listed.**
  - Terminal 1's `/resume` picker, inside the holding session, listed three entries: `/login` (run 5), "History of version control systems" (run 4) and run (1)'s.
  - The next `--resume` listed the same plus the holder's own session (`a899f90f`). The fallback's session was in neither.
  - The fallback's session file (`7757fe2b…`) is not in A's state ([state-files.txt](results/claude-code-interactive-2026-10-21/runs/r08-concurrent/t3-resume-after/state-files.txt)).
- **The chain continued unchanged.** The holder's attempt started from generation 27, which run (6)'s detached half released, with `matches_release: true`, and released 28. The final `--resume` launch released 29 from it.

## Pass conditions

Every value below is from each attempt's `check.json`; [report.md](results/claude-code-interactive-2026-10-21/report.md) tabulates them.

| §6.3 pass condition | Evidence |
| --- | --- |
| Every receipt settled, six classes active without gaps, `tree_empty` true | All 31. Every summary says `6/6 classes active, no gaps`; no observer gap at all |
| `credentials` lists one id with `never_staged` | All 31: only `claude-oauth`, `mode: vault`, `never_staged: true`. The summary's use count equals the proxy results carrying the id in every attempt (2–7 each), with 0 credential refusals |
| `state_cleanup` `released`, generations chaining, `matches_release` true | All 30 persistent attempts. In A, generations 1 to 29 form one chain: each `generation_start` is the previous `generation_end` and each `inherited_from` the previous attempt (`chains_generation`, `chains_attempt`). The first attempt in A and the one in B are `new_state`; every other has `matches_release: true`; every `secret_scan` is `clean`. `state show` lists the chain ([A](results/claude-code-interactive-2026-10-21/runs/r08-concurrent/t3-resume-after/state-show.txt)) |
| Run (8)'s second session: `attempt_fallback`, `complete`, summary `NOT kept` | As above |
| Every run exits 0 except run (4)'s hangup, which still settles with verified tree death | 30 attempts `exited 0` with no error. Run (4): `signaled 9 (operator_signal)`, settled, tree death verified |
| Every attached run has `applied.terminal.restored` with all five fields true; the detached half of run (6) has none | All 29 attached attempts other than run (4) have all five true; run (4) is the hangup exception. Every attached snapshot says `terminal: attached`. The detached half has no `applied.terminal`, its snapshot omits `terminal`, and its pre-exec line says `terminal: detached (stdin is not a terminal)` |
| The token is absent (K70) | See [Exposure](#exposure) |
| After each attached run, the harness's shell reads none of the session's bytes (K62) | 0 bytes pending after each of the 29 attached runs with a shell afterwards, after the detached one, and at run (4)'s `^Z` |
| Run (6): the 2026-10-17 row's task and evidence conditions | Both halves: `greeting.txt` is `hello`, `is_error: false`, only the three grants above, use count as summarised. The summary reproduces, with `released` in place of `complete` |

Beyond the conditions:

- **Summaries reproduce (K52).** In all 30 attempts that ended with a shell, the summary the terminal showed equals `tail --summary` line for line, and `--json`'s text fields equal it. `summary_check.py` recomputed every line, fact and number of all 31 on the host, and again from the committed copies (31/31).
- **Pre-exec lines.** Every attempt printed the lines §3.7 and §4.7 require, matched exactly:
  - attached runs print `terminal: attached (/dev/pts/N) · wall 8h · ^C and ^Z go to claude, not the jail; to end the attempt, exit claude or run `kill -INT PID``, naming the launch profile as §8 item 29 says;
  - every attempt prints `state: claude, new for this workspace` or `state: claude, this workspace, generation N (from att_…)` with the chain's values;
  - the fallback prints its own line instead (run (8)).

Durations are `exec→settled` from the summaries: run (1) 17.2 s, run (2) 9.1 and 9.3 s, run (7) median 9.6 s (8.1–11.2 s), run (3) 11.5 s, run (4) 20.6 s, run (5) 18.4 s, run (6) 4.2 and 6.0 s, run (8) 29.2 s (holder), 13.0 s (fallback) and 4.0 s. Most of that is the harness's typing and waiting, so they are not performance figures.

## Exposure

- **What was searched.** The token's value was searched for as a fixed string, `grep -rlF -f` on its source file, file names only, on the host.
- **Per attempt.** The run directory with that run's transcripts and raw byte streams, the attempt directory, the workspace and the state's directory: 31 searches, 0 hits ([token-search.json](results/claude-code-interactive-2026-10-21/runs/r01-first-launch/A/token-search.json) in each attempt).
- **After the runs** ([k70-sweep.txt](results/claude-code-interactive-2026-10-21/k70-sweep.txt)):
  - the runs (510 files), the attempt directories (217), the state (35), the host evidence (7) and both workspaces, every search exit 1;
  - the positive control on the private config directory found only `credentials/claude-oauth`.
- **This results directory.** Searched as a whole on the host before it was compressed and committed: 568 files, exit 1.

As in the headless record, this is a search of files and transcripts. This record ran no sampler of process environments.

## The vendor facts (§6.3)

| §6.3 question | Answer for Claude Code 2.1.302, native | Evidence |
| --- | --- | --- |
| Is `CLAUDE_CODE_OAUTH_TOKEN` honoured interactively, so that no login prompt appears? | Yes. Onboarding skipped its login step (theme, security notes and folder trust only) in runs (1), (3) and (8), and every turn was answered through the substituted credential. `/login` itself warns that the variable is set | run (1) and (5) screens; use counts |
| Which hosts does an interactive first launch contact? | `api.anthropic.com` (8 results in run (1)) and `platform.claude.com` (1). The preflight checks `api.anthropic.com/api/hello` and `platform.claude.com/v1/oauth/hello` and exits 1 if either fails, which the pilot found and §8 item 30 settled. `downloads.claude.ai:443` and `github.com:443` were each tried once and denied (`host_not_allowed`), despite `DISABLE_AUTOUPDATER` and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC`; nothing visible came of it. Later launches contact only `api.anthropic.com`; headless runs too | journals; summaries' network lines |
| Is `home_is_state` needed? | No. `HOME` is unset in the child and every session worked. Each interactive attempt records two refused writes: a `mkdir` of `~/.local/state` (digest `sha256:4251803132e6…`, as in the headless record) and a second `mkdir` outside the known roots (`sha256:f85580ab64b0…`) whose path this record did not identify. Headless runs record only the first | `fs.deny` in every `check.json` |
| Which files does Claude Code write in its state? | `.claude.json` and up to five `backups/.claude.json.backup.<ms>`, `.last-cleanup`, `history.jsonl`, `projects/<workspace path>/<session>.jsonl` (one per session) and `projects/<…>/memory/`, `file-history/<session>/<hash>@v2`, `plugins/marketplaces/`, `policy-limits.json` with its `.signature.json` and `.stamp.json`, `remote-settings.json` and `.synced-at`, `settings.json`, `sessions/`. Never `.credentials.json`. `state show` names no files (see the deviations), so these come from a listing of `vendor/` on the host | `state-files.txt` per attempt |
| Does it use the alternate screen? | Yes: `?1049h` when its interface starts, `?1049l` at exit. It also turns on mouse tracking (`?1000h`, `?1002h`, `?1003h`, `?1006h`), focus reports (`?1004h`), bracketed paste (`?2004h`) and `?2031h`. At startup only, it queries DA1, XTVERSION, the kitty keyboard flags and OSC 7501 | [report.md](results/claude-code-interactive-2026-10-21/report.md), "Terminal facts" |
| Does it stop on `^Z` or handle it? Does it give the terminal to another process group? | It handles `^Z`: it reads the byte, prints its own message, restores the terminal and stops itself, and the jail's relay works (above). It does not hand the terminal to another group: the external editor runs in Claude Code's own group, which stays the foreground group, and returns normally | run (4) |
| Is the contained environment enough for its interface? | Yes. The child's environment names are `PATH`, `PWD`, `LANG`, `TERM`, `TMPDIR`, `CLAUDE_CONFIG_DIR`, the profile's two variables, `CLAUDE_CODE_OAUTH_TOKEN` (the placeholder), the proxy and CA variables. No `HOME`, `COLORTERM` or `LC_*`; no `TZ`, since the host shell had none. Without `COLORTERM` it draws in 256 colours (no truecolor sequence in any transcript), and its box drawing and symbols render | `environment_names` in every receipt; transcripts |
| State growth per session | A first session with one task: 158 KB, mostly the session transcript (151 KB). Each resumed or continued turn adds 9.5–17 KB. A `-p` run adds a new 136 KB session file, which the picker does not list. A session without a prompt adds about 2 KB. Run (4) added 40 KB. After 29 generations A's state was 752 KB in 21 files; B's was 8.7 KB | `state-list.json` per attempt |

Also observed:

- 2.1.302 starts in "auto mode", which lets Claude Code decide permission prompts itself. Getting its own prompt at the keyboard took one shift+tab to "manual mode" (run (1)).
- Esc on the picker of `claude --resume` exits Claude Code with status 1 (seen in the pilot). Run (3) therefore opened the picker with `/resume` inside its session, and run (8)'s last launch picked a session instead of cancelling.
- A session made only of `/login` is listed as `/login`; one without any prompt is listed by its id.

## Deviations from §6.3 as written

1. **Run (4)'s hangup cannot satisfy "restored with all five fields true".** The terminal is gone, so the first four steps fail and the receipt says so. §6.3's condition was amended on 2026-10-21 to expect `restored` with `after_tree_death` true and the other four false after a hangup. The harness's automated check of the exception (`terminal_hangup_exception`) asserts the five fields and `after_tree_death` true, not that the other four are false; noted on review 2026-10-21, the receipt's own values (above) carry that half, and a future harness should assert all five.
2. **"The files Claude Code writes in its state, by `state show`."** `state show` prints the state's metadata and generation log and names no file. The files above come from a listing of `vendor/` made on the host by the harness, the way the operator can make one. §6.3 was amended the same day.
3. **Run (5)** follows §6.3 as amended by §8 item 30: `platform.claude.com` is allowed. Two fake codes were used, because the plain one never leaves Claude Code.
4. **Run (1)'s permission prompt** needed manual mode (above). The switch was made at the keyboard, inside the session.
5. **Runs (3) and (8)** reached the picker without cancelling it (above). Run (3)'s "launch in B" is a plain `ukai-jail claude`; its check uses `/resume` inside that session.
6. **Run (7)** ran each repetition as both launches of run (2), right after run (2).
7. **The binary was built by the operator, not by the record's own command.** Its build facts are copied unchanged.
8. **`TZ`.** §6.3 lists it among the contained environment; the host shell had none, so there was nothing to forward.

## Confirmation on the release build

After this record, `dev` took two TLS advisory fixes (`rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10, `e598d06f7`) and a CI-only change (`cccf5db30`). No file under `crates/ukai-jail/` changed, but the build inputs did. The driver therefore ran again end to end on the release build, with nothing else changed:

- **When.** 2026-10-21, 10:31–10:42 UTC, on the reference host, with nothing else running on it.
- **Binary.** The operator's clean build of `cccf5db30196a9f0a1de5570a7af3f99e252e3ea` (`dirty: false`, Rust 1.98.1, `--locked --release`), left at `~/rc4-build` and copied unchanged:
  - inputs `sha256:893f85686e76cffeeb87f57c33ba27fe16685524d73676ec7b72c937e7c20d03`;
  - binary `sha256:40621f6df47571c501ddf3558407b3e144905c826f001c6a1900d2bcd9756928`.

  Both are in [build-version.json](results/claude-code-interactive-2026-10-21/release-build/host-evidence/build-version.json) and [build-ukai-jail.sha256](results/claude-code-interactive-2026-10-21/release-build/host-evidence/build-ukai-jail.sha256).
- **Unchanged.**
  - Claude Code 2.1.302 native (`sha256:60d7eb7f…`);
  - the bundled profile;
  - two fresh repositories, starting from an empty state;
  - ten repetitions of run (2);
  - the harness, byte for byte: [harness.sha256](results/claude-code-interactive-2026-10-21/release-build/harness.sha256) equals this record's, and `summary_check.py` is the same file at both revisions;
  - a fresh private directory on the host, removed afterwards.

| Run | §6.3 | Attempts | Result on `cccf5db30` |
| --- | --- | --- | --- |
| [r01](results/claude-code-interactive-2026-10-21/release-build/runs/r01-first-launch/) | (1) | 1 | **Passed.** Onboarding was theme, security notes and trust, with no login. Manual mode, the permission prompt answered at the keyboard, `greeting.txt` is `hello`. Generation 1, `new_state` |
| [r02](results/claude-code-interactive-2026-10-21/release-build/runs/r02-resume-continue/) | (2) | 2 | **Passed.** `--resume` and `--continue` continued run (1)'s session; no onboarding |
| [r07](results/claude-code-interactive-2026-10-21/release-build/runs/) | (7) | 20 | **20/20 passed.** Generations 3–23 |
| [r03](results/claude-code-interactive-2026-10-21/release-build/runs/r03-workspace-b/) | (3) | 1 | **Passed.** "No conversations found" in B |
| [r04](results/claude-code-interactive-2026-10-21/release-build/runs/r04-signals-hangup/) | (4) | 1 | **Passed, with the hangup exception.** Resize 120 to 100 columns while generating; `^C` interrupted the turn. nano opened in Claude Code's group and returned. `^Z` relay with the reset, then `fg`. The hangup ended `signaled 9 (operator_signal)`, settled 0.4 s later with tree death verified; `restored` false for four steps, `after_tree_death` true. Generation 24 |
| [r05](results/claude-code-interactive-2026-10-21/release-build/runs/r05-login/) | (5) | 1 | **Passed.** The same two messages ("Invalid code…", "Request failed with status code 400"). One `platform.claude.com:443` result, with no credential. No `.credentials.json`; `discarded: 0` |
| [r06](results/claude-code-interactive-2026-10-21/release-build/runs/r06-headless/) | (6) | 2 | **Passed, both.** Attached restored all five steps; detached has no `applied.terminal`. `hello` both times, `is_error: false` |
| [r08](results/claude-code-interactive-2026-10-21/release-build/runs/r08-concurrent/) | (8) | 3 | **Passed.** The fallback said so before exec, was `attempt_fallback`/`complete` and `NOT kept`, and is listed nowhere. The holder's chain went on (28, 29) with `matches_release: true` |

Across all 31 attempts:

- every receipt is settled with six classes active and no gaps, `tree_empty` and one credential `never_staged`;
- every persistent attempt is `released`, chained, with clean scans;
- 0 bytes were pending in every K62 probe;
- the live summary equals `tail --summary` in all 30 attempts that ended with a shell;
- `summary_check.py` recomputed all 31 on the host;
- every pre-exec line matched exactly, naming `claude`.

The token search after the runs ([k70-sweep.txt](results/claude-code-interactive-2026-10-21/release-build/k70-sweep.txt)):

- the runs (510 files), attempts (217), state (35), host evidence (7) and both workspaces: every search exit 1;
- the positive control found only the vaulted copy;
- the compact evidence below: searched again on the host before it was copied, 248 files, exit 1.

**Difference from the first pass: none in any check.** The outcomes, network lines, workspace lines, use counts, refused writes, generations, restore records, K62 results and pre-exec lines are identical attempt for attempt. Only the vendor's free choices differ:

- the title Claude Code generated for run (4)'s session ("Version control systems history" instead of "History of version control systems");
- the session ids;
- the durations (`exec→settled` 3.5–34.0 s; run (7) median 9.7 s);
- the state's size, by at most 1 KB per generation.

[release-build/](results/claude-code-interactive-2026-10-21/release-build/) keeps the compact evidence, with its own `SHA256SUMS`:

- per attempt: `check.json`, the receipt, the summary the terminal showed (`live-summary.txt`), `tail --summary`, the pre-exec lines and `summary_check.py`'s output, and the token search;
- per run: `run.json`;
- at the top: the report, the host and build evidence, and `package_confirm.py`, which selected these files.

The transcripts, raw streams, journals, policy snapshots and state listings were searched on the host as above and left out.

## Before this record: the pilot

A pilot of every run on the same day, with a development build of `dev` `b760fc95e`, found two things that changed `79200cfda` before this record:

- With `platform.claude.com` denied, every interactive first launch, every launch after `state rm` and every throwaway fallback ended at the preflight with exit 1. The operator chose to allow the host (§8 item 30).
- The attached pre-exec line named Claude Code's version-named binary (`^C and ^Z go to 2.1.302`); it now names the launch profile (§8 item 29).

The pilot's own evidence was a development aid and is not part of this record.

## Limits of the claim

- **One combination.** One build, one host, one Claude Code version, and one terminal, the one the harness emulates. Real terminal emulators answer more queries (XTVERSION, the kitty keyboard query) and may lead Claude Code to other modes.
- **K62 was barely stressed.** Claude Code sends its terminal queries only at startup, so no reply was in flight when a session ended, and the harness never typed ahead. A terminal whose replies arrive late, or an operator typing during exit, was not tested.
- **The hangup was a window close** (`SIGHUP` to ssh), not a dropped network connection.
- **Short sessions.** None lasted more than about 30 s; the 8 h wall was not exercised.
- **No real `/login`.** The fake codes show what a failed exchange looks like. That `.credentials.json` would be written and then removed unread at release is the design (§4.5), not observed here.
- **Two denied hosts at first launch, and one unidentified refused `mkdir`.** Both are recorded and caused no visible failure.
- **`doctor` is unchanged.** It still reports `interactive_sessions unrecorded`: the binary does not change with a record, as for the headless row.

## Not covered

The Raspberry Pi, npm installs, other Claude Code versions, other terminal emulators, and OpenCode, as §6.3 says. Also not covered:

- the API-key credential;
- a real `/login`;
- a network drop;
- long sessions;
- hosts other than the reference host.

## Files

[results/claude-code-interactive-2026-10-21/](results/claude-code-interactive-2026-10-21/) holds:

- `runs.sh`, `harness/` and `harness.sha256`;
- `host-evidence/` (host, build, `explain`, `doctor`, `credential set`'s line);
- `report.md`, `results.ndjson`, `chain.json`, `facts.json`, `driver.log` and `k70-sweep.txt`;
- one directory per run under `runs/`. Each holds the run's observations (`run.json`), its transcripts (`transcript-*.ndjson.gz`, gzip of the ndjson), its rendered screens and, per attempt:
  - the receipt, policy snapshot and journal (`attempt/trace.ndjson.gz`);
  - `check.json`;
  - `tail --summary` in both forms and `summary_check.py`'s output;
  - `state list`, `state show` and the state's file listing;
  - the token search.

The raw byte streams were searched on the host and left out; the transcripts hold the same bytes. `SHA256SUMS` covers every file of this first pass. `release-build/` holds the confirmation on `cccf5db30`, with its own `SHA256SUMS`. To recompute a summary, unpack the journal next to the receipt and policy, then run `python3 docs/specs/jail-v1/summary_check.py <dir> <dir>/../tail-summary.json`.
