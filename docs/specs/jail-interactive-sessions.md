# Jail proposal: interactive agent sessions (J14)

Status: design proposal, 2026-10-18. Nothing here is implemented, and
nothing here is decided until the operator settles the questions in §7.
This is the milestone that
[jail-launch-and-summary.md](jail-launch-and-summary.md) §7, decision 7,
names after J12 and J13 and outlines in its §3.8. It was written against
`dev` at `b693b1573`, two documentation commits after the
`ukai-jail-v0.1.0-rc.3` tag (`f95f2d396`). Until it is implemented, the
[north star](../../north-star.md), [Jail v1](jail-v1.md) (revision 25),
[Jail v2](jail-v2.md) and the launch proposal govern unchanged. Where this
proposal amends them, §5 says so row by row. The milestone name J14 and the row numbers K55–K75
are provisional and follow the launch proposal's sequence.

Each claim says where it comes from:

- **measured**: a run whose evidence is in this repository;
- **by reading**: kernel, bubblewrap, sudo or vendor source or
  documentation, not run;
- **inferred**: argued from those, not observed.

Normative words follow jail-v2. **must** is a release gate. **initial** is a
tunable default that must be recorded. **candidate** is unproved until the
named measurement passes.

Today one combination is supported: Claude Code 2.1.302, headless, as
recorded in the
[A-row](../benchmarks/jail/claude-code-compatibility-2026-10-17.md):

```text
ukai-jail claude -p "…" --dangerously-skip-permissions
```

The form most developers use, `ukai-jail claude` with no `-p`, starts but
nothing claims it works. The agent gets no resize events, `/dev/tty` fails,
`^C` ends the attempt rather than the agent's current turn, and every run is
Claude Code's first launch. After this proposal it would look like this
(illustrative, not a recorded run):

```text
ukai-jail claude
ukai-jail: claude = /home/u/.local/share/claude/versions/2.1.302 (read-only: /home/u/.local/share/claude/versions)
ukai-jail: terminal: attached (/dev/pts/3) · state: claude, this workspace, generation 4 (from att_…)
…Claude Code's interactive interface: prompts answered at the keyboard, resizes, ^C, ^Z and fg…
ukai-jail: settled · exited 0 · 47m12s exec→settled · survivors: none (verified)
ukai-jail: workspace: 6 paths opened for writing, 2 in renames
ukai-jail: network: allowed api.anthropic.com:443 (212)
ukai-jail: credential claude-oauth: vault, never staged · used on 212 proxy results · 0 refusals
ukai-jail: state: kept, generation 5 · started from what att_… released, unchanged
ukai-jail: evidence: 6/6 classes active, no gaps · reads and file contents are not observed
ukai-jail: receipt /home/u/.local/share/ukai/attempts/att_…/jail.json
```

## 1. Scope

In scope, two mechanisms that ship and are tested independently:

- **Terminal mode (§3).** When standard input is the operator's controlling
  pseudo-terminal and the jail is the foreground job, the contained command
  runs in the caller's session instead of a new one. It gets its own process
  group, which becomes the terminal's foreground group, so resizes,
  `/dev/tty`, terminal signals and job control reach it. Off a terminal,
  nothing changes.
- **Persistent vendor state (§4).** An operator-owned state directory per
  launch profile and workspace. It survives attempts, so the agent's
  settings, onboarding and session history persist and `--resume` can work.
  Headless runs can use it too.

Excluded, each for a stated reason:

- **A pseudo-terminal relay** (the jail allocating its own pty and copying
  bytes, as `sudo`'s `use_pty`, `ssh -t` and `docker -t` do). It was
  considered (§3.3, alternative b) and is not proposed for J14.
- **`none`.** It already runs uncontained, in a new session
  (`uncontained.rs`), and there is no boundary for terminal mode to protect.
  Nothing changes there.
- **The managed gate.** An owner plans from its own inputs (jail-v1 §8.2)
  and has no terminal (north star: fleet stdin is `/dev/null`). `--gate-fd`
  always runs detached and refuses persistent state.
- **`learn`.** It is an ordinary contained run the operator starts (jail-v2
  §5.1), so terminal mode could apply to it. It stays detached in J14
  because nobody has recorded a need to learn under an interactive agent,
  and recording reads under a terminal interface is unmeasured. A later
  change can lift this; it needs K55–K63 rerun under `learn`.
- **Seeding state from `~/.claude`.** jail-v1 §12 says "the runtime does
  not discover and mount all files in an agent's home directory", and the
  launch proposal §1 says the alias stages nothing from it. State starts
  empty (§4.8).
- **Virtual consoles and serial lines** never attach (§3.2).
- **Filtering escape sequences** the agent writes (§3.5, row 9).
- **macOS**, which refuses execution until J11.

## 2. Invariants kept

| Invariant | Source | How this proposal keeps it |
|---|---|---|
| The child cannot reach host processes | jail-v1 §15 S02 | Measured with plain bubblewrap: dropping `--new-session` alone lets `kill(0, …)` from inside the PID namespace reach a process outside it that shares the process group (in the probe, a non-interactive `sh`). The jail's filter does not touch `kill`, so the jail would do the same, and in a real job the group holds the supervisor (inferred). The command therefore gets a process group of its own, which confines it to the PID namespace again (§3.1, §3.3). |
| Nothing widens silently | jail-v1 §6.2; north star §4.3 | An attached terminal and persistent state both enter the policy snapshot (and so the policy digest), `explain`, the pre-exec line and the receipt (§3.7, §4.7). |
| Child stdio matches direct execution | jail-v1 §15 X05 | Terminal descriptors still pass through untouched, with no relay. The jail's own lines (the pre-exec lines, §3.6's two reset sequences, the summary) are written only before exec and after the tree's end, as the pre-exec line and summary are today. |
| The backend prevents `TIOCSTI`-style injection | jail-v1 §8.3 | The filter's `TIOCSTI` denial stays. On hosts where the kernel still allows it, the denial becomes the only barrier. `TIOCLINUX` and `TIOCSETD` join it, and virtual consoles never attach (§3.5). |
| No host configuration | [operating.md](jail-v1/operating.md#install) | Nothing depends on `legacy_tiocsti`, `ldisc_autoload` or any other host setting. The design holds on a host where `legacy_tiocsti` is 1. |
| Credentials stay in the vault | launch proposal §3.5; `claude.toml` | Persistent state refuses every credential mode except `vault`. A profile's discard list removes named files at release. A candidate scan quarantines state that holds a vault value (§4.5). |
| No trace, receipt or export includes vendor state | jail-v1 §12 | Receipts carry a state id, generations and a comparison result, never content or a content digest (§4.7). |
| No agent names in the execution core | jail-v1 §15 I02 | New keys are generic. `.credentials.json` appears only in profile data. |
| Support lives in the compatibility record | jail-v1 §§14.1, 15 | The interactive A-row is a separate row (§6.3). `doctor` keeps reporting profiles `experimental`. |

## 3. Terminal mode

### 3.1 What happens today

From the code at `b693b1573`:

- Every contained plan passes bubblewrap `--new-session`
  (`bwrap.rs`, `NAMESPACE_OPTIONS`), as jail-v1 §8.3 and §9.2 and the
  north star §4.3 require. A terminal on standard input is passed through
  untouched (§8.3). `--new-session` makes only the sandboxed child a new
  session. bubblewrap's outer process and the watcher (`watch.rs`) are
  spawned with no `setsid` or `setpgid`, so they stay in the supervisor's
  process group (by reading of the spawn path).
- The supervisor catches `SIGINT`, `SIGTERM` and `SIGHUP` as stop requests
  (`supervisor.rs`, `signals::install`). It does not catch `SIGQUIT` or
  `SIGTSTP`. bubblewrap's outer process and the watcher keep default
  dispositions for all five (by reading).
- The launcher puts back the signal mask the supervisor inherited, which the
  supervisor reads from its main thread's current mask
  (`launch::blocked_mask`, passed in `boundary.rs`). That function is
  documented as relying on the main thread never changing its mask.
- Every contained baseline answers `ioctl` with `EPERM` when the request's
  low 32 bits equal `TIOCSTI` (`0x5412`). The kernel's `cmd` is an
  `unsigned int`, so the low word is the whole request. A non-native ABI is
  refused by the architecture check before any number is compared, so the
  compat `ioctl` path is unreachable (`seccomp.rs`, `sd_arg_low`). The
  evidence tables pin this rule
  (`jail-v1/evidence/seccomp-table-*.txt`). `linux_mechanisms.rs`
  (`ioctl_tiocsti`) proves it on the reference host with standard input on
  `/dev/null`, so the `EPERM` is the filter's answer and not a terminal's.
  No other terminal ioctl is filtered.
- The jail's `/dev` is bubblewrap's `--dev`. The audit treats `/dev/tty`
  (5:0) as a standard device (jail-v1 §11.3).
- The observer leaves group-stopped tracees stopped with `PTRACE_LISTEN`
  (`tracer/sys.rs`, `is_group_stop`), so a job-control stop is not undone by
  tracing.

**Measured** on the reference host on 2026-10-18
([evidence](../benchmarks/jail/results/j14-terminal-probe-2026-10-18/README.md)).
The probe ran plain bubblewrap with the jail's namespace options except
`--clearenv`, on a fresh pty, under Ubuntu's stock `unpriv_bwrap` AppArmor
confinement. It had no seccomp filter, no jail launcher, no cgroup and no
observer. The session leader was a non-interactive `sh` without job
control, so bubblewrap ran in that shell's own process group:

| Variant | `/dev/tty` | Resize from outside | `TIOCSTI` | `kill(0, SIGURG)` from inside |
|---|---|---|---|---|
| `--new-session` (today) | `ENXIO` | no `SIGWINCH` | `EIO` | stays inside |
| without it, inherited process group | opens | `SIGWINCH` delivered | `EIO` | **reaches the shell outside the namespace that shared the group** |
| without it, own process group made foreground from inside (`SIGTTOU` ignored) | opens¹ | `SIGWINCH` delivered | `EIO`¹ | stays inside |

¹ Measured before the `setpgid`/`tcsetpgrp` calls, in the same process.

The host has `dev.tty.legacy_tiocsti = 0` and `CONFIG_LEGACY_TIOCSTI` unset
(measured, [host.txt](../benchmarks/jail/results/j14-terminal-probe-2026-10-18/host.txt)),
so the kernel refused `TIOCSTI` in every variant. The Raspberry Pi could not
be reached on 2026-10-18 (its SSH tunnel refused the connection, as the
evidence README records), so its setting is **unmeasured**. The design does
not depend on it.

These consequences explain why interactive use is unsupported today. They
are **by reading** of `drivers/tty` and the spawn path, and not run.
Terminal signals go to the supervisor's foreground group, which holds the
supervisor, bubblewrap's outer process and the watcher, but not the
sandboxed command:

- `^C`: the supervisor takes it as a stop request. bubblewrap's outer
  process and the watcher die of it, and `--die-with-parent` then ends the
  tree. The attempt ends either way, with the helpers' deaths unnamed
  (operating.md, "A killed helper is not named").
- `^\`: all three die of the default action. The receipt is left unsettled
  until `gc`.
- `^Z`: all three stop, and the detached command keeps running. The kernel
  applies job control only to a terminal's own session
  (`__tty_check_change` returns at once when the terminal is not the
  caller's controlling terminal), so the command keeps reading the terminal
  while the shell has it back, and the two split the operator's keystrokes.

### 3.2 When terminal mode applies

Terminal mode attaches only when every one of these conditions holds. The
supervisor checks them while it resolves the policy, so the result enters
the snapshot:

1. The verb is `run` (the alias included), and the profile is contained
   (`agent`, `tool`, `build`).
2. Neither `--gate-fd` nor `--terminal detach` is given, and `config.toml`
   does not set `[jail] terminal = "detach"`.
3. Standard input is a terminal (`isatty(0)`) and is the supervisor's
   controlling terminal (`tcgetsid(0) == getsid(0)`).
4. The jail is the terminal's foreground job (`tcgetpgrp(0) == getpgrp()`),
   so `ukai-jail claude &` stays detached.
5. The terminal is a pseudo-terminal slave: its device major is 136–143, the
   Unix98 pty slaves (by reading of the kernel's device list). A virtual
   console (major 4), a serial line or anything else stays detached (§3.5,
   rows 2–3).

Otherwise the run is detached exactly as today. Its argv still carries
`--new-session`, and the snapshot gains no `terminal` field. With
attempt-private vendor state (§4.7), the snapshot is byte-identical to the
one rc.3 writes for the same inputs. When stderr is a terminal and
condition 3, 4 or 5 fails, the pre-exec line says why, for example
`terminal: detached (not the foreground job)`. Conditions 1 and 2 are the
operator's own choices and print nothing. Standard output and standard error carry no condition. They pass
through or are relayed as today.

### 3.3 Process groups: the design

1. **Before release** the supervisor records its own process group and
   saves the terminal's `termios` (`tcgetattr`). The saved copy is the one
   §3.6 restores.
2. bubblewrap starts **without `--new-session`**. Every other namespace
   option stays.
3. **The trusted launcher**, inside the boundary, takes the foreground as
   its last steps before the exec. It calls `setpgid(0, 0)`, then calls
   `tcsetpgrp(0, getpgrp())` with `SIGTTOU` blocked, then sets the mask the
   jail hands the target, as it already does (jail-v1 §9.2). Measured: both
   calls succeed inside bubblewrap, and the inside group then receives
   resizes and its `kill(0, …)` stays inside. The probe *ignored*
   `SIGTTOU`. That *blocking* it lets `tcsetpgrp` proceed just as well is by
   reading (the kernel's `is_ignored` treats a blocked and an ignored
   signal alike); K56 measures it.
4. **The supervisor captures the mask it inherited once, at start**, before
   any thread changes one. `launch::blocked_mask` reads the main thread's
   *current* mask, so a later block there would reach the target. After
   that it blocks `SIGTTOU` only around its own terminal calls (`tcsetpgrp`,
   `tcsetattr`, `tcflush`, and its writes to stderr while another group
   holds the foreground). The kernel lets a caller that blocks or ignores
   `SIGTTOU` through instead of stopping it (by reading). K56 checks that the
   target's blocked set (`SigBlk` in `/proc/<pid>/status`) is the
   operator's.
5. **At the target's end** the supervisor takes the foreground back before
   settlement (§3.6).

The command's group holds only processes inside the PID namespace.
bubblewrap's outer process, the watcher and namespace init stay in the
supervisor's group, which is not the terminal's foreground group in
terminal mode, so terminal signals no longer reach them. A contained
process cannot join or name a group outside the namespace: `setpgid` and
`tcsetpgrp` resolve group ids in the caller's namespace, where an outside
group has no number. This is by reading, and it is consistent with the
measured `getpgrp() = 0` for the inherited outside group. S02's "cannot
reach host processes" therefore keeps holding on every kernel. The command
can still signal processes inside the namespace outside its own group,
such as namespace init or the `agent` bridge (which starts its own session,
`launch.rs`), as it can today.

Alternatives considered:

- **(a) A shared process group** (only drop `--new-session`). This breaks
  S02: measured with plain bubblewrap, and inferred for the jail, whose
  filter leaves `kill` alone. Terminal `^C` would also reach both the supervisor,
  as a stop request, and the agent, and `^Z` would stop the supervisor in
  the middle of persistence steps. It can be repaired with Landlock's signal
  scope (`LANDLOCK_SCOPE_SIGNAL`, ABI 6, kernel 6.12 or later; the reference
  host reports ABI 8, measured), with `SI_KERNEL` discrimination of
  terminal-generated signals, and with a `SIGTSTP` handler. That ties
  terminal mode to a kernel version for a property that a process group
  gives on every kernel.
- **(b) A pseudo-terminal relay.** The supervisor allocates a pty and gives
  its slave to the command as controlling terminal in a new session (so
  `--new-session` stays). It copies bytes and window sizes between the
  operator's terminal and the master, and could offer an escape key such as
  ssh's `~.`. The agent never holds the operator's terminal, so rows 1–6 of
  §3.5 become unreachable on every host whatever the filter says. The costs:
  - every byte passes through the supervisor, which reverses §8.3's "no PTY
    emulation";
  - X05's byte equality no longer holds for terminal runs (the pty's output
    processing sits between them);
  - raw mode on the operator's side, size propagation, end-of-file and flow
    control become jail code;
  - escape sequences still pass unless the jail parses the agent's output.

  This is the fallback if the K62 injection rows find a vector that the
  filter and the settlement restore cannot close.

### 3.4 Signals and job control

"The supervisor's group" is the supervisor, bubblewrap's outer process and
the watcher (§3.1). Every cell is by reading except the two marked
measured.

| Event | Today (new session) | Terminal mode |
|---|---|---|
| `^C` | The supervisor's group: a stop request, and the helpers die; the attempt ends (§3.1). | The command's group only. The agent decides (Claude Code interrupts its turn: vendor behaviour, recorded by §6.3). The supervisor's group is not in the foreground and gets nothing. |
| `^\` | The supervisor's group: all three die (§3.1). | The command's group only. |
| `^Z` | Stops the supervisor's group; the command keeps reading the terminal (§3.1). | Stops the command's group; the supervisor relays the stop (below). |
| Resize | Not delivered (measured). | `SIGWINCH` to the command's group (measured). |
| Hangup | The kernel signals the session leader, the shell. bash forwards `SIGHUP` to its jobs' groups, and the foreground group gets `SIGHUP` when the shell exits. The supervisor takes it as a stop request; bubblewrap's outer process and the watcher die of it, which ends the tree. | bash's forwarded `SIGHUP` reaches the supervisor's group as today, with the same effect. The command's group gets `SIGHUP` when the shell exits. The supervisor also treats `POLLHUP` or `POLLERR` on its terminal as a stop request, so a shell that neither forwards nor exits still ends the attempt. |
| `SIGINT`, `SIGTERM`, `SIGHUP` sent to the supervisor with `kill` | Stop request. | Unchanged. |

**The stop relay** follows the model of `sudo` without a pty (by reading of
its `exec_nopty`): a supervisor whose command stops stops itself, so the
shell sees its job stopped and gives the operator the prompt back.

1. **Detect.** The command's group leader (the target) enters a
   group-stop. With observation on, the tracer already sees group-stops.
   With observation off, the supervisor reads `/proc/<target>/stat` once per
   supervision step (initial: at most 100 ms apart in terminal mode).
2. **Quiesce.** The supervisor starts no new persistence step and waits
   for the one in flight under its existing rule: a 5-second no-progress
   budget, not a completion bound (jail-v1 §13.3). A stall is handled as
   today. It journals a lifecycle note with the transition
   `terminal_stopped`. Transitions are safe names in the event schema
   (`$defs/name`), so this needs no schema change.
3. **Hand back.** The supervisor takes the foreground (`tcsetpgrp` to its
   own group), restores the saved `termios`, and stops its own process group,
   which holds bubblewrap's outer process and the watcher, with the signal
   that stopped the target.
4. **Continue.** On `SIGCONT` from the shell's `fg` or `bg`, the supervisor
   restarts its no-progress clocks and saves `termios` again, since the
   shell may have changed it. After `fg`, when its group holds the
   foreground again, it gives the foreground back to the command's group.
   Then it sends `SIGCONT` to the command's group and journals
   `terminal_continued`.

What this costs, and what stays open:

- The execution wall keeps running while the job is stopped
  (`CLOCK_BOOTTIME`, §6.4) and is acted on when it continues, as after a
  machine suspend.
- A descendant that moved itself to another process group is not stopped
  by `^Z` and keeps running while the supervisor is stopped. Every call the
  observer traces and every `connect` the mediator holds then blocks until
  the supervisor continues, which fails closed. No deadline can be acted on
  in that window, and the proxy is stopped too.
- A stop in a group the target gave the terminal to is not detected. This
  is a target that does job control itself, such as a shell, or an editor
  run in its own group. The terminal then belongs to a stopped group until
  the operator signals it from elsewhere. §6.3 records whether Claude Code
  does this.

### 3.5 Terminal injection: analysis

"Today" means a contained run with a terminal on standard input, which is
the common case, since §8.3 passes terminals through untouched. Rows marked
"by reading" are kernel behaviour not run here.

| # | Vector | Today | Terminal mode | Proposal; what it costs | Basis |
|---|---|---|---|---|---|
| 1 | **`TIOCSTI`**: pushes bytes into the terminal's input queue, which the shell reads after the agent ends | Filter: `EPERM`. Kernel, on every host: refused, because the terminal is not the caller's controlling terminal (`EPERM`). On the reference host also by `legacy_tiocsti = 0` (`EIO`, checked first). | The controlling-terminal precondition now holds. On a host with `legacy_tiocsti = 1` the kernel would inject, and the filter's `EPERM` is the only barrier. On the reference host the kernel still refuses. | Keep the rule in every contained baseline. `doctor` reports the host's `legacy_tiocsti` (text only) so the operator knows which barrier holds. Cost: nothing new. | Filter measured (`ioctl_tiocsti`). `legacy_tiocsti` measured on the VPS, unmeasured on the Pi. Order of the kernel's checks by reading, consistent with the measured `EIO`. |
| 2 | **`TIOCLINUX`** (virtual consoles only): paste of a selection into input, blanking, scrolling and other console subcommands | Allowed by the filter. Refused by the kernel without the console as controlling terminal (by reading). On a pty: `ENOTTY` (measured). | On a console: setting and pasting a selection, and loading the selection table, need `CAP_SYS_ADMIN` since Linux 6.7, and kernel-message redirection needed it long before (by reading; the reference host runs 7.0, the Pi unmeasured). The remaining subcommands, such as blanking and scrolling, become reachable. | Deny `TIOCLINUX` (`EPERM`) in every baseline, and never attach a console (§3.2). Cost: new seccomp tables and freeze digests. No agent is known to need it. | By reading; pty `ENOTTY` measured. |
| 3 | **Console keyboard and font ioctls** (`KDSKBENT`, `KDSKBSENT`, `KDSETKEYCODE`, `KDSKBMODE`, `PIO_FONT`…): remapped keys or function-key strings outlive the attempt, because keymaps are shared by all consoles | Refused without the console as controlling terminal or `CAP_SYS_TTY_CONFIG` (by reading `vt_ioctl`). | Reachable if a console were attached. | Never attach a console (§3.2). Cost: an operator at the Linux text console gets detached mode, or runs inside tmux or screen, which provide a pty. | By reading. |
| 4 | **`TIOCSETD`**: changes the terminal's line discipline, which breaks the operator's terminal after the attempt. Rarely used disciplines have historically been a route to kernel bugs. | Reachable on an inherited terminal descriptor; no controlling terminal needed (by reading). With `ldisc_autoload = 0` (measured on the VPS), only disciplines already loaded. | Same. | Deny `TIOCSETD` in every baseline. Cost: tables and digests. Nothing known breaks. | By reading. |
| 5 | **`termios` and window size** (`TCSETS*`, raw mode, echo off, `TIOCSWINSZ`) | Reachable on the descriptor. A killed agent leaves raw mode. | Same. Every terminal interface needs it. | Not filtered. Restore at settlement and on every relayed stop (§3.6). Cost: a deliberate `stty` change made from another terminal during the run is undone. | Inferred; K61 measures. |
| 6 | **Foreground process group** (`TIOCSPGRP`) | Refused without the controlling terminal. | The agent can give the terminal to another of its own groups, but cannot name the shell's group across the PID namespace (§3.3). | Take the foreground back at settlement and at a relayed stop. Cost: none. | By reading; inside view measured. |
| 7 | **Signals to the job** (`kill(0, …)`) | Stay inside (new session). | With a shared group: reach processes outside the namespace that share the group. Measured for the probe's shell, which shared it. In a real job that group holds the supervisor, bubblewrap's outer process and any pipeline member (`ukai-jail … \| tee`) (inferred). | Own process group (§3.3). Cost: the stop relay (§3.4). | Measured with plain bubblewrap (§3.1). The job's members are inferred. |
| 8 | **`/dev/tty`** | `ENXIO` (measured). | Opens: a second handle to the same terminal, not a new device (measured). Inside, `ttyname(0)` reads `/dev/console`, where bubblewrap's `--dev` binds a terminal (measured). Which descriptor's terminal bubblewrap binds there is by reading (standard output's, it appears); the probe had one pty on all three. | Allowed. This is part of what the mode is for. | Measured, except that one detail. |
| 9 | **Escape sequences written to the terminal**. Replies the terminal sends back to queries (cursor reports, `DECRQSS`, window-title reports where a terminal still allows them, colour and clipboard queries) land in the input queue, which the shell reads after the agent ends. OSC 52 writes the operator's clipboard. OSC 8 hyperlinks can hide their target. Cursor movement and attributes can hide or imitate the jail's own lines. | **Identical**: the agent writes the terminal directly today. | Identical: terminal mode adds nothing to what can be written. | No filtering: the jail does not parse output, and a partial filter would be a promise it cannot keep. After verified tree death the supervisor flushes the input queue (`TCIFLUSH`), discarding replies the agent asked for and did not read, and writes an attribute reset (`SGR 0`) and cursor-visible before the summary. Still open: clipboard writes, hyperlinks, a reply arriving after the flush (network latency; **candidate**: a status-report sentinel read before the flush, measured on the terminals of §6.3), lines forged before the summary, and the terminal emulator's own bugs. Cost: keys the operator typed while the agent was ending are discarded, and two short sequences go to stderr, only when stderr is a terminal. | By reading of terminal behaviour; not measured. Varies by terminal. |
| 10 | **Reading the operator's input after `^Z`** | Possible (§3.1, by reading). | A stopped group cannot read, and a background reader gets `SIGTTIN` (by reading). | Fixed by the mode itself. | By reading. |

What stays refused, whatever the agent does:

- attaching a virtual console, a serial line, or a terminal that is not the
  controlling terminal;
- terminal mode under `none`, under `--gate-fd`, or for a background job;
- `TIOCSTI`, `TIOCLINUX` and `TIOCSETD`;
- any signal from the command's group to a process outside the PID
  namespace;
- access to the operator's terminal after a settled attempt: settlement
  requires verified tree death (X07), so no descendant survives to read or
  write it. An attempt whose tree death is unproved says so (L01's explicit
  unknown, L05), and its receipt records the restore as made without that
  proof (§3.7). A survivor there is the existing `tree_unknown` case, and
  the operator runs `gc`.

### 3.6 Settlement in terminal mode

After the tree is verified dead and before the summary, in this order, each
step recorded in the receipt (§3.7). When tree death cannot be verified,
the supervisor still runs the steps before it exits, because the operator
needs a usable terminal, and the receipt says they ran without that proof:

1. Take the foreground back (`tcsetpgrp` to the supervisor's group, with
   `SIGTTOU` blocked).
2. Restore the `termios` saved at preparation, or at the last continue
   (`TCSANOW`).
3. Flush pending input (`TCIFLUSH`).
4. Write `ESC [ 0 m` and `ESC [ ? 25 h` to stderr when it is a terminal.

The window size is never restored, because it reflects the real terminal. A
failed step does not change the exit code. It is recorded and printed on
the cleanup line (`terminal not restored (termios: EIO): run reset`). If
the supervisor itself is killed, nothing is restored, and the shell takes
the foreground back when its job ends. That is a named limit.

### 3.7 Disclosure

- **Policy snapshot:** a new optional top-level `terminal` with the value
  `"attached"`. It is omitted when detached, so every detached snapshot and
  policy digest is unchanged. `explain` shows it with the condition that
  decided it.
- **Pre-exec line**, when stderr is a terminal: `terminal: attached
  (/dev/pts/N) · wall 8h`, or `terminal: detached (reason)` when conditions
  3–5 fail. The wall is shown because attached runs get their own default
  (§7, decision 8). With persistent state the same line continues with the
  state part §4.7 specifies.
- **Receipt:** a new optional `applied.terminal`, present when attached:
  `{device: "pty", session: "caller", process_group: "own", stops: N,
  restored: null | {foreground, termios, input_flushed, reset_written,
  after_tree_death}}` (booleans; `null` until the supervisor's end).
  `after_tree_death` is false when the steps ran without verified tree
  death.
- **Journal:** lifecycle notes `terminal_stopped` and `terminal_continued`
  (§3.4).

### 3.8 Costs in one place

- Two new filter rules, which means new seccomp tables, new digests and a
  new milestone freeze.
- One `setpgid`/`tcsetpgrp` step in the launcher.
- The stop relay in the supervisor, a `/proc` read per step only with
  observation off.
- Restore and flush at settlement, which lose type-ahead.
- `^C` and `^\` no longer stop the attempt from the terminal. The operator
  stops it through the agent, by closing the terminal, or with
  `kill -INT <supervisor>`. `doctor` and the guide say so.
- A `-p` run started from an interactive shell becomes attached too
  (condition 3 holds), so its `^C` now goes to the agent. Scripts that need
  today's behaviour pass `--terminal detach`.
- Attached runs get a longer default wall (8 h initial, §7, decision 8), so
  a forgotten session holds its grants and its credential lease longer.

## 4. Persistent vendor state

### 4.1 Today

A launch profile with `state_var`, `home_is_state` or credentials gets
attempt-private vendor state at `<data>/attempts/<id>/vendor-state/`. It is
created mode 0700 (`state::create_vendor_state`) and bound at
`/run/ukai/state` (`CLAUDE_CONFIG_DIR` for `claude`). Credentials are staged
in it. It is removed by anchored no-follow traversal once tree death is
verified (`cleanup::remove_vendor_state`). The receipt's `state_cleanup`
goes `pending` → `complete`, and `gc` resumes an interrupted removal
(jail-v1 §12, §14.2). The trace names no path below it: such a path is a
digest with the reason `vendor_state` (jail-v1 §11.3).

The A-row measured Claude Code's writes there (`.claude.json` and its lock)
and one refused `mkdir` of `~/.local/state` per run, with `HOME` unset. So
every run is a first launch, `--resume` has nothing to resume, and what the
operator configured inside one session is gone in the next.

### 4.2 Granularity: per launch profile and workspace

State is keyed by **the launch profile's name and the workspace's canonical
path** (the workspace §3.2 of the launch proposal resolves).

- **Why not per profile alone.** One state shared by every workspace would
  be the only channel between workspaces that the jail otherwise closes. An
  attempt in repository A, prompt-injected by a file it read, could plant
  something there that runs in repository B's next attempt with B writable:
  user-level hooks, helper commands, MCP server definitions, permission
  allow rules or memory, which Claude Code's documented user settings can
  hold (by reading of the vendor's documentation, not re-read for this
  proposal). The same attempt could read B's session transcripts and send
  them to an allowed host.
- **What per-workspace scoping costs.** The agent's own first-launch steps
  (theme, onboarding, folder trust) happen once per repository instead of
  once per host. A linked worktree is its own workspace and gets its own
  state, which matches Claude Code keeping history per working directory
  (by reading).
- **What it adds beyond today.** Little. The agent can already persist into
  its workspace (a project `.claude/settings.json`, a `CLAUDE.md`), which
  the next run reads, jailed or not. Persistent state reaches only the next
  jailed runs in the same workspace, and an unjailed `claude` never reads
  it, because it uses `~/.claude`. What is new is that the place is hidden
  from `git status`, which is why the receipt chain (§4.7) and `state show`
  (§4.9) exist.

### 4.3 Layout and ownership

```text
<data>/state/                       0700, private, under the runtime state root (jail-v1 §6.2)
  <launch-name>/                    0700
    <key>/                          0700; key = first 32 hex digits of
                                    SHA-256("ukai.jail.state/1\0" ‖ launch name ‖ "\0" ‖ canonical workspace path bytes)
      state.json                    private metadata, never mounted: state id `st_<uuid>`, launch name,
                                    workspace path (canonical codec), the workspace root's (dev, ino) at creation,
                                    generation, last release {attempt, private digest, time},
                                    holder {attempt, released}, quarantine, a bounded log of generations
      lease                         flock taken by the supervisor that holds the state; never reaches the child
      vendor/                       the directory bound at /run/ukai/state
```

- **Owner.** The operator's uid. Every level is created through anchored
  no-follow handles with the private-directory and private-group rules the
  attempt root already follows (jail-v1 §6.2). An existing level with
  another owner, wider modes, a symlink or a special node refuses
  (`unsafe_state_path`).
- **Registration.** The attempt's `jail-state.json` records
  `{kind: "persistent", state_id, key}` before the bind (jail-v1 §7
  registers resources before populating them), so `gc` knows which attempt
  last held which state.
- **The bind.** `vendor/` is opened by the anchored walk and bound through
  that handle, as credentials and the install root are, so a swap between
  the check and the bind cannot redirect it. The mount point stays
  `/run/ukai/state` and `state_var` stays the same, so absolute paths the
  vendor stores in its own state stay valid across runs.
- **The workspace check.** If the workspace root's `(dev, ino)` differs from
  the one recorded at creation (a repository deleted and cloned again at the
  same path), the run refuses with `state_workspace_changed`, naming
  `ukai-jail state rm`. ext4 can reuse an inode number immediately after
  delete and re-create, so the check can miss. That was seen in this
  project's earlier work but is not recorded in this repository; K74
  measures it. It is a named limit.

### 4.4 Protection

- **From the workspace.** The state lies under the data directory, which no
  grant may contain or lie inside (jail-v1 §6.2; the home refusal). A hard
  link between the workspace and state crosses two bind mounts and fails
  with `EXDEV` (by reading of `link(2)`), so neither side can alias a file
  of the other.
- **From other attempts.** Only attempts whose launch profile and workspace
  give this key bind it. The lease admits one attempt at a time (§7,
  decision 6). A different workspace's attempt never sees it.
- **Between attempts.** Nothing contained runs. The operator's own processes
  (same uid) can change it. The next acquisition detects that and records
  it (§4.6).
- **From its own content.** The supervisor reads state that a possibly
  compromised agent wrote, so every host-side walk (release, digest, scan,
  discard, `state rm`) is anchored and no-follow and never crosses a
  device. It opens only regular files, with `O_NOFOLLOW | O_NONBLOCK`, and
  records every other type without opening it: FIFOs, sockets and
  character devices. An unprivileged process can create a 0:0 character
  device, an overlayfs whiteout, without `CAP_MKNOD` since Linux 5.8, and
  the filter allows `mknod` (by reading). Each walk is bounded in entries
  and depth, as `cleanup.rs`'s `Limits` already is for removal, and, new
  here, in bytes read.

### 4.5 Credentials never persist

1. **Vault only.** A launch profile with `state = "persistent"` may declare
   only `vault` credentials. `copy_rw` and `bind_ro` refuse at load
   (`invalid_config`). `copy_rw` writes the credential's bytes into vendor
   state, where they would outlive the attempt. `bind_ro` binds the source
   read-only over a mount point there, so the bytes are not written. But
   with either mode the agent reads the real value, and any copy it makes
   lands in state that the next attempts inherit. The bundled `claude`
   profile already declares only vault credentials. The child holds an
   attempt-scoped placeholder, so anything the vendor saves from its
   environment is useless in a later attempt.
2. **A discard list.** `state_discard = [".credentials.json"]` is profile
   data: relative paths, validated like `state_subdirs`. Each one is removed
   at release with the cleanup walker, never followed, and its contents are
   never read. For `claude` this covers a `/login` made inside a session.
   Such a login should fail anyway, because the profile does not allow
   `platform.claude.com`, which the vendor documents for the token exchange.
   That is inferred, not run: the A-row recorded only that headless runs
   never contacted it, and §6.3 run 5 tests it. The receipt counts the
   entries removed and names none.
3. **A candidate secret scan.** The release pass that computes the private
   digest also searches every regular file for the value of each vault
   credential this attempt loaded, which the supervisor holds in memory.
   Vault credentials are never staged, so the value exists only there. It
   is a fixed-string search, as the benchmarks' exposure checks do. Any hit
   quarantines the state: the release is recorded, the receipt gets
   `credential_persisted`,
   and the next acquisition refuses `state_quarantined` until the operator
   runs `state rm`. The value is never printed. The file is named only by
   `state show` on the operator's host, never in a receipt. This is what
   catches a server that reflects the secret into a transcript (jail-v2 §1:
   vaulting cannot promise the child never learns it). Encoded, compressed
   or split copies are not found. Its cost is measured by K73 before it
   becomes a must.

### 4.6 Acquisition and release

**Acquisition** happens during preparation, under the preparation budget,
before the bind:

1. Derive the key and open or create the levels.
2. Take the lease without blocking. If it is held, refuse `state_busy`,
   naming the holding attempt.
3. Read `state.json`. If `holder.released` is false, the last holder died
   before releasing, so refuse `state_busy`, naming it and `ukai-jail gc`.
   If the state is quarantined, refuse `state_quarantined`.
4. Run the workspace check (§4.3).
5. Recompute the private digest and compare it with the last release's:
   `matches_release` is `true` or `false`, or `null` with a reason when there
   was no release (a new state) or the walk passed its bound.
6. Record `holder = {this attempt, released: false}`. Only now is the state
   bound.

The private digest is SHA-256 over a canonical manifest: sorted entries of
relative path bytes, type, mode bits, size, the SHA-256 of a regular file's
content, a symlink's target bytes. It lives in `state.json` only.
**Initial** bounds per pass: 256 MiB of content and 65,536 entries. Past
them the digest is unavailable (`state_too_large`) and no comparison is
claimed. **Candidate:** an incremental manifest keyed on
`(ino, size, mtime, ctime)`, adopted only if K73 shows the full pass is too
slow. The coarse change-time residual of the launch proposal's §8 item 20
applies to it.

**Release** happens after verified tree death, in place of today's removal:

1. Apply the discard list.
2. Recompute the digest, run the scan (§4.5), increment the generation, and
   append the log entry.
3. Write `holder.released = true` durably.
4. Drop the lease.
5. Set the receipt's `state_cleanup` to `released`.

The state directory itself is never removed by the supervisor. If the tree
is unproved or integrity is lost, the state is retained with
`holder.released` false, exactly as vendor state is retained today, and
nothing can acquire it until `gc` finishes the release (§4.9).

### 4.7 What the receipt says about state that outlives the attempt

- **`state_cleanup`** gains the value `released`: "persistent state was
  released: discards applied, digest and generation recorded, lease
  dropped; kept by design". A receipt with persistent state is never
  `complete`. It is `pending` from acquisition until the release is
  durable, and `not_needed` keeps its meaning. A settled receipt can stay
  `pending`, as today, for the same reasons.
- **A new optional `vendor_state`**, present only for persistent state:

  ```json
  "vendor_state": {
    "kind": "persistent",
    "state_id": "st_…",
    "generation_start": 4,
    "generation_end": 5,
    "inherited_from": "att_…",
    "matches_release": true,
    "matches_release_reason": null,
    "discarded": 0,
    "secret_scan": "clean"
  }
  ```

  The fields:
  - `generation_end` is `null` until release.
  - `inherited_from` is the attempt whose release produced the starting
    state, `null` for a new state.
  - `matches_release_reason` is one of `new_state`, `state_too_large` or
    `unreadable` when `matches_release` is `null`.
  - `secret_scan` is `clean`, `found`, `not_scanned` or `null` before
    release.

  No path, file name, size or content digest appears. The private digest
  stays in `state.json`, where only the operator can compare it, so a
  shared receipt is no oracle for guessing the state's content (the
  jail-v1 §12 revision 21 reasoning, applied to vendor state).
- **Inheritance is explicit.** A reader of attempt N+1 learns which state
  it started from, which generation, which attempt last wrote it, and
  whether anything changed it in between. Auditing N+1 therefore means
  auditing N too, and so on back. The log in `state.json` lists the chain
  (`state show`). What the receipt cannot say: what the state contains, or
  whether an earlier attempt's writes were benign.
- **The policy snapshot** gains `roots.vendor_state = {kind: "persistent",
  profile: NAME}` beside today's `{kind: "managed"}`, plus
  `launch.state_discard`. That list is present only when the state is
  persistent, and omitted otherwise, including for a profile that declares
  it run with `--state attempt`. An attempt-private run therefore keeps
  rc.3's snapshot bytes. Persistence changes the policy digest: the agent
  sees data that other attempts wrote.
- **The pre-exec line**, when stderr is a terminal, names the state before
  exec: `state: NAME, this workspace, generation N (from att_…)`, or
  `state: NAME, new for this workspace`. When the acquisition found the
  state changed since its last release, it adds `· changed outside the jail
  since att_… released it`. In terminal mode this continues the
  `terminal:` line (§3.7); otherwise it is a line of its own.

### 4.8 Settings: never `~/.claude` wholesale

State starts empty. Nothing from `~/.claude`, `~/.claude.json` or any other
home file is copied, linked or read, the jail-v1 §12 rule as before. The
operator configures the agent inside a session (theme, permissions,
memory), and that persists through §4.6 like any other write. A seeding
mechanism (named, explicit, read-only files copied into a new state) is
left for a later proposal. With one, an operator could copy
`~/.claude/settings.json`, which can hold helper commands and environment
values meant for the host.

### 4.9 `gc` and the `state` verbs

- **`gc` never deletes persistent state** on its own, and never treats a
  state directory as a cleanup target. It is operator data, like the
  workspace.
- **`gc` finishes a pending release.** It acts for an attempt whose
  `holder.released` is false and whose tree death the receipt or `gc`'s own
  verification proves: the same permission rule as a pending vendor-state
  removal today (jail-v1 §14.2). It applies the discard list, digest,
  generation and `released = true`. It records the scan as `not_scanned`:
  only the dead supervisor held the vault value, and `gc` does not read
  credential sources. It completes the receipt's `state_cleanup`
  to `released` when the receipt itself permits (otherwise it records the
  release in jail state and its report, as today), and appends the receipt
  note jail-v1 §13.3 describes. Lost integrity leaves the state held and
  quarantined. The report gains a `persistent_state` field per attempt it
  touched.
- **New verbs.**
  - `ukai-jail state list [--json]`: launch name, workspace path, id,
    generation, size, last attempt, quarantine.
  - `state show NAME [--workspace PATH]`: metadata and the generation log;
    names files only on the operator's host.
  - `state rm NAME [--workspace PATH]`: refuses while leased; anchored,
    no-follow removal.

  `state` joins the built-in verbs that are never launch names (launch
  proposal §3.1).

## 5. Contract changes, row by row

| Where | Today | Change | Kind |
|---|---|---|---|
| North star §4.3, "bubblewrap with … `--die-with-parent`, `--new-session` …", applied for every profile other than `none` | Always `--new-session` | Amended like jail-v1 §8.3 below: terminal mode omits `--new-session` and gives the command its own process group. | Contract change |
| jail-v1 §6.4, initial error codes | `invalid_config` … `internal_error` | Adds `state_busy`, `state_quarantined`, `state_workspace_changed` and `credential_persisted`. The receipt schema's `code` is a free string, so the schema itself does not change for them. | Error codes |
| jail-v1 §7, attempt layout | `vendor-state/` "only when a launch profile requires it" | Adds `<data>/state/<launch>/<key>/` outside every attempt, registered by the attempt that holds it (§4.3). | State layout |
| jail-v1 §8.1, steps 2 and 9 | Register vendor resources; after settlement "clean managed vendor state" | Step 2 also acquires persistent state (§4.6). Step 9 releases it instead of removing it. | Lifecycle |
| jail-v1 §8.3, "The command runs in a new session; INT/TERM/HUP received by the supervisor request termination." | Always a new session | "…in a new session, except in terminal mode (§3.2), where it runs in the caller's session in its own process group, made the terminal's foreground group by the launcher. Terminal-generated signals then reach only that group. INT/TERM/HUP received by the supervisor, and a hangup of its terminal, request termination." | Contract change (§7, decision 7 of the launch proposal asked for it) |
| jail-v1 §8.3, "No PTY or interactive job-control emulation is provided." | — | Kept: terminal mode attaches the operator's terminal and emulates nothing. Adds the stop relay (§3.4), which is job-control propagation, not emulation. | Clarification |
| jail-v1 §8.3, "the backend must prevent TIOCSTI-style terminal injection" | `TIOCSTI` filtered | Adds `TIOCLINUX` and `TIOCSETD` to the filter, pty-only attachment, and the settlement restore (§3.5, §3.6). | Strengthening |
| jail-v1 §9.2, "a new session"; "terminal injection" | One `ioctl` rule | Same wording as §8.3. The `ioctl` rule lists three requests. New `seccomp-table-*.txt` evidence for all ten tables, and new digests in [milestone-1-freeze.toml](jail-v1/milestone-1-freeze.toml) at the next freeze. | Filter, evidence |
| jail-v1 §12, "On pre-exec refusal or verified tree death, remove vendor state…" | Always removed | "…remove attempt vendor state; release persistent state (§4.6), which is never removed by the supervisor or `gc`." | Contract change |
| jail-v1 §12, grammar | `state_var`, `home_is_state`, `state_subdirs` | Adds `state = "attempt" \| "persistent"` (default `attempt`) and `state_discard`. `persistent` refuses `copy_rw` and `bind_ro` credentials. | Launch-profile grammar |
| jail-v1 §12, initial profile table, `claude` row | `CLAUDE_CONFIG_DIR` to vendor state | The bundled `claude.toml` gains `state = "persistent"` and `state_discard = [".credentials.json"]` (§7, decision 7). | Profile data |
| jail-v1 §13.2, field groups | Cleanup: `not_needed`/`pending`/`complete` | Cleanup adds `released`. New groups: optional `vendor_state` (§4.7) and optional `applied.terminal` (§3.7). | Receipt |
| [jail-receipt.schema.json](jail-v1/jail-receipt.schema.json) | `ukai.jail.receipt/1` | Re-blessed in place: one enum value and two optional objects. All additive. The precedents are the J12 `by` value and the `resolver_refused` field in [frozen-schemas.toml](jail-v1/frozen-schemas.toml). Fixtures for attached, persistent-new, inherited, changed-outside, pending and quarantined. | Schema |
| [policy-snapshot.schema.json](jail-v1/policy-snapshot.schema.json) | `ukai.jail.policy-snapshot/1` | Re-blessed in place: optional `terminal`, `roots.vendor_state` kind `persistent` with `profile`, and `launch.state_discard`, present only with persistent state. Omitted values keep today's canonical bytes. | Schema |
| [jail-summary.schema.json](jail-v1/jail-summary.schema.json) | `ukai.jail.summary/1`, lines `status`…`cleanup` | Re-blessed in place: a `state` line (facts: the `vendor_state` object's values). The `cleanup` line also carries a failed terminal restore. | Schema |
| [jail-event.schema.json](jail-v1/jail-event.schema.json) | — | Unchanged. The new lifecycle transitions are safe names the schema already admits. | None |
| Launch proposal §4.1, "At most eight lines" | 8 | 9: the `state` line, printed whenever state is persistent. K48 changes with it. | Presentation |
| Launch proposal §3.6 table and §3.7 | "Vendor state… empty at start, deleted at settlement"; "no `--resume`" | Superseded by this proposal once implemented; the launch proposal gets a pointer. | Docs |
| [operating.md](jail-v1/operating.md) | — | Commands (`--terminal`, `--state`, the `state` verbs), Launch profiles (the removal bullet), Zero-config launch (the interactive example without `-p`), `gc`, the summary, and new Named limits (escape sequences, stopped-job deadlines, a stray descendant during a stop, VT and serial terminals detached, inode reuse in the workspace check, no seeding). | Guide |
| operating.md, Profiles table, `agent` wall | 2 h | 8 h initial for attached runs only (§7, decision 8). Detached runs keep 2 h. The receipt records the applied wall as it does today. | Default limit |
| CLI | — | `run --terminal auto\|detach`; `[jail] terminal` in `config.toml`; `run --state attempt\|persistent` (overrides the profile, so `--state attempt` keeps today's behaviour); `state list/show/rm`. The alias still parses no jail option. | CLI |
| `doctor` | — | Text only, as J12's additions were: whether a run here would attach and why not, the host's `legacy_tiocsti`, and the profile's state (present, generation, held, quarantined). `ukai.jail.doctor/1` is unchanged. | Doctor |
| [agent-compatibility.md](jail-v1/agent-compatibility.md) | One Claude Code row (headless) | A separate interactive row (§6.3). | Support record |
| North star §4.5 `claude` row | Node-local credential and settings files | Already amended by the launch proposal. Settings now persist from inside sessions, not from host files. | Docs |

## 6. Tests and the compatibility run required before "supported"

### 6.1 Terminal rows

The K49 pseudo-terminal harness drives these rows. Each attached-mode row
also runs detached, where it must show today's behaviour.

| Row | Claim |
|---|---|
| K55 | Mode selection: attached exactly when §3.2's five conditions hold. Otherwise argv contains `--new-session`, the snapshot has no `terminal`, and with attempt-private state the snapshot and policy digest are byte-identical to rc.3's for the same inputs. `--gate-fd`, `none`, `learn` and `--terminal detach` stay detached and print nothing. A console (major 4), a serial-like device (a test seam standing in for one), a background job and stdin that is not the controlling terminal stay detached, and the pre-exec line names the reason. |
| K56 | Attached, under `agent` and `tool` with observation on and off: `/dev/tty` opens, `TIOCGWINSZ` matches the harness, a resize made by the harness delivers `SIGWINCH` to the target, and the target's group is the terminal's foreground group. The launcher's `tcsetpgrp` with `SIGTTOU` *blocked* succeeds (the probe only showed *ignored*). The target's blocked set (`SigBlk`) equals the operator's, including when the operator's shell starts the jail with signals blocked. |
| K57 | S02 extended: `kill(0, …)`, `kill(-pgid, …)` for every pgid visible inside, `setpgid` to an outside group and `tcsetpgrp` to an outside group never reach or affect the supervisor, bubblewrap's outer process, namespace init, the shell, or another member of the operator's job (a `ukai-jail … \| cat` pipeline member that traps every catchable signal). |
| K58 | Signals: harness `^C` and `^\` reach the target's group only, and the attempt continues if the target survives them. `SIGINT`, `SIGTERM` and `SIGHUP` sent to the supervisor, and a harness hangup (master closed), each end at verified tree death (L01 extended). |
| K59 | Job control: harness `^Z` stops the target's group, the supervisor takes the foreground back, restores `termios` and stops, and the harness's shell sees the job stopped. `fg` gives the foreground back and resumes both; `bg` resumes without the foreground. Observation on and off. A descendant that left the group keeps its observed calls and connects blocked while the supervisor is stopped. A wall deadline that passes during the stop is acted on at continue. `terminal_stopped` and `terminal_continued` are journaled. |
| K60 | Filter: `TIOCSTI`, `TIOCLINUX` and `TIOCSETD` return `EPERM` in every contained baseline, on the controlling terminal and on `/dev/null`, so the answer is the filter's on a host whose kernel already refuses. Other ioctls reach the kernel. The ten tables are re-pinned and the freeze recomputed. |
| K61 | Settlement restore: a fixture that leaves raw mode and echo off, gives the foreground to another of its groups, leaves elicited replies in the input queue and sets `SGR 8` (conceal). After settlement: `termios` equals the saved copy, the foreground is the jail's group, the input queue is empty, the summary bytes follow the reset, and `restored` reports all five fields true. The same after a wall expiry, after an external `SIGKILL` of the target, and with a step forced to fail (recorded false, exit code unchanged). With tree death made unprovable by a test seam, the steps still run and `after_tree_death` is false. |
| K62 | Injection regression: an in-jail fixture tries every vector of §3.5 rows 1–7 and 9. After the jail exits, the harness's session leader reads none of the fixture's bytes from the terminal. |
| K63 | X05 in terminal mode: the target's bytes reach the pty unchanged and in order. The pre-exec line, the reset sequences and the summary appear only before exec and after tree death. |
| K64 | Disclosure: `explain` text and JSON, the pre-exec line (with the wall an attached run gets), the snapshot and the receipt show attached and detached as §3.7 says. An attached run's receipt records the attached-run wall default, and a detached one keeps 2 h. The re-blessed schemas validate every new fixture. |

### 6.2 State rows

| Row | Claim |
|---|---|
| K65 | Grammar: `state`, `state_discard` and their validation. `persistent` with a `copy_rw` or `bind_ro` credential refuses at load. `--gate-fd` with persistent state refuses. `--state attempt` restores today's behaviour exactly: `launch.state_discard` is omitted, so the snapshot equals rc.3's for the same inputs. |
| K66 | Layout and protection: modes and owners, anchored creation, the handle bind, and a swap between check and bind refusing. Another workspace's attempt cannot see the state. A hard link between workspace and state fails. Symlinks, FIFOs and sockets the agent leaves are never followed or opened by any host-side walk, and `state rm` removes them as links. |
| K67 | Lease: a second concurrent attempt on the same key refuses `state_busy` naming the holder (decision 6). A supervisor killed mid-run leaves `holder.released` false, and the next attempt refuses until `gc` releases. The lease descriptor never reaches the child (X06 enumeration). |
| K68 | Release: discards applied without following links, the generation incremented, the log appended, the receipt `released` and `vendor_state` filled. The directory is still present. L05: an unproved tree retains the state unreleased. |
| K69 | Chain: N+1's `inherited_from` is N and `matches_release` is true when nothing touched the state. An operator edit between them makes it false, and the summary says `changed outside the jail since att_… released it`. A new state reports `null` with `new_state`. No receipt carries a content digest or any name below the state (a search over the receipts of every K69 run). |
| K70 | Secret scan (candidate): a test origin that reflects the substituted header into a response the fixture writes into state. Release quarantines, the receipt has `credential_persisted` and `secret_scan: found`, the next acquisition refuses `state_quarantined`, and the value is found nowhere in receipts, journal or stderr. |
| K71 | `gc`: never removes a state. It finishes a pending release under the jail-v1 §14.2 permission rules, appends the receipt note, and changes nothing in a dry run. `state list/show/rm` behave as §4.9 says, and `rm` refuses while leased. |
| K72 | Summary: golden fixtures for the `state` line (new, inherited unchanged, changed outside, pending, quarantined, digest unavailable) and for a failed terminal restore on the cleanup line. K52 still holds: `tail --summary` equals the live lines, and `summary_check.py` is extended. |
| K73 | Cost on the reference host: acquisition and release for states of 1 MiB, 64 MiB and 256 MiB, and at the entry bound; the scan's added time; the result against the 30-second preparation budget. Past the bound, the digest is unavailable and nothing claims a match. |
| K74 | The workspace check: a workspace removed and re-created at the same path with a different inode refuses `state_workspace_changed`. The same-inode case is recorded as the named limit, not as a pass. |
| K75 | I02: no agent name in the new code. `.credentials.json` occurs only in profile data, docs and fixtures. |

### 6.3 The interactive Claude Code compatibility record (A-row)

A separate row from the 2026-10-17 headless one. It makes interactive
`ukai-jail claude` supported for one build.

- **Where and what.** The reference host, stock. A clean `ukai-jail`
  revision with its binary SHA-256 recorded. Claude Code from the native
  installer, with its version and the resolved executable's SHA-256
  recorded. The bundled `claude` profile, unchanged and persistent.
  `claude-oauth` through the vault. Two fresh git repositories, A and B. The
  terminal is a pty driven by a scripted harness that records both
  directions with timestamps, and is reached over SSH, the way an operator
  reaches the reference host.
- **Runs.**
  1. First interactive launch in A with an empty state: whatever onboarding
     appears is answered at the keyboard, then the A01 fixture task with
     Claude Code's own permission prompt answered at the keyboard (no
     `--dangerously-skip-permissions`), then `/exit`.
  2. Second launch in A: no onboarding expected. `--resume` lists run (1)'s
     session and continues it, and `--continue` does too.
  3. A launch in B: run (1)'s session is not listed.
  4. Inside a session: a resize during generation (the interface reflows),
     `^C` during generation (the turn is interrupted, the attempt
     continues), `^Z` then `fg` (the interface comes back), and a hangup
     (the attempt ends settled).
  5. `/login` inside a session: it fails visibly (`platform.claude.com`
     denied), and no `.credentials.json` remains after release.
  6. A headless `-p` run started from the interactive shell, now attached,
     and the same run with stdin a pipe, detached. Both pass the 2026-10-17
     row's task and evidence conditions, with `state_cleanup` `released` in
     place of its `complete`.
  7. Ten repetitions of (2), each failure kept.
- **Pass conditions.**
  - Every receipt is settled with six classes active without gaps,
    `tree_empty` true, `credentials` listing one id with `never_staged`,
    and `state_cleanup` `released`, with generations chaining from run to
    run and `matches_release` true.
  - Every run exits 0 except run (4)'s hangup, whose outcome is whatever
    the agent does on `SIGHUP` (recorded, exited or signaled) or the
    supervisor's stop, and it must still settle with verified tree death.
  - Every attached run has `applied.terminal.restored` with all five fields
    true. Run (6)'s detached half has no `applied.terminal`.
  - The token's value is absent from receipts, journals, workspaces, the
    harness transcript and the state (the K70 search).
  - After each attached run, the harness's shell reads none of the
    session's bytes (K62).
- **Vendor facts this run settles**, each recorded with its evidence:
  - whether `CLAUDE_CODE_OAUTH_TOKEN` is honoured interactively, so that no
    login prompt appears;
  - which hosts an interactive first launch contacts;
  - whether `home_is_state` is needed;
  - the files Claude Code writes in its state, by `state show`;
  - whether it uses the alternate screen;
  - whether it stops on `^Z` or handles it, and whether it ever gives the
    terminal to another process group (an external editor), which §3.4
    cannot relay;
  - whether the contained environment (`PATH`, `LANG`, `TERM`, `TZ` and the
    profile's variables; no `COLORTERM`, no `LC_*`) is enough for its
    interface;
  - state growth per session.
- **Not covered.** The Raspberry Pi (its `legacy_tiocsti` is unmeasured,
  and rows 1–2 of §3.5 assume nothing about it), npm installs, other
  versions, other terminal emulators beyond the one the harness emulates,
  and OpenCode. Each needs its own row.

## 7. Decisions for the operator

Each has a recommendation. The body above follows the recommendation, and
changes with the decision.

1. **Process groups.** Recommended: the command gets its own process
   group, made foreground by the launcher, and the supervisor relays stops
   as `sudo` does (§3.3, §3.4). The alternatives are (a) a shared group
   repaired with Landlock's signal scope, which needs kernel 6.12 or later
   and makes `^C` and `^Z` reach the supervisor, and (b) a pty relay, the
   strongest isolation, but the jail becomes a terminal relay and X05
   equality ends.
2. **When terminal mode applies.** Recommended: automatically, on every
   contained `run` that meets §3.2's conditions, with `--terminal detach`
   and `[jail] terminal = "detach"` to keep today's behaviour. The
   alternative is an opt-in flag, which would leave `ukai-jail claude`
   broken interactively unless the operator knows the flag. Automatic mode
   changes what `^C` does for every terminal-started run (§3.8), which is a
   contract change of the kind jail-v2's no-legacy rule allows.
3. **Filter additions.** Recommended: deny `TIOCLINUX` and `TIOCSETD` in
   every contained baseline, attached or not. That is one table per
   baseline, but new digests and a new freeze. The alternative is to deny
   them only when attached, which means two variants of every table.
4. **Terminal restore at settlement.** Recommended: take back the
   foreground, restore `termios`, flush input, and reset attributes and the
   cursor, accepting that type-ahead is lost (§3.6). The DSR-sentinel drain
   stays a candidate until measured.
5. **State granularity.** Recommended: per launch profile and workspace
   (§4.2). The alternative, per launch profile, gets onboarding once per
   host but opens a channel between workspaces.
6. **Concurrent attempts on one state.** Recommended: refuse the second
   with `state_busy`, naming the holder. The alternatives are to fall back
   silently to attempt-private state (refused here: it would hide that the
   session is not persisted), to fall back with a visible pre-exec line, or
   to share the directory (Claude Code locks its own files, but the receipt
   chain would no longer say which attempt wrote what).
7. **The bundled `claude` profile.** Recommended: `state = "persistent"`
   with `state_discard = [".credentials.json"]`, and the secret scan as a
   candidate that K73 must clear. The alternative is persistence as an
   operator opt-in, which keeps every run a first launch for the default
   user.
8. **The execution wall in terminal mode.** The `agent` default is 2 h
   (operating.md, Profiles), and an interactive session is often longer.
   Recommended: an initial 8 h for attached runs, shown in the pre-exec
   line and recorded in the receipt as any wall is. The alternative is to
   keep 2 h and document `--limit wall=…`, which the alias cannot pass.
