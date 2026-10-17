# Claude Code's workspace line: the two remaining gaps (decision, 2026-10-17)

[The finding before this one](claude-code-workspace-line-2026-10-17.md)
named Claude Code's temporary file and left 15 unnamed results in the A01
run: the rename of that file to `greeting.txt` (`relative_to_dirfd` on both
sides), 13 opens of `/dev/null` (digests `outside_known_roots`), and one
`unlinkat` through a descriptor in scratch. It left two decisions open. This
note takes them, says what changed, and gives the evidence.

| | Decision |
|---|---|
| 1. A call with no returned descriptor, through a directory descriptor | **Resolve it**, below the descriptor's own link, only when that link reads the same at the entry and exit stops (`path_basis: directory_link`). A disagreement leaves the call relative and is a counted bookkeeping gap (`path_anchor_unverified`). The working directory, which jail-v1 §11.3 already resolved from one read, is held to the same two reads. |
| 2. `/dev/null` | **A digest reason, `standard_device`**, for a successful open the kernel corroborated whose returned descriptor is, by device number, one of the six character devices bubblewrap's `--dev` creates. Not a label on `/dev`. |

On the reference host the A01 workspace line goes from
`1 path opened for writing · 15 results with unnamed paths · 1 refused write`
to `1 path opened for writing, 2 in renames · 1 refused write`, still
`6/6 classes active, no gaps`.

## 1. Names through a directory descriptor

The question: `rename(/proc/self/fd/14/greeting.txt.tmp…, /proc/self/fd/14/greeting.txt)`
returns no descriptor, so nothing the kernel hands back says which directory
it resolved the names through. Reading `/proc/<tid>/fd/14` at a stop says
which directory descriptor 14 named *when it was read*.

### The argument for keeping `relative_to_dirfd`

- **No corroboration.** The open case was named because two kernel facts
  agreed (the directory's link and the returned descriptor's). A rename has
  one fact, read from a table every sibling thread shares (`CLONE_FILES`). A
  sibling that `dup2`s another directory onto 14 while the call runs makes
  the event name a path the call never touched. A false name is worse than
  no name.
- **Under-naming is honest.** K46 forbids overclaiming, not underclaiming.
  "15 results with unnamed paths" is true.
- **The rule was deliberate and is pinned.** "True `dirfd` resolutions keep
  their distinct `relative_to_dirfd` reason" (§11.3), `j4_o06_foreign_dirfd`,
  `j4_o06_two_paths_independent`, `r6_a_foreign_dirfd_is_not_resolved_against_a_cwd`,
  and O06.2, "a dirfd never resolves against the wrong directory".
- **The procfs spelling adds an assumption.** `/proc/self/fd/14/x` reaches
  descriptor 14 only if the tracee's `/proc` is procfs. A process that can
  mount (`none`, or a nested bubblewrap under `none`) can make it something
  else, and then the substituted name is false in every view.
- **The working-directory precedent proves less than it seems.** Its
  residual (a sibling's `chdir`) was never stated, and it was read once, at
  the entry stop. Citing it is citing a weakness.

### The argument for resolving

- **Equal evidence, equal claim.** Since 2026-10-10 (f7fbf5520) the jail
  names `mkdirat(AT_FDCWD, "made")` from one read of `/proc/<tid>/cwd`, a
  structure siblings share (`CLONE_FS`), for every call, renames included.
  `AT_FDCWD` is the descriptor that means "the working directory". Refusing
  `mkdirat(N, "made")` for a descriptor of the same directory does not track
  any difference in evidence. It tracks history: J4 pinned
  `relative_to_dirfd` on 2026-09-23, when no relative name was resolved at
  all, and the working-directory change left descriptors as they were
  without an argument either way.
- **The race is a residual the jail already accepts.** §11.4 (audit L8): for
  every call without a returned descriptor, the exit re-read bounds a name
  to "the argument memory was stable across the call", because a sibling can
  flip the bytes for the kernel and restore them. That race produces exactly
  the false name above. The jail accepts it, catches the persistent case
  with a second read, and states the rest. Holding the anchor to the same
  two reads puts it at the same bar, no lower.
- **Never a prefix or a spelling.** The name is two complete strings: the
  kernel's `d_path` of the directory (no symlinks, no `..`), byte-identical
  at both stops, and the complete relative name, which has no `.` or `..`
  (those stay digests). A link that is not a path, or ends in ` (deleted)`,
  names nothing.
- **Separable.** A distinct `path_basis` (`directory_link`) lets a consumer
  that trusts only argument snapshots and corroborated opens drop it.

### What decided it

Every argument for keeping applies with the same force to two things the
jail already does: resolving relative names against the working directory,
and reporting the pathname bytes of every non-open call. The jail cannot
honestly hold descriptors to a stricter rule than those two, and dropping
those two is not on the table: they name most of what tools write. The one
argument specific to the open case, that a corroborated name is stronger,
still holds: a successful open is still named only by its returned
descriptor, never below the directory.

What the first argument does add: a race should leave a visible trace. One
read cannot catch anything. So the decision is not "read the link at the
stop", but:

- read the anchor at the entry stop **and** at the exit stop, for
  descriptors and for the working directory;
- resolve only when the two reads are byte-identical;
- on a disagreement, keep the relative claim, deliver the event, and record
  one bookkeeping `path_anchor_unverified` gap per call, counted in
  `lifetime.native.details.path_anchors_unverified`. Like
  `path_claim_unverified`, it degrades no class and never stops a strict
  run: no result is missing, and the cause can be innocent (another process
  renaming an ancestor of the directory).

The procfs assumption is handled by the profile. The spelling is resolved
this way only where `/proc` is pinned: a contained profile, whose baseline
refuses every mount interface, `chroot`, `pivot_root`, `unshare`, `setns` and
namespace clone (jail-v1 §9.2) under a `/proc` bubblewrap mounted. Under
`none` it stays `relative_to_dirfd`. A true `dirfd` needs no `/proc`. A
symlink's target is stored by the call, not resolved, and is never read
through a descriptor.

### The residual, measured

A ptrace observer cannot see the moment the kernel looks the anchor up; it
sees the anchor before and after. A sibling that swaps it and swaps it back
between the two reads leaves a false name and no gap. The race test
measures that, live:
[race.txt](results/claude-code-workspace-line-2026-10-17/anchors/race.txt).
One thread calls `mkdirat` 200 times through the anchor. Another swaps the
anchor between two directories in a tight loop. Each call makes a new name,
so the disk says where the kernel put it.

| Profile | Anchor | Named | Named below the directory the kernel did not use | Unresolved (gap) |
|---|---|---|---|---|
| `tool` | `dirfd` | 162 | 15 | 38 |
| `tool` | `/proc/self/fd/N/` | 110 | 37 | 90 |
| `tool` | working directory | 116 | 42 | 84 |
| `agent` | `dirfd` | 118 | 45 | 82 |
| `agent` | `/proc/self/fd/N/` | 105 | 49 | 95 |
| `agent` | working directory | 98 | 47 | 102 |

Under this deliberate worst case, 7 to 25% of the raced calls carry a name
below the wrong directory, and 19 to 51% are caught. That is the size of the
residual, not a rounding error, and §11.4 now says so. Three things bound
what it means:

- **It needs a hostile process.** It takes a thread swapping the anchor
  continuously while another thread makes path calls through it. In the A01
  run with this build, Claude Code moved no anchor during a call
  (`path_anchors_unverified` is 0). No other agent was run with this build.
- **It is the bytes' residual, not a new one.** The pathname-bytes race in
  the same run (`j4_o06_racing_pathname_is_only_a_literal_snapshot`) left
  161 names and caught 139 of 300 calls. A process that wants to misreport
  a rename's directory can already do it through the bytes.
- **It is no longer silent for the working directory.** Before this change
  the working directory was read once, at the entry stop. Every
  working-directory call counted "unresolved" above would have been named
  against that read, with no gap, and wrongly whenever the kernel used the
  other directory.

The summary prints no path names in its text line, and its evidence line
drops `no gaps` when any bookkeeping gap is present. The receipt names the
gap and its count. Closing the residual needs an observer that sees the
kernel's own lookup (an eBPF or LSM hook on the path operation), which this
note does not attempt.

### The rule, as implemented

- Tracer, entry stop
  ([`args.rs`](../../../crates/ukai-jail/src/platform/linux/tracer/session/args.rs)):
  for a complete name through a descriptor (`dirfd` ≠ `AT_FDCWD`, or
  `/proc/{self,thread-self}/fd/N/`), read `/proc/<holder>/fd/N`: the group's
  table for `self`, the thread's otherwise. The working directory is read
  only for names at `AT_FDCWD`, no longer for names under a true `dirfd`.
- Tracer, exit stop
  ([`exit.rs`](../../../crates/ukai-jail/src/platform/linux/tracer/session/exit.rs),
  `verify_anchors`): re-read each anchor and keep it only when it reads the
  same. A successful open keeps none (it is `descriptor_link` or nothing).
- Writer ([`audit.rs`](../../../crates/ukai-jail/src/platform/linux/audit.rs),
  `below_directory`): join the kept link and the name; classify like any
  path (workspace, scratch, vendor state, roots, outside);
  `path_basis: directory_link` when either path of the call was named so. A
  moved working directory is `relative_to_unresolved_cwd`. The procfs
  spelling is used only with `with_proc_pinned(true)`, set by the contained
  boundary alone.
- jail-v1 §11.3 and §11.4, the O06 row (§15) and the K30 row (jail-v2 §11
  and the acceptance map, K30.2 to K30.4, O06.2) say the same.

The A01 run: the rename names `greeting.txt.tmp.2.f74859419087` and
`greeting.txt` (`directory_link`, `path_dirfd` 14), and the scratch
`unlinkat` through a descriptor is `scratch_relative`
`claude-1000/fswatch-probe-…/probe`. `path_anchors_unverified` is 0.

## 2. `/dev/null`

### The argument for leaving it

The 13 opens are unnamed, and the line says how many results are unnamed.
Nothing is overclaimed. A label must not hide a write: `/dev/fd/<N>/<name>`
is a symlink spelling of the descriptor route into the workspace,
`/dev/stdout` and its kin are symlinks to whatever descriptor 1 is, a file
below `/dev/shm` is a real file on a tmpfs, and an operator can bind a device
in (`--dev-bind`, a GPU). Any rule on the spelling `/dev/…` would hide some
of those.

### The argument for a rule

The unnamed count is there to bound the uncertainty about workspace writes.
13 of the 15 were writes the kernel itself says went to the null device. A
count that is mostly noise is one a reader learns to ignore, which defeats
it. Vendor state set the precedent: a result established not to be a
workspace path does not count as an unnamed one.

### Decision: by the kernel's descriptor, never the spelling

A successful open whose name is otherwise a digest `outside_known_roots`
becomes a digest with the reason `standard_device` when:

1. K30 corroborated it, so the returned descriptor's link is exactly the
   absolute snapshot;
2. the name is below `/dev/` (only these pay for the extra read); and
3. `stat` of the returned descriptor at the exit stop says it is a
   character device numbered `null` 1:3, `zero` 1:5, `full` 1:7, `random`
   1:8, `urandom` 1:9 or `tty` 5:0, the nodes bubblewrap's `--dev` creates.
   None of them stores what is written to it.

What stays as it was, and is tested: `/dev/fd/<N>/<name>` reaching a
workspace file (K30 downgrades it, since the link is not the snapshot); a
file below `/dev/shm` (not a device); `/dev/stdout` (a symlink, downgraded);
`/dev/mem` and a granted `/dev/nvidia0` (not one of the six); and a device
node the classifier could name inside the workspace (named, as before). A
`rename` or `unlink` of `/dev/null` is refused by the kernel and counted as
a refused write, as before. The residual is K30's: a sibling that replaces
descriptor `ret` with a `/dev/null` descriptor before the exit stop.

## Verification

- Reference host, release build of this commit's working tree,
  `UKAI_CONFORMANCE=1`, inside `systemd-run --user --scope -p Delegate=yes`:
  `j4_closed_set_linux` 17/17 (new
  `j4_o06_a_descriptor_moved_between_the_stops_is_not_resolved`; updated
  `j4_o06_a_name_through_a_descriptor_is_named_by_the_kernels_resolution`
  with `/dev/null`, `/dev/fd/<N>/`, `/dev/shm`; `j4_o06_foreign_dirfd`,
  `j4_o06_two_paths_independent`), `review_linux` 46/46 (`r6` updated), and
  the `ukai-jail` library 919/920. The one failure is
  `vault::origin::linux_tests::a_process_execd_with_a_loader_environment_is_refused_at_the_pin`
  (review F8), which also failed 3 of 5 times run alone. It exercises only
  `vault/origin.rs` test code this change does not touch, and the session
  that recorded a5bb3e36b saw it fail once under load. Its child-exec wait stops at
  the first unreadable `/proc/<pid>/exe` link, which looks like the cause
  (not verified): a follow-up.
- Outside a delegated scope, the `none` and bootstrap tests refuse to skip
  under `UKAI_CONFORMANCE=1` (they need the delegated leaf) and pass inside
  one. `r9_an_explicit_pids_ceiling_runs_only_when_enforced` likewise.
- New unit tests: the tracer keeps an anchor only when both stops agree
  (eleven scripted cases: both spellings, a true `dirfd`, the working
  directory, moved, closed, never readable, a successful and a refused open,
  a symlink's target), reads a device number only for a corroborated name
  below `/dev/`, charges the links to the queue; the writer names below a
  kept link, gates the procfs spelling on `/proc` being pinned, and gives the
  six devices, and no other, `standard_device`; the observed half treats
  `path_anchor_unverified` as bookkeeping.
- `clippy -D warnings` on `ukai-jail` and `ukai-fixture`, all targets, on
  the host and on macOS; `ukai-fixture` tests on both (new `race-dirfd` mode,
  `open --dev-fd`).
- macOS: the workspace suite under `UKAI_CONFORMANCE=1`, 1740 passed and
  0 failed, including `portable_summary` 60/60 (K45 golden for this shape,
  K46's generator with `standard_device` digests and unresolved renames, K52
  recomputation) and xtask (acceptance map against both specs); every
  `contracts.yml` check; `i02-scan` 0 hits; `fmt`.
- A01 on the reference host (Claude Code 2.1.302, `agent`, vault, a fresh
  repository; `ukai-jail` sha256 `a647fb65…`):
  [anchors/](results/claude-code-workspace-line-2026-10-17/anchors/). It
  settled, exited 0, wrote `hello`, and used the credential on 4 proxy
  results. `summary_check.py` recomputed every line from the archived
  receipt and journal, and the token is in none of the run's files
  (`grep -F`, file names only, on the host).

| | [after a5bb3e36b](results/claude-code-workspace-line-2026-10-17/after/tail-summary.txt) | [this change](results/claude-code-workspace-line-2026-10-17/anchors/tail-summary.txt) |
|---|---|---|
| workspace | `1 path opened for writing · 15 results with unnamed paths · 1 refused write` | `1 path opened for writing, 2 in renames · 1 refused write` |
| the rename to `greeting.txt` | `relative_to_dirfd` both sides | `workspace_relative` `greeting.txt.tmp.2.…` → `greeting.txt`, `directory_link` |
| `/dev/null` opens | 13 digests `outside_known_roots`, counted | 13 digests `standard_device`, not counted |
| scratch `unlinkat` through a descriptor | `relative_to_dirfd`, counted | `scratch_relative`, not counted |
| evidence | `6/6 classes active, no gaps` | `6/6 classes active, no gaps` |

## Follow-ups, not done here

- **A symlink's target is counted as "opened for writing".** The workspace
  line takes `path2` of every `fs.create`. For `symlink`/`symlinkat` that is
  the target string, which the call stores without touching, and a relative
  one is joined to the working directory, which is not what it resolves
  against (O01 pins that join). For `link`, `path` is the existing file. Both
  overstate what the call did, and are K46 territory. Done the same day:
  [summary-links-decision-2026-10-17.md](summary-links-decision-2026-10-17.md).
- **Name bookkeeping gaps in the evidence line.** Today a
  `path_claim_unverified` or `path_anchor_unverified` gap only removes
  `no gaps`. Naming it, with its count, would let a reader of the text line
  see that names in this run rest on a raced anchor.
- **A working-directory open could be corroborated exactly.** K30 compares
  only the tail of a relative name with the returned descriptor's link.
  Requiring the working directory and the name to equal the link, as
  `descriptor_link` does, would close this residual for opens through the
  working directory.
- **The F8 vault test** above.
