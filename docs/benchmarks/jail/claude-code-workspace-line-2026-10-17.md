# Claude Code's writes in the summary's workspace line (2026-10-17)

The [Claude Code compatibility record](claude-code-compatibility-2026-10-17.md)
found that the end-of-run summary never names the workspace files Claude
Code writes: r02 printed
`workspace: 0 paths opened for writing · 85 results with unnamed paths`
although Claude Code had written `greeting.txt`. This note finds the cause on
the reference host, says what changed in Ukai, and what still is not named.

Evidence: [results/claude-code-workspace-line-2026-10-17](results/claude-code-workspace-line-2026-10-17/).
Claude Code 2.1.302 (native, the same build as the record), the reference
host as recorded there (Ubuntu 26.04.1, kernel 7.0.0-31), `ukai-jail claude
-p "Create a file named greeting.txt containing the single word hello."
--dangerously-skip-permissions --output-format json` in a fresh git
repository, under `agent`, the credential through the vault as in the record.

## Cause: Claude Code writes through `/proc/self/fd/<N>/`

A [bpftrace probe](results/claude-code-workspace-line-2026-10-17/open.bt) of
every `openat` with `O_CREAT` during the run (read-only, outside the jail)
shows how Claude Code writes the file
([before/opens-claude-code.log](results/claude-code-workspace-line-2026-10-17/before/opens-claude-code.log), line 29):

```text
OPEN pid=740533 tid=740545 comm=Bun Pool 0 dfd=-100 flags=02500301 ret=15 path=/proc/self/fd/14/greeting.txt.tmp.2.ab0417c1c039
```

Descriptor 14 is the workspace directory, which Claude Code holds open
(the after run below shows its link; Claude Code's own code checks a staging
directory's identity before an atomic write). The write creates the
temporary file `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` *through
procfs*, as a runtime whose file API has no `openat` (Bun's) must to stay
below a pinned directory, and renames it to the final name the same way: the record's r02 journal has a `rename` whose second path digest is
`sha256("/proc/self/fd/14/greeting.txt")`, the same digest in r02, r06 and
r07 although their workspaces differ.

So the tracer's snapshot of the open is `/proc/self/fd/14/greeting.txt.tmp…`
and the descriptor it returned links to
`/home/ubuntu/…/ws/greeting.txt.tmp…`. The K30 corroboration compared the
snapshot as an absolute path, component by component, so the two could never
agree. The claim was downgraded (`path_truncated`, `path_complete: false`)
with one bookkeeping `path_claim_unverified` gap per write. The rename's two
paths were classified by their spelling as digests `outside_known_roots`.
Both were counted as unnamed, and nothing was named.

The other suspects do not apply: the flags carry no `O_TMPFILE`; no rename
race is involved (the two spellings never match, whatever the timing); the
bind mount is not at fault (`python3`'s absolute `__pycache__` writes in the
same workspace were corroborated and named in r03). It is Bun's own I/O.

The rest of the 85, counted in the run below with the fixed build (the
digests are the same): 69 results (28 opens, 15 mkdirs, 13 removals and 13 renames) are Claude
Code's own state under `/run/ukai/state` (`.claude.json` and its temporary
files, backups, `sessions/`, `projects/`), 13 are opens of `/dev/null` (their
digest is `sha256("/dev/null")`), and one is an `unlinkat` through a
descriptor in scratch. All
but the last were digests `outside_known_roots`: the audit classifier labelled
the workspace, scratch and the system and grant roots, not vendor state.

## What changed

1. **The procfs spelling is a descriptor resolution.**
   `/proc/self/fd/<N>/<name>` and `/proc/thread-self/fd/<N>/<name>` are
   classified exactly as `openat(N, name)`: `unavailable` /
   `relative_to_dirfd`, with `path_dirfd: N`. They are no longer a digest
   "outside the known roots" (the call landed in the workspace), and an open
   spelled so is corroborated as the relative name it is, so no spurious
   `path_claim_unverified` gap. A symlink below the directory still fails the
   comparison and is still downgraded.
2. **An open through a descriptor is named by the kernel's resolution when
   both links agree** (`path_basis: descriptor_link`, jail-v1 §11.3). At the
   open's exit stop the tracer already reads `/proc/<tid>/fd/<ret>`. It now
   also reads the directory descriptor's own link (the group's table for
   `self`, the thread's for `thread-self` and a true `dirfd`), and only when
   that link followed by the name is exactly the returned descriptor's link
   does the event name that link, classified as any path is. A removed
   directory or file (` (deleted)`), a link that is no path, a `..`, a
   symlink and `O_TMPFILE` never name anything. This applies to a true
   `dirfd` open too, so `openat(N, "slug.py")` is named the same way.
3. **Vendor state has its own digest reason.** A path below `/run/ukai/state`,
   when the attempt staged vendor state, is a digest with the reason
   `vendor_state`: still never named (jail-v1 §12: no trace includes vendor
   state), but the summary no longer counts it as an unnamed workspace path,
   as it never counted scratch.

`summary_check.py` follows the new unnamed rule, and the K45, K46 and K52
tests cover it.

## Why this keeps the honesty rules

- **§11.3, "a prefix is never asserted as a path":** nothing is named from a
  snapshot prefix or from a spelling. A name comes only from two complete
  kernel links read at the same stop, and only when they agree with the
  tracee's own name. Everything else keeps the weaker claim it had or a weaker
  one (`relative_to_dirfd` is a weaker claim than a digest of a spelling).
- **K46, never overclaim:** the counts can only move from "unnamed" to
  "named" on that evidence. The only number that shrinks is the unnamed count,
  by vendor-state results, on the same spelling basis that already keeps
  scratch and grant paths out of it.
- **Residuals, stated:** the descriptor table is shared, so a sibling thread
  could swap both descriptors between the kernel's resolution and the two
  reads; K30's corroboration already has this residual. A rename, unlink or
  mkdir *through a symlink planted in vendor state* is labelled by its
  spelling, as one through scratch already is; opens through such a symlink
  are caught by the corroboration.

## What is still not named

Claude Code's rename of the temporary file to its final name has no returned
descriptor, so it stays `relative_to_dirfd`. The line therefore counts the
temporary file (`greeting.txt.tmp.<pid>.<hex>`, listed by name in
`tail --summary --json`), not `greeting.txt`, and the rename stays among the
unnamed results. Naming it would mean resolving a directory descriptor read at
the syscall stop for calls with no result to check it against, which jail-v1
§11.3 deliberately does not do for true `dirfd`s (the J4 tests pin it). That
is a separate decision.

The 13 `/dev/null` opens are still counted as unnamed. Labelling the jail's
`/dev` the way vendor state now is would remove them, but `/dev/fd/<N>/<name>`
is a symlink spelling of the same descriptor route as `/proc/self/fd/<N>/`, so
a label on `/dev` by spelling could hide a real workspace write from the
count. That needs its own rule and is not part of this change.

## Before and after on the reference host

The same A01 fixture, Claude Code 2.1.302 (sha256 `60d7eb7f…`), each in a
fresh repository. Before: the F2 review build left on the host (`ukai-jail`
sha256 `a4db85dd…`, built on 2026-10-17 from that branch; its exact revision
was not recorded, and `git diff` shows no change to the audit, tracer or
summary code between that branch and the record's 56f9fb15), which
reproduced r02's workspace line exactly. After: this change (`ukai-jail`
sha256 `8664dee5…`, built on the host from the working tree of this commit).

| | [before](results/claude-code-workspace-line-2026-10-17/before/tail-summary.txt) | [after](results/claude-code-workspace-line-2026-10-17/after/tail-summary.txt) |
|---|---|---|
| workspace | `0 paths opened for writing · 85 results with unnamed paths · 1 refused write` | `1 path opened for writing · 15 results with unnamed paths · 1 refused write` |
| evidence | `6/6 classes active` (one `path_claim_unverified` gap) | `6/6 classes active, no gaps` |
| the temporary file's open | `unavailable` / `path_truncated`, `path_complete: false` | `workspace_relative` `greeting.txt.tmp.2.84efbb107b12`, `path_basis: descriptor_link`, `path_dirfd: 14` |
| its rename to `greeting.txt` | two digests `outside_known_roots` | `relative_to_dirfd` both sides, `path_dirfd`/`path2_dirfd: 14` |
| vendor-state results | 69 digests `outside_known_roots`, counted as unnamed | 69 digests `vendor_state`, not counted |

Both runs settled, exited 0, wrote `hello`, used the credential on 4 proxy
results, and `summary_check.py` recomputed the after run from its archived
receipt and journal
([summary-check.txt](results/claude-code-workspace-line-2026-10-17/after/summary-check.txt)).
The token appears in neither run's files (`grep -F` with the vault source,
file names only, run on the host).

## Verification

- Unit tests (Linux, reference host): the procfs spelling parser, the
  descriptor predicate, the tracer's exit path (nine scripted cases: both
  spellings, the group's and the thread's table, a true `dirfd`, a moved or
  removed directory, `O_TMPFILE`, a disagreeing name), and the classifier and
  writer (`descriptor_link`, `relative_to_dirfd` with its descriptor,
  `vendor_state`).
- `j4_o06_a_name_through_a_descriptor_is_named_by_the_kernels_resolution`,
  under `tool` and `agent` on the reference host, with `ukai-fixture`'s new
  `open --dirfd DIR [--proc-fd]` and `rename … --dirfd DIR --proc-fd`: Claude
  Code's exact call shapes, plus a true `dirfd` and a symlink below the
  directory (still downgraded, the run's only gap).
- K45 golden for this shape, K46's generator and truth extended with
  `vendor_state` digests, writes outside the roots and descriptor writes, K52
  recomputation of the new case; `summary_check.py` and the binary agree on
  all 2,029 archived receipt and journal pairs under `docs/benchmarks`.
