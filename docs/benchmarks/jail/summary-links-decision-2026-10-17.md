# The workspace line and links: count the entry a call created (decision, 2026-10-17)

[The decision before this one](claude-code-workspace-line-decisions-2026-10-17.md)
left a follow-up: the end-of-run summary's workspace line took both
`fields.path` and `fields.path2` of every successful `fs.create` and called
them "opened for writing". Two calls have a second path that the call never
writes:

- `symlink(target, link)` and `symlinkat`: `path2` is the target, a string
  the kernel stores in the new link without resolving it (the closed set puts
  the link in `path`). Worse, a relative target was joined to
  the caller's working directory by the audit classifier, which is not what
  it resolves against: whoever follows the link resolves it later, against
  the link's own directory and their own root. The O01 matrix pinned the join.
- `link(existing, name)` and `linkat`: `path` is an existing file that gets a
  new name. Nothing is opened, and nothing is written to it.

So `ln -s README.md link` in the workspace printed README.md as opened for
writing. This is a K46 overclaim, and the archive has two of them (below).

| | Decision |
|---|---|
| 1. The summary | **Count only what each call wrote**, by `fields.syscall`: both sides of a rename; of an `fs.create`, the entry it created (`path2` of `link`/`linkat`, `path` of `symlink`/`symlinkat`, `path` of everything else). An `fs.create` with a `path2` and any other `syscall` names neither path and counts as unnamed. A written path the event did not record at all counts as unnamed too. |
| 2. The event | **A symlink's target is never a path**: a digest of its bytes with the reason `symlink_target`, relative or absolute, with no `path2_dirfd`, and no working directory is read for it. Unavailable as any snapshot when incomplete (`path_truncated`) or empty (`empty_path`). |

## 1. The summary: the entry a call created

### Alternatives

- **Drop `path2` of every `fs.create`.** It mends `symlink` and breaks `link`:
  a hard link's new name is the one entry it created, and it is in `path2`.
- **Drop the second path everywhere but `fs.rename`, and count `path`.** It
  mends `symlink` and leaves `link` counting the existing file, the second
  half of the overclaim.
- **Key on the call (chosen).** `fields.syscall` is on every audit result
  this build and every earlier one writes, and the closed set fixes which
  argument each row puts in which field. It is the only reading that is right
  for both.

### When the call does not say

An `fs.create` carrying a `path2` whose `syscall` is none of the four can only
come from a journal this build did not write. Taking `path` would be wrong
for a `link` (the existing file), taking `path2` wrong for a `symlink` (the
target), so neither is named. Counting it as a result with an unnamed path
keeps it visible without naming anything, which is the rule unnamed results
already follow. For the same reason a written path that is absent from its
event (a `link` result with no `path2`) is now unnamed rather than silently
not counted. No producer writes either shape: a successful call always has
both pointers, and the tracer describes every path it read.

### What K46 now checks

The property test already compared every count with the generated run's
truth. A count can be right while a name is wrong, so it now also requires
that every listed path is one a result wrote. Its generator adds symlinks
whose target is a `symlink_target` digest or, as journals from earlier
builds have it, a workspace path; hard links whose existing file is named or
not; and creations that do not say which path they made, all using names
(`t-only`) that no result writes. Reverting the `link` rule to both paths
fails K45's new golden and K46 at once; the three mutations of
`summary_check.py` tried (a target counted, an absent path not unnamed, a
creation that does not say which path it made read as `path`) each fail K52.

## 2. The event: a target is stored, not resolved

### The argument for keeping a classified target

An absolute target that spells a workspace file says something a reader
wants: this link points at README.md. A digest hides it.

### The argument against

The classification asserts a relationship to a root (jail-v1 §11.3: "only
when its relationship to that root is established"), and a target has none
at event time: the call stores the bytes, and only a later reader resolves
them, against their own root. The same bytes mean different files inside and
outside the jail. An absolute `/tmp/x` classified `scratch_relative` names
the attempt's scratch, but the link, left in the workspace, points at the
host's `/tmp/x` once the run is over. A relative target was worse: joined to
the caller's working directory, it named a file the target may never reach.
A target spelled `/proc/self/fd/N/x` also got a `path2_dirfd` it never used.

### Decision

A complete target is `{kind: digest, reason: symlink_target}` of exactly its
bytes. It keeps the event-time evidence — whether a link still holds what it
was created with can be checked against the digest — without naming a path.
`unavailable` would have thrown the bytes away for no gain. The tracer no
longer reads the working directory for a target (it already read no
descriptor), so a sibling's `chdir` during a `symlink` with an absolute link
is no `path_anchor_unverified` gap of a name nothing resolved. The link
itself is classified as any path: relative to the working directory, below a
directory descriptor, or absolute.

## What it changes in the archive

Every one of the 2,031 archived attempts (a `jail.json` and a
`trace.ndjson` anywhere under `docs/`) was summarized by the binary of
f96a94721 and of this change, and `summary_check.py` recomputed this change's
summary of each: it agrees on all 2,031. Exactly two summaries change, the
two OpenCode reruns of the [Claude Code record](claude-code-compatibility-2026-10-17.md)
(`runs/o01-a01`, `runs/o02-a01`):

| | f96a94721 | this change |
|---|---|---|
| workspace | `1 path opened for writing · 155 results with unnamed paths` | `0 paths opened for writing · 155 results with unnamed paths` |
| the one path | `testing`: the target of OpenCode's `symlink("testing", …)` outside the workspace, joined to its working directory | none |

OpenCode wrote nothing into the workspace in either run. The archived
`tail-summary.*` files stay as recorded; the record now says what they
overstate.

## Verification

- Reference host, release build of this commit's tree, `UKAI_CONFORMANCE=1`,
  inside `systemd-run --user --scope -p Delegate=yes`: the `ukai-jail`
  library 921/921 (new `a_symlink_target_is_a_digest_never_a_path`),
  `j4_closed_set_linux` 18/18 (new
  `j4_o06_a_link_names_only_the_entry_it_creates`, which also summarizes its
  own run; the O01 matrix now expects a `symlink_target` digest and has an
  absolute target under every profile), `observer_regression_linux` 30/30
  (`r25` now asserts no working directory is read for a target),
  `review_linux` 46/46, `observer_linux` 17/17, `portable_summary` 61/61,
  `ukai-fixture` 253/253, and `clippy -D warnings` on `ukai-jail` and
  `ukai-fixture`, all targets.
- Mutation on the host: with the target classified as before and the working
  directory read for it again, the four O01 matrix tests, the new live test,
  `r25` and the new unit test fail.
- macOS: the workspace suite under `UKAI_CONFORMANCE=1`, 1741 passed and
  0 failed. A first run hung once in
  `bridge::tests::bytes_flow_both_ways_and_half_close_is_forwarded`, code
  this change does not touch; it passed 5 of 5 times alone and in the full
  rerun. Within it, `portable_summary` 61/61 (K45 golden
  `k45_links_count_only_the_entry_they_create`, K46 with the new generator
  case and the listed-name check, over 1,000 cases rather than 600 so that a
  disagreement is still reached, K52 with a links case), xtask 233/233
  (acceptance map against both specs, new clause O06.6), every
  `contracts.yml` check, `i02-scan` 0 hits, `clippy`, `fmt`, and the archive
  sweep above.
