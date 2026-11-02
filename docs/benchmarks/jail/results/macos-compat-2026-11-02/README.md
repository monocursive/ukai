# macOS compatibility measurements — 2026-11-02

**Development evidence only. No release gate is promoted; NC01 stays open
and the protected-Mac release run (K104) remains explicitly blocked.** This
run closes the three open findings the [2026-11-01 custody
spike](../macos-custody-spike-2026-11-01/README.md) left: default-host
process headroom, whole-stop-path timing, and the full SQLite repository
build. Same retained Tart VM (`ukai-custody-spike-20261101`, macOS 27.0
build `26A428`, SIP disabled, ad-hoc entitlement, isolation re-verified at
every entry; fresh guest root `/Users/admin/ukai-compat-20261102`).

## 1. Process headroom (amended rule 6, jail-macos §4.1)

The spike's refusal (wanting 1376 against a default `kern.maxprocperuid`
1333) is fixed by the amended rule: the full 1024 headroom where it fits,
otherwise **the inherited ceiling itself** — never raised, kernel-bounded,
membership-table-sized — provided the ceiling clears the operator's
snapshot by at least 128; below that preparation refuses naming the
numbers and the remedy. The receipt now records the applied allowance and
a `process_headroom_clamped` flag; the supervisor plans it at prepare time
and the guardian's read-back remains the gate.

| Measurement (this VM) | Result |
| --- | --- |
| Default ceiling 1333, quiet host (~300 procs), smoke 2/2 | PASS, `headroom=1024 clamped=false` |
| Default ceiling 1333, busy host (665 procs — the spike's refusal shape), smoke 2/2 | **PASS, `headroom=668 clamped=true`** |

## 2. Whole-stop-path timing (NC09/NC11 reconciliation)

The receipt now carries `stop.phases` (continuous clock): `requested →
freeze_done → first_kill → result → guardian_record → settled`, plus the
guardian's own machine marks in its record (`stop_phases`); a unit test
pins their ordering and shared clock. K92 rerun with 3 trials × 5
adversarial shapes, all PASS ([k92.json](results/k92.json)), and the
reconciliation table is [k92-phases.json](results/k92-phases.json):

- The machine's whole stop is **20–74 ms** (freeze ≈ 0, first kill at the
  20 ms sweep, result by 74 ms) under every shape including fork storms and
  exec loops; the guardian's record lands by **~330 ms** after the request.
- The spike's 2.4–5.3 s "operator stop to oracle" interval is therefore
  **harness-side measurement overhead** (the finish wait plus the
  per-identity snapshot oracle), not product stop latency. The two clocks
  measured different intervals, as suspected; now the receipt's own marks
  bound the product's contribution. NC09/NC11 acceptance still requires a
  qualified oracle, but the cancellation path is no longer uninstrumented.

## 3. Full SQLite source-tree build (K93's ordinary large-repository shape)

**Diagnosis** (host-measured): Apple's `tclsh8.5` creates its `exec`
error-capture files **without honoring `TMPDIR`** (a capture succeeds with
an unwritable TMPDIR) and stats the system `P_tmpdir /private/var/tmp`;
under the profile that stat is denied (`EPERM`, which Tcl surfaces as
"not owner"), and no write is ever attempted — the member TMPDIR already
points at the granted scratch root, so the spike's failure was tool
behavior, not a missing product grant.

**Resolution** with explicit, receipt-recorded operator grants (no silent
broadening; both appear in `profile_parameters`):

- `--rw /private/var/tmp` for Tcl's error files, and
- the workspace also granted `--ro`, which admits it as an **exec root**
  while the later read-write entry keeps writes allowed (last-match-wins,
  re-measured here: `./hello` from the workspace executes, writes still
  succeed). This is the interim shape of §13.3 step 4's
  workspace-helper review — build tools generate executable helpers
  (`lemon`, `mkkeywordhash`, `jimsh`) in the workspace — pending the
  per-helper digest design the section requires.

Result: [k93-full-var-tmp.json](results/k93-full-var-tmp.json) — configure
and `make -j4` complete, `sqlite3`, `libsqlite3.a` and `sqldiff` built,
`select sqlite_version()` answers **3.53.2**, exit 0, both custody streams
contiguous and observation active for the whole build. The 2026-11-01
amalgamation-passes/source-tree-fails split is closed for the development
tier.

## §4.10 amendment recorded the same day

The Mach allowlist is now structurally empty (the bootstrap strip leaves
members no port to look anything up through); admitting any future service
requires the guardian-side broker design, with its own threat review,
receipt record and per-entry K90 probe — see jail-macos §4.10.

## Configuration

- Product: `9c8ce2297` + this branch's uncommitted jail work (headroom
  amendment, stop instrumentation, both pinned by new tests); host build,
  Rust 1.98.1, release, `--locked`. Staged binary and harness hashes in
  [provenance.json](provenance.json); [harness/](harness/) is the exact
  guest script set (Trial gained `extra_rw`; setup's en0 check asserts
  address-absence).
- Guest evidence archive: [guest-evidence.tar.gz](guest-evidence.tar.gz)
  (sha256 beside it); per-trial receipts in [receipts/](receipts/),
  including the two clamped-headroom smoke receipts. Final guest check
  PASS (no test-owned processes or jobs); VM stopped and retained
  ([vm-final-state.json](vm-final-state.json)).
