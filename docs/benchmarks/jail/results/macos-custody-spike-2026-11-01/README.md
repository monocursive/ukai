# Native custody measurement spike — 2026-11-01

**Development evidence only. NC01 is not accepted; no release gate is promoted.**
The spike found a workload-reachable launchd deputy route to both custodians.
The native default-off gate, entitlement, packaging, K95/K96 fault and memory
pressure tests, K104 protected-Mac run and all other native release requirements
remain in place. This does not establish an external-only both-lost residual.

## Results

The final measurements are summarized in [summary.json](summary.json); raw guest records are
retained in [guest-evidence.tar.gz](https://github.com/monocursive/ukai/releases/download/evidence%2Fmacos-custody-spike-2026-11-01/macos-custody-spike-2026-11-01-guest-evidence.tar.gz) (a release asset over the evidence
store's 5 MiB limit; [bundle.json](bundle.json) names its SHA-256). Every independent process snapshot precedes
harness cleanup. A positive result describes only the recorded fixture and
configuration, not the complete acceptance row.

| Check | Result | Scope |
| --- | --- | --- |
| Documentation and acceptance-map repair | Pass | All nine prior documentation failures repaired; 34 documentation tests, contract validation and 71 xtask gate tests pass. K98 and K99 wording agrees between spec and map. |
| Native/J17 smoke with adjusted guest limit | 2/2 pass | Command and mutation runs settle; `macos-closed-v1` attaches; six expected mutation actions appear. Full K105–K107 remain untested. |
| K90 class-2 fresh preloaded-job `kickstart` | 2/2 fail | Sandboxed requests start an unsandboxed job that sends `SIGCONT` successfully to the supervisor or guardian. Both outside positive controls succeed. |
| K90 class-2 fresh-job `load` | 2/2 pass | No inside execution marker; both outside controls execute and reach the live custodian. This is only a subset of class 2. |
| K92 adversarial drain | 25/25 drain checks pass; timing qualification open | Five repetitions of parallel forks, mutual `SIGCONT`, an orphaned group with a stopped member, a fork chain and an exec loop. Both custody streams are contiguous and all recorded identities are dead before cleanup. |
| K93 event load | 10/10 bounded checks pass | Five fork/exec storms and five signal floods; both custody streams remain contiguous, including the guardian under signal load. No observed custodian loss. |
| K93 SQLite amalgamation fixture | Pass | Four parallel configurations produce their libraries with active J17 coverage and contiguous custody streams. |
| K93 full SQLite source-tree build | Fail / qualification blocked | Configure stops in Tcl subprocess error capture with `couldn't create error file for command: not owner`, including after explicit SDK and writable temporary-directory settings. The project build does not reach `make -j4`; the smaller fixture cannot satisfy this requirement. |

K92 operator-stop-to-independent-oracle-start: **p50 2,426 ms, p95 4,386 ms,
maximum 5,274 ms**, all 25 samples retained. The last exec-loop trial was only
independently confirmed after five seconds, while its receipt's internal drain
timer reports 20.3 ms against 5,000 ms. The two clocks measure different
intervals; this does not establish when that tree actually became empty.
The harness's drain pass is not a timely-end acceptance claim. Instrument the
whole cancellation path and poll identities across the deadline before
accepting NC09/NC11; do not discard the slow sample or loosen the stop budget.

K93's ten event-load samples have operator-stop-to-oracle-start **p50 2,418 ms
and p95 2,651 ms**. These are bounded stress measurements, not a guarantee
against all notification load or memory pressure. All K92/K93 recorded workload
identities and both custodians were gone at the retained pre-cleanup checks.

## Configuration and attribution

- Product revision: `9c8ce2297bcb4da80e5912dc38e9ef23a234c1b5`, dirty build, Rust
  1.98.1, release optimization. `provenance.json` records its build-input digest,
  staged binary hash and exact input archive. `product-source.patch` captures
  the already-present candidate `mach-bootstrap` denial and its regression
  test. The spike does not modify product source or replace the candidate.
- Tested profile digest:
  `1c72b38b2059f20dc4f559323a3c0a861823ddf7967a893917d9731ca4789039`.
  The candidate denial is insufficient: `kickstart` still executes outside
  the sandbox. A receipt's verified descendant tree does not include that
  launchd-created deputy and therefore does not prove full containment.
- Fresh Tart VM `ukai-custody-spike-20261101`: macOS 27.0 build `26A428`, SDK
  27.0, four virtual CPUs, 8 GiB RAM, UID 501. The pinned Cirrus image digest
  is in `provenance.json`. The guest has SIP disabled and an ad-hoc ES
  entitlement; no Apple provisioning profile or signing credentials.
- Host SIP stays enabled. No host shares, clipboard, audio or USB passthrough.
  Guest Ethernet is disabled; IPv4 and IPv6 default routes are absent. System
  tunnel defaults were explicitly removed in the guest. Tart's VM socket
  carries only curated inputs and results; no operator credentials are copied.
- Guest `kern.maxprocperuid` was raised from 1,333 to 2,000 while
  `kern.maxproc` stayed 2,000. The runner uses a 2,000 soft process limit.
  With the default ceiling, two smoke attempts refused during preparation:
  the guardian needed 1,376/1,378 slots against an inherited hard limit of
  1,333. This is an unresolved default-host compatibility issue, not a release
  recommendation to raise system limits. See `guest-process-limits.json`.
- SQLite 3.53.2 amalgamation sources were downloaded on the host from SQLite's
  official distribution and hashed in `sqlite-source.json`; the guest builds
  four configurations with `make -j4` entirely offline. The separate full
  canonical SQLite 3.53.2 source tree contains 2,202 files / 111,727,666 bytes,
  revision `d6e03d8c777cfa2d35e3b60d8ec3e0187f3e9f99d8e2ee9cac695fd6fcdf1a24`.
  Its archive URL and hash are in `sqlite-full-source.json`. Its failed
  configure does not satisfy K93's large-repository build requirement.

## Harness checks and retained failed attempts

The first smoke product receipt settled, but the harness failed during cleanup
because `proc_pidinfo` does not supply a custodian audit token. The corrected
signal selector uses the independently checked unique process identity plus
the current PID/version; it is explicitly not presented as a captured token.
[Apple's XNU lookup](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_proc.c)
checks PID/version for this operation. A separate guest control confirms that
the wrong version returns `ESRCH`, leaves the sleeper alive, and the correct
version terminates only the test sleeper. Raw selector checks are archived.

The first adjusted-limit run stopped at a missing absolute `/sbin/mount` path
in the isolation guard. The first deputy fixture then exited 77 because its
post-sandbox VM check queried a denied sysctl. The fixture now checks the
allowed `hw.model` for `VirtualMac2,1`; the outside Python guard independently
requires the VM bit, disabled guest SIP, disabled Ethernet, no default routes
and no host share. The revised fixture refuses on the host before creating a
log or forking (`host-refusal-check-v2.json`). Earlier failed-attempt logs and
trial directories are retained and excluded from successful-run counts.

The five full-repository attempts remain separate raw records. The first two
used a compiler wrapper in the writable workspace; the current native profile
only executes programs from admitted read-only roots, so autosetup did not
accept that wrapper. Adding `PATH` did not solve it. Calling the admitted
compiler directly exposed missing SDK selection; explicitly supplying the SDK
passed those header checks. Both the SDK-configured attempt and the final
attempt with a private writable temporary directory then stopped in Tcl error
capture. `guest-tcl-denial.log` records sandbox denials including
`file-read-metadata /private/var/tmp` for the test Tcl process. This needs a
focused compatibility diagnosis; the record does not attribute every failure
to that one denial. No policy rule or grant was broadened to force a pass.

The process oracle compares stable birth identities, excludes zombies and
records known survivors before any emergency cleanup. It is an independent
fixture oracle, not a system-wide proof that no unrecorded process exists.
The signal-flood result additionally requires a contiguous guardian stream;
ordinary-build results require loss-free custody and J17 coverage. Missing
readiness or controls never count as a pass.

## Next implementation work

1. Close the existing-job deputy route. Require a fresh idle job, execution
   marker and working outside positive control against each live custodian;
   a nonzero `launchctl` exit status alone is insufficient. Rerun the exact
   profile's full defense matrix before adding workflow grants.
2. Resolve normal-host process-headroom startup compatibility. Preserve
   preallocation/read-back checks and measure a supported configuration.
3. Resolve the full-repository build failure and instrument the complete stop
   interval. Review workspace helper execution and tool temporary-file behavior
   in the native development-loop plan; do not silently broaden shared paths or
   move workload operations outside containment. Then continue the native Claude
   plan. K95 both-lost recovery, K96 memory pressure, full J17 loss/refusal
   trials, credential/state support, packaging and K104 remain required.

The acceptance map retains `untested` on the complete live rows. Component
test coverage and this SIP-disabled spike cannot satisfy those release gates.

## Final state

The final guest check found no test-owned processes or launchd jobs remaining;
Ethernet remained disabled, both route tables had no default, and no host share
was mounted. `final-guest-state.json` retains signed-binary and final harness
hashes separately from the initial staging manifest. The VM is stopped after
evidence collection and retained for follow-up; see `vm-final-state.json`.
