# K90 kickstart-fix rerun — 2026-11-02

**Development evidence only. NC01 is not accepted; no release gate is promoted.**
This rerun closes the workload-reachable launchd deputy route that the
[2026-11-01 custody spike](../macos-custody-spike-2026-11-01/README.md)
found, on the exact shipped profile template. The native default-off gate,
entitlement, packaging, K95/K96 fault and memory pressure tests, K104
protected-Mac run and all other native release requirements remain in place.

## The fix

Template digest `b6c731c2…` (2026-11-01 candidate) →
`b2ae082d8d41f393bdc5f83b3cc3f2e84a017b3a4aff68beeb81325c037dc5e4` (this run;
pinned by both K90 test files and recorded by every rerun receipt under
`lifetime/native/details/profile_digest`). The change is
[product-source.patch](product-source.patch): the class-2 section now denies
executing `/bin/launchctl` outright, after the exec grants.

Why this is the mechanism: `(deny job-creation)` stops `submit`, `bootstrap`
and `load`, and launchd's audit-token sandbox checks cover only job creation
and service lookup/registration (reading its published source), while SBPL
`(version 1)` has no filter for Mach sends to the inherited bootstrap port —
so no denyable operation names the kickstart route, and `(deny
mach-bootstrap)` measurably changed nothing. The remaining profile-visible
lever is the client binary. Members have no legitimate `launchctl` use, and
execution is confined to admitted read-only roots, so no other copy can run.

Boundary of the claim: the class is closed exactly as far as the exec
allowlist. Any executable later admitted at a read-only root that speaks the
bootstrap-port protocol directly would need its own deputy probe row; K90's
"anything that runs is recorded" requirement is unchanged, and the full K90
row (classes 1–4 against both custodians, other members during a stop, and
the operator's other processes) remains untested release acceptance.

## Results

Raw guest records are in [guest-evidence.tar.gz](guest-evidence.tar.gz)
(sha256 in [guest-evidence-sha256.txt](guest-evidence-sha256.txt)); the
per-trial JSON with receipts is under `trials/`, and
[summary.json](summary.json) is the index.

| Check | Result | Scope |
| --- | --- | --- |
| K90 class-2 preloaded-job `kickstart` vs supervisor | PASS | Inside: exec refused (exit 126), job stayed `runs = 0`, no execution marker. Outside control: exit 0, job ran, `SIGCONT` reached the live supervisor (`rc=0 errno=0`). |
| K90 class-2 preloaded-job `kickstart` vs guardian | PASS | Same shape against the guardian. |
| K90 class-2 fresh-job `load` vs supervisor and guardian | 2/2 PASS | Same shape; previously denied via `job-creation`, now also refused at exec. |
| Defense matrix, exact pinned digest (host, macOS 27.0.1/26A434) | 17/17 pass | Sleeper and sibling targets, including the kickstart regression row and the digest anchor ([host-defense-matrix.log](host-defense-matrix.log)). |
| Sandbox profile suite (host) | 37/37 pass | Compile, digest, spelling and behavioral rows ([host-sandbox-profile.log](host-sandbox-profile.log)). |
| Guest isolation and cleanup | PASS | `guard()` on every guest entry; final check found no test-owned processes or launchd jobs; Ethernet service disabled with no address on en0, no default routes, no host share. |

Every inside row's verdict requires its outside positive control to have
reached the live custodian (`positive_control_reached_target`); a refused
inside attempt with a dead control never counts as a pass.

## Configuration and attribution

- Product revision: `9c8ce2297` plus the uncommitted fix in
  `crates/ukai-jail/src/platform/macos/sandbox.rs` and both K90 test files
  ([provenance.json](provenance.json) records hashes, build inputs and the
  staged binary digest). Host build, Rust 1.98.1, release optimization,
  `--locked`.
- Guest: the retained `ukai-custody-spike-20261101` Tart VM (macOS 27.0
  build `26A428`, SDK 27.0, four vCPUs, 8 GiB, UID 501, SIP disabled,
  ad-hoc ES entitlement), booted for this rerun with a fresh guest root
  `/Users/admin/ukai-k90-rerun-20261102`. IPv6 tunnel defaults reappeared at
  boot and were removed again; `kern.maxprocperuid` was raised 1333 → 2000
  exactly as in the spike. Host SIP stays enabled; no host shares,
  clipboard, audio or USB passthrough; the Tart VM socket carried only
  curated inputs and results.
- Harness: the 2026-11-01 harness, with one strengthened check —
  [setup_guest.py](harness/setup_guest.py) now asserts en0 carries no
  inet/inet6 address instead of the previous link-state wording (Tart's
  emulated link reports active with the service disabled). All other
  scripts are byte-identical; `harness/inputs.json` pins what was staged
  and `results/guest-setup.json` records the in-guest rebuild and signing.
- The VM was shut down after evidence collection and is retained for
  follow-up ([vm-final-state.json](vm-final-state.json)).

## What this does not do

The 2026-11-01 spike's other open findings are untouched: default
process-headroom startup compatibility, the full SQLite repository build
failure, and whole-stop-path timing instrumentation for K92/NC09/NC11. K90.1
stays `untested` in the acceptance map; this rerun is component and
development-VM evidence against the exact profile digest, not the full
defense-matrix row on a release candidate, and NC01 remains open.
