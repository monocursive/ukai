# Ukai candidate qualification — 15 November 2026

The current frozen Linux candidate `0be9d1e82`, version `0.1.0-rc.7`, passed
its `linux-preview` qualification and is signed locally with the existing
release identity. It is unpublished. This
does not establish full-specification production readiness, native macOS
containment, or qualification of later runtime changes.

The [earlier readiness snapshot](production-readiness-2026-11-15.md) retains
the implementation history and failed runs. [Draft PR #51](https://github.com/monocursive/ukai/pull/51)
contains the isolated Linux candidate, excluding unrelated local Arena work.

## Current status — 16 November 2026

| Candidate or gate | Current result |
| --- | --- |
| Linux `0be9d1e82`, `0.1.0-rc.7` | Signed private candidate. Hosted and release jobs, exact-J strict conformance, actual native archives and production-signed bootstraps passed. Unpublished. |
| Mac runtime `8db910892` (R), `0.1.0-preview.2` | Signed private package, independent artifact review, seven installer cases and five-output archived source rebuild passed. It admits the newly measured cached-disk image through native-v7 evidence. Unnotarized and unpublished. |
| Qualification tools `2c7d894d1` (S) | Corrected stale guest measurement constants; all six hosted jobs passed. Separate from the frozen R binaries and original R source archive. |
| Installed R native version | Corrected S harness passed the managed `/3` version/sync experiment and independent replay with synthetic credentials. No provider request. |
| Fresh installed R API-key checks | Missing-source and A01 passed. The coding task passed its functional checker but failed sampling. The sequence stopped: two passes, one failure, eleven unrun. No retry. |
| Fresh installed R operations | K109/K111/K112 owning rows passed; collection stopped on a five-second holder-check timeout. Separate longer-bound cleanup passed. Fresh source-watch and warm passed. Fault collection stopped: three lanes passed, both client-suspension variants failed, six lanes unrun. Cleanup passed. |
| Earlier `bef699262` API sequence | Eight passes and six failures remain unchanged. Later source changes and fresh partial results do not relabel those failures. |
| Storage | Disposable cache and proven task-duplicate recovery completed; source code, signed artifacts and qualification/failure evidence preserved. |
| Post-stop export repair `d8290c287` | Source repair and focused regressions passed; absent from frozen R. A fresh image and installed qualification remain required. |
| OAuth | Deliberately pending at the user's request. |
| Notarization and native macOS Endpoint Security | Pending; usable local notarization credentials and an exact Ukai ES profile were not established. |

Full production readiness and public release are not established. The current
installed results and their limits follow; earlier sections retain their
original candidate and failure history.

## Current installed Mac candidate — R with S qualification tools

The runtime candidate is `8db910892527dec5d331f5c8f8753bbb048c53ab` (R).
Its private Developer-ID-signed DMG is unnotarized and unpublished. The image
contains the unchanged signed Linux rc.7 candidate J. R admits the measured
cached-disk image; `.cached` with `.full` synchronization is a mitigation for
the earlier guest failure, not proof of its underlying cause or all future
kernel health.

The separate qualification harness is
`2c7d894d119a73472a5a20b7cfb570a037f09788` (S). Its only changes from R are
three stale candidate constants and their regression tests. S is not shipped
inside the R source archive. The first R native probe refused at those stale
harness pins before creating a credential source, VM or workload. That refusal
is retained; the corrected experiment has its own source and evidence identity.

| Check | Result and scope |
| --- | --- |
| R hosted CI | All six jobs passed. macOS: 2,512 passes; Ubuntu: 3,073 passes. Python: 1,183 cases, 84 explicit skips, zero failures. |
| S hosted CI | All six jobs passed. Rust counts unchanged; Python: 1,185 cases, 84 explicit skips, zero failures. All 230 compiled input blobs and modes equal R. Hosted capability skips are not strict Linux reference conformance. |
| R package | 38 independent checks passed, including six signatures, all 1,093 source files and exact payload bytes/modes. |
| R installed cases | All seven cases passed. Fourteen installed files retained exact identity; negative fixtures were cleaned up and the DMG detached. |
| R archived source rebuild | All five outputs rebuilt from the original archive in an isolated directory. This establishes rebuildability, not byte reproducibility. |
| Corrected native version probe | 27 execution and eight sync facts passed; independent normal and optimized replay agreed. Complete contract `/3` sampling recorded three ticks, no scan errors or hits, and one late poll. Synthetic credential only; no provider request. |
| Fresh API-key sequence | Two passes, one failure, eleven unrun. Missing-source and A01 passed. The coding task passed its independent 11-fact checker but failed complete periodic sampling. |
| Fresh operational checks | All three owning K109/K111/K112 rows passed. The original collector and finalizer failed their five-second holder-check limit; separate cleanup recovered. The fresh continuation passed source-watch and warm; faults stopped at three passes, two failures and six unrun lanes, with successful final cleanup. |

The coding-task report retains 92 sampling ticks and 90 readable exact-program
argv and environment observations each, with `inventory_vanished: 15`. Its
remaining 28 facts passed, including the correct task result, exact retained
checker evidence, source preservation and complete cleanup. No secret hit was
reported, but incomplete sampling cannot establish absence of exposure. The
report has no per-error PID, tick or read-stage attribution, so the cause of
those 15 entries remains unassigned. The original strict failure remains a
failure.

An isolated local fake-proc diagnostic used the unchanged sampler and passed
eight cases normally and optimized. Removing a known unrelated or relevant
synthetic process at directory-open, stat or status read produced identical
anonymous counters and strict incomplete results. This demonstrates lost
attribution, not the cause of the real 15 errors or grounds to waive incomplete
coverage. No VM, provider or production-source change occurred. Bounded numeric
diagnostics could improve future attribution; they would not make missing
observations complete. Capturing short-lived relevant processes requires a
separate observation design, precise contract and fresh image qualification.

The API sequence stopped immediately, with the ten repetitions and vendor
revocation unrun. There were two provider-capable CLI invocations and no
retry. Their vendor-reported cost totals approximately USD 0.0146826; this is
not an independent billing measurement. The requested USD 0.50 across invoked
lanes is a vendor budget setting, not an independently enforced billing ceiling.
The private source/config copies were removed, the service and owned process
groups stopped, and the exact workspace image detached. The original API-key
source remained unchanged. OAuth remains deliberately pending.

The independent gate replay confirmed all three owning K109/K111/K112 passes.
The outer operational collector then stopped because its five-second `lsof`
check timed out; its failure and the same timeout in its finalizer remain
unchanged. A separately reviewed cleanup supplement used the existing
30-second holder-check bound. All five calls completed with empty output and
exit 1, the exact owned workspace image detached, and no process, holder or
answering socket remained. That supplement does not rewrite the original
collector failure or create its missing acceptance. K112 tests refusal of the
unsupported owner-loss bound; it does not provide that guarantee.

A fresh continuation omits those completed gate measurements and retains the
original collection failure as a prerequisite alongside its recovered cleanup.
Its synthetic source-watch experiment passed all 21 facts and independent
replay: source removal disconnected the local plaintext stream, blocked the
later request and left clean exports and service state. It does not qualify
TLS, vendor revocation or K113.

The same installed R candidate then passed 20 service and 20 actual-client warm
attempts, plus one route control, on one guest/service boot. All timed attempts
met the existing 1,000 ms budget. Observed maxima were 189.9 ms from service
connect to release and 480.8 ms from client execution to first host workspace
write. Independent replay agreed with the retained per-attempt facts and
timings. These measurements describe this cohort, not a guaranteed latency.
Fault collection stopped at the third group: secrets and both client-kill
lanes passed; both client-suspension variants failed; six later lanes are
unrun. The partial group reports keep their original missing-coverage FAIL
status, and the requested suspension failures remain actual failures. Both
clients were observed stopped, their workloads continued and finished, but
receipt completion and same-boot follow-up failed. Both guest console traces
identify the same call: journal-file export through `conn.sendall` timed out
under the connection's 250 ms timeout, after verified workload-tree stop.
The collector stopped rather than running later groups. Final cleanup passed,
the exact workspace image detached and both failed disks were retained. The
settled free-space observation was 38,314,934,272 bytes.

Independent replay confirmed the exact failed predicates. Both retained 8 MiB
system journals verify structurally and show no observed kernel-corruption
signatures, but neither reaches shutdown and both filesystems need journal
recovery; this is not a clean-runtime result. A bounded local socket-pair
probe using the unchanged send closure reproduced its 250 ms timeout after
only a 4,096-byte prefix of an allowed journal frame. That diagnostic changes
no frozen source or failed result.

Source commit `d8290c287bece36a09cf07465eebb5dca0e62755` addresses that
transmission defect separately from R. After verified warm-session tree stop,
one sender continues exact unsent byte suffixes across short socket timeouts,
refreshes the watchdog, and shares a 20-second write budget across exported
frames and `done`. Failure poisons the sender so no new frame can be appended
to an incomplete one. Live and legacy sending, frame/file/journal caps and
existing queued cancellation handling are unchanged. The budget does not
promise a hard filesystem-I/O or whole-cancellation deadline, and the existing
post-stop two-second revocation-ACK race remains unqualified.

Local main/journal/warm/export regressions recorded 127 passes and two existing
Linux-only skips in normal and optimized runs. After strengthening the
queued-cancellation test to interrupt an actual five-byte partial frame, all
ten final export controls passed again in both modes. The controls cover slow
drain, finite stall, peer closure, interrupted partial frames, one budget across
frames and `done`, correct cancellation ordering and subsequent warm reuse.
Independent review found no remaining patch issue. This source-only repair
was not inserted into R: a new image containing it, new admission evidence and
fresh installed suspension/warm-session qualification are still required.
The API sampling failure and all unrun lanes remain open.

The user-authorized storage recovery removed disposable compiled caches and
proven duplicate task installations/staging. Observed free-space increases
were 14,898,229,248 bytes for pre-existing Gradle/Xcode caches and 3,120,893,952
bytes for exact task duplicates. These shared-filesystem observations are not
exclusive allocation measurements. Routine retirement of newly created
package stages is excluded. A later roughly 23 GB increase was unattributed
and is not credited to this cleanup. Source checkouts, prepared images,
original vendor executable, signed artifacts, source archives and all unique
qualification and failure evidence were preserved.

| Artifact | SHA-256 |
| --- | --- |
| R DMG | `ed24b0fb762858aa660d71fcb652022366d1c633dc33e241365e9cc1725746c2` |
| Original R source archive | `9bfc41a1204b736523004ea2d11f5405f412b3fbd266522b143b7362726b5fab` |
| R runtime build inputs | `2c0def0696f2230a0ec69c3b640a09bf7904c6372e2acdaca702aac268081583` |
| Separate S harness source archive | `df49e773dca906539646866dd5b4f3a7764faa09fc1a4e25e93853c1f3693eb7` |

All records below are relative to
`evidence/production-2026-11-15/warm-vm-current/` and retain the earlier
results unchanged:

- `cache-recovery-summary-2026-11-16.json` — SHA-256 `9511188fb5856142bb553a662f94832ee2eaf1f66c3bfe8b553c1abe9a4e2051`.
- `source-R-ci-8db910892/summary.json` — SHA-256 `8107a8a82c70b19af77760b057af7a54eb6afa67aa2fa0e60541367241f79652`.
- `source-S-ci-2c7d894d1/summary.json` — SHA-256 `eaab4341c9a99dda8b3e77244cea224d2c07bf79100f08646588e64865e96f86`.
- `guest-native-package-independent-R-8db910892/attempt/verification.json` — SHA-256 `f1cdb994f766b64fc60ed013f66086406a22351f2f26e05505e8ae3cdaefa19a`.
- `guest-native-installer-execution-R-8db910892/completion.json` — SHA-256 `9021cfdfad23d46c4943d9ea09543d3f6bec1d9071e6fe0c599250e886d8276b`.
- `source-rebuild-R-plan-8db910892/completion.json` — SHA-256 `7a7de0190036b327c71df07c147695efa76c2129918861418603b43bb8e610b6`.
- `guest-native-version-independent-R-S2c7d894d/settled-review/review.json` — SHA-256 `6dcfc80453dfb0a57dd005e806aa70a4b69c821a4169326a0baaf4f1c767d799`.
- `guest-native-api-control-R-8db910892/api-sequence-summary.json` — SHA-256 `01d1747968258532912f2e1e7fd53a8a0a7c8556714867ba63b2408eb296b4ac`.
- `guest-native-api-independent-R-S2c7d894d/small-task-failure-diagnosis.json` — SHA-256 `0fcb9ba3ff0b6b7ffc250ad291b55f2bb349fd825b78bca219b724095482fbd4`.
- `guest-native-api-independent-R-S2c7d894d/stopped-sequence-review.json` — SHA-256 `eeb17e7558ce95355a38cc13ccf5d3c05404bd3438e52e453d1ee27c7435ce37`.
- `managed-sampler-inventory-R-S2c7d894d/diagnosis.json` — SHA-256 `0b47dfa176b666c6880d3a2915b0d1bfc49f62b4c1a091ab59d496a5bf215a72`.
- `guest-native-operational-independent-R-S2c7d894d/gates-incomplete-collection-review.json` — SHA-256 `cf6c7ac0631483780c32476cc95c456fa5256862b8242bde5fa1831e2e4f429a`.
- `guest-native-operational-control-R-S2c7d894d/cleanup-supplement-1.json` — SHA-256 `92d7ec3075b35804767e4ec98813ac0e5b99b48417d4a141f8233ab1ad03da17`.
- `guest-native-operational-independent-R-S2c7d894d/gates-cleanup-supplement-review.json` — SHA-256 `ca59e89252de87977015594a6adbfc2ec50435b9a33015d3adc41df8ce1e2153`.
- `guest-native-operational-independent-R-S2c7d894d/source-watch-review.json` — SHA-256 `d753bdb884863d6954ec17130ec0d2abb98bd2e01cf0a86eee1bb013c8371270`.
- `guest-native-operational-independent-R-S2c7d894d/warm-review.json` — SHA-256 `d91fe9e064e9744e8e5233fd52e622c600b4e6f6df792bb910df9a98f01dd653`.
- `guest-native-operational-control-R-S2c7d894d-continuation6/completion.json` — SHA-256 `883bae8fb34a0c0e4d1631a3c273542f77e216b8644918ff6f3a86fcb9de5662`.
- `guest-native-operational-control-R-S2c7d894d-continuation6/faults-collection.json` — SHA-256 `f41d441e93745e628ebdba7f534c9491a1d9ea2dcaeabb9b1a1b3927f6180f32`.
- `guest-native-operational-control-R-S2c7d894d-continuation6/fault-final-lifecycle.json` — SHA-256 `eca88ac3b4a61e6b1f2a996e084327fda65526087a9c14d215fb955967e59a68`.
- `guest-native-operational-independent-R-S2c7d894d/faults-failure-diagnosis.json` — SHA-256 `6255e41b7484f940ecd2e19a08900e5600f2b343c781f7f2fb1ae03714531f2f`.
- `guest-native-operational-independent-R-S2c7d894d/export-backpressure-probe.json` — SHA-256 `4757d28c1959e4349311e47eb4811522ff3e10e68e2e2980ad7838b7811833cf`.
- `guest-native-operational-R-S2c7d894d-continuation6/readonly-journals/review.json` — SHA-256 `34b8fe48803843af31a6026a55acb33bf2830d6309291b4827d61e64f123fc5c`.
- `bounded-evidence-export-S2c7d894d/validation.json` — SHA-256 `a809bd534942c7a3191558e58769b26f2730d5cac6b9155a7c8e6350c90400b9`.

Full production readiness remains unproven. The fresh sampling and suspension failures,
unrun API/fault lanes, notarization and usable Ukai Endpoint Security provisioning
remain open. Vendor-binary redistribution authority and cross-UID distribution
are not established. No merge, public tag, release or deployment is implied by
these private results.

## Earlier frozen Linux candidate — rc.6

| Identity | Value |
| --- | --- |
| Source | `6ffff05dc6ae08602a39630b947c704bf9cf05a9` |
| Source tree | `a63c46638bf091e1824d5edd1196e9c168805115` |
| Runtime inputs | `sha256:efdc169e8e09f514c908e02bb6f972bc8761d2efc9af94d9b53d914a436f14e6` |
| Toolchain | Rust 1.98.1, optimization level 3, no debug assertions, clean source |
| Version and scope | `0.1.0-rc.6`, `linux-preview` |

The PR merge tree `09b77e2e0d0348444744f8fa3b8f8e6609feca0e` exactly matches
the candidate tree. Hosted [Rust and dependency policy](https://github.com/monocursive/ukai/actions/runs/43713641335),
[contracts and website](https://github.com/monocursive/ukai/actions/runs/43713641393),
[fleet](https://github.com/monocursive/ukai/actions/runs/43713641334), and
[both architecture builds and assembly](https://github.com/monocursive/ukai/actions/runs/43713655207)
passed. The ordinary hosted Ubuntu lane lacks bubblewrap and skipped the D2
receipt test; it is distinct from strict reference conformance.

The exact-source [strict reference run](https://github.com/monocursive/ukai/actions/runs/43713652987)
passed **3,041 tests, zero failures, 18 deliberate ignored tests, and zero
runtime skips** across 117 groups. Both D2 integration checks executed and
passed. The unprivileged Ubuntu 26.04.1 reference host retained its enabled
AppArmor user-namespace restriction. Doctor reported ready with the exact
clean source and runtime inputs above. The gate report has no problems or
warnings for `linux-preview`; `all_noncredential_gates_pass` remains false
because unsupported, elsewhere and credential rows are retained.

The downloaded reference artifact is `14162159514`, SHA-256
`89d721461c81cea2a703f15e539b16863c24e5167a95a758432402e42bbd137d`.
Its complete log, doctor, gate verdict and checksums are retained in
`evidence/production-2026-11-15/candidate-6ffff05dc/conformance/`.

Both actual downloaded CI archives passed native installation, repeat-install
refusal, upgrade/downgrade, tamper rejection, tool/agent doctor, workspace write,
outside read refusal, one-second wall expiry, and verified complete cleanup.
Both tool/agent receipts show enforced containment and observed execution.
Native deterministic restaging reproduced each archive hash:

| Target | Archive SHA-256 |
| --- | --- |
| x86_64 Linux | `c074b81a3cacb69090544b64e45b44b1268f3f4ff06a452969501dd5f4d9b962` |
| ARM64 Linux | `bef11e6e96ac3a980f5a4e084cb7008439e246446aa4b99e933746377c53c7ce` |

These are candidate-specific native checks. They do not turn the earlier
failed full ARM64 baseline into a pass, qualify stock OrbStack credential
launches, or claim the Apple/HVF CPU can execute AArch32 EL0. The unavailable
Raspberry Pi has no new qualification. The full x86 reference and supplemental
ARM32 TCG evidence retain their separate scopes.

The documented local release key was available. The unsigned CI plan's
`production_signing_identity_not_configured` meant signing arguments were
omitted from that invocation; it was not proof that no identity existed.
Local signing preserved both CI archives byte for byte and verified against
the exact checked-in release public key. `publish_release.py check` passed.
Each native host then passed the signed bootstrap without Minisign in its
installation PATH, including tampered private-archive rejection without
changing the existing installation.

An independent artifact review checked the signature, all eight candidate
files, all six signed assets, native binary format/provenance, runtime input
digest, complete attribution, immutable old/new pins, installers and native
bootstrap results. It found no artifact defect. The local signed bundle is
`evidence/production-2026-11-15/candidate-6ffff05dc/ukai-jail-0.1.0-rc.6-signed-candidate.zip`,
9,315,245 bytes, SHA-256
`39453865f0a4e7635316341d99f0bd3cc2c9e5ec2d8c97151cf0fa1a877d575b`.
It contains no private key. The plan still requires operator review of host
support and validation. No tag, public release, public download check, PR merge
or website deployment has occurred.

## Separate signed warm-VM baseline

Clean source `fa1d3392d9a1649a74782315a298a06686200514` adds verified local
signed-candidate preparation without changing the frozen Linux runtime inputs.
Its guest contains the exact signed ARM archive above. Its Developer-ID-signed
preview.2 DMG has SHA-256
`7889733ada5fd7bcbf77e0ea43ddbe04f983799ea95037b796770c0ffc42e6a1`.
This baseline is **unnotarized and unpublished**. Its raw evidence is retained
under `evidence/production-2026-11-15/warm-vm-current/`.

- All six strict signature checks and all seven actual mounted-DMG installer
  cases passed, including conflict preservation and manifest/payload tampering.
- All 536 embedded source files match the baseline commit. All five components
  rebuild from that archive with the pinned toolchain. This establishes source
  rebuildability, not byte reproducibility.
- All ten existing guest capability measurements and the separate execution
  boundary judge passed. The strengthened judge also checks each guest attempt
  and actual guest process boot identity. Measurement alone does not promote a
  capability in the client.
- Twenty warm service attempts and twenty installed-client attempts passed on
  one guest/service boot. Maximum connect-to-release was 104.3 ms; maximum
  installed-client launch to first host workspace write was 334.5 ms.
- All nine fault scenarios and both actual-client lanes passed, with no omitted
  cases. K109, K111 and K112 passed within their recorded scope. K111 explicitly
  reports no exported guest journal in this baseline. K112 verifies refusal of
  unsupported kernel-bound owner-loss requests; it does not provide that bound.
- The installed client's synthetic credential attempt correctly refused before
  release with `vm:not-measured:credential_staging`. K113 remains unqualified.

Baseline guests were stopped and the DMG detached after the observed verdicts.
The task-only images and evidence remain available. Later guest-journal,
credential-revocation and measurement-tool changes are a separate workstream;
they must receive their own source-bound package and live results before any
capability or compatibility claim changes.

## Signed guest admission follow-up

The separate signed package at clean source
`53e5605fd9d0728ea46da2449c635f364ba2b4f4` includes bound guest journal export,
source-generation revocation and the actual guest Session contract handshake.
Its DMG SHA-256 is
`b399e8f7116180f3fe9dbb2c4c8540387f101e44a762bd567f23389644431c44`.
All six strict signature checks and seven actual mounted-DMG installer cases
passed. Independent verification matched installed bytes, source provenance,
the signed Linux guest and the Apple Developer ID requirement.

All ten guest capability rows passed again on this image. A separate boundary
judge passed 121 checks across four resource/tree attempts. A synthetic raw
transport experiment passed 24 checks after correcting its offline judge to
accept the complete valid Outcome schema. The unchanged original FAIL report
is retained. The guest acknowledged removal in about 114 ms; the accepted
upstream stream closed about 204 ms after revocation, and a subsequent request
was denied without another upstream credential use. Full bound journal export,
cleanup and same-boot disk scans passed.

The [bounded reproducible proof](results/macos-vm-admission-2026-11-15/README.md)
backs twelve image-scoped capability rows. Both the guest disk and seed must
match before any capability answers available; the exact guest revocation and
journal contracts remain mandatory before secret transfer. Rebuilding or
re-signing host helpers requires fresh installed-client validation and does
not inherit host qualification. Unsupported policy carry, swap capability and
owner-loss guarantees remain unavailable.

The full VM Python suite at clean tooling `1cb8f1af7` passed 517 tests with
three explicit platform skips, using byte-snapshots of this signed package's
service/client. It exercised no live VM. The earlier full Mac workspace run at
`bb10b8572` passed 2,449 tests with seven deliberate ignored tests; subsequent
handshake changes received targeted Rust and guest/service checks. These are
component and portable checks, not native Endpoint Security acceptance.

Normal installed-client source revocation and independent installed-host
checks are recorded below for a later host build. Vendor compatibility, full
K113 and notarization remain separate gates.
K113 still needs guest-native program resolution and `@program` binding,
the bundled profile's attempt-state/environment carry, independent summary
recomputation and sampled-environment exposure checks. A specifically named
headless `--state attempt` combination can be qualified without implementing
the separate interactive/persistent-session matrix; that does not qualify the
default persistent alias. The required two authentication modes remain part
of the headless row. Metadata inspection found the configured `anthropic`
source file present, regular, private and operator-owned, but `claude-oauth`
absent. No source value or provider validity was inspected by that check.

## Corrected signed host candidate

The separately qualified warm-host baseline is built from clean source
`9ceada86135895ba7e2ea84a2cdea6b7022d9b39`. Its DMG SHA-256 is
`900c3707c0244ce60cf6d8c0b70c74800c12cb6cd656e17fca18847d1f145d7e`;
the host runtime inputs are
`sha256:ba9809bc979a32fe6a8b0641f1e92a98754ff3d6885f0aca4dfd4cd374e648f3`.
It retains the measured guest disk and seed above. It is not notarized,
stapled or published. Later documentation changes do not change this artifact's
source identity or qualify a rebuilt executable.

The previous signed `abf523fee` package failed runtime qualification on the
second Mac: after the execution wall expired, the guest cancelled but the
host client repeatedly requested shutdown and consumed a CPU indefinitely.
The corrected client reports wall expiry once and drains final frames or EOF
under a fixed five-second stop budget. Repeated stop requests cannot extend
that budget. Its 116 VM tests, strict all-target lint and two independent
reviews passed. All six hosted checks at the corrected source passed:
[Rust and dependency policy](https://github.com/monocursive/ukai/actions/runs/43726730417),
[contracts and website](https://github.com/monocursive/ukai/actions/runs/43726730423),
and [fleet](https://github.com/monocursive/ukai/actions/runs/43726730413).

The exact corrected DMG and installed payload passed six strict Developer ID
checks and seven mounted-DMG installer cases. Independent verification matched
every installed file and mode, manifest, source identity and executable
signature. All 573 embedded source files and modes match the clean commit;
all five native components rebuild from that archive alone with pinned Rust
1.98.1, locked offline Cargo dependencies and the locked Python build
environment. This establishes source rebuildability, not byte reproducibility.
The archive's SHA-256 is
`1f1680e55140e3b4cf448001ce68a1f01b22a71f2e5365def54b068a2fd5279b`.
Its 26 bounded proof files also replay successfully.

On the primary protected Mac, the actual installed client's synthetic
credential-source revocation passed all 21 checks. Removing the private source
closed the accepted stream in 813 ms; a later request returned 403 without
another upstream credential use. The child remained alive for a further
2.503 s, beyond the revocation acknowledgement budget. The complete bound
guest journal contains 16 events and exactly one credential use. Strict
six-class coverage, host and guest settlement and the same-boot disk scan
passed. The attempt-state/workspace scan covered 23 files with no synthetic
credential spelling found; retained exact inputs and attempt bytes were also
scanned before export. The harness pinned the service-lock descriptor before
stop, acquired its exclusive lock after service cleanup and held it through
scanning. This witnesses completion of the cleanup critical section, not OS
process reaping. Independent review rehashed the
exact retained inputs and attempt, verified the journal and binding, and
recomputed both summaries with the signed client. Live peer timestamps and
the destroyed disk scan remain recorded host observations, not offline
attestation. This is synthetic plaintext evidence, not vendor/TLS compatibility.

Twenty warm service attempts and twenty actual installed-client attempts
passed on one guest/service boot. The maximum connect-to-release time was
104.6 ms against the 1,000 ms budget; the maximum client launch to first
workspace write was 329.5 ms. Granted writes, protected-write and network
refusals, receipt binding and cleanup were checked. The installed workspace,
receipt/summary and unsupported owner-loss row harnesses also passed within
their recorded scope. These development measurements do not promote K108–K113.

The complete fault harness passed all 11 lanes in 614.893 s: secrets, client
kill and suspension with both the stand-in and actual installed client,
service/custodian/VZ kills, all-controller suspension, socket EOF and service
process-group suspension. No lane was omitted. All verdicts were recorded
before cleanup, and no emergency cleanup kill was needed. Independent offline
recomputation reproduced all 118 facts from the retained observations and
matched the installed client/service hashes. This checks the harness's named
fixtures and observations; it is not a new independent process census or a
promotion of the full installed release clauses.

Actual installed wall-three-second probes returned in 3.129 s on the primary
Mac and 3.148 s on the second protected Mac, without the previous CPU spin.
Their host receipts honestly retain `wall_expiry`, unknown outcome, lost
integrity and no verified empty-tree claim: these lease cancellations returned
no bound guest final receipt. No late marker appeared during the
retained observation window. This is a bounded-host regression result, not a
complete process-population inventory or a clean wall receipt. K110 requires
termination under its full fault matrix before cleanup; it does not require
inventing a guest result after the client lease is lost.

The second protected Apple Silicon Mac independently verified the exact DMG,
six strict signatures, fresh installation, installed tree/modes and packaged
helper hashes. Its actual agent/tool commands and bounded wall regression
ran. Its synthetic source-watch experiment did **not** pass: the local HTTP
witness accepted no request, so no source revocation was triggered. A separate
credential-free diagnostic reproduced the timeout with a direct host request
to that Mac's own LAN address, outside Ukai, while the same listener answered
over loopback. This establishes a host non-loopback peer-reachability
limitation; it does not identify the particular firewall, filter or routing
cause. No security setting was changed. The original long-socket-path setup
failure, unreachable-peer attempt and diagnostic remain retained under
`spare-mac-9ceada861/`. The primary-Mac synthetic result is not substituted
for this missing independent-host revocation result.

Exact records are retained under
`evidence/production-2026-11-15/warm-vm-current/`: `deadline-fixed-package/`,
`deadline-fixed-installer/`, `deadline-fixed-credential-revocation/`,
`deadline-fixed-warm/`, `deadline-fixed-gate-rows/`,
`deadline-fixed-faults/`, `deadline-fixed-wall-v2/` and
`source-rebuild-9ceada861/`.
`deadline-fixed-qualification.json` binds the completed primary-host records;
the final process inventory found no remaining task VM/service/custodian
processes.
The earlier failed package, setup failures and corrected offline-judge records
remain separate and unchanged. [Draft PR #52](https://github.com/monocursive/ukai/pull/52)
is stacked on the frozen Linux candidate; neither candidate inherits the
other's runtime qualification.

## Guest-native implementation and retained startup failure

[Draft PR #53](https://github.com/monocursive/ukai/pull/53), stacked on #52,
adds image-bound guest program resolution, source-only credential forwarding,
the unchanged bundled launch profile and explicit attempt state, full guest
journal/summary verification, and separately reported environment/argv sampling.
It does not qualify native macOS Endpoint Security containment or a vendor
authentication mode. The guest still runs the frozen signed Linux candidate
at `6ffff05dc`; the host and guest controller changes have separate identities.

The [native-v2 component proof](results/macos-vm-admission-2026-11-15/native-v2/README.md)
retains 81 bounded text/source files. Its relocated offline replay passed with
access to original evidence paths, process execution, networking and writes
denied. It binds ten guest capability rows, 121 execution-boundary facts,
24 synthetic raw-vault facts and 24 actual program-binding facts. The latter
allowed an original executable to use a synthetic credential while denying a
byte-identical copied executable with a distinct inode. The independent
upstream observed exactly one substituted request. These are component
measurements; they do not prove the native alias or host source watcher.

That proof admits the exact v2 disk/seed pair separately from the original
image. A second native-program predicate also pins the catalog, entry,
unchanged profile and executable. The bootstrap sampler control detected its
owned public canary in both environment and argv, reaped the child and
reported zero scan errors. This detector control is not vendor sampling or a
jail execution receipt.

Clean source `e8d0c2b074d8c02cf2f33c2e58db75769c7f7884` produced private DMG
`4263d036dd87395aa790a6a83e208c1cf669c98000280a20d8c6e4815d220bbe`.
All six strict Developer ID signatures and seven actual mounted-DMG installer
cases passed. Independent review matched every installed file and mode,
all 677 archived source files against that commit, and the exact prepared
guest/catalog/control inputs. These checks establish artifact consistency;
they do not inherit runtime qualification from the earlier warm-host baseline.

All six hosted jobs at e8d0 passed: [Rust and dependency policy](https://github.com/monocursive/ukai/actions/runs/43742239906),
[contracts and website](https://github.com/monocursive/ukai/actions/runs/43742239889),
and [fleet](https://github.com/monocursive/ukai/actions/runs/43742239957).
The Linux test runner reported 3,057 successes and 18 deliberate ignores,
including 512 explicit runtime skips; the macOS runner reported 2,486
successes, seven ignores and no runtime skips. Both had zero failures.
The Python contract job ran 693 cases with 77 explicit platform/test-seam
skips. Hosted Linux lacked bubblewrap and did not execute the contained D2
check. These results are not strict reference-host conformance.

The first normal installed `--from-path --launch claude --state attempt --
--version` attempt **failed before execution**. The guest config directory's
0710 mode allowed traversal but prevented the frozen Linux supervisor from
listing uncontained-run markers. The retained error is `unsafe_state_path` at
resolving, followed by an unknown host lifetime outcome. No guest receipt or
journal was available, sampling was unavailable, and the shutdown-lock witness
and disk/export scans did not qualify. Its private synthetic source was
removed. No provider source was read or provider call requested. The failure
is retained under `guest-native-version-e8d0c2b07/`; correcting the guest
requires new image measurements and a fresh installed native result. The
failed package is not a qualified native candidate.

The e8d0 archive rebuild preflight separately used an incorrect legacy replay
filename and stopped before compilation. That harness error is retained under
`source-rebuild-e8d0c2b07/`; no source-rebuild pass is claimed for this package.
The independently verified archive and extracted source remain available.

The config-directory fix at `23e18ef2b` grants the marker-listing permission
while preserving the private credential directory and file modes. A real
dropped-UID Linux regression reproduces the earlier refusal and verifies the
corrected listing/read behavior without granting writes, rename or unlink.
The next native version/help probes executed successfully, but exposed a
separate sampler defect: the jail supervisor and its launched workload have
different process identities. The earlier report incorrectly equated them.

Clean source `9fdf7edc89d010e2acfce31cd640b5d1bc24b321` corrects that binding
with sampled-exposure contract `/2`. It retains the actual Released supervisor
PID and captured birth separately from the receipt workload, and requires
positive environment/argv reads of that exact catalog workload before reporting
complete coverage. Another process cannot supply those observations. Invalid,
unavailable or incomplete sampling does not rewrite a verified execution
outcome. Targeted guest, Rust, independent-reader and service checks passed;
the actual Linux sampler/control run passed 43 cases without skips.

The fresh [native-v4 component proof](results/macos-vm-admission-2026-11-15/native-v4/README.md)
binds the new image to ten capability rows, 121 boundary facts, 24 raw-vault
facts and 24 executable-binding facts. Its 76 retained files include the
integrity manifest; 54 derivation checks, 29 focused tests and 18 relocation/
tamper controls passed. The original image proof and native-v2 history remain
unchanged. No v3 measurement is inherited by v4.

The private 9fdf DMG has SHA-256
`70ff6d702fd9d5b13498a7f5f6498563be9ad617331935c3d5e9923990390540`.
Six strict Developer ID signatures and seven actual installer cases passed.
Independent mounted-DMG review matched every installed file/mode, all 679
archived source files and modes against the clean commit, and the exact
prepared guest/catalog/detector inputs. This intermediate package does not
yet admit its new image through the normal installed native route.

Its raw native version probe passed all 19 execution checks and exported a
valid `/2` report. Sampling was honestly **incomplete**, with no hits or scan
errors and no positive vendor-process reads. The complete guest journal
records only 17.807167 ms between that workload's exec and exit, shorter than
the 100 ms sampling period; this permits a missed observation and does not
prove continuous coverage. The original diagnostic FAIL is retained under
`guest-native-raw-version-9fdf7edc8/`. All owned VM processes stopped and the
task workspace volume was detached after the component runs. No provider
credential has been read or used by these measurements.

Hosted [contracts/website](https://github.com/monocursive/ukai/actions/runs/43747310959)
and [fleet](https://github.com/monocursive/ukai/actions/runs/43747310962) passed
at 9fdf. The [Rust run](https://github.com/monocursive/ukai/actions/runs/43747310984)
passed its Linux and dependency lanes but **failed on macOS**: the byte-relay
test delivered its entire 49,163-byte request without forwarding the half-close
within 20 seconds. The unchanged bridge reproduced that failure locally.
The failed CI log is retained; this source has no all-checks-pass claim.

The subsequent diagnostic isolated the failure to the test peer's blocking
timeout read: the bridge had drained all bytes and successfully called
shutdown 20,001 ms before the peer timed out; an immediate poll then reported
readable/hang-up and an actual read returned EOF. The test peer now uses a
nonblocking read/poll loop under the same monotonic deadline. It still requires
real EOF and the complete exact payload. A live peer that sends all bytes but
withholds its half-close must still time out. The complete production bridge
source preceding its test module is byte-identical to the frozen Linux
candidate; no Linux release artifact change follows from this test fix.
All eight bridge tests, 400 fixed-binary repetitions and 135 VM tests passed,
along with strict lint and formatting. The original local and hosted failures
remain retained under `bridge-half-close-9fdf/` and `guest-native-ci-9fdf7edc8/`.
A fresh hosted run and the admitted-host checks below supersede the pending
status for those checks. Provider qualification remains separate.

## Admitted native guest candidate

Clean source `aedc1003dfe5f5e70d2a3891447fd2e528f9c31d` admits the exact
native-v4 disk/seed pair and its six component-admission pins. It refuses the
intermediate native-v2 pair while preserving that historical proof unchanged.
The original legacy-image admission table remains unchanged.

The private signed DMG is
`b3c3c25d9f199b5e50d59b5889636ba209bf5c0ae22e9fd377acaf088e8fa580`.
All six strict Apple Developer ID signature checks and seven actual installer
cases passed. Independent mounted-DMG review verified all installed bytes and
modes, all 755 archived Git files and modes, and the exact prepared image,
catalog and detector inputs. All five components rebuilt as ARM64 from that
archive using pinned Rust 1.98.1 and locked Python dependencies; the source
remained unchanged and the rebuilt client's provenance matched the package.
This is source-build verification, not byte reproducibility or notarization.

The first archive preflight stopped on a stale whole-object comparison in the
historical legacy replay recipe. The current derivation adds one contract
observation field. The corrected preflight verifies that exact additive field
separately, then compares every original field with the untouched historical
record. Eight mutation controls passed. Both the original failure and the
corrected preflight/rebuild remain retained under `source-rebuild-aedc1003d/`
and `source-rebuild-aedc1003d-v2/`; the historical README command is not claimed
to pass unchanged.

All six hosted jobs passed for this source: [Rust and dependency policy](https://github.com/monocursive/ukai/actions/runs/43749751698),
[contracts and website](https://github.com/monocursive/ukai/actions/runs/43749751688),
and [fleet](https://github.com/monocursive/ukai/actions/runs/43749751662).
The tested PR merge commit and candidate have the same tree. Linux reported
3,058 test successes, 18 ignores and 519 runtime skip diagnostics; macOS
reported 2,491 successes, seven ignores and no runtime skip diagnostics.
Both reported zero failures. Python suites ran 1,002 cases with 79 explicit
skips. The hosted macOS acceptance report still leaves specification gates
unsupported or unproved; green CI does not replace live release acceptance.
Exact logs, merge binding and counts are in `guest-native-ci-aedc1003d/`.

The normal installed native `--version` route passed 27 execution, provenance
and cleanup checks with the expected CLI version and no provider call.
Its valid `/2` sampling report remained incomplete: five ticks, no vendor
process observations, no secret hits and one vanished-inventory scan error.
This is not complete workload sampling or K113 qualification.

On the primary Mac, 20 service attempts and 20 actual installed-client attempts
passed on one warm guest boot. Maximum release latency was 99.7 ms and maximum
client-exec-to-first-write latency was 343.6 ms, each below the one-second
bound. All 11 failure lanes passed, including actual client termination and
suspension, service/custodian/VM loss, all-process suspension, EOF and service
group stop. Fresh K109, K111 and K112 rows passed; K113 remained unjudged.
The normal installed synthetic source-watch test passed all 21 facts, with
one upstream substitution, stream termination after source removal and a
later denied request without another substitution. These are synthetic
plaintext measurements, not vendor/TLS compatibility evidence.

Records are retained under `guest-native-version-aedc1003d/`,
`guest-native-warm-aedc1003d/`, `guest-native-faults-aedc1003d/`,
`guest-native-gates-aedc1003d/` and `guest-native-source-watch-aedc1003d/`.
On the second Apple Silicon Mac (macOS 27.2), the exact DMG passed six Apple
Developer ID signature checks, installation and repeat-install refusal. Both
agent and tool workloads passed containment and independently recomputed
receipt/journal summaries. The first cold workload took 79.74 seconds; the
next warm tool workload took 0.355 seconds. A three-second wall limit returned
in 3.168 seconds with an explicit unknown/lost, unverified outcome and no late
marker. That bounded-cancellation check does not prove a clean guest drain.
The normal installed synthetic source-watch lane passed 22 facts using the
explicit Apple Python peer. Offline replay independently verified its full
guest journal, use counts, summaries and retained input bindings. These
second-machine records are in `spare-mac-aedc1003d/`; they do not establish
vendor compatibility or notarized release acceptance.
All 14 installed files and modes remained unchanged, no owned processes
remained, and both task mounts were detached. The first offline driver failure
is retained; the corrected replay accounts for the harness's exact portable
helper-path rendering and does not alter workload evidence.

The first bounded native API-key A01 measurement used that exact installed
candidate and its archived helper. The prior missing-source control passed
all six facts, returned `credential_unavailable` with both bundled hints and
created no workload. The paid A01 task created `greeting.txt` containing
`hello` and a newline. The vendor reported two turns on `claude-sonnet-5-5`
and USD 0.0060354, below the requested USD 0.25 budget. All execution,
containment, credential-use accounting, summary, export and cleanup facts
passed. The original credential source's generation remained unchanged.

The A01 measurement nevertheless **failed overall**: 27 of 28 facts passed,
but its `/2` sampler retained one `inventory_vanished` error. It recorded
192 ticks and 188 positive environment and argv reads of the exact receipt
workload, with no secret hits. The error counter does not retain the vanished
process identity, so this run cannot establish whether the missing inventory
entry was inside or outside the measured workload. It is not waived. The
failed record is retained under `guest-native-api-a01-aedc1003d/`; no automatic
paid retry or repetition followed it. Later provider rows remain unmeasured.

The subsequent diagnostics preserve that failure. One fixed synthetic cold/warm
`--version` pair reproduced an unidentified vanished inventory PID. Its original
console reader rejected the serial console's LF-to-CRLF transformation; a
separate offline replay verified the exact terminal-CR transformation without
rerunning or replacing the failed record. Neither the retained reports nor the
guest journal identify that process generation.

A separate disposable image then captured numeric Linux process-connector
events around exactly two further synthetic version launches. Its collector
retained 340 envelopes, 130 initial process/thread identities and start/end
fork-and-exit anchors on both guest CPUs. The bounded framing, report binding,
per-CPU sequence-window checks and cleanup passed. No inventory error occurred
in this pair, so it provides no attribution of the earlier failures. The warm
sampler instead retained one `selected_process_vanished` error without the
failed PID. Both short sampler reports remain incomplete, with no positive
receipt-program reads. The event stream does not prove continuous coverage or
the absence of delayed kernel producers.

These diagnostic images used the unchanged `aedc1003d` controller and sampler,
synthetic credentials and no provider calls. All task processes exited and
owned volumes were detached; original evidence is unchanged. Records are in
`sampler-inventory-diagnostic-aedc1003d/`,
`cn-proc-feasibility-aedc1003d/` and `cn-proc-attribution-aedc1003d/`. They do not
qualify K113 or promote the installed candidate.

Controller revision `b54086a3e` replaces the cgroup wrapper's external
`grep`/`sleep` polling with a same-process pipe gate. Root pins the child with a
pidfd, moves it into the attempt cgroup, initializes the existing native
sampler, then releases the gate. EOF, an invalid byte or timeout refuses exec;
setup failures use the pinned process descriptor for bounded cleanup. The
gate closes before the jail execs, and byte argv/environment are preserved.
The sampler implementation and its failure criteria are unchanged. This
removes source-known setup churn; it does not establish the cause of the
earlier unidentified errors.

The exact gate source passed 222 optimized guest test cases on macOS (204
passes and 18 explicit Linux/root skips), and 149 on an actual Linux ARM64
guest (148 passes and one existing root-permission skip). All new Linux gate
and pidfd controls executed. A 2.5-second public-canary control used an unused
workload UID, observed only its exact owned PID/birth, collected later periodic
environment/argv reads and joined its observer with no scan errors. It created
no vendor receipt and does not qualify a vendor launch. Evidence is retained
under `guest-pipe-gate-406a91a66/`. The controller does not inherit the
native-v4 candidate's results. Its Python-to-jail executable transition can
still overlap an observation; the unchanged sampler must report any resulting
identity error rather than suppress it.

The fresh native-v5 image and private signed baseline package were built from
clean `b54086a3e31d1097954448e2bd37278f20beab7c`. All six CI jobs passed on that
revision. Actual package verification passed six Apple signature checks and
seven installer cases, and independently matched 758 source-archive files
and modes to Git. This is a private, unnotarized component candidate.

Fresh component measurements and independent replays passed ten capability
rows, 121 execution-boundary facts, 24 raw vault/revocation facts and 24
literal executable-binding facts. The owned processes exited and workspace
volume detached. Their 88-file retained bundle is
`results/macos-vm-admission-2026-11-15/native-v5/`; its manifest SHA-256 is
`2aabcfd2155c092acbe53bffa4f630708203d57944ed898a859b10efd4f22701`.
All 183 prior proof files remain unchanged. The copied offline tools passed
67 tests, admission derivation passed 54 checks, and relocated read-only
validation passed 24 positive/tamper controls, including rejection of an
intact old capability/boundary pair substituted beside the new image.

The updated client admission replaces the native-v4 disk/seed pair with this
exact native-v5 pair and its actual measurement timestamps. The legacy table
is unchanged. Tests reject native-v2, native-v4 and mixed image pairs; the
four catalog/entry/profile/executable pins remain identical. All native
vendor, K113, release and new-host-runtime qualification flags remain false.
The following results belong to the newly admitted host. They do not change
the earlier failed A01 or promote full K113 qualification.

## Native-v5 installed candidate and API-key pilot

Clean source `6c1f95567cf77cc671064fd45a1a78bf3cdfe211` produced private DMG
`8c0eeb816b5e7dda7c7c14cc54e34912b5380bdebd08bb3db9d21b5b25157b1c`.
Six strict Developer ID checks and seven mounted-DMG installer cases passed.
Independent verification matched every installed file and mode, all 846
archived Git files and modes, and the unchanged native-v5 image inputs. All
five ARM64 components rebuilt from that archive with locked offline Cargo and
Python dependencies. These are source-build and artifact-consistency checks;
the package remains unnotarized and unpublished.

All six hosted jobs passed: [Rust and dependency policy](https://github.com/monocursive/ukai/actions/runs/43764980991),
[contracts and website](https://github.com/monocursive/ukai/actions/runs/43764980953),
and [fleet](https://github.com/monocursive/ukai/actions/runs/43764980899).
macOS reported 2,491 passes, seven deliberate ignores and no runtime skips;
Ubuntu reported 3,058 passes, 18 ignores and 519 runtime skip diagnostics.
Python suites ran 1,052 cases with 80 explicit skips. This ordinary hosted
Linux lane is distinct from strict reference conformance. Exact records are
under `guest-gate-ci-6c1f95567/` and `source-rebuild-6c1f95567/`.

The normal installed native version route passed all 27 facts with no provider
call. Its short sampler was honestly incomplete, with no workload reads,
secret hits or scan errors. Synthetic source-watch revocation passed all 21
facts: one substitution, stream closure, a later denied request and a further
2.503-second child hold. Twenty service and twenty actual-client warm attempts
passed on one boot. Maximum release latency was 107.4 ms; maximum client exec
to first workspace write was 297.3 ms, each below the one-second bound.

The primary Mac's K109 and K112 rows passed, but **K111 failed** when the
attempt socket closed before Ready after 175.6 seconds. The configured startup
budget remains 150 seconds; the old service retained no stage timings that
identify where this boot stalled. The attempt had no verified workload
execution or guest receipt. K112 refuses an
unsupported request before boot; its pass is not a successful-boot control.
The original failed row, stopped boot disk, empty serial console and lifecycle
record remain under `guest-native-gates-6c1f95567/` and
`guest-native-measurements-6c1f95567/gates-startup-failure/`.

Read-only host and disk diagnostics confirmed that this guest reached Linux
and wrote early boot journal entries. The new journal tail was incomplete;
the unchanged base image's journal verified with the same reader. This does
not identify the cause of the startup failure. No failed disk was mounted,
repaired or booted again. The diagnostic record is in
`k111-disk-readonly-6c1f95567/`; K111 remains failed and unwaived.

An explicit execution-order supplement then allowed independent fault and
second-machine evidence collection without changing that verdict. All 11
fault lanes passed within the original 1,800-second outer budget; offline
review recomputed all 118 facts. All verdicts preceded cleanup, with no
emergency cleanup kills. The complete matrix and supplemental lifecycle are
under `guest-native-faults-6c1f95567/` and
`guest-native-measurements-6c1f95567/faults-supplement-final.json`.

On the second protected Apple Silicon Mac, the exact DMG passed signatures,
installation and repeat-install refusal. Cold agent and warm tool work took
81.418 seconds and 0.293 seconds respectively, with bound guest journals and
independently recomputed summaries. A three-second wall limit returned in
3.261 seconds with a truthful unknown/lost, unverified outcome and no late
marker. Synthetic source-watch revocation passed all 22 facts. Installed
bytes were unchanged, all owned processes exited and both task mounts were
detached. These results are in `spare-mac-6c1f95567/`; they do not waive the
primary Mac's K111 failure or establish provider compatibility.

The user selected API-key qualification and left OAuth pending. Exactly one
new bounded API-key A01 pilot ran on this installed candidate after a fresh
missing-source control passed all six facts without creating a workload.
A01 passed **all 28 facts**: it created `greeting.txt` containing `hello` and a
newline, exported a complete 161-frame guest journal with four exact
credential uses, and retained complete `/2` periodic sampling. The sampler
recorded 42 ticks and 37 environment and argv reads of the exact receipt
workload, with zero hits or scan errors and a 104.729 ms maximum gap. These
are periodic observations, not continuous coverage. Six-class scans of 34
files found no secret material in retained output or exports.

The vendor reported two turns on `claude-sonnet-5-5` and USD 0.0062454; this
is reported usage, not independently metered billing. Independent offline
review reproduced all 28 facts in 56 checks. All 29 final lifecycle checks
passed: the original credential source generation was unchanged, the private
copy was removed, no owned VM or build process remained and the workspace
was detached. Evidence is under `guest-native-api-a01-6c1f95567/`,
`guest-native-api-independent-6c1f95567/` and
`guest-native-api-pilot-plan-6c1f95567/`. The small task, ten fresh repetitions
and real vendor mid-stream revocation remain pending. The earlier failed A01
is retained; this successful pilot does not establish full K113 acceptance.

## Startup diagnostics and qualification tooling

Source `57d6a68ddc7bd593fc3463d2a2f8d3c4bbab406f` retains bounded, typed startup
stage observations and failure causes in a private failed-boot record. It
does not retain helper payloads or credential text, extend the existing
deadlines, retry boots or alter guest/image admission. Fault tooling now
retains explicitly incomplete progress after each judged and cleaned lane,
and cleans its current case before propagating interruption. These changes
improve diagnosis and evidence retention; they do not claim to repair the
unknown K111 startup cause.

The source archive now includes the exact 596-byte portable-tail test fixture
`docs/specs/jail-v1/examples/event-note-learning-read.json`. The prior archive
built all five production components, but could not compile all test targets
without this fixture. Coverage verifies its exact bytes and excludes an
unrelated sibling. The corrected archive is expected to contain 847 files.

Local and independent checks passed 66 service unit tests, 43 fake-service
integration tests, 11 fault-table tests and 37 packaging tests, plus strict
all-target lint and formatting. The first hosted run at 57d6 nevertheless
failed both Rust lanes before tests: three test-only standard-library reader
type names matched the existing I02 vendor-token ban. The other four jobs
passed. That failure remains in `guest-gate-ci-57d6a68dd/`; no rerun or package
was produced from that revision. The correction uses borrowed byte slices in
those three tests without changing production code. The following candidate
provides fresh CI and installed evidence for that correction.

## Corrected diagnostics candidate

Clean source `bef6992628f19e870ca15b264c7c02db74b1a81e` produced private signed
DMG `b8b25b6c978d608771ee66e4ddc149bb1692b8cfb30cc691b9feeaf16fba286f`.
All six Developer ID signatures and seven actual mounted-DMG installer cases
passed. Independent review passed 25 checks against every installed file and
mode, all 847 archived Git files and modes, the exact portable-tail fixture,
and the unchanged native-v5 guest inputs. The source archive SHA-256 is
`369777187d92d2a06d223eeee07620063e7079e2bd265732d0817433c791b1ef`.

All five native components rebuilt from that archive in a fresh no-Git source
tree. A separate fresh extraction on the spare Mac passed an offline,
all-target compile using its existing task-owned compiler cache. This
confirms the archive contains the previously omitted compile-time fixture;
it is not a byte-reproducibility claim. Records are under
`source-rebuild-bef699262/` and `guest-native-package-independent-bef699262/`.

All six hosted jobs passed on the first attempt, with the tested merge tree
identical to the candidate tree. macOS reported 2,497 passes, seven deliberate
ignores and no runtime skips; Ubuntu reported 3,064 passes, 18 ignores and
519 runtime skip diagnostics. Python suites ran 1,055 cases with 81 explicit
skips. Exact logs and source binding are in `guest-gate-ci-bef699262/`.
The ordinary hosted Linux lane remains distinct from strict reference
conformance of the frozen Linux release candidate.

On the primary Mac, K109, K111 and K112 passed. K111 completed in 52.2 seconds
with a verified empty tree and no host/guest receipt contradictions. This is
a new successful measurement; the earlier intermittent startup failure and
its unknown cause remain recorded. K112 still establishes correct refusal
of unsupported owner-loss requests, not that unavailable guarantee.

The normal installed version route passed all 27 execution facts. Its valid
sampling report was incomplete: five ticks, no exact workload reads, one
`inventory_vanished` and one `supervisor_unobserved` error. These errors are
retained; the short version probe contributes no API exposure qualification.
Independent replay passed 48 checks while preserving that distinction.

Synthetic source-watch revocation passed all 21 facts and 47 independent
replay checks, including a 2.500580-second post-refusal child hold. On one
warm boot, all 20 service and 20 actual-client attempts passed. Maximum
release latency was 100.4 ms, and maximum installed-client exec to first
workspace write was 318.3 ms, each within the one-second bound. All 51 final
lifecycle checks passed; owned processes were absent and the workspace was
detached before the API workspaces were prepared.

These results are retained under `guest-native-gates-bef699262/`,
`guest-native-version-bef699262/`, `guest-native-source-watch-bef699262/`,
`guest-native-warm-bef699262/`, `guest-native-measurements-bef699262/` and
`guest-native-runtime-independent-bef699262/`.

The second Mac passed the same signed package's six signature checks,
installation and repeat-install refusal. Cold agent and warm tool work took
80.338 seconds and 0.378 seconds respectively. A three-second wall limit
returned in 3.217 seconds with an explicit unknown/unverified outcome.
Synthetic source-watch revocation passed all 22 facts, and four complete
summaries independently recomputed. All 14 installed files and modes were
unchanged, owned processes were absent and both task mounts were detached.
The retained bundle contains 147 files; independent bounded review passed
171 checks. These results are in `spare-mac-bef699262/`.

The final-candidate API-key sequence began with a successful missing-source
control: all six facts passed, without a workload or credential-source read.
Exactly one paid A01 then created the requested public `hello` file and
settled cleanly, but **failed qualification with 27 of 28 facts passing**.
Its sampler recorded 42 ticks, 37 exact workload environment and argv reads,
zero secret hits and two `inventory_vanished` errors. Those errors lack process
attribution; complete periodic sampling is not established. The original
counter values and failed verdict remain unchanged.

Independent diagnostic replay reproduced all 28 facts, the complete 161-frame
guest journal, four exact credential uses, both summaries and native bindings.
The vendor reported two turns on `claude-sonnet-5-5` and USD 0.0062354.
A separate bounded public-file witness confirms the task output after clean
settlement; it does not change the failed sampling verdict. All 38 final
lifecycle checks passed, with the original credential source generation
unchanged, the private copy removed and the owned workspace detached.

The remaining 12 paid lanes (small task, ten repetitions and vendor revocation)
were not run in this stopped sequence.
Evidence is in `guest-native-api-completion-bef699262/` and
`guest-native-api-control-bef699262/`. OAuth, notarization and publication
remain pending. Later documentation-only changes do not change the frozen
artifact's source identity above.

The final candidate's fault matrix was subsequently collected independently
of the stopped API sequence. All 11 lanes passed in 627.317 seconds, including
both actual-client lanes. Independent replay reproduced all 118 owning facts,
and all 80 final lifecycle/preservation checks passed. No emergency kill or
retry was needed. Owned processes and disk holders were absent and the exact
workspace was detached; expected failed-component boot disks remain retained.
The matrix SHA-256 is
`5a69e4fbdb76da6ab0fad3ce0837a7340e7ecd8ca9e82ed92aabb62b44f39b28`.
Records are under `guest-native-faults-bef699262/`,
`guest-native-measurements-bef699262/` and
`faults-collection-supplement-bef699262/`. This result qualifies these fault
fixtures and observations; it does not change the failed API sampling verdict.

The separate API continuation reused the exact A01 repository and volume, with
the original qualification criteria and failed results unchanged. It allowed
only collection of the remaining distinct lanes after independent replay of
each predecessor; it did not authorize a repeat of A01. The small-task lane ran
once and stopped collection after 69.676 seconds. Its task checker passed and
the vendor reported six turns and USD 0.0119804, but only 25 of 28 qualification
facts passed. The sampler reported 176 ticks, four `inventory_vanished` errors
and one `supervisor_unobserved`, with positive exact workload observations and
no secret hits. Sampling remains incomplete.

The other two false facts concern evidence retention. The test wrapper tried
to create `task-check.stdout` and `task-check.stderr` after the owning helper
had already written them, raising `FileExistsError` before full vendor-attempt
retention. This is a harness defect, not evidence that the missing records
were retained. The original failure is preserved while a repair is tested
offline. The ten repetition lanes and real vendor revocation did not run
in this stopped continuation.
Owned cleanup and exact-volume detach completed; no retry occurred. Records
are under `guest-native-api-continuation-bef699262/` and the existing API
completion/control directories.

## Completed API-key collection

A separate finite continuation collected the ten remaining repetitions and
one real vendor-stream revocation, once each. It allowed collection to proceed
after a well-formed incomplete sampling report only when independent replay
confirmed every other owning fact, positive exact workload observations,
ordered supervisor exit, no detected hits and clean source/process lifecycle.
It did not change the qualification criteria or any earlier result.

All ten repetition tasks succeeded. Repetitions 02, 04, 05, 06, 07, 08 and 10
passed all 28 facts. Repetition 01 failed sampling with one
`inventory_vanished` error; repetition 03 recorded one `identity_changed` and
three `selected_process_vanished` errors; repetition 09 recorded ten
`inventory_vanished` errors. Those three results remain 27/28 failures.
All ten retained positive exact workload environment/argv observations and
no detected hits. This does not establish complete coverage for failed rows.

The real revocation lane completed in 238.25 seconds without collector
intervention. An actual content delta preceded removal of the pinned private
credential copy. The journal records three credential uses, termination of
active request 3 with `credential_revoked`, and denial of retries 4–14.
The client and both bound receipts exited with code 1 and settled cleanly.
Its original verdict failed two of 36 facts: sampling was incomplete
(1,864 ticks, 1,859 exact reads per channel, nine `inventory_vanished` and one
`selected_process_vanished` error), and the vendor-failure predicate rejected
the terminal subtype. No hits were detected.

The exact terminal fields are `type=result`, `subtype=success`, `is_error=true`,
`terminal_reason=api_error` and two turns. The predicate incorrectly required
an `error_` subtype. Anthropic's
[SDK error contract](https://github.com/anthropics/claude-agent-sdk-python/blob/main/src/claude_agent_sdk/_errors.py)
explicitly permits the observed shape when the loop completes with a final
API error. The source predicate now accepts it while still requiring the
literal error flag and separate matching nonzero receipts. A full persisted
replay regression reproduced the original rejection; all 29 revocation tests
then passed, including non-error and malformed-terminal rejection. This is a
tooling correction, not a rewrite of the frozen live result or a sampling pass.
Independent evaluation of the retained terminal and receipts first reproduced
all 36 original facts, then confirmed that the corrected adapter changes only
`vendor_reported_failure`. Its derived result still fails sampling. The separate
record is `guest-native-api-continuation-bef699262/corrected-terminal-fact.json`;
the original report and aggregate remain unchanged.

Across this candidate's 13 provider-capable invocations, the vendor reported
30 turns and USD 0.04277980 in total; these are reported usage values, not
independent billing measurements. The original source generation and frozen
artifacts remained unchanged. Private copies/configurations were removed,
owned processes and disk holders were absent, and the exact workspace volume
was detached. A final observer used the wrong cleanup-record shape; its
failure is retained alongside the corrected lifecycle record. Per-lane
workspace witnesses are available, but no final directory rescan is claimed.
The complete matrix is `guest-native-api-continuation-bef699262/api-matrix-aggregate.json`,
SHA-256 `921ab02326f3628e0832b08357039e74fd0adeabb975fa7b7d4329fdf8340eac`.
All 14 requested rows have been collected; the matrix and full K113 remain
unqualified. No completed paid lane was repeated and OAuth was not accessed.

The source harness now owns small-task checker retention directly. It retains
the vendor attempt and inputs first, then separately exports the checker
journal, receipts, both summaries and fixed task files without recreating
already-written output files. Offline replay binds exact input hashes to the
owning report, verifies distinct attempts on the same boot, and requires host
and guest enforcement for a successful checker verdict. A well-formed nonzero
checker result is retained and replays as FAIL; malformed receipt outcomes
are refused. Checker export failure cannot discard the vendor export.
Eleven focused controls passed independently, including the actual order of
output and retention, changed input hashes, unprotected host receipts, malformed
exit-code types and retained failed checkers. No paid small task was rerun,
and this repair cannot reconstruct the original missing vendor export.

## Source archive follow-up

Source commit `42ac20b54` adds the root `install.sh` to the archive's explicit
selection. The exported experimental image builder reads its public Linux
archive pins through `dist/coordinates.py`; the earlier 847-file archive
could build all five native components but could not import that builder.
An actual archive/extraction regression reproduced the missing-file failure
before the fix. All 38 packaging tests then passed, including an isolated
builder import with process and network creation prohibited. The expected
archive now has 848 source files. The later provisional `c25c297fc` package
below verifies that closure. It does not change the frozen `bef699262`
artifact or its recorded qualification.

All six hosted jobs passed at follow-up head `277d09a33`. The tested merge
commit `fe7809e9966aedc45be3d92c8d7552870aea5b88` has the same source tree,
`7404b9a2f793c09914a1b33587e16de24b273b3d`. macOS reported 2,497 passes,
seven ignores and no runtime skips; ordinary Ubuntu reported 3,064 passes,
18 ignores and 519 runtime skip diagnostics. Python suites ran 1,056 cases
with 81 explicit skips, and 535 documents had no broken links or anchors.
The exact logs and checkout bindings are in `guest-gate-ci-277d09a33/`.

The terminal/checker/socket follow-up at `cf5bae9de` also passed all six hosted
jobs on their first attempt. Its tested merge `5f6e5f3b55ec456c5ffd1e17df37a72c59c12a31`
and head share tree `5f03e60f14fdc501d83427a0f8e55d161ef84790`.
macOS reported 2,497 passes, seven ignores and no runtime skips; ordinary
Ubuntu reported 3,064 passes, 18 ignores and 519 skip diagnostics. Python ran
1,068 cases with 81 explicit skips, including 798 VM cases; 535 documents
had no broken links or anchors. The separate combined local VM run had
778 passes and 20 explicit skips. These results precede the sampler correction.
Exact hosted logs are retained in `guest-gate-ci-cf5bae9de/`.

The sampler follow-up `e82209aa8` passed all six hosted jobs on their first
attempt. Tested merge `a98ae7512b5c142effa5404ba0a74eb9fc54d5b4` shares
head tree `0ea51ee3df201d9dcb36e580fca3876dba0143cd`. Rust counts were unchanged;
Python ran 1,069 cases with 81 explicit skips, including 799 VM cases.
The exact checkout bindings and logs are in `guest-gate-ci-e82209aa8/`.

The installer follow-up `c25c297fc` passed all six hosted jobs on their first
attempt. Tested merge `cc508200772328cec6532c3642bb6a4fec25350e` shares
head tree `c94641caa7368ae9df715355a862185797ccb1e2`. Rust counts were unchanged;
Python ran 1,084 cases with 81 explicit skips, including 814 VM cases.
All 535 documents passed link and anchor validation. Exact checkout bindings
and logs are in `guest-gate-ci-c25c297fc/`.

## Separate diagnostic guest build failure

A synthetic diagnostic image build on the second Mac failed before its
planned cold/warm measurement pair. The corrected 848-file source overlay
imported successfully, but the guest's `sync` command hit a kernel Oops on
`7.0.0-38-generic`. The retained stack enters `_raw_spin_lock_irq` through
`flush_workqueue_prep_pwqs`, `__flush_workqueue` and `ext4_sync_fs`.
The VM helper reached its existing boot timeout after 601.408 seconds.
The image remains unqualified; neither a provider call nor the diagnostic
pair ran.

Read-only inspection also found a `systemd-journald` segmentation fault and
a damaged primary ext4 superblock. Two consistent backup superblocks allowed
bounded in-memory interpretation of the filesystem without repairing it or
replaying its journal. Both retained journal files passed `journalctl --verify`.
The `sync` executable, libc and loader match the original prepared guest.
The initiating kernel, virtualization, memory or storage cause is not known;
these observations do not attribute the earlier API sampling or startup failures.

The failed disk was not repaired or rebooted. Its hash remained
`4858535cf177884795ffeb62e59fed06714c92894b713ae5a03de4303fa2d83e`.
The original prepared image, frozen sources and installed files remained
unchanged, with no owned VM processes, disk holders or mounts left behind.
The diagnosis and preservation records are under
`sampler-inventory-attribution-bef699262/v3/`.

The next diagnostic preparation cloned the original clean guest image, without
using the failed disk. It failed when an early-boot synchronous service-start
check reached its 20-second bound. Later setup refused the recorded failure
before rewriting the service, running controls or syncing; the VM reached its
existing 600-second boot timeout. No diagnostic pair or provider call ran.
The failed clone and console are retained under
`sampler-inventory-attribution-bef699262/v4/`; independent review verified
cleanup and original-input preservation. This setup failure does not establish
the cause or resolution of the earlier kernel Oops.

A fifth diagnostic preparation moved the bounded service-start check out of
early boot. Preparation passed in 133.99 seconds, including the original
public-canary control's seven facts, unchanged kernel/packages/sampler,
explicit sync and clean poweroff. The resulting primary filesystem state
was clean. Independent review verified the exact prepared bytes and preservation
of the earlier failed disks. This does not explain or resolve the kernel Oops.

Its subsequent fixed cold/warm diagnostic invocation failed during service
startup, before either native attempt. The typed startup record observed owner
creation at 609 ms and the VZ start callback at 749 ms, but no connection,
guest Ready or validated session. The helper reached its existing 120-second
boot timeout at 120,817 ms. The retained console was empty; no sampler report,
collector frame or numeric attribution exists. The result is FAIL/INCONCLUSIVE,
not evidence about the API sampling errors. No retry or provider call occurred.
The failed per-boot disk and startup records remain preserved; the service
group was reaped, the workspace detached and the original prepared image,
sources and installed bytes remained unchanged. The settled records and
independent review are under `sampler-inventory-attribution-bef699262/v5/`.

Bounded read-only inspection of that failed boot found cloud-init requesting
network readiness because the diagnostic seed contains `bootcmd`, then waiting
for `systemd-networkd-wait-online`. Its early-boot dependencies precede the
controller. The persisted journal contains 562 entries through 2.661 seconds
and no controller or collector start; it does not cover the entire timeout.
This establishes a diagnostic startup-ordering hazard, not the cause of the
separate kernel Oops or the historical API sampling errors. The inspection
did not mount, repair, replay or modify the failed disk.

A sixth diagnostic preparation used the installed cloud-init disable marker
after its successful canary control and before checked sync/poweroff. It passed
with the original kernel and sampler. Its first measurement invocation reached
the collector but the strict host reader rejected an exact terminal-control
prefix before a frame; neither native attempt ran. A separately tested reader
accepts only those exact bytes at a physical line boundary immediately before
the frame marker, retaining the full raw console and all loss/binding checks.

With that reader, both fixed native `--version` attempts completed on one boot
and each passed all eleven execution, journal, binding and cleanup facts.
Both sampling reports were incomplete. The collector emitted 162 frames but
never supplied its required tail, so the fixed 15-second tail wait expired
and the attribution judge did not run. The invocation remains FAIL/INCONCLUSIVE.
Its source, image, raw output and earlier failed invocation remain unchanged
under `sampler-inventory-attribution-bef699262/v6/`.

The collector kept one console descriptor open while getty initialized. An owned
Linux PTY control demonstrated that a held descriptor returns EIO after
hangup while a fresh open can write; the installed getty unit specifies
`TTYVHangup=yes`. This proves the mechanism, not the unrecorded errno of the
failed diagnostic. A separate diagnostic-only correction opens and closes
the console for each frame without retries or relaxed loss counters. It does
not change the production sampler or retrospectively attribute API failures.

That diagnostic correction passed preparation and reached both version attempts.
The collector then emitted events beyond both attempts, but a different terminal
metadata prefix caused the strict reader to refuse framing; the final collector
checkpoint was absent. This seventh invocation remains FAIL/INCONCLUSIVE.
Its cold sampling report was complete; the warm report recorded one inventory
loss and no exact workload reads. All eleven execution/binding facts passed
for each attempt, and owned cleanup and original-artifact preservation passed.

Partial read-only inspection of its retained frames found that warm tick 2
could not open PID 623. Visible process events record that PID as a direct
child of the actual jail supervisor, exiting about 4.9 ms before the failed
open. It is distinct from receipt workload PID 634. No executable, birth or
UID was recovered for PID 623, so it cannot be identified as a particular
helper or excluded from scope. This supports an in-scope exit race in that
diagnostic, without establishing complete trace attribution or explaining any
historical API failure. The original refusal remains unchanged; no additional
pair was run. Records are under `sampler-inventory-attribution-bef699262/v7/`.

## Sampler process identity correction

A separate source review found that four observation checks compared the entire
parent/birth/UID tuple even though the process identity is PID plus birth tick.
This incorrectly recorded `identity_changed` when an already selected process
was reparented or changed UID without being replaced. The corrected comparisons
use birth ticks while retaining every metadata read and error path, anchored
proc-directory check, executable check and fresh selection on each tick.
Selection roles remain historical observations, not immutable process attributes.

Nine transition cases before observation and during environment/argv reads
reproduced the defect before the fix. The corrected sampler still detects the
public canary in both channels, and the existing birth-reuse, directory/executable
replacement, unreadable/vanished and malformed-metadata controls pass.
The sampler, positive-control and summary suites ran 82 cases: 79 passed with
three Linux-only skips on macOS; all 82 passed in the existing Linux development
guest, including actual `/proc` controls. Independent source review also passed.

This correction has no established causal link to repetition 03's retained
`identity_changed` counter and does not address unrelated inventory losses.
Frozen reports and the original prepared guest remain unchanged. This sampler
change requires fresh image-bound proof and installed qualification.

A fresh standard image was subsequently prepared from clean source `e82209aa8`
in 51.50 seconds. Its public-canary control passed all seven facts with no
scan errors. Independent review passed 93 checks covering the exact source,
signed Linux inputs, ISO payload, disk/seed hashes, clean sync/poweroff and
resource cleanup. The new disk is
`35154ce2c3ad62725b5dffb595062f167a6896e1c5b840c2de514a61e8fa7957`;
its seed is `26800da8b107139f3d4b01cf1114c44ba4c01731588a3ca86ed86683e2556526`.
This product image is separate from the old-sampler diagnostic V6 above.
Its provisional signed package and fresh component admission are recorded
below; a rebuilt host still needs installed runtime qualification.

## Installer storage and fixture cleanup

Image expansion previously skipped only wholly zero one-megabyte chunks.
The installer now tracks smaller zero runs and, on supported macOS filesystems,
deallocates their aligned interiors after all writes and exact size/checksum
verification. Unsupported hole punching keeps the valid seek-based image;
other errors retain the existing partial-output cleanup. Memory remains bounded
by the fixed six-GiB image limit. Actual-file controls and independent review
verified the native ABI, alignment, flush ordering and unchanged bytes.

One expansion of the frozen signed `bef699262` image verified the full six-GiB
post-expansion hash and reduced allocation from 2,855,272,448 to 1,587,146,752
bytes: 1,268,125,696 bytes saved (44.41%). Expansion took 7.31 seconds and the
separate full-file hash took 2.51 seconds. Original inputs were unchanged;
only the new duplicate was removed after recording its successful validation.
This measures that image on this APFS volume, not every future image or filesystem.

Installer checks now retain a passed negative case's exact mutation, output
hashes, postconditions and fixture identity before removing that generated
copy. Unexpected installer failures retain their fixtures; evidence-write or
cleanup failures fail the check and stop the sequence. The actual mounted-DMG
path and all seven installer assertions remain unchanged. Existing qualification
outputs are not removed. This prevents the three successful tamper controls
from retaining redundant payload copies.

The focused sparse-image suites passed 40 cases normally and under optimized
Python; the installer-check suite passed 37 cases. Both changes passed independent
review. The combined local VM suite ran 814 cases: 794 passed and 20 had explicit
platform/parser skips. Source bytes stayed unchanged during the suite and its
owned process group exited. These checks do not replace a newly signed package
and its actual installed acceptance.

The subsequent private provisional package at clean source
`c25c297fc61b7d0edb71d929a1b067faeeb03b53` contains that unchanged native-v6
image. Its DMG SHA-256 is
`b66023375eec009785363a4768573e4f6d699215eba47d1eff9fa53ceca8da2e`;
its retained source archive is
`8e7e446e4d53ff4c7bb5d6a8707daa984875efbf728e9658261ec555141290e0`.
All six strict Developer ID signatures, complete signed payload bytes/modes,
848 archived Git files and seven actual mounted-DMG installer cases passed.
The new negative fixtures were removed only after their proofs were retained.
The redundant new package staging directory was likewise removed only after
comparison with the signed DMG and retention of its source archive and proof.

Independent review passed 44 checks, including another full installed disk
hash, all signatures and the source closure. The installed six-GiB image
allocates 1,570,349,056 bytes. Installer free space remained above 14.74 GB,
and all owned mounts and processes settled. Evidence is in
`guest-native-package-build-c25c297fc/` and
`guest-native-package-independent-c25c297fc/`. This is a component-preparation
package: native-v6 is not yet admitted, no VM or provider ran in these package
checks, and no notarization or release qualification is claimed.

Five subsequent component phases passed on those exact signed installed bytes:
ten capability rows from sixteen attempts, 121 execution-boundary facts,
24 synthetic vault/revocation facts, same-image signed credential staging,
and 24 literal executable-binding facts. The binding control allowed the
authorized program and denied an actually executed byte-identical copy at a
different file identity. All five phases ran once, using three guest boots
and twenty total attempts. No native vendor or provider request ran.

Final verification passed fifty preservation and lifecycle checks: installed
bytes and generations, helper sources, package/image inputs and frozen source
stayed unchanged; owned processes and mounts were absent. Minimum free space
was 15,509,397,504 bytes. Two supplementary offline checker errors concerned
existing output schemas, not live results; both original refusals and corrected
checks are retained. Completion is
`guest-native-measurements-c25c297fc/completion.json`, SHA-256
`4ff325c51dfc94b7c40a95503ffb8512daec00cbde8acff224cebe9a7e90fea0`.
These measurements do not qualify native vendor execution or sampled exposure.

The [native-v6 component bundle](results/macos-vm-admission-2026-11-15/native-v6/README.md)
retains the fresh records and exact c25 offline tools. Its replay recomputes
the component verdicts, signed-image bindings and six native admission pins;
it does not replay signing, live scans or cleanup. The source admission now
selects this disk/seed pair and its twelve actual measurement timestamps.
The superseded native-v5 image, older intermediate images and mixed pairs
refuse; their original proof files remain unchanged. All 77 targeted Rust
VM tests passed with no failures or ignores. Vendor, K113, release and rebuilt
host qualification flags remain false.

The signed-install verifier also now handles a disk image that attaches
partially before `hdiutil` fails or times out. Cleanup identifies only the
new exact-image attachment, refuses ambiguous or pre-existing devices and
proves absence before removing its empty private directories. Uncertain cleanup
preserves those directories and reports failure. Signature and payload checks
are unchanged. All 29 focused tests passed normally and with optimized Python,
and independent review passed. One actual successful verification of the
signed c25 installation completed in 6.70 seconds with one attach/detach,
unchanged artifacts, equal before/after image inventories and no remaining
temporary directory. The record is
`credential-staging-attachment-cleanup-c25c297fc/actual-success.json`.

Hosted checks at `8aaff8e4b` passed five of six jobs. The macOS suite stopped
at the descriptor-exhaustion fixture after 1,792 passing tests; its client
setup returned EINVAL in the one-free-descriptor case. The original failure
and exact head/merge-tree logs remain in `guest-gate-ci-8aaff8e4b/`.
An isolated local socket probe reproduced EINVAL when setting a timeout
after Darwin discarded a peer during an exhausted accept. The corrected
fixture uses bounded nonblocking reads, keeps descriptors exhausted until
empty EOF and requires a subsequent successful proxy request. It neither
ignores errors nor changes the production proxy. All 69 proxy tests then
passed locally, with the one expected child-helper ignore. The separate
socket controls and source review are retained in
`macos-fd-exhaustion-8aaff8e4b/`; a fresh hosted result is still required.

The subsequent first-attempt hosted checks at `5a176eaa0` passed all six
jobs, including the macOS descriptor-exhaustion fixture. The tested merge
`3dc2e422db56923f583989b5580c71942f72a99a` has the same tree as that source
head. Exact job logs and source bindings are retained in
`guest-gate-ci-5a176eaa0/`. These portable hosted checks do not replace
the strict Linux reference lane or installed VM qualification.

The isolated Linux CLI change at `61830dc2d` allows `--gate-fd` together with
`--from-path`. The owner must independently authorize the resolved plan;
program and install-root rechecks still run after release. Reserved attempt
ids, label-only mode, persistent state and profile `none` remain refused.
All 55 portable native-path tests, nine gate tests and 72 acceptance-map
tests passed. New map clause I03.5 requires the actual Linux boundary test;
the focused reference execution recorded below subsequently passed it.
The fresh onboarding/learning record below now covers the changed Linux inputs.
Full strict conformance and the tested freeze still need refreshing before a
new Linux release candidate. A new image remains required.

## Managed native sampling integration

The current guest now holds native execution at the Linux managed gate until
it has independently checked the Prepared receipt against the requested
policy, arguments, limits, program and selected vault credential. It retains
the exact Prepared bytes privately, rechecks the image inputs and credential
source generation, and requires a successful first sample before releasing
the workload. The main controller alone writes release; cancellation and the
existing wall deadline remain active while the worker validates and samples.
Early positive control messages refuse, and a terminal refusal closes the
gate. Split and coalesced control frames retain their individual and total
size bounds.

The resulting `ukai.vm.sampled-exposure/3` report binds Prepared identity,
validation, arming, release and terminal observation. Both host readers
check those bindings and distinguish a valid incomplete observation from
a complete one. Missing required nullable fields, changed Prepared bytes,
wrong policy or process identity and current-session contract downgrades
refuse. The live host still checks the final receipt against its independently
planned network policy and limits before inspecting sampling evidence.
The shared test vector is part of the checked build-input closure.

The combined local VM suite ran 871 cases: 851 passed and 20 had explicit
platform/parser skips. Its exact release-built service helper and all VM
source bytes stayed unchanged; the owned process group exited and free space
remained above 15.14 GB. The first combined invocation and its failures are
retained: that command omitted the release helper path, and six current
revocation fixtures still described version 2. Corrected current fixtures now
exercise version 3 and explicitly reject downgrades; historical fixtures were
not changed. The final record is
`managed-native-v3-integration/python-suite-corrected.json`.

Focused Rust VM, sampler, service and provenance checks, normal and optimized
Python reader/guest tests, strict all-target Clippy, formatting and all 536
document links also passed. Independent reviews covered the release boundary,
the two readers and the shared fixture. Local release builds succeeded with
the existing missing-`libLLVM.dylib` stripping warning retained; these builds
are test helpers, not distribution qualification.

A separate local tooling probe found the matching LLVM library already in
the pinned toolchain's `lib` directory. Supplying that directory only through
the probe's `DYLD_FALLBACK_LIBRARY_PATH` made `rust-objcopy --version` and
debug stripping of a disposable Mach-O object succeed. Debug information was
present before stripping and absent afterward; tool and library bytes stayed
unchanged. `toolchain-strip-environment-1.98.1/result.json` retains the result.
No toolchain installation was modified, and a future package build still
requires its own recorded environment and verification.

All six first-attempt hosted jobs at `f745bfbfc` subsequently passed. The
tested merge `1693568fe23466f3e6b2e275054fa2ea2fd24dac` has the identical
source tree. macOS ran 2,512 passing Rust tests with seven ignores and no
runtime skip diagnostics. Ubuntu reported 3,073 passes, 18 ignores and 520
explicit runtime capability/header skips. The hosted VM Python suite ran
871 cases with 82 explicit platform skips; the frozen native-v6 component
replay passed. Full logs and bindings are in `managed-native-v3-ci-f745bfbfc/`.

The exact clean optimized `f745bfbfc` Linux binary then passed the actual
managed native gate test and both D2 boundary tests on the reference host,
with three executed tests and zero skips. The gate test exercised successful
release, wrong policy digest, gate EOF, program replacement and install-root
replacement. Doctor matched the owning reference manifest. Twenty-one final
checks verified source and binary preservation, retained evidence and cleanup
of all three scopes and their clients. No VM or provider ran.

That binary's SHA-256 is
`348e4c2b9ade7d0d5109a9c78c275be322da76524ba70763f9a7945c153c295a`;
its 230 compiled input files have digest
`sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.
The later onboarding-harness revision `dce53219b` has identical compiled
input blobs, modes and sizes. This equality does not relabel the executed
binary's source revision. The focused result is
`managed-native-cli-gate-8aaff8e4b/focused-f745bfbfc-v3/final-summary.json`,
SHA-256 `755168f3b815481e2773ba96b64bc0f118e3ec400200a7b480ad07bfea1d4e08`.
Full strict conformance remains pending.

Historical version-2 reports retain their original semantics and proof bytes.
Known older guest Sessions remain usable for literal operations; current
native credential-bearing execution requires version 3. The new source does
not promote the earlier failed API sampling rows or the existing native-v6
component image. Full strict Linux conformance, a newly pinned guest image and
installed acceptance remain necessary before this path can be qualified.

## Fresh onboarding evidence collection

The onboarding harness now permits one vendor invocation per workload, with
the existing two-attempt behavior retained as the default. The option is
forwarded and recorded by both runners. Selecting one permits at most two
CLI launches across onboarding and learning; it does not bound the vendor's
internal API requests, token usage or billing.

The host reads the API credential once through a bounded no-follow descriptor
and transfers those exact held bytes into an exclusive private guest file.
It never writes a host credential copy or records a value digest. The guest
removes only that file's verified identity, including when vault setup times
out. A workflow timeout now triggers a separate bounded evidence retrieval
before VM teardown. Teardown, temporary-directory cleanup, original-source
verification, retained-file scanning and final recording are independent;
one failure cannot bypass the remaining checks. Unverified cleanup or changed
source identity blocks the result.

All 22 synthetic harness tests and independent review passed. CI now discovers
both the guest and outer-VM test modules. The retained-output scan covers raw
key bytes in regular files; it is not encoded-secret or guest-memory coverage.
These source-validation checks themselves ran no VM or provider workload.

Hosted checks at `dce53219b` passed both onboarding modules but exposed a
separate simulated-jail publication race. The fixture marked a jail started
before its scenario had created the workload child; the cancellation test
could then index an empty child list. Both fixture branches now publish
started only after scenario initialization. An event-gated control fails
deterministically with the old bytes and passes the correction. The 117
affected guest tests ran normally and with optimized Python: 104 passed and
13 had explicit platform skips in each run. Independent review passed.
Production guest code and the real Linux gate results are unchanged; the
original failed hosted result remains retained in
`onboarding-harness-ci-dce53219b/`.

All six first-attempt hosted jobs at `264e85a84` subsequently passed. The tested
merge `76e614318bc25f062fb3c97c720df042d6a84722` has the identical source tree.
macOS reported 2,512 Rust passes and seven ignores; Ubuntu reported 3,073 passes,
18 ignores and 520 explicit runtime skips. Contracts ran 1,159 cases with
82 platform skips, including 872 VM cases and all 22 onboarding tests. The
native-v6 offline replay and all downstream stages passed. Full logs and
bindings are in `guest-harness-publication-ci-264e85a84/`; ordinary hosted
checks still do not replace strict reference conformance.

## Current-input Linux onboarding and learning

The [fresh rc.7-labelled record](results/release-preview-2026-11-16-rc7/README.md)
was collected once in a disposable x86_64 QEMU VM on the reference host. It ran
the exact clean optimized `f745bfbfc` binary, SHA-256
`348e4c2b9ade7d0d5109a9c78c275be322da76524ba70763f9a7945c153c295a`,
with build inputs
`sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.
The host and guest harnesses are exact committed `dce53219b` bytes; later
fixture/documentation changes do not relabel the executed binary.

Signed installation through the first contained OpenCode result took
152.032 seconds, including its download and excluding the 460.846-second
VM/package bootstrap. OpenCode 1.18.32 used `anthropic/claude-sonnet-5-5` and
the API-key vault. Exactly two vendor CLI rows ran, each with attempt one of
one; there was no retry. This is not an API-request, token or billing cap.
Installation, contained `true`, the agent task, learning, upgrade, archive
corruption rejection and signature corruption rejection passed.

Both agent receipts settled with enforced containment, observed execution,
verified empty process trees, exit zero and all six coverage classes active
without gaps. The learning proposal grants only `/etc/nsswitch.conf` from
its own denied-read evidence. The intended learning fixture was not proposed;
15 unresolved reads remain ungranted, and no network grant was proposed.
This supports the recorded narrow proposal, not blanket path attribution.

The entire invocation completed in 773.324 seconds. The VM, scratch data and
temporary credential source were removed; the original primary source's
generation was unchanged. Held-byte scans of retained outputs completed with
zero key matches. The final copy verified all 100 retained files and their
remote before/after generations; no credential source was reread for copying.
The owning summary passed 28 checks and the independent review passed 274,
including both unchanged `verify_preview_evidence.py` checks. Records are
`reference-onboarding-plan-G/coordinator/final-summary.json` (SHA-256
`a697cec41faf8eaccf1bab53099a7789f68da357f4367c264519e02c2f216dd3`) and
`reference-onboarding-independent-GF/review.json` (SHA-256
`e7a7b82957a4917d12ddb201ec0fc0dedb0687407f9308d956493a524e370043`).

The package used an ephemeral test signing key. These current-input K11/K27
results do not qualify an ARM image, native Mac vendor execution, earlier
failed API lanes, OAuth, production signing or public release. The subsequent
strict reference result is recorded below.

## Strict current-input reference conformance

Commit `a8e4aecb071a0367001f309a659897d6aa336600` passed all six first-attempt
hosted checks: [Rust and dependency policy](https://github.com/monocursive/ukai/actions/runs/43817037176),
[contracts and website](https://github.com/monocursive/ukai/actions/runs/43817037136),
and [fleet](https://github.com/monocursive/ukai/actions/runs/43817037155).
Its PR merge tree exactly equals the source tree. Ordinary hosted Linux
retains 520 runtime-skip diagnostics and is distinct from strict conformance.

The exact-source [reference run](https://github.com/monocursive/ukai/actions/runs/43817218080)
passed 3,073 tests, zero failures, 18 explicitly ignored tests and zero
runtime capability skips across 117 groups. Both D2 integration checks,
managed native gate checks and K11/K27 release-evidence checks executed and
passed. Its own doctor reports the clean optimized source and input digest
`sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.

The `linux-preview` gate report has no problems or warnings. Unsupported,
elsewhere and credential rows remain explicit; full-specification acceptance
is not established. The [retained bundle](results/conformance-2026-11-16-a8e4aecb/README.md)
preserves all 16 raw artifact files unchanged, including the gate report's
stale descriptive notes about older K11/K27 evidence. The source notes now
refer to the verified current evidence index; no clause or test was changed.
The run's own compiled `xtask` generated the tested freeze from its own doctor,
and `freeze --check` passed. Only the tested build identity, input digest,
executable hash and supervisor scope changed; the frozen policy and toolchain
sections stayed byte-identical. The following rc.7 record supplies the later
exact-candidate builds and final-commit checks; this tested-I freeze is unchanged.

## Signed private Linux rc.7 candidate

The [final rc.7 proof](results/release-candidate-2026-11-16-rc7/README.md) binds
source `0be9d1e820b0d47493883053253491bbd2196ba3`, tree
`245e70ec60791c1108186e360764fc7c38dc3d07`, and the unchanged 230 compiled
inputs `sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.
The PR merge has the identical tree. All six first-attempt hosted jobs passed:
[Rust/dependencies](https://github.com/monocursive/ukai/actions/runs/43822389786),
[contracts/website](https://github.com/monocursive/ukai/actions/runs/43822389760)
and [fleet](https://github.com/monocursive/ukai/actions/runs/43822389837).
macOS recorded 2,512 passes / zero failures / seven ignores; Ubuntu recorded
3,073 / zero / 18. Python ran 1,159 cases, including 82 explicit platform skips,
872 VM cases and the 22 onboarding cases. The ordinary hosted Ubuntu lane
retains 520 capability-skip diagnostics.

All four [rc.7 build/assembly jobs](https://github.com/monocursive/ukai/actions/runs/43822535195)
passed once. The separate exact-J [strict reference run](https://github.com/monocursive/ukai/actions/runs/43822530994)
passed 3,073 tests, zero failures and 18 pinned ignores across 117 groups with
zero runtime capability skips. Its own clean optimized doctor, exact source
inventory, D2/managed gate and K11/K27 checks were verified. All 16 raw artifact
files are retained once in the final proof. `linux-preview` has no gate problems
or warnings; `all_noncredential_gates_pass` remains false. The tested-I freeze
SHA-256 `39fafd8684997a3414a6a530df50fd5b3796de91356f8a39bb55e0c3b10fa2be`
was not regenerated after J.

Both downloaded native archives passed actual Linux tool, agent and deadline
cases, doctor, archive installation, installer regressions and deterministic
restaging. ARM used one disposable HVF boot, 37.821 seconds for the phase;
x86 took 14.685 seconds. Independent ARM review passed 572 checks; x86
compressed-proof replay passed 46 plus 15 final lifecycle checks.

The existing production release identity signed this candidate once after
native validation. All eight candidate files were independently verified;
archives, installers and notes remain byte-identical to the verified CI
candidate. Actual production-signed bootstrap then passed on both targets:
ARM 26.556 seconds overall / 0.620 seconds in its bootstrap scope, and x86
1.521 seconds. Signature verification preceded Minisign-free fresh and repeat
installation; modified private archives were refused while preserving the
existing installation. ARM independent review passed 179 checks; x86 passed
71 remote checks and 74 checks of its retained compressed proof. These checks
used locally supplied files, not a public release download. The final private
eight-file ZIP is 9,378,850 bytes, SHA-256
`141a89bd3f22a9787b7cc3b757e2a24abe9bd17f225de215bb9bb2fbabb6a5fe`;
its independent 56-check review passed, and it contains no private key.

All owned processes, VM scopes and image holders settled. Original source,
images, downloaded artifacts and every historical failure remain preserved.
The signed candidate is private: no tag, publication or PR merge was created.
These results qualify this Linux preview scope only. They do not qualify a
managed version-3 Mac guest image or installed host, notarization or native
macOS Endpoint Security. The earlier 14 API-key lanes remain eight strict
passes and six failures; OAuth remains deferred. No historical API or kernel
failure is relabelled. The documentation-only record leaves this release's J identity, signed bytes
and tested-I freeze unchanged.

## Next guest-image prerequisites

This is the earlier prerequisite and storage snapshot. The current R/S results
above supersede its pending image, package, source-rebuild and capacity status;
the observations and failures below retain their original scope.

A read-only security follow-up found that Ubuntu lists
[CVE-2026-99103](https://ubuntu.com/security/CVE-2026-99103) as pending for
Resolute, with its fix in `7.0.0-44.44`. The observed Security/Updates packages
were still `43.43`; `44.44` was available only in Proposed. Exact `43.43`
workqueue source retains the affected ordering, while `44.44` contains the
upstream fix. The measured ARM guest is `38.38`; its exact source tag resolved,
but bounded source-byte requests failed, so no direct inspection of that
version is claimed. This finding does not attribute the earlier kernel Oops.
The report is `ubuntu-kernel-cve-2026-99103-readonly/review.json`.

The initial metadata-only review authenticated a stable Ubuntu 26.10 ARM64 minimal image with
checksum metadata for `release-20261105`, with expected SHA-256
`bac15af78c37fec8e9474a9a784041c13ddb2603b9095435b7e4269e3faf3064`.
Its authenticated manifest names kernel `7.3.0-10.10`; Ubuntu lists this release
as unaffected by that CVE. The image checksum signature and matching
`20261106T000000Z` Stonking, Updates and Security snapshot metadata verified
against fingerprints independently published by Ubuntu. The isolated keyring
did not change system trust. `ubuntu-2610-authentication-2026-11-16/review.json`
retains the records. No image or package payload was downloaded, no image was
selected, and layout, boot, userland and containment compatibility remain
unqualified. A future builder must pin matching suites and the actual new
signed ARM executable before collecting fresh admission evidence.

A subsequent bounded read-only prerequisite check verified the actual
413,204,480-byte image against that authenticated digest and all six ARM64
main/universe indexes against the matching signed snapshot SHA-512 entries.
The standalone, unencrypted qcow2 has a 4,831,838,208-byte virtual disk with
ARM root, an additional ext4 XBOOTLDR `BOOT` partition and EFI/FAT32. Both GPT
copies verified; the two ext4 primary superblocks report clean flags. These
header observations are not a filesystem check or boot qualification. The
whole-disk converter and 6 GiB extension need no partition-index assumption.

Authenticated package records expose a session-bus provider difference:
`dbus-broker` enables a global user `dbus.service` alias, while the packaged
`dbus-daemon --nofork` unit matches the guest's existing MainPID-only bus
preservation. Four public package payloads were inspected read-only; no
package was installed. This is a compatibility inference, not an observed
broker failure. The reviewed builder explicitly selects and verifies that daemon before
enabling the controller, without changing the system bus or guest process
allowlist. The same source slice pins signed J's ARM ELF,
the dated Stonking image/snapshot, and refuses unexpected standard APT source
entries before update. Signature, profile, catalog and native guards remain.

The [subsequent prerequisite record](results/guest-image-prerequisites-2026-11-16/README.md)
binds the final source/test results: 34 tests passed normally and with optimization
enabled, zero skips, plus 34 independent source checks. Only the builder and its tests change;
the owning 230 compiled inputs remain `sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.
Nine independent provider controls also passed. A read-only show of the already-active
reference-host daemon was accepted by the exact frozen properties parser; no
start, reload, selection or process reads occurred. That formatting observation
is not proposed-image qualification.
J's signed Linux candidate and tested-I freeze remain unchanged. Dependency
resolution, image boot, userland, containment, managed-native version-3 evidence,
fresh admission and installed Mac qualification still require actual runs.
The earlier metadata-only record and all historical failures remain intact.

Measured prior allocations require about 16.64 GB free to prepare a comparable
image, and 21.59 GB for the fresh image plus bounded package/installer checks,
while preserving the 12 GiB reserve. The primary Mac had about 15.19 GB free;
the last spare-Mac measurement was also insufficient. A bounded APFS audit
found only 26.3 MB of private disposable objects in the original target and
512.1 MB in the protected current build cache. Most other reported allocation
is shared with unselected clones and cannot be counted as reclaimable space.
Neither set had been deleted at that observation. At those measured values,
even the known private total left about 914 MB short for preparation and
5.86 GB short for the combined package/install work.
`managed-v3-arm-storage-feasibility-H.json` and
`compiler-cache-feasibility-H-review.json` retain those bounds. Historical
images, executables, sources and proof records remain preserved.

Later rc.7 native/bootstrap work reclaimed only the two new successful
reassembly archive copies, successful ARM native overlay/vars.fd and bootstrap
overlay/vars fixtures, and 23 explicitly reviewed non-executable `.rmeta` paths in the task compiler
cache. Their private allocation total was 135,421,952 bytes. All held deleted
file descriptors were closed before measuring the immediate 11,853,824-byte
free-space gain; a later whole-filesystem observation was 14,913,376,256 bytes
free. The other 2,755 cache files retained exact metadata. The later bootstrap
fixture cleanup observed another 137,940,992-byte increase; its initial
allocation-only metadata refusal remains retained. These observations
do not guarantee a corresponding allocation gain or solve the approximately
22 GB planning requirement for the next image/package. A reviewed external
storage route remains pending. No historical image, proof, source or executable
was deleted; exact cleanup records are included in the final rc.7 proof.

The pinned Mac toolchain's stripping warning was traced to a missing LLVM
library path. A private clone of Rust 1.98.1 with one internal relative library
symlink passed the unchanged packager environment filter, exact compiler
selection, a tiny offline Rust release build and real debug-info stripping
without warnings. All 350 original and copied toolchain file hashes and modes,
global settings and packager inputs stayed unchanged. The initial probe's
overbroad refusal of unrelated Android emulators is retained separately;
those processes were untouched. Evidence is in
`toolchain-rpath-plan-1.98.1/attempt-v3/execution/result.json`. Actual Ukai
compilation and package qualification remain pending; the small probe does
not resolve the disk-capacity constraint.

## Remaining release limits

Local inspections did not establish usable Ukai Endpoint Security provisioning
or notarization credentials. They do not establish Apple's account-side
approval status. Native macOS containment remains separate from the warm-VM
route and still requires the relevant authority, remaining native workflow
engineering, a signed/notarized candidate and protected-Mac acceptance. The
earlier unsigned native candidate passed its scoped staging/install/upgrade/
removal checks and correctly refused production distribution and native
workload admission.

The warm-VM route does not require Endpoint Security. Its current R API-key
sequence is incomplete: the coding task passed its functional and evidence
retention checks but failed sampling, leaving ten repetitions and revocation
unrun. The historical failures remain unchanged. OAuth is deliberately pending
at the user's request. The two failed suspension lanes and six unrun fault lanes also remain open.
The source-only export fix requires a fresh image and live qualification before
it can address those candidate failures.
Complete vendor qualification, installed release
acceptance on notarized/stapled bytes, cross-UID distribution and vendor-binary
redistribution authority remain unestablished. No notarization submission or
public release occurred.

The original guest kernel failure's cause remains unassigned. Successful
cached-disk image measurements do not establish universal runtime health.
Unsupported owner-loss guarantees remain explicit; passing their refusal test
does not provide those guarantees. Full production readiness is not claimed.
