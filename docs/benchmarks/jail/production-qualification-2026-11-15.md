# Ukai candidate qualification — 15 November 2026

The frozen Linux candidate passed its `linux-preview` qualification and is
signed locally with the existing release identity. It is unpublished. This
does not establish full-specification production readiness, native macOS
containment, or qualification of later runtime changes.

The [earlier readiness snapshot](production-readiness-2026-11-15.md) retains
the implementation history and failed runs. [Draft PR #51](https://github.com/monocursive/ukai/pull/51)
contains the isolated Linux candidate, excluding unrelated local Arena work.

## Current status — 16 November 2026

| Candidate or gate | Current result |
| --- | --- |
| Linux `6ffff05dc`, `0.1.0-rc.6` | Signed private candidate; strict reference conformance and both native installers passed; unpublished. |
| Warm-VM `bef699262`, `0.1.0-preview.2` | Signed private candidate; all six CI jobs, source rebuild, package/installer verification, primary runtime checks and second-Mac checks passed. |
| Claude API-key qualification on `bef699262` | All 14 distinct lanes collected: eight strict passes and six failures. Seven of ten repetitions passed fully; three failed sampling. A01, the small task and vendor revocation also failed qualification. OAuth remains deferred. |
| Final-candidate fault matrix | All 11 lanes passed; 118 facts independently recomputed, with complete owned cleanup. |
| OAuth, notarization, native macOS Endpoint Security | Pending. OAuth is deferred at the user's request; no usable local notarization credential or ES profile was established. |

The API failures remain failures. Synthetic diagnostics are investigating
sampling gaps without provider calls. The original sequence and first
continuation stopped at their failures; a separately scoped continuation
collected the remaining distinct lanes without retrying a completed lane.
Full production readiness and public release are not established.
The sections below retain the source identities, evidence and earlier failures.

## Frozen Linux candidate

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
archive now has 848 source files. This packaging correction has not produced
a new signed candidate and does not change the frozen `bef699262` artifact
or its recorded qualification.

All six hosted jobs passed at follow-up head `277d09a33`. The tested merge
commit `fe7809e9966aedc45be3d92c8d7552870aea5b88` has the same source tree,
`7404b9a2f793c09914a1b33587e16de24b273b3d`. macOS reported 2,497 passes,
seven ignores and no runtime skips; ordinary Ubuntu reported 3,064 passes,
18 ignores and 519 runtime skip diagnostics. Python suites ran 1,056 cases
with 81 explicit skips, and 535 documents had no broken links or anchors.
The exact logs and checkout bindings are in `guest-gate-ci-277d09a33/`.

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

## Remaining release limits

No usable Endpoint Security provisioning profile was found among the 17 local
profiles decoded for this task. This does not establish Apple's account-side
approval status. Native macOS release still requires that authority, remaining
native workflow engineering, a signed/notarized candidate and protected-Mac
acceptance. The actual unsigned native candidate at the frozen Linux source
passed staging/install/upgrade/removal checks and correctly refused production
distribution and native workload admission.

The warm-VM route does not require Endpoint Security, but still needs resolution
of the failed API sampling and small-task retention qualification, OAuth
qualification, investigation of the retained startup and diagnostic kernel
failures, complete installed release acceptance on notarized/stapled
bytes, and notarization. The API-key pilot does not satisfy the complete
vendor matrix; OAuth remains pending at the user's request. No usable
notarization credential was located in
the inspected local metadata; no notarization submission was made. Existing
scope limits, including unsupported owner-loss guarantees, remain explicit.
