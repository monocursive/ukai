# Ukai candidate qualification — 15 November 2026

The frozen Linux candidate passed its `linux-preview` qualification and is
signed locally with the existing release identity. It is unpublished. This
does not establish full-specification production readiness, native macOS
containment, or qualification of later runtime changes.

The [earlier readiness snapshot](production-readiness-2026-11-15.md) retains
the implementation history and failed runs. [Draft PR #51](https://github.com/monocursive/ukai/pull/51)
contains the isolated Linux candidate, excluding unrelated local Arena work.

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
A fresh hosted run, final admitted-host validation, source-archive rebuilding
and provider qualification remain open.

## Remaining release limits

No usable Endpoint Security provisioning profile was found among the 17 local
profiles decoded for this task. This does not establish Apple's account-side
approval status. Native macOS release still requires that authority, remaining
native workflow engineering, a signed/notarized candidate and protected-Mac
acceptance. The actual unsigned native candidate at the frozen Linux source
passed staging/install/upgrade/removal checks and correctly refused production
distribution and native workload admission.

The warm-VM route does not require Endpoint Security, but still needs full
K113 engineering and vendor evidence, complete installed release acceptance
on the notarized/stapled bytes, and notarization. Its successful synthetic
source-watch measurement does not satisfy vendor compatibility. No usable
notarization credential was located in
the inspected local metadata; no notarization submission was made. Existing
scope limits, including unsupported owner-loss guarantees, remain explicit.
