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

Normal installed-client source revocation, vendor compatibility, full K113,
independent installed-host acceptance and notarization remain separate gates.
K113 still needs guest-native program resolution and `@program` binding,
the bundled profile's attempt-state/environment carry, independent summary
recomputation and sampled-environment exposure checks. A specifically named
headless `--state attempt` combination can be qualified without implementing
the separate interactive/persistent-session matrix; that does not qualify the
default persistent alias. The required two authentication modes remain part
of the headless row. Metadata inspection found the configured `anthropic`
source file present, regular, private and operator-owned, but `claude-oauth`
absent. No source value or provider validity was inspected by that check.

## Remaining release limits

No usable Endpoint Security provisioning profile was found among the 17 local
profiles decoded for this task. This does not establish Apple's account-side
approval status. Native macOS release still requires that authority, remaining
native workflow engineering, a signed/notarized candidate and protected-Mac
acceptance. The actual unsigned native candidate at the frozen Linux source
passed staging/install/upgrade/removal checks and correctly refused production
distribution and native workload admission.

The warm-VM route does not require Endpoint Security, but still needs its
normal installed-client credential lifecycle, full K113 evidence, independent installed-host
acceptance and notarization. No usable notarization credential was located in
the inspected local metadata; no notarization submission was made. Existing
scope limits, including unsupported owner-loss guarantees, remain explicit.
