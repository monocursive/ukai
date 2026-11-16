# Ukai production-readiness work — 15 November 2026

This snapshot covers completed release hardening and qualification before the
final candidate build. Linux preview conformance passed; this does **not**
establish full-specification production readiness or supported native macOS
execution. No production release or website deployment was performed. Final
candidate commit checks and artifact results are tracked on [PR #51](https://github.com/monocursive/ukai/pull/51)
and in the local `evidence/production-2026-11-15/` records.

The later [qualification follow-up](production-qualification-2026-11-15.md)
records the exact frozen Linux candidate's completed checks and the separately
built warm-VM baseline. This pre-build snapshot remains a historical record.

## Source and scope

- Initial qualification snapshot: `8f8c0f753e1ca2ccf03c3bbe18eb0f16a4220977`.
- Native Linux candidate source: `5cfcf0c64e9832ba81b46b5f698374a863564790`.
- Integrated implementation snapshot: `5d359b9d8` in the main checkout and
  `128ff2273` on the isolated validation branch; the final candidate adds the
  tested freeze, this evidence snapshot and verified third-party attribution
  without changing runtime inputs.
- Jail build inputs: `sha256:efdc169e8e09f514c908e02bb6f972bc8761d2efc9af94d9b53d914a436f14e6`, independently matched by clean Mac and native x86_64 and ARM64 Linux builds.
- The existing unrelated website edits were excluded from the clean snapshot
  and preserved in the main checkout. Website dependency validation used the
  initial snapshot's site with the exact dependency patch subsequently included
  in `0d7393afb`. A separate main-checkout build also passed with those edits
  present (68 pages), without adding them to the release snapshot.

The published coordinates remain Linux `0.1.0-rc.5` and macOS VM
`0.1.0-preview.1`. The scope and requirements in [RELEASING.md](../../RELEASING.md)
and [the macOS specification](../../specs/jail-macos.md) remain in force.

## Completed changes

- Updated `rusqlite` to the 0.41 line and locked `libsqlite3-sys` 0.39.1,
  which bundles SQLite 3.54.1. This removes the affected bundled SQLite version
  identified by [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html).
- Conformance provenance now marks visible untracked source as dirty; copying
  such files to a build host cannot produce a clean-revision claim.
- Release assembly refuses to replace an existing Linux archive or Mac image
  pin with different bytes. Refusal occurs before creating or signing a
  candidate; identical archive bytes remain accepted.
- Generated Linux preview support notes (`30afbdced`) no longer assign old
  Raspberry Pi qualification to every future ARM64 binary. Both architecture
  entries distinguish binary/installer targets from runtime host qualification
  and require attached validation matching the candidate revision and input
  digest plus operator review. Signing does not clear that publication blocker;
  historical host limitations remain in force unless matching evidence supersedes
  them. Existing Pi records were not rewritten.
- Queued DNS requests reuse an answer completed while they awaited a worker;
  expired deadlines refuse even when an answer is cached.
- VM execution and `doctor` now select the same installation, including custom
  prefixes and explicit overrides. A broken adjacent image refuses instead of
  falling back silently; numeric prerelease identifiers sort correctly.
- Warm-VM packaging now builds and signs both the service and its `ukai-jail`
  client, checks clean client provenance, and preflights both command links.
  Installation rolls back failed activation and serializes concurrent installs;
  independent review reproduced two races and verified their repairs. No new
  DMG was built, notarized or accepted as part of this tooling change.
- Native macOS candidate tooling (`8381400b1`) now stages the exact `Ukai.app`
  layout and macOS 27 Info.plist, verifies clean native artifact provenance,
  and provides per-user install, upgrade, removal and interrupted-transaction
  recovery. Signing requires an approved matching ES profile, Apple-anchored
  Developer ID verification, standard enabled SIP and OS launch validation;
  decoded profile metadata is not authority. Notarization and stapling are
  separate explicit actions. Only an unsigned candidate has been built and
  locally installed; no native runtime gate was enabled.
- Onboarding commands retain their own newly created attempts, streams and
  changed vendor diagnostics before evaluating failures. They cannot borrow an
  earlier command's receipt. The existing one-Bad-Request retry and all
  acceptance assertions remain unchanged; pinned-agent debug logging is enabled.
- Promoted fresh current-input onboarding and learning evidence (`265b83054`)
  after both evidence verifiers passed. OpenCode 1.18.32 succeeded with
  `anthropic/claude-sonnet-5-5`; the previous alias's absence is preserved as a
  separate failed attempt, not hidden by the successful rerun.
- Linux containment and observation fixtures now select native syscall numbers,
  native headers and native filter evidence on ARM64. The i386 compatibility
  instruction probe runs only on x86_64; native denial checks remain on both.
  The terminal byte-comparison fixture waits for its direct-run output to drain.
- Foreign-ABI observation fixtures (`318e84637`) now include a genuine static
  ARM32 ELF32 EABI executable and check its sentinel bytes, syscall results and
  receipt degradation. The x86 behavior and strict unsupported-host failures
  remain in place; no runtime input changed.
- The N4 queued-control-frame fixture now uses an explicit readiness handshake
  (`38a2a77a4`) instead of an 800 ms scheduling margin. A poll-removal negative
  control still fails the repaired assertion. The socket-family host control
  (`b65ec13d4`) accepts IPv4 localhost with optional IPv6 localhost while retaining
  exact host comparison for the uncontained profile and all contained denials.
- CI test logs now live outside the source checkout. This fixes an untracked
  log making the provenance gate dirty without excluding untracked source from
  that gate or weakening its acceptance criteria.
- Updated [Astro to 7.4.12](https://github.com/withastro/astro/releases/tag/astro%407.4.12),
  [Wrangler to 4.162.0](https://github.com/cloudflare/workers-sdk/releases/tag/wrangler%404.162.0),
  and compatible transitive dependencies. The website and CI now require Node
  22.23.4, matching Astro's published requirement. Global runtime defaults were
  not changed.

## Completed verification

| Check | Source and result | Limit |
| --- | --- | --- |
| Remaining contracts-workflow Python suites | Initial snapshot: 628 cases, 625 passed, 3 skipped, 0 failures | Portable and fixture evidence; not live release conformance |
| VM transport and packaging regressions | Included above: 425 cases, 422 passed, 3 skipped | No release VM lifecycle qualification |
| Final VM package/client regressions | `07760c635`: 435 cases, 432 passed, 3 skipped; 66 focused package/installer checks and independent review passed | Synthetic installer payloads and real Bash execution; no built DMG or K108–K113 qualification |
| Native macOS candidate packaging | `8381400b1`: 49 Python tests passed on macOS and Linux/Python 3.14.4; independent review passed | Synthetic signature/profile failures and installer transactions; no real production signing or native workload acceptance |
| Actual native macOS unsigned stage | Clean `cc74f1d2b`, Rust 1.98.1: stage, manifest validation, temporary-home installation, version check and removal passed; operator state preserved | Distribution validation refused the unsigned bundle; doctor returned 125, `ready=false`, `native_development_disabled` |
| Onboarding evidence regressions | `e8ed786af`: 5 new command-level tests and 5 existing evidence-verifier tests passed; independent review passed | Harness integrity, not a successful real-agent run |
| Current-input clean-VM onboarding and learning | `265b83054` records native x86_64 candidate `5cfcf0c64`: installation, real agent, learning, upgrade and corruption checks passed; both K11/K27 evidence verifiers passed | Ephemeral test signing key and unpublished rc.6 candidate; one provider/model workflow, not general agent reliability |
| Distribution regressions | Included above: 39 passed, including actual ephemeral Minisign signing and wrong-key rejection | No production signing or publication |
| Generated host-support claim regressions | `30afbdced`: all 40 distribution tests passed, including actual ephemeral Minisign signing and wrong-key rejection | Candidate assembly keeps matching-validation/operator-review blockers; it does not supply host qualification |
| Link and evidence-store validation | Passed | Repository consistency only |
| Installer and host-manifest shellcheck | Passed | Static shell analysis |
| Website clean install and static build | Node 22.23.4; passed; all 67 HTML routes retained | Clean site plus dependency patch only |
| Served installer and public key | Build outputs equal repository files byte for byte | Local output; deployed bytes were not changed |
| npm dependency audit | Initially 8 affected production dependency packages; final production-only and full-tree audits both report 0 findings | Registry advisory results at check time, not a security audit |
| Rust dependency policy | Patched lockfile: advisories, sources, licenses and bans passed | Advisory database at check time |
| Ledger tests after SQLite update | 237 passed | macOS component and integration tests |
| Clippy | Clean snapshot: workspace/all-targets, warnings denied, passed | Native macOS compilation |
| Intel macOS compile check | `0d7393afb`: workspace/all-targets passed with warnings denied | Compile only; no Intel Mac execution |
| First complete macOS workspace run | `73d005650`: 2,430 passed, 1 failed, 7 ignored | One proxy EOF timeout; not an all-green run |
| Integrated macOS workspace rerun | `b5c8a4248`: 2,431 passed, 0 failed, 7 ignored | Component, portable and refusal coverage; no entitled native release execution |
| Current-input Linux reference conformance | `34c11f520`: 3,041 passed, 0 failed, 18 ignored; run `43706742434` passed, with no gate problems or warnings | `linux-preview` publication scope; unsupported macOS and broader specification clauses remain open |
| Initial Linux reference conformance | `8f8c0f753`: 3,035 passed, 4 failed, 18 ignored | Failed verdict: two stale freeze assertions and stale K11/K27 onboarding records; not final-source conformance |
| Native x86_64 final build and installation | `5cfcf0c64`: release build, tool/agent doctor, signed installation, upgrade/downgrade, tamper rejection, confinement, limits and verified cleanup passed | Unpublished rc.6 stage, temporary signing identity; full reference conformance recorded separately |
| Native ARM64 final build and smoke | `5cfcf0c64`: release build, Clippy, signed installer, tool/agent doctor, containment, limits and wall cleanup passed | Ubuntu 26.04.1 in the existing OrbStack guest; full stock-host qualification does not pass |
| Native ARM64 full suite | `b5c8a4248`, identical runtime inputs: 3,014 reported passes, 26 failures, 18 ignored; 17 explicit skip messages | Nine failing targets; reported passes include tests that emit skip messages |
| Fresh Ubuntu ARM64 HVF strict suite | `5cfcf0c64`: 3,035 passed, 5 failed, 18 ignored | Failed baseline: host IPv6 fixture, two stale K11/K27 records, and two foreign-ABI checks; not a passing full qualification |
| ARM64 HVF targeted repairs | IPv6 host assertion at `b65ec13d4` passed; refreshed release-evidence target at `265b83054` passed against the unchanged runtime binary | Targeted reruns only; the native Apple/HVF CPU cannot execute the ARM32 helper |
| ARM32 foreign-ABI observation in a TCG guest | `318e84637`: both strict D2 checks passed with the real static ARM32 helper; native ARM compilation and Clippy passed | Supplemental emulated-CPU guest evidence; no claim that native Apple/HVF supports AArch32 EL0 |
| Direct ARM32 execution comparison | Identical ELF32 helper: TCG guest exit 0 with its expected sentinel; native HVF guest `execve` refused `ENOEXEC` (8), with no sentinel | Both guest inventories had no qemu-user executables or ELF binfmt handlers; the native failure remains explicit |
| Hosted Ubuntu Rust rerun | Isolated CI `0f27becf1`, job `132789737305`: 3,041 reported passes, 0 failures, 18 ignored; dependency policy passed | Ordinary CI can contain explicit capability skips; this is not the reference conformance lane |
| Hosted macOS Rust rerun | Isolated CI `0f27becf1`, job `132789737491`: 2,431 passed, 0 failed, 7 ignored; provenance gate passed | Component/portable/refusal coverage; not entitled native runtime execution |
| Hosted contracts, website and fleet rerun | `0f27becf1`: contracts run `43706871491`, fleet run `43706871547`, and Rust run `43706871498` all passed | This revision predates the new native packaging and later ARM32 fixture/support-note changes |

The proxy header-budget test timed out while reading the exact-budget CONNECT
tunnel's EOF in that first complete run. Five isolated reruns and the full
proxy suite (69 passed, one ignored helper) passed afterward. The cause was not
established; no timeout or assertion was weakened. The original failure is
retained in `macos-workspace.log` and `macos-workspace-summary.json`. The complete
integrated rerun subsequently passed and is retained separately in
`macos-final-workspace.log` and `macos-final-workspace-summary.json`.

The earlier OrbStack ARM64 failures comprise 19 safe credential refusals caused by OrbStack's
virtual resolver mount, five reference-host assumptions about namespace/socket
support, and two observation-off execution-confirmation outcomes. The deep
cleanup fixture now requires observation and passes all 18 credential tests
with confirmed execution; the other observation-off boundary fixture remains
unconfirmed. No corresponding runtime safeguard was removed. A targeted K41
credential diagnostic passed in a private mount namespace with an identical
resolver copy, original user namespace, operator UID/GID and zero capabilities;
the original guest namespace and resolver were unchanged. That adaptation does
not establish support for stock OrbStack credential launches.

`arm64/qualification.json` and its logs retain these distinctions. The native
`0.1.0-rc.6` artifact in `arm64/stage-rc.6-unqualified/` is explicitly unpublished
and unqualified, despite successful native signed-installer checks. Its highest
required glibc symbol is `GLIBC_2.39`, and its build inputs match the clean Mac
build. The unavailable Raspberry Pi was not replaced by a claim of equivalent
host qualification.

A separate disposable Ubuntu 26.04 ARM64 VM using macOS HVF removed the OrbStack
resolver limitation and ran the strict suite with release evidence enabled.
Its five-failure baseline is retained in `arm64-hvf/logs/strict-baseline-summary.json`.
The IPv6 host-control repair and fresh K11/K27 evidence subsequently passed
targeted reruns without changing the runtime binary or disabling guest IPv6.
The remaining two strict foreign-ABI failures cannot be converted into native
HVF passes: a direct execution probe confirmed the host limitation. The same
static ARM32 ELF32 helper ran successfully in a separate TCG guest, returning
exit 0 and its expected sentinel, while `execve` in the native HVF guest returned
`ENOEXEC` (8) with no sentinel. Both inventories excluded qemu-user executables
and ELF binfmt handlers, so this is guest-kernel compatibility execution rather
than a user-mode emulator substitute. It corroborates the earlier capability
register observation that this native CPU lacks AArch32 EL0 even though its
guest kernel enables compatibility support.

Both strict D2 observation tests subsequently passed in the TCG guest with
the genuine ARM32 fixture from `318e84637`. Those targeted results supplement,
but do not rewrite, the failed full native HVF baseline. Final consolidated
ARM64 qualification and x86 regression verification of the shared fixture remain
pending in this record. No assertion was weakened and no explicit skip counts
as a conformance pass.
`arm64-compat-tcg/summary.json` and its raw logs bind both passing checks and the
direct-execution comparison to the fixture commit, unchanged runtime inputs and
helper SHA-256 `40f7d86dbb33e2a7066dae20d2ba8704f241b97f852cb18e19ee83faacc692c7`.
The TCG result is compatibility evidence, not native ARM32 performance evidence.

The three skipped VM tests are the two Linux `pidfd`/`/proc` process tests
and the non-folding-filesystem test, which excludes Darwin. They do not count
as passing Linux lifecycle or filesystem evidence.

The initial x86_64 reference conformance completed with no other failing
tests. Its four failures were the lockfile and manifest freeze comparisons
(already repaired by the tree-only freeze), and the K11/K27 evidence bound to
the previous runtime inputs. The failed verdict and all logs are retained in
`conformance/`. The final-source binary subsequently built cleanly on that
native host with Rust 1.98.1 and the current input digest; this build alone
does not replace the required final-source conformance run.
The current-input x86_64 reference run at isolated CI revision `34c11f520`,
including refreshed onboarding and the deterministic N4 fixture, passed:
[run 43706742434](https://github.com/monocursive/ukai/actions/runs/43706742434).
Its 3,041 tests passed with zero failures and 18 ignored helper/doc tests. The
`linux-preview` gate evaluation reports no problems or warnings; the broader
`all_noncredential_gates_pass` field is still false because the full specification
includes unsupported clauses. This is a scoped preview verdict, not a waiver.
The complete downloaded artifact is retained in `conformance-current-inputs/`.
Its clean doctor record generated a new tested freeze on the isolated validation
branch; `freeze --check` verified matching inputs, ancestry and unchanged frozen
inputs. Final candidate checks must still run on their exact named commit.

The first fresh Ubuntu x86_64 VM run installed the candidate, executed the
contained `true`, and passed archive/signature corruption and upgrade checks.
OpenCode 1.18.32 exited with a generic `UnknownError` server response after
23.2 seconds; the workflow stopped after 42.8 seconds. K11/K27 did not pass.
The VM was destroyed and the provider key appeared in none of the 49 recorded
files. The original records remain under `onboarding/`. The failed-run harness
did not preserve this vendor attempt's receipt and trace, so this record does
not attribute the failure to Ukai or to a specific upstream service.

The second fresh-VM attempt used the repaired evidence-preserving harness.
Its retained OpenCode diagnostics explicitly report `ProviderModelNotFoundError`
for `anthropic/claude-sonnet-4-5`, absent from the fetched model catalog. Ukai's
receipt retained enforced containment, verified cleanup and exit 1. The VM was
destroyed and the recorded-file key scan found no matches. This diagnosis
applies to that second run; it does not supply the first run's missing evidence.

The third fresh-VM attempt passed with `anthropic/claude-sonnet-5-5`, unchanged
credential/network grants and unchanged acceptance assertions. Its tracked
[rc.6 evidence record](results/release-preview-2026-11-15-rc6/README.md) includes
the verified official image, binary/input hashes, command results, receipts and
VM teardown. Signed installation through the first contained real-agent result
took 74.174 seconds, including agent download and excluding VM/dependency
bootstrap. Learning, upgrade, archive-corruption rejection and
signature-corruption rejection also passed, with no provider retry. Both real
agent receipts record exit 0, observed execution, an empty verified process tree,
complete state cleanup and all six coverage classes active without gaps. The
learning proposal is bound to its own receipt and denied-read evidence.

The disposable VM was destroyed; the runner scanned all 91 recorded files for
the actual key bytes and found none, and an independent scan agreed. This is
recorded-file evidence, not a guest-memory claim. Both onboarding and learning
verifiers passed before [the current evidence index](release-preview-current.json)
was promoted. This closes the current-input K11/K27 evidence gap for the tested
candidate; it is neither a production signature nor public release authority.

The website uses `output: 'static'`, with no SSR adapter or Node request server.
The reported npm findings concern its build, development and deployment
dependencies; they do not establish an exploitable endpoint in the deployed
static site. The refreshed lockfile also removes the vulnerable Sharp version
covered by [GHSA-wq5f-xc86-pv6w](https://github.com/advisories/GHSA-wq5f-xc86-pv6w).

Local raw logs, command results and their SHA-256 manifest are retained under
`evidence/production-2026-11-15/`; this ignored directory is not a published
evidence bundle. `portable-checks.json` binds the records to their source scope.
`native-package/checks.json` binds the unsigned Mac artifact, 49-test results,
actual temporary-home installation/removal and tooling hashes. Its raw logs
retain the expected native doctor refusal and failed unsigned distribution
validation. `native-package/linux-python-tests.log` records the separate Linux
fixture-test run; it is not native Mac execution evidence.
`ukai-production-2026-11-15-contracts-extra.json` records every check's exit
status, and `ukai-production-2026-11-15-website-summary.json` records the tested
package-file hashes and output comparisons. The original and repaired npm
audit JSON and full build/test logs are retained beside them.

[Draft PR #51](https://github.com/monocursive/ukai/pull/51) contains the readiness
changes on an isolated branch based on the remote `dev`, excluding unrelated
local Arena commits. Its jail input digest was independently checked and is
identical to the native candidate's. Hosted contracts (including website) and
fleet checks passed on `ed6a4af92`. That initial Rust workflow failed: Ubuntu's
N4 fixture observed 773.071 ms against its fragile 800 ms margin, and macOS's
2,431 passing tests, zero failures and seven ignored tests were followed by a
provenance-gate refusal because CI had written an untracked `test-output.txt`
inside the checkout. Both failures remain recorded in `ci/first-run-summary.json`
and the original job logs. The handshake fixture and external test-log path
repair these causes without changing runtime inputs or weakening the clean-source
gate. The complete `0f27becf1` rerun passed: Ubuntu 3,041/0/18, macOS 2,431/0/7,
dependency policy, contracts, website and fleet. Raw job logs and
`ci/0f27-summary.json` retain the results and their scope. Hosted Rust, contracts,
website and fleet also passed at `aaf11225e`, including new packaging, ARM32
fixtures and support notes. The x86 bare-observer D2 test executed and passed;
its receipt counterpart explicitly skipped in hosted Ubuntu because bubblewrap
was absent. That lane does not replace strict reference evidence. Subsequent
guidance, freeze and evidence-only commits require their own final CI. These
are intermediate checks, not final release authority.

## Release conditions

### Attribution follow-up before the final build

The intermediate `1e4dc0026` candidate passed hosted Rust, contracts, website and
fleet checks and both native Linux packaging jobs. Its exact archives passed
installation, upgrade, containment, deadline and cleanup checks on native
x86_64 and ARM64 hosts; unsigned Mac staging and installation also passed.
Independent artifact review then found a stale CA attribution label and missing
upstream dependency notices. Those artifacts remain preserved under
`final-candidate/` as superseded evidence. The `43710003697` reference run was
cancelled during compilation, before tests started; its exact owned remote
process group was stopped and its logs retained. It has no conformance verdict.

Commits `d9e11c543` and `d748c17fe` correct the label and add a shared, generated
attribution bundle to Linux, native Mac and VM host packages. The bundle covers
73 external dependencies across the three shipped targets, 142 upstream notice
files, ring's legal source headers, Rust standard-library notices and the custom
Unicode data notice. Extraction uses checksum-verified crate bytes; packaging
refuses stale source bindings or modified bundle content. Existing VM guest
attribution remains separate from the newly packaged host client.

Distribution tests (52), native Mac packaging tests (49), VM package tests (36),
exact bundle regeneration, optimized-Python guards and independent coverage
review passed. Documentation validation found zero broken links in 530 files.
CI now checks the committed attribution and its regression tests. These changes
do not alter the jail input digest above. New final packages must include the
bundle and have their own exact-commit CI, reference and artifact results;
those results belong in the PR and retained artifacts rather than a later
self-referential edit to this pre-build snapshot.

| Required evidence | Status in this record |
| --- | --- |
| Linux x86_64 reference conformance | Current-input `34c11f520` run `43706742434` passed. The final candidate must have its own exact-commit run, recorded in PR checks and downloaded artifacts |
| Final-source ARM64 native execution and installation | Native builds/installers, targeted IPv6/K11/K27 repairs, two strict TCG ARM32 checks and direct HVF/TCG execution comparison completed. The failed full native baseline remains explicit in `arm64-hvf/summary.json`. Final candidate bytes require native rebuild, installation and staging evidence |
| Current-input clean-VM onboarding and real-agent learning | Passed on the third fresh x86_64 VM; current K11/K27 evidence index promoted after both verifiers passed. Earlier two failures retained |
| Tested freeze and exact-release-commit CI | Tested freeze regenerated from the passing `34c11f520` doctor and `freeze --check` passed on the isolated branch. Final-commit CI/conformance remains a release condition, tracked outside this snapshot |
| Candidate signing, final artifact installation and public delivery | Both native Linux stages and test-key installation checks passed; ARM64 remains unqualified, with no production signing or public delivery |
| Native macOS entitled bundle and protected-Mac acceptance | Packaging/transaction tooling and actual unsigned staging completed; approved ES profile, real Developer ID signing/notarization and protected-Mac qualification remain blocked or unverified |
| Warm-VM K108–K113 acceptance on the shipped, notarized candidate | Unverified; development and component tests do not satisfy these rows |

The local provisioning inventory decoded 17 profiles and found none for the
Ukai Endpoint Security identity. That observation establishes no usable local
release profile; it does not establish Apple's current account-side decision
on the entitlement request. A granted and installed profile, a genuinely signed
and notarized candidate, and the specified SIP-enabled protected-Mac runs are still required before a
native release claim. The remaining fault, pressure, real-agent and independent
security-review gates must retain their actual verdicts; passing local suites
does not waive them.
