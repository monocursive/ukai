# Ukai Jail rc.7 — signed private Linux preview

The exact `0be9d1e820b0d47493883053253491bbd2196ba3` candidate passed its
`linux-preview` checks, native archive checks on x86_64 and ARM64 Linux, and
production-signed bootstrap checks on both architectures. It remains private
and unpublished. Full-specification production readiness is not established.

[The report](report.json) records exact pins and scope. [The source binding](proof/source-binding.json)
binds tree `245e70ec60791c1108186e360764fc7c38dc3d07` and all 230 compiled
Git blobs/modes to input digest
`sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.
The freeze remains `39fafd8684997a3414a6a530df50fd5b3796de91356f8a39bb55e0c3b10fa2be`,
tested at ancestor `a8e4aecb071a0367001f309a659897d6aa336600`; it was not
regenerated after this candidate's conformance run.

| Evidence | Result |
| --- | --- |
| [Hosted Rust/dependencies](https://github.com/monocursive/ukai/actions/runs/43822389786), [contracts/website](https://github.com/monocursive/ukai/actions/runs/43822389760), [fleet](https://github.com/monocursive/ukai/actions/runs/43822389837) | Six first-attempt jobs passed. macOS: 2,512 passed / 0 failed / 7 ignored; Ubuntu: 3,073 / 0 / 18. Python: 1,159 cases, including 82 platform skips and both onboarding modules' 22 cases. |
| [Release workflow](https://github.com/monocursive/ukai/actions/runs/43822535195) | All four first-attempt jobs passed. Both exact native archives and assembly independently verified. CI signing used an ephemeral test identity. |
| [Exact-J strict reference](https://github.com/monocursive/ukai/actions/runs/43822530994) | 3,073 passed / 0 failed / 18 pinned ignores, across 117 groups, with **zero runtime capability skips**. Managed gate, D2 and current K11/K27 checks executed. |
| [ARM native](proof/native-arm-review.json) | One disposable Linux/HVF boot; 572 independent checks passed, including tool/agent/deadline, actual archive install, installer regression and exact deterministic restaging. Whole phase: 37.821 s. |
| [x86 native](proof/native-x86-final-review.json) | The same three cases, installer and restaging passed in 14.685 s. Independent retained replay: 46 checks plus 15 final lifecycle checks. |
| [Production signature](proof/signed-candidate-review.json) | All eight candidate files verified against exact J, its public key and both CI archives. Signing occurred once, separately from CI. |
| [ARM signed bootstrap](proof/bootstrap-arm-review.json) | One disposable boot, 26.556 s overall / 0.620 s bootstrap scope; 179 independent checks. |
| [x86 signed bootstrap](proof/bootstrap-x86-final-review.json) | 1.521 s; 71 remote checks, followed by 74 checks of the retained compressed proof. |

Both bootstrap checks verified the production signature first, then exercised
fresh and repeat installation with Minisign absent from the bootstrap PATH.
A modified private archive was refused while preserving the existing install.
These tests used locally supplied candidate files; public network downloading
was not tested. The [signed manifest](candidate/SHA256SUMS), [signature](candidate/SHA256SUMS.minisig),
[public key](candidate/release.pub), [plan](candidate/release-plan.json) and
[unchanged release notes](candidate/RELEASE_NOTES.md) are retained here; binary
archives and private signing material are excluded. The separate private
[ZIP review](proof/signed-archive-review.json) passed 56 checks: eight exact
files, 9,378,850 bytes, SHA-256
`141a89bd3f22a9787b7cc3b757e2a24abe9bd17f225de215bb9bb2fbabb6a5fe`.
The ZIP itself is retained outside this tracked proof record.

| Target | Archive SHA-256 |
| --- | --- |
| x86_64 GNU/Linux | `a9eb6b07b4925cc3828fa2a264cbc5d0208aea1b1ed2929f67ec0d5f1436c7a1` |
| ARM64 GNU/Linux | `15766ac8d68eaa563bc0dabccd6a03d83a6319d2f76ccd67828ed287a1e00ce6` |

The [strict doctor](conformance/doctor.json), [gate report](conformance/gates.json)
and [full test log](conformance/test.log) are this run's own bytes. The gate
report has no problems or warnings for `linux-preview`, while
`all_noncredential_gates_pass` remains false. Unsupported, elsewhere and
credential gates are preserved. Ordinary hosted Ubuntu emitted 520 capability
skip diagnostics; those are not substituted for strict reference coverage.
The macOS log also retains a hardlink-to-sudo probe skip.

Current K11/K27 evidence retains the actual F binary/G harness identities;
compiled inputs match J. Onboarding took 152.032 s excluding 460.846 s of
bootstrap. Exactly two vendor CLI workloads ran, once each. Learning granted
only `/etc/nsswitch.conf`, no network hosts; the intended fixture was not
proposed, and 15 unresolved reads remained ungranted. These are supported
subset results, not blanket path coverage or a limit on API calls, tokens or
billing. The existing onboarding bundle is referenced, not duplicated here.

All owned native/bootstrap scopes and clients settled; disposable VM process
and image-holder checks passed. Original inputs and failed attempts were
preserved. Compressed x86 native/bootstrap proofs are retained locally and
remotely without extracting another set of binary files. Observer-only
preflight/retention refusals remain separate from the successful owning runs;
no workflow or native workload was retried.

Capacity work removed only two new successful reassembly archive copies,
the successful ARM native overlay/vars.fd and bootstrap overlay/vars fixtures,
and 23 explicitly reviewed
non-executable `.rmeta` files in the task's compiler cache. The latter were
135,421,952 private allocated bytes; their immediate measured free-space gain
was 11,853,824 bytes after closing all held file descriptors, with a later
whole-filesystem observation of 14,913,376,256 bytes free. The other 2,755 cache
files retained their metadata. The later bootstrap fixture cleanup observed
a 137,940,992-byte free-space increase; its initial allocation-only metadata
refusal and exact refreshed authorization are preserved. These time-specific observations do not promise
an equivalent allocation gain. Historical evidence, source, images, original
artifacts and executables were not deleted. The next Mac image/package still
needs roughly 22 GB of free capacity or a reviewed external-storage route;
a tiny private toolchain stripping probe does not qualify an actual Ukai build.

The earlier `bef699262` API-key matrix remains **14 lanes: eight strict passes
and six failures**, including three sampling failures among ten repetitions.
A01, the small task and vendor revocation remain failed. OAuth is deferred at
the user's request. No managed version-3 guest image or installed Mac host is
qualified, and no notarization, stapling or native macOS Endpoint Security
qualification is claimed. The retained startup/kernel failures are unchanged.
GNU/Linux binaries require glibc 2.39 or newer; musl is unsupported, stock
Ubuntu 24 execution remains refused, and real-agent reliability is experimental.

The documentation-only commit records these results without changing the
release's J revision, tested-I freeze, candidate files, or unpublished status.
