# Linux runtime audit for the scoped x86_64 release

The fixes from this review shipped in stable 0.1.0 for the tested x86_64
configuration. [Signed release and public install results](benchmarks/jail/release-0.1.0-linux-x86_64.md).

The published Linux rc.8 binary requires a new build before stable promotion.
This review identified three Medium findings in the October-to-rc.8 changes.
Commit `a0d3bd778` addresses all three. No High finding was identified in
this review.

## Candidate and scope

The comparison starts at the October audit's `549569975` and ends at the
signed `ukai-jail-v0.1.0-rc.8` source, `bf3656651`. The Git diff under
`crates/ukai-jail/src`, excluding the macOS platform directory and the
`ukai-vm` binary, touches 78 files. That count includes shared code.
The review followed the operator and child entry points below and checked
the corresponding tests. It was a self-directed, risk-based review.

The proposed support statement covers the unprivileged operator on the
provisioned Ubuntu 26.04.1 LTS x86_64 host with Linux 7.0.0-31-generic,
bubblewrap 0.11.1, ptrace observation and the reference cgroup configuration.
For vendor workflows the recorded combination is OpenCode 1.18.32,
`anthropic/claude-sonnet-5-5`, and the operator's `opencode-vault` launch
profile. The ten repair trials exercised fresh vendor state. The review also
covered adjacent operator surfaces shipped in the same binary, including
credential entry and persistent-state handling. ARM, native macOS, the warm
VM, ledger attestations and other vendors have separate qualification records.

## Findings and disposition

| Severity | Finding in rc.8 | Change in the reviewed successor |
| --- | --- | --- |
| Medium | A terminal error could leave echo enabled while `credential set` prompted for and read a long-lived provider key. The prompt was emitted before terminal configuration finished. | Terminal input proceeds only after configuration succeeds and a readback confirms both echo flags are clear. An unexpected terminal error returns before the prompt or the read. Pipes and regular files still work. [Credential command](../crates/ukai-jail/src/main.rs) |
| Medium | Persistent-state acquisition and release retained whole relative paths for digest sorting and hit reporting. The file-content and entry limits left supervisor memory exposed to large totals of metadata. Recursive listings also reserved the same entry allowance at several levels. | The scanner reserves entries when listing each directory and limits retained line and hit payloads to 16 MiB. Exceeding the budget withholds the digest and a clean-scan claim. A hit on the boundary still triggers quarantine. [Manifest implementation](../crates/ukai-jail/src/persistent.rs) |
| Medium | The state walker attempted to restore read permission before deciding whether an entry crossed a mount. Changing the mode of a multiply linked regular file could also change access through another name. Some state and discard paths accepted unknown Linux mount status. | The walker establishes the mount boundary first. Regular-file mode recovery requires a single link and uses a checked, pinned inode on Linux. State layout and discard operations also refuse unverified Linux mount boundaries. [Persistent-state specification](specs/jail-interactive-sessions.md) |

## Other reviewed changes

| Surface | Checks performed and remaining limits |
| --- | --- |
| Launch policy and execution | Followed workspace discovery, credential selection, read-only derived install roots, interpreter and dynamic-loader validation, source isolation, mount pinning and the final launcher check. Inspected the contained terminal-mode change to session creation and its ioctl filter. The host kernel, bubblewrap and operator-managed installation roots remain trusted. [Resolution](../crates/ukai-jail/src/supervisor/from_path.rs) · [Executable validation](../crates/ukai-jail/src/program.rs) · [Linux boundary](../crates/ukai-jail/src/platform/linux/boundary.rs) |
| Network and credentials | Traced approved-address connection, TLS authority validation, vault substitution, revocation and separate accounting for confirmed and partial head writes. Source and executable binding depend on the selected operator profile. An authorized upstream can reflect a secret. [Proxy](../crates/ukai-jail/src/proxy/conn.rs) · [TLS](../crates/ukai-jail/src/proxy/tls.rs) · [Vault lease](../crates/ukai-jail/src/vault/lifecycle.rs) |
| Observation and receipts | Checked executable confirmation, descriptor and path corroboration, proxy loss accounting, and bounded receipt and journal reads. A shared descriptor table can change during observation. The receipt records gaps when the observer cannot establish the result. [Observation](../crates/ukai-jail/src/platform/linux/observed.rs) · [Path evidence](../crates/ukai-jail/src/platform/linux/tracer/session/evidence.rs) · [Summary](../crates/ukai-jail/src/summary.rs) |
| Lifetime, state and cleanup | Traced terminal restoration, tree-death checks before release, persistent-state leases, generation records, quarantine and GC retention on lost integrity. The October M1 fix detects deletion at polling intervals. Uncontained execution and hostile processes already running as the operator are outside the stable containment claim. [Settlement](../crates/ukai-jail/src/supervisor/attempt.rs) · [GC decisions](../crates/ukai-jail/src/gc/decide.rs) |
| October findings and dependencies | The tagged source retains relative-script confirmation (H2′) and the M1 epoch-marker checks. Both named regression tests passed in rollout CI. Ledger verification continues to report the local-UID authenticity bound (L1). The locked workspace passed `cargo deny --workspace check advisories` against RustSec database revision `472a4c9a7850`. [October review and remediation](security-audit-2026-10-15.md) |

## Verification of the repairs

A clean optimized native build of `a0d3bd778` produced input digest
`sha256:81a2a1b453dd2c0427800235bc7148e5cd84f23d642319a726ffb543931e3def`.
On the x86_64 reference host, a disposable PTY reported echo off at the
credential prompt and restored echo after successful storage. A simulated
terminal configuration error returned exit 1 before the prompt, with no
input supplied and no file created. The installer suite passed against this
binary using a temporary test signing key. [Terminal check](benchmarks/jail/results/production-rc8-2026-11-18/check-credential-terminal.py).

All 76 focused Linux tests passed, including the new metadata-budget and
state-boundary checks. The optimized `tool` and `agent` profiles copied a
fixture, and `build` compiled and ran a C program. All three receipts
recorded enforced containment, observed execution, verified empty process
trees, complete cleanup and zero coverage gaps. Local checks also passed
for Clippy, 54 distribution tests, 41 Mac contract tests and 17 native
macOS refusals. [Candidate verification and receipt digests](benchmarks/jail/results/production-rc8-2026-11-18/runtime-audit.json).

The first full Linux run also exposed a test-harness race in K64. The shell
reported process exit on a separate pipe before the PTY reader finished
collecting `explain` output. Test-only commit `438337674` now waits for
the expected text or a complete JSON document and checks exit status. Its
23-test terminal suite passed on the reference host. The clean optimized
build at that revision repeated the three workloads, the credential PTY
checks and temporary-key install checks. Its binary SHA-256 is
`94fe3305e3fcb69f33a967647b5905827bc05fa08a6bf1d5feeadc92d7b248b2`.

K17 passed on that binary with 540 measured launches and 18 warmups. The
worst p95 added startup was 98.62 ms against a 500 ms ceiling. Median
post-start file-operation overhead was 41.41% in a plain session and 39.67%
in a delegated scope against a 100% ceiling. Replaying all 558 records
reproduced the six comparison rows and the verdict. [Evaluator](benchmarks/jail/performance.py) · [Measurements](benchmarks/jail/results/production-rc8-2026-11-18/runtime-audit.json).

The matching K27 onboarding and K11 learning checks then passed in a fresh
Ubuntu guest. OpenCode 1.18.32 ran once for each workflow with the
vault-backed Anthropic credential. Install through first task took 186.00 s.
The guest used an ephemeral signing key and the private fixture version
`0.1.0-rc.9`. The runner destroyed the guest, removed its temporary files,
and scanned all 92 retained files with zero literal-key matches. Both
repository gate verifiers accepted the records for the patched inputs.
[Guest results](benchmarks/jail/results/linux-x86-runtime-audit-2026-11-18/guest/result.json) · [VM record](benchmarks/jail/results/linux-x86-runtime-audit-2026-11-18/vm.json).

## Conformance and release decision

The repaired runtime passed strict Linux release conformance from the clean
checkout at `bb5979a30`. The suite reported 3,075 passed, zero failed and
18 ignored. The initial run had failed K64 and rejected the rc.8 evidence
for K11 and K27. The rerun accepted all three and verified the binaries
after the suite. The Linux gate report contains 65 passes, seven passes
with limits, two passes with unsupported clauses, 21 unsupported gates
and 14 assigned to another environment. A01 is the manual credential
gate covered by the OpenCode record above. The tested freeze records this
checkout and its runtime input digest.
[Conformance counts and evidence digests](benchmarks/jail/results/production-rc8-2026-11-18/runtime-audit.json) · [Tested freeze](specs/jail-v1/milestone-1-freeze.toml).

The reviewed fixes and local results qualify the runtime for a stable
candidate on the specified x86_64 configuration. The publication record above closes the distribution work described below.

The ten repair trials in the [compatibility register](specs/jail-v1/agent-compatibility.md)
ran on signed rc.8. The repaired runtime has one fresh onboarding run and
one fresh learning run on its own build inputs. The support statement above
is limited to the measured configuration and workflows.

The current release plan declares `linux-preview`, assembly requires both
native Linux targets, and the publisher sets the GitHub prerelease flag.
To ship a stable x86_64 release, the project needs reviewed stable version
and target settings, installer and publisher support for that scope,
production signatures on the resulting artifacts, and a public install
verified on the reference configuration. The existing rc.8 assets still
contain the three findings above. [Release coordinates](../crates/ukai-jail/dist/release.json) · [Assembly](../crates/ukai-jail/dist/prepare_release.py) · [Publisher](../crates/ukai-jail/dist/publish_release.py).
