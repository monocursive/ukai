# Production readiness of Linux rc.8, 18 November 2026

Ukai Jail rc.8 is a signed Linux developer preview. On the Ubuntu 26.04.1
x86_64 reference host, the release commit passed strict Linux conformance.
All five rollout workflows passed on `753fa9661`. The stable-release decision
still needs a security review of the Linux candidate and a support statement
limited to host, profile and agent combinations with matching evidence.
[Publication record](release-preview-2026-11-18.md) · [Rollout CI](https://github.com/monocursive/ukai/commit/753fa9661c8ba4c7410d9b7b57637c730a32ce0a/checks).

## Checks completed on the published binaries

| Check | Result |
| --- | --- |
| Release contents | All eight files downloaded anonymously from GitHub passed the production signature and digest checks. Both GNU/Linux archives contained the exact reviewed third-party notice bundle. The bootstrap matched the tagged installer with the release pins applied, and the low-level installer matched its tagged source. [Asset check](results/production-rc8-2026-11-18/published-source-check.json) |
| Upgrade and rollback | An unprivileged user installed public rc.5 into an empty prefix, upgraded to rc.8 by default, confirmed that an implicit downgrade refused, explicitly rolled back to rc.5 and restored rc.8. Both versions recovered their original binary and notice digests on both hosts. [x86_64](results/production-rc8-2026-11-18/host-x86_64.json) · [ARM64](results/production-rc8-2026-11-18/host-aarch64.json) |
| Installed execution | On the reference host and the Ubuntu ARM64 OrbStack guest, `tool` and `agent` copied a fixture file without vendor credentials. `build` compiled and executed a C program with GCC, read-only source, a writable output directory and a 512 MiB memory ceiling. All six runs produced the expected output and settled with enforced containment, verified empty trees and complete cleanup. The host reports above include individual receipt hashes. |
| OpenCode repair | On the x86_64 reference host, OpenCode 1.18.32 repaired the same Python function in ten consecutive fresh workspaces. All ten agent runs and all ten independent judges settled with verified empty process trees and complete cleanup. Median agent time was 12.91 s (range 9.32–15.94 s). [Trial results and receipt digests](results/production-rc8-2026-11-18/opencode-repair.json) |
| K17 performance | The signed x86_64 executable passed the release's fixed benchmark. Across 540 measured launches and 18 warmups, there were zero exclusions. Worst p95 added startup with observation off was 94.2 ms against a 500 ms ceiling. Median post-start overhead on file operations was 37.4% in a plain session and 40.1% in a delegated scope against a 100% ceiling. The default observation mode added 452.7% and 451.0% respectively versus direct execution on the same fixture. [K17 measurements](results/production-rc8-2026-11-18/performance.json) · [Evaluator](performance.py) |

The ARM build check first tried an unconfigured memory limit, an unavailable
`cc` alias and a source tree without an input grant. The successful fixture
used `gcc` with explicit source and output grants. This qualifies a local
build on that guest. A real provider call and a full native ARM64 conformance
run are separate tests.

The benchmark used the tagged release's `xtask perf run` and `ukai-fixture`
on the four-CPU reference host with `--profiles tool --sessions plain,scope
--max-load 3.0 --launches 30 --warmup 1`. The largest measured one-minute load
was 2.62. Replaying the 558 raw records reproduced every measurement and verdict.
All 60 observation-off no-op timings carried the documented `exec_unconfirmed`
flag. The fixture's own timestamps established timing while the supervisor
could not independently confirm the short-lived exec. The raw records have
SHA-256 `cee9cdad681d125b316405969ece939cd575e3fcbb6c38926b8f0cb1585832eb`.

The repair trials used the installed, signed x86_64 binary, the operator
`opencode-vault` profile and `anthropic/claude-sonnet-5-5`. Each trial started
with fresh vendor state. OpenCode ran the requested tests and preserved the
original test file in all ten runs. An independent judge ran the three original tests
in a second jail whose workspace held only the repaired module and those tests.
All six observation classes were active and gap-free on every agent receipt.
Each recorded the credential as never staged. A scan of all 420 regular trial
files found zero occurrences of the literal provider key, and the temporary
vault directory was removed. The counts cover ten repetitions of one task on
one host. [Repair fixture](agent_matrix.py) · [Vault profile](onboarding_guest.py).

## Full specification replay

Running `xtask gates` without the Linux-preview switch against both rollout CI
logs for `753fa9661` yielded 68 passing gates, seven passing with limits, one
manual credential gate (A01), and 34 gates with untested clauses. The failures
match the 34 exclusions in that revision's Linux preview manifest. The Linux
reference-host driver and macOS suite both ran. [Full verdict](results/production-rc8-2026-11-18/rollout-full-gates.json).

One of those clauses, K22.2, is now covered in the development tree. On native
macOS the new CLI test exercised both valid command-rule forms, `deny` and
`forbid`. Each invocation returned the configuration exit code 2 at resolution,
identified `jail.commands`, and left the workload marker absent. All 17 tests
in the Mac refusal suite passed. Future Linux preview builds require this Mac
check. The signed rc.8 plan retains its original 34 exclusions. The other 33
clauses concern native Mac or warm-VM qualification. [Native test](../../../crates/ukai-jail/tests/macos_refusal.rs).

## Decisions still open

| Scope | Evidence still needed |
| --- | --- |
| Stable Linux security claim | The last repository-wide audit located covers `549569975`. The rc.8 source retains the October fixes for relative script execution (H2′) and uncontained epoch markers (M1). Their named regression tests passed in rollout CI. M1 retains a polling window. Ledger verification still bounds authenticity to the local UID (L1). The proposed stable scope still needs review of the intervening runtime changes and zero open High or Medium findings. The written policy allows a self-directed pass initially. [Audit policy](../../specs/jail-v2.md#13-publication-and-evidence) · [October audit](../../security-audit-2026-10-15.md) |
| Real-agent support | Ten fresh repair trials passed for the exact x86_64 OpenCode configuration recorded above. Onboarding and learning also passed with the release's build inputs. Broader tasks, agents, hosts and credential modes still need their own evidence. Earlier matrices recorded timeouts and provider refusals. [Compatibility register](../../specs/jail-v1/agent-compatibility.md) |
| Broader Linux host support | The ARM64 install and workload checks cover the named guest. Full native ARM64 qualification remains open, including the foreign-ABI tests on a host capable of AArch32 EL0. The Raspberry Pi was unreachable through both configured routes today. Stock Ubuntu 24 execution remains refused. [ARM baseline and targeted tests](production-readiness-2026-11-15.md) |
| Warm macOS VM | The signed development package passed the installed operational and fault checks. Claude exposure sampling, the applicable real-vendor workflows, distribution rights for any bundled client, and K108–K113 acceptance on the exact notarized and stapled package remain open. OAuth qualification was deferred. [Installed operational checks](results/macos-vm-operations-2026-11-18/README.md) · [Qualification history](production-qualification-2026-11-15.md) |
| Native macOS | A fresh local inventory decoded 20 provisioning profiles. None granted Endpoint Security. Native execution still needs the exact Apple-authorized identity, protected-Mac containment and workflow acceptance, and a signed, notarized distribution. Only the local inventory was checked. [Native release requirements](../../RELEASING.md) |

The macOS gates apply to their respective distributions. Linux can be considered
separately with a narrower support statement. The existing publisher creates
Linux previews and the rc.8 tag identifies the tested preview bytes. A stable
version needs its own reviewed release coordinates, signed packages and public verification.
