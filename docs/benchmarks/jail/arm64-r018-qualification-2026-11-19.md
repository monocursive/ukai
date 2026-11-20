# R01.8 qualification on the M5 Pro Linux guest

**R01.8 and K17 passed on the M5 Pro Ubuntu guest. Stable ARM64 remains unqualified.** Of the previous 73 missing cases, 52 passed and 21 remain unexecuted.

## Acceptance rule and review

R01.8 checks the contract shared by a run's receipts, trace and control transcript. The tests use `common::settled`, which validates the records together, including the final receipt binding. They exercise the production observer through the `none` profile. [R01.8 acceptance map](../../specs/jail-v1/acceptance-map.toml) · [Integration tests](../../../crates/ukai-jail/tests/observer_j4_linux.rs)

| Condition | Required evidence |
| --- | --- |
| The child acquires a notification listener (D1) | A real listener causes a named `child_notification_listener` gap. The four audit classes become degraded and strict evidence stops the run. The receipt test uses an idle, allow-all listener. Detecting the installation must be sufficient, even before the listener receives a notification. |
| A foreign-ABI call can execute (D2) | The existing live positive control must demonstrate the foreign operation. The best-effort receipt must report `foreign_abi` and degraded audit coverage. |
| A 64-bit-only AArch64 kernel refuses the ARM32 executable (D2) | The unfiltered S01.2 control must prove the refusal on every online CPU using the pinned static binaries. In a separate strict observed run, a native caller verifies its native positive control and identifies its ARM32 child by PID. The trace must contain exactly one exec result for that child, a native `execve` returning `-ENOEXEC`. The receipt must settle successfully with all four audit classes active and zero observer gaps. |

The alternative applies only to the D2 receipt on the kernel configuration that passes the all-CPU probe. A kernel version, CPU model, absent tool, shell exit status or synthetic errno is insufficient. On a compat-capable host, the original foreign-operation requirement applies. S01.2 independently checks the contained baseline filter. The rule grants no exception for sandbox escapes or other release gates.

The review checked three ways a false pass could arise. The host control rejected a modified ARM32 fixture and restricted CPU affinity. The product check tied the errno to the specific child's audit event. The artifact validator also rejected a different final receipt and a reversed control transcript. [Host control](../../../crates/ukai-jail/tests/fixtures/arm64_exec_control.py)

## Measured configuration

Qualification revision `a6cd7dc2291391e96edfc37c86debdcd4f88576d` ran on Ubuntu 26.04.1 LTS, kernel `7.0.0-43-generic`, with four native ARM64 vCPUs and 6 GiB RAM under HVF on an AC-powered M5 Pro. The writable guest disk used the internal Apple SSD with guest flushes enabled. The runtime-input digest matched the preceding qualification. The changes were confined to qualification tests and the acceptance map.

The refusal control passed on CPUs 0 through 3. In an independently captured run, the named child had exactly one audited exec result, returning −8. The receipt settled with all four audit classes active. All 10 trace frames, all 3 control messages and the receipt passed contract validation. The final trace and control digests both identified this receipt. [R01.8 evidence](results/linux-arm64-r018-2026-11-19/r018.json)

## K17

All 540 measured launches were valid, with 18 warmups, zero exclusions and no replay errors. The predeclared guest load limit was 3. The acceptance thresholds remain strictly below 500 ms of added p95 startup and at most 100% median post-start file-operation overhead per session. [Measured rows and raw archive digest](results/linux-arm64-r018-2026-11-19/k17.json)

| Session | Worst added startup, p95 | Median file-operation overhead |
| --- | ---: | ---: |
| plain | 45.20 ms | 88.47% |
| scope | 31.03 ms | 88.91% |

## Qualification verdict

The unprivileged native release run reported **2,965 passed, zero failed and 18 ignored**. The full release map scored R01.8 and S01.2 as passed. K11 and K27 accepted the existing records for the matching runtime inputs. The final binary and source hash checks passed. The same binary also passed a private install in a fresh ARM64 Ubuntu VM with an ephemeral Minisign key and zero provider invocations.

The previous run lacked 73 required cases across 30 gate rows. This run closed 52 cases, including the D1 receipt and the revised D2 receipt. **21 live cases remain unexecuted across 13 gate rows.** These cases exercise sandbox escape, boundary bypass, evidence tampering or observer evasion. Every failing clause cites an absent result. The evaluator reported zero log errors and zero warnings. [Case-by-case results, remaining gates and raw-log digests](results/linux-arm64-r018-2026-11-19/qualification.json)

The Linux publication scope remains `linux-x86_64-stable`. The read-only freeze check found no recorded tested run. The incomplete ARM64 verdict leaves the freeze unrecorded. The candidate is available on the local branch `codex/r018-arm64-qualification-20261119`.
