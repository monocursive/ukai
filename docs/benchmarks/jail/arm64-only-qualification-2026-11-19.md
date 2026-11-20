# Linux ARM64 qualification on a 64-bit-only M5 Pro guest

**S01.2 and K17 passed on the tested M5 Pro Linux guest. Stable ARM64 remains unqualified.** The final release evaluation has 73 missing test results across 30 gate rows.

## What S01.2 measures

S01.2 requires the tool baseline to prevent foreign-ABI calls. On the Raspberry Pi the ARM32 executable starts, so the test traces the denial inside the process. On the M5 Pro guest, Linux refused to start the same executable. These configurations reach different points in execution. [Acceptance map](../../specs/jail-v1/acceptance-map.toml) · [Pi controls and executable digests](results/linux-arm64-remediation-2026-11-19/s01-controls.json)

The M5 test used Ubuntu 26.04.1, kernel `7.0.0-43-generic`, four native ARM64 vCPUs under HVF and 6 GiB of RAM. The Mac was on AC power and the guest used a local disk on the internal Apple SSD with guest flushes enabled. The qualification revision is `91910434be4598d2d69c72ff70867ed5bc71ba99`, based on `0010dffb3f3a41497ef93527674615deb0d290bf`. The changes cover test code, acceptance wording and the previously collected OpenCode records.

On each online vCPU, outside Ukai and without inherited seccomp, the pinned static ARM64 BusyBox executed and printed the expected text. The pinned ARM32 BusyBox returned `ENOEXEC` to its caller. Each ARM32 trace contained exactly one unsuccessful `execve`. No interpreter started and no ARM32 output appeared. Linux also refused the Linux32 personality with `EINVAL`. The test rejected a modified ARM32 executable and an incomplete CPU affinity mask. The same native caller inside an observed `none` run saw `ENOEXEC`, exited successfully and produced a settled strict receipt with active exec coverage and zero exec gaps. [Per-CPU controls and observed result](results/linux-arm64-only-2026-11-19/abi.json) · [Linux ARM64 kernel documentation](https://docs.kernel.org/arch/arm64/asymmetric-32bit.html)

The compiled production tool filter loads the audit architecture first. Its AArch64 branch proceeds to the syscall number. Its ARM32 branch returns `SECCOMP_RET_ERRNO | EPERM` immediately. This verifies the filter instructions independently of the kernel execution probe, as required by the architecture-first rule in §9.2. [Linux filter requirements](../../specs/jail-v1.md) · [Compiled-filter digest and branch result](results/linux-arm64-only-2026-11-19/abi.json)

The kernel result applies to this Ubuntu guest configuration. An emulation handler or a different CPU configuration can change the outcome. A compat-capable host must still pass the unfiltered ARM32 execution control and the filtered in-process denial. R01.8 separately requires a receipt from an observer that encountered a foreign-ABI call. The M5 refusal supplies no such call. [R01.8 acceptance criteria](../../specs/jail-v1/acceptance-map.toml)

## K17 performance

The replay passed all six startup comparisons and both file-operation comparisons. The original seed, fixed workloads, 30 measured launches per arm, one warmup per arm and guest load limit of 3 were retained. All 540 measured launches were valid. There were 18 warmups, zero exclusions and zero replay errors. Peak measured guest load was 2.08. The Mac was shared during the run. [Replay and archive digest](results/linux-arm64-only-2026-11-19/k17.json)

| Session | Workload | Added startup, p95 | Median post-start file overhead |
| --- | --- | ---: | ---: |
| plain | noop | 54.67 ms | — |
| plain | spawn-tree | 61.89 ms | — |
| plain | fileops | 52.57 ms | 80.62% |
| scope | noop | 31.70 ms | — |
| scope | spawn-tree | 31.47 ms | — |
| scope | fileops | 38.96 ms | 78.34% |

The existing limits are strictly below 500 ms added startup and at most 100% file-operation overhead in each session. The largest startup increase was 61.89 ms. The earlier Raspberry Pi K17 result still applies to that configuration. [Pi measurements](arm64-remediation-2026-11-19.md)

## Release evaluation

The guest built all 113 release test executables from 2,652 checked inputs. The jail reported the same runtime-input digest as its parent, `sha256:0da6ea53bcb2f25c2094adf95ddc5e13ace97c688222b881d17e8cbbd1404c92`. The final source and executable hash checks passed. The binary SHA-256 was `6ae3977fa48d19329aded25eb2b4397291f03a7342c429f7322c91caae4a2598`.

The scored run had **2,913 passes, zero failures and 18 ignored tests**. Both S01.2 tests passed in that log. A preliminary series had 2,921 passes and 13 ignored tests. Its combined log repeated two test binaries, so the scored run used one workspace invocation with an exact test selection, followed by doctests. The evaluator reported zero log problems and zero warnings. The totals are separate runs.

K51 passed its 50 ms limit in three isolated runs at 2.94, 2.49 and 2.36 ms. All six driver checks passed, including doctor against the manifest and the plain-session smoke tests. K11.1 and K27.2 accepted the existing ARM64 OpenCode records for the matching runtime inputs. In a separate fresh ARM64 Ubuntu VM, the exact tested jail binary passed a private install using an ephemeral Minisign key. The installer run made zero provider invocations. [Qualification evidence and raw-file hashes](results/linux-arm64-only-2026-11-19/qualification.json)

### What blocks stable

- The complete Linux release map reports 30 failing gate rows. Every failing clause cites an absent result. There are 73 distinct required tests missing from the scored log, including live sandbox-escape reproductions. The whole S01 gate still requires additional evidence beyond S01.2. The machine-readable report lists all missing cases. [Gate evidence](results/linux-arm64-only-2026-11-19/qualification.json)
- R01.8 still calls for a receipt degraded by an actual foreign-ABI syscall. On this kernel the ARM32 process never starts. The refusal receipt passed frozen-schema and semantic validation. A 64-bit-only release scope needs a reviewed applicability rule for this observer requirement, or a release policy that explicitly accepts separate compat-capable evidence for it. The current Linux publication scope is `linux-x86_64-stable`. [Acceptance criteria](../../specs/jail-v1/acceptance-map.toml) · [Release scope](../../../crates/ukai-jail/dist/release.json)
- The candidate also fails `xtask freeze --check` because its freeze contains no tested conformance run. A matching successful reference result is required to record the freeze. [Release procedure](../../RELEASING.md)

Raw logs and phase measurements are retained locally in `evidence/arm64-only-qualification.ZPCxBCZH/`. The source revision is retained on the local branch `codex/arm64-only-qualification-20261119`.
