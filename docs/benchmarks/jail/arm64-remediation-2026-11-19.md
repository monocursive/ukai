# ARM64 remediation on the Raspberry Pi 4

**ARM64 remains preview-only.** The corrected candidate passed S01.2 and K51 in full Pi conformance. All six K17 startup comparisons missed the 500 ms ceiling. The slowest added p95 startup was 2,136.13 ms for the plain-session spawn tree. The release limits were retained.

The [earlier qualification](arm64-qualification-2026-11-19.md) identified three open checks on the Pi-hosted Ubuntu guest. This run used Ubuntu 26.04.1, kernel `7.0.0-43-generic`, three virtual CPUs and 2 GiB of guest RAM. The Pi ran Debian 13. Its firmware intermittently reported active undervoltage and throttling (`0x50005`) and an ARM clock of 600 MHz during measurements. Other samples showed `0x50000` and 1.5 GHz. Both active flags appeared in 52 of 102 samples taken during the first full replay on the patched runtime. [Power samples](results/linux-arm64-remediation-2026-11-19/pi-power.json) [Raspberry Pi firmware status bits](https://github.com/raspberrypi/utils/blob/master/vcgencmd/vcgencmd.1)

The [subsequent SSD-backed Ubuntu run](arm64-ssd-qualification-2026-11-19.md) measured the same candidate on an AC-powered M5 Pro.

## S01.2 foreign-ABI baseline

The ARM64 test runs the same packaged BusyBox `echo` with native and ARM32 executables. It checks the ELF class and machine, confirms successful exec in the kernel trace and then inspects heap initialization. The native filtered process and the ARM32 unfiltered process must print the sentinel and complete successfully. The filtered ARM32 process must return no sentinel and every observed heap call must return `EPERM`. A crash or timeout alone cannot satisfy the assertion. The existing x86_64 test still exercises its own ABIs.

To provision another qualification guest, extract matching Debian `busybox-static` packages for `arm64` and `armhf`. Install the executables at `/usr/local/lib/ukai-conformance/arm64/busybox` and `/usr/local/lib/ukai-conformance/armhf/busybox`. The host must execute ARM32 user programs natively and supply `strace` with `--kill-on-exit`, `setpriv` with `--seccomp-filter`, `prlimit` and GNU `timeout`. This run used Debian package version `1:1.37.0-6+b9`. The qualification-only fixtures and the four observed controls are recorded with their SHA-256 digests. [ARM control evidence](results/linux-arm64-remediation-2026-11-19/s01-controls.json)

## K51 journal summaries

The original release took 128.77–132.45 ms in isolated Pi guest runs. CPU sampling pointed to repeated JSON decoding and string validation. The new reader borrows UTF-8 path names and selects the first requested names before sorting. It can parse independent blocks of repeated single-path audit writes in parallel. It obtains the field positions from a decoded frame, compares all fixed bytes, validates each variable token and merges blocks in order. A changed layout, invalid sequence, missing exchange partner or malformed input returns that block to the ordinary reader. Regression tests compare results with the ordinary reader, including the valid prefix of a damaged journal.

The optimized runtime at `70bd7844da47bc3c8427c10abeb1df58942ef989` summarized the 7,145,825-byte, 13,108-frame fixture in **31.21, 30.47 and 29.79 ms** on three successive invocations of the release test. Each invocation rebuilt the fixture and checked the summary was complete and exact. The limit is strictly below 50 ms. The reviewed byte-search dependency was already locked and included in the distribution notices. The candidate’s runtime input digest is `sha256:0da6ea53bcb2f25c2094adf95ddc5e13ace97c688222b881d17e8cbbd1404c92`. [K51 samples](results/linux-arm64-remediation-2026-11-19/k51.json)

## K17 warm startup

In the original guest trace, six durable write calls accounted for about 3.24 seconds of one 3.52-second startup. The longest file sync took about 1.45 seconds. [Matched syscall timings](results/linux-arm64-remediation-2026-11-19/k17-profile.json)

The qualification used the fixed 200-child and 5,000-round workloads, 30 measured launches and one warmup per arm, in both plain and delegated sessions. The predeclared maximum guest load was 3. The evaluator recomputes p95 added startup against direct execution and the median post-start file-operation overhead from the raw launch records. The respective limits are strictly below 500 ms and at most 100%.

The first storage configuration used a preallocated Pi-local raw disk, ext4 ordered data with barriers and a dedicated fast-commit journal. A first attempt to enable the feature on an existing disposable volume failed when the kernel aborted its journal. Its records were preserved and a freshly formatted volume passed a file-and-directory sync check. The formal run used that fresh volume with `max_batch_time=0`. Ukai retained every file sync, atomic publication and directory sync. A separate six-launch diagnostic on a network-backed SSD took 1.20–1.59 seconds per whole command and was excluded from qualification.

On the first corrected summary build, a complete ext4 replay found six failing startup comparisons from 543.84 to 1,016.17 ms. Both file-operation overhead comparisons passed at 30.32% and 30.17%. [Intermediate ext4 run](results/linux-arm64-remediation-2026-11-19/k17-ext4.json)

## Observer shutdown during the F2FS trial

A second Pi-local raw disk used F2FS with barriers and `fsync_mode=strict`. In an observation-on warmup, the child completed all 5,000 file operations in 9.17 seconds. The supervisor still polled after the tracer thread had exited. The harness reached its five-minute deadline and excluded the launch. The run stopped after 189 recorded launches so the correction could be tested. [F2FS mount options](https://docs.kernel.org/filesystems/f2fs.html)

The supervisor now distinguishes an idle sender from a disconnected and completely drained event stream. It processes every queued event before resolving the outcome. When required exit evidence is missing, it reports an unknown outcome and performs bounded cleanup. A regression test keeps a final child-exit event across the drain batch boundary and checks that the stream closes only after delivery.

On the same volume, the corrected executable completed the workload and returned failure in 49 seconds. Its receipt recorded an unknown outcome, lost observation coverage and unverified tree death. This configuration remains unsuitable for the observed workload. [Before and after](results/linux-arm64-remediation-2026-11-19/f2fs-observer.json)

## K17 after the observer fix

The ext4 replay for commit `70bd7844d` validated all 540 measured launches and 18 warmups. Each comparison had 30 valid launches per arm and zero exclusions. The guest stayed below its predeclared load threshold. All six startup comparisons failed the 500 ms ceiling. Both file-operation overhead comparisons passed the 100% ceiling. [Replayed verdict and raw-data digests](results/linux-arm64-remediation-2026-11-19/k17-final.json)

| Session | Workload | p95 added startup | Median post-start file overhead |
| --- | --- | ---: | ---: |
| plain | noop | 591.38 ms | — |
| plain | spawn-tree | 733.29 ms | — |
| plain | fileops | 624.49 ms | 31.11% |
| scope | noop | 580.79 ms | — |
| scope | spawn-tree | 541.82 ms | — |
| scope | fileops | 539.40 ms | 29.66% |

## Packaging the corrected source

The first full run exposed a missing Minisign executable in the disposable Ubuntu guest. After installing Ubuntu’s `minisign 0.12-1build1`, packaging rejected stale input hashes in the third-party notice inventory. Regenerating the inventory changed two SHA-256 entries for `Cargo.lock` and `crates/ukai-jail/Cargo.toml`. The attribution text and the dependency list matched the regenerated output. An ARM64 test installation using a temporary signing key then passed its upgrade, downgrade and tamper checks. The updated private candidate is `0010dffb3f3a41497ef93527674615deb0d290bf`. Its runtime inputs match the earlier optimized build.

## Full conformance on the corrected candidate

The first attempt reached the 30-minute build limit. The next completed suite exposed the packaging issues above. For the final run, a clean native ARM64 Cargo cache was built at the same source paths on another ARM64 host and transferred to the guest with checksums. The Pi guest invoked both release build commands, reported ready in doctor, ran the smoke checks and executed the full release suite. The jail, fixture and ledger executable hashes matched before and after the suite.

The final run recorded **3,077 passed, 2 failed and 18 ignored** across 117 test summaries. S01.2, the K51 timing test and the signed-installer check (K27.1) passed. K11.1 and K27.2 rejected the earlier OpenCode results. Those two failures also kept the clean-suite clause I01.3 open. The driver used the existing release clause selection named `linux-x86_64-stable`; doctor identified the actual build target as `aarch64-unknown-linux-gnu`. The K17 figures come from a separate benchmark replay on the same guest. [Conformance results, executable hashes and log digests](results/linux-arm64-remediation-2026-11-19/conformance.json)

## Timings with the conformance binaries

A second K17 replay used the jail and fixture whose SHA-256 values the final conformance run recorded and rechecked. It used the same random seed, workloads, load cutoff and ext4 settings as the preceding replay. There were 540 measured launches, 18 warmups, zero exclusions and no replay errors. Maximum one-minute guest load was 1.74 against the cutoff of 3. Both file-operation overhead comparisons passed. All six startup comparisons failed. [Exact-pair K17 verdict](results/linux-arm64-remediation-2026-11-19/k17-qualified-pair.json)

| Session | Workload | p95 added startup | Median post-start file overhead |
| --- | --- | ---: | ---: |
| plain | noop | 706.84 ms | — |
| plain | spawn-tree | 2,136.13 ms | — |
| plain | fileops | 638.76 ms | 30.75% |
| scope | noop | 543.23 ms | — |
| scope | spawn-tree | 616.78 ms | — |
| scope | fileops | 558.45 ms | 29.16% |

The firmware reported current undervoltage and throttling in 59 of 122 samples during this replay. The ARM clock ranged from 600 MHz to 1.5 GHz. The exact conformance build also summarized the unchanged K51 fixture in 30.94, 30.36 and 29.97 ms in separate invocations. [Firmware samples](results/linux-arm64-remediation-2026-11-19/pi-power-qualified.json) [Isolated K51 results](results/linux-arm64-remediation-2026-11-19/k51-qualified.json)

## Remaining release work

Repeat K17 on the Pi with a power supply and cable that keep the firmware undervoltage flag clear under load. A locally attached SSD would also allow a direct check of the storage latency seen in the startup trace. Keep durable writes enabled and retain the same workloads, sample counts, load cutoff and limits. The current measurements do not isolate the effects of storage and power.

Fresh ARM64 OpenCode onboarding and learning records are conditional on passing the performance checks. The verifiers rejected both earlier records because the runtime inputs changed. Neither paid invocation ran. The published x86_64 release remains at 0.1.0. The patched source also needs a new x86_64 reference run for the milestone freeze before it can replace that release.

The corrected source is retained locally on `codex/arm64-private-qualification-20261119`. The verified Git bundle and raw benchmark and conformance records are in `evidence/arm64-remediation-20261119/`. The final suite is in `strict-final-notices/`, and `k17-guest-built/raw.tgz` contains the exact-pair launches and replayed summary. The disposable guest and its storage were removed after collection. The Pi had 7.6 GiB free, with SSH and Tailscale active.
