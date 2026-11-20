# ARM64 qualification on an AC-powered M5 Pro

**K17 passed on the SSD-backed Ubuntu ARM64 guest at `0010dffb3f3a41497ef93527674615deb0d290bf`.** Native ARM32 compatibility prevents this configuration from meeting the current stable release requirements.

## Measured configuration

The MacBook Pro ran from AC power with its internal battery attached. All twelve power samples during the benchmark reported AC, and macOS reported no thermal or CPU-power warnings at the start and end. QEMU used HVF with the native M5 Pro CPU, four guest CPUs and 6 GiB of RAM. Ubuntu 26.04.1 ran kernel `7.0.0-43-generic`. Its ext4 state volume resided in a writable qcow2 disk on the Mac’s internal Apple SSD. QEMU reported that guest flush requests were enabled.

The unprivileged guest user built the full release workspace and all test executables from 2,641 verified source files. Doctor reported ready. The runtime input digest was `sha256:0da6ea53bcb2f25c2094adf95ddc5e13ace97c688222b881d17e8cbbd1404c92`. The jail executable matched the Pi binary byte for byte. The locally rebuilt fixture had a different executable hash. Both hashes are recorded with this benchmark.

## K17

The benchmark used the Pi replay’s seed and settings, including the 200-child spawn tree, 5,000 file-operation rounds and maximum guest load of 3. There were 30 measured launches per arm for each workload and session, plus one warmup per arm. All 540 measured launches were valid. The evaluator replayed the results without an integrity error. Peak observed one-minute guest load was 2.09. [K17 verdict and raw archive digest](results/linux-arm64-ssd-2026-11-19/k17.json)

| Session | Workload | p95 added startup | Median post-start file overhead |
| --- | --- | ---: | ---: |
| plain | noop | 59.25 ms | — |
| plain | spawn-tree | 70.52 ms | — |
| plain | fileops | 48.39 ms | 79.51% |
| scope | noop | 44.43 ms | — |
| scope | spawn-tree | 33.08 ms | — |
| scope | fileops | 35.21 ms | 84.08% |

All six startup results passed the existing limit of strictly below 500 ms. Both file-operation overhead results passed the 100% ceiling. The Pi still has a failing K17 result on the same runtime. The two configurations differ in CPU, power, storage and virtualization. This comparison cannot isolate their individual effects. [Prior Pi qualification](arm64-remediation-2026-11-19.md)

## Native compatibility and installation

The guest executed the packaged ARM64 BusyBox control. The kernel returned `ENOEXEC` for the unfiltered ARM32 BusyBox control from the same Debian release. The installed cross-binutils and control executables were present. S01.2 requires a successful unfiltered ARM32 control before the baseline denial can count.

A fresh Ubuntu ARM64 guest with no Rust installation completed the installer workflow using the exact measured jail executable and an ephemeral Minisign key. It passed the private distribution checks. Stable publication remains scoped to x86_64.

## Release verdict

In the initial SSD-host workspace run, **2,617 passed, 3 failed and 9 were ignored**. The failures were S01.2’s native ARM32 control and the two OpenCode record checks (K11.1 learning and K27.2 onboarding). At that point the OpenCode records carried earlier runtime inputs. The paid checks ran separately afterward. K51 passed in the workspace tests and in three isolated runs at 6.85, 5.10 and 6.39 ms against the existing 50 ms limit. The signed-installer test (K27.1), plain-session smoke tests, manifest comparison and executable hash recheck passed.

The full Linux release map was evaluated against these logs. The execution covered selected suites. Live sandbox-escape reproductions and other unexecuted cases have no SSD-host result. The evaluator therefore counted missing evidence alongside observed failures; its 50 failing gate rows are not 50 observed runtime defects. The published map’s scope label is `linux-x86_64-stable`. The native ARM64 K17 verdict above comes from the separate replay of this host’s raw measurements. [Qualification results and evidence digests](results/linux-arm64-ssd-2026-11-19/qualification.json)

### OpenCode follow-up on the same binary

**K27.2 onboarding and K11.1 learning passed.** Each ran once in its own disposable Ubuntu ARM64 guest on the AC-powered Mac. Both installed the jail executable from the K17 run and used OpenCode 1.18.32 with the vaulted Anthropic key. The onboarding workflow finished in 15.77 seconds against its ten-minute limit. Learning proposed read-only access to `/etc/nsswitch.conf` and no network access. The verifier traced that read to a recorded denial. Both guests were destroyed and the key-exposure scans found zero matches across 83 files per run. [OpenCode results](results/linux-arm64-ssd-2026-11-19/opencode-checks.json)

The ARM64 release-evidence index now selects the new records. Both release-mode Rust tests passed in a focused native Linux ARM64 rerun. The initial workspace totals and release-map verdict above remain the historical results of that run. The native ARM32 control still fails on this Mac. [Onboarding record](results/linux-arm64-ssd-2026-11-19/onboarding/guest/result.json) · [Learning proposal](results/linux-arm64-ssd-2026-11-19/learning/guest/opencode-learned.toml)

K17 can be closed for the measured M5 Pro/HVF configuration. Stable ARM64 under the current requirements still needs a single configuration with native ARM32 execution, a passing K17 benchmark and complete conformance. The raw SSD-host evidence is in `evidence/arm64-ssd-0010dffb3-20261119/`.
