# Linux ARM64 qualification, 19 November 2026

The [subsequent Pi remediation run](arm64-remediation-2026-11-19.md) covers the patched runtime and the three gaps recorded below.

The candidate uses the 0.1.0 source at `8a80ed085430049e7cc6e6212d776b23039aea7c`. Its optimized GNU/Linux ARM64 executable has SHA-256 `1cc88ea25133d776cbea50ad1e59afc248feaa7e1b7dbb1ad6343eda1224b4b9`. Its runtime input digest is `sha256:81a2a1b453dd2c0427800235bc7148e5cd84f23d642319a726ffb543931e3def`. The public 0.1.0 release contains one x86_64 archive. [Public release](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0)

## Physical Raspberry Pi 4

The Pi ran Debian 13, kernel `6.18.50+rpt-rpi-v8` and bubblewrap 0.12.0. The initial boot exposed CPU and PID controls. The file-copy workloads passed under `tool` and `agent`. The `build` profile refused its requested memory limit. After adding `cgroup_enable=memory` to the existing boot command line and rebooting once, all three workloads passed. The build compiled and ran a C program with a 512 MiB memory ceiling. All three receipts showed enforced containment, a verified empty process tree and complete cleanup. The original boot configuration is backed up on the Pi at `/boot/firmware/cmdline.txt.ukai-20261119.bak`. [Before reboot](results/linux-arm64-2026-11-19/pi-before-reboot.json) · [After reboot](results/linux-arm64-2026-11-19/pi-after-reboot.json) · [Raspberry Pi kernel maintainer’s explanation](https://github.com/raspberrypi/linux/issues/6980)

The physical CPU executed the retained static ARM32 ELF helper and produced its exact sentinel. The only registered binary-format handler was Python. Both strict D2 tests passed on hardware, including the receipt check. The optimized test executables were built on native ARM64 from the release tag. A private mount namespace exposed the same source at the compiler’s recorded path. The post-reboot run used Debian’s installed ARM cross-binutils 2.44. [ARM32 control, tests and binary digests](results/linux-arm64-2026-11-19/pi-arm32.json)

## Performance

Each host ran the fixed K17 benchmark with 540 measured launches and 18 warmups. The gate compares observation-off execution with direct execution. Each row had 30 valid subject and 30 valid baseline launches. Recomputing the summaries from the raw records passed all six comparisons on the physical Pi and OrbStack. Three of the six comparisons on the Ubuntu KVM guest exceeded the startup budget.

| Host | Worst p95 added startup | Median file-operation overhead, plain session | Median file-operation overhead, delegated scope |
| --- | ---: | ---: | ---: |
| Raspberry Pi 4, Debian 13 | 348.1 ms | 15.9% | 16.1% |
| ARM64 Ubuntu, OrbStack kernel 7.2.12 | 49.8 ms | 46.6% | 30.2% |
| Raspberry Pi 4, Ubuntu KVM | 1,869.9 ms | 30.3% | 30.9% |
| K17 limit | <500 ms | ≤100% | ≤100% |

The OrbStack guest also passed the three installed-binary workload checks. [Pi K17](results/linux-arm64-2026-11-19/pi-k17.json) · [Ubuntu K17](results/linux-arm64-2026-11-19/ubuntu-k17.json) · [Ubuntu workloads](results/linux-arm64-2026-11-19/ubuntu-profiles.json) · [Pi Ubuntu KVM K17](results/linux-arm64-2026-11-19/pi-kvm-k17.json)

## Clean installation and real-agent workflows

Disposable Ubuntu ARM64 guests verified private packages signed with ephemeral test keys. The installation-only guest installed the candidate, ran a contained `true`, checked the pinned ARM64 OpenCode archive, rejected a damaged release archive and signature, and passed the upgrade check. These distribution checks also passed on the subsequent vendor runs.

The first onboarding attempt used the x86_64 qualification’s Sonnet 5.5 identifier. The pinned ARM64 OpenCode 1.18.32 client rejected it during model lookup. Its trace recorded only the model-catalog destination. An offline listing from the same verified ARM64 client included `anthropic/claude-sonnet-5`. Separate fresh guests then passed onboarding and learning using that model and the operator’s vault. Onboarding took 9.23 seconds from the start of installation through the first contained workflow. Learning proposed one read and no network grants. The verifier checked the grant against the recorded attempt. Both guests shut down, their temporary disks were removed, and the key scans found zero matches. [Initial refusal](results/linux-arm64-2026-11-19/first-onboarding.json) · [Onboarding](results/linux-arm64-2026-11-19/onboarding/guest/result.json) · [Learning](results/linux-arm64-2026-11-19/learning/guest/result.json)

The release gate now selects the evidence by build target and workflow. It checks the ARM64 build target and the guest’s measured architecture before crediting K11 or K27. The retained VM records omit the operator hostname, local file identities and temporary host paths. Each records a digest of its complete original. The guest results, receipts, learning journal and proposal retain their original bytes. [Evidence index](release-preview-current.json) · [Verifier](verify_preview_evidence.py) · [Matched and mismatched records](results/linux-arm64-2026-11-19/verifier-results.json)

To repeat a single workflow, use `onboarding_vm.py --target aarch64-unknown-linux-gnu` with the ARM64 image, its verified SHA-256 and `--arm-firmware`. Use `--only install` for a credential-free distribution check or select `--only onboarding` or `--only learning` for one vendor workflow. For the two recorded vendor workflows, the runner used `--model anthropic/claude-sonnet-5 --vendor-attempts 1`. The VM records identify the image digest and signing identity.

## Full Linux conformance

The supplementary release-mode suite on OrbStack recorded 3,034 passed tests, 40 failures and 18 ignored tests across 117 test summaries. The failures included Ubuntu AppArmor capability expectations, nested sandbox behavior and vault mount checks. OrbStack remains outside the verified stable configuration. [OrbStack test results](results/linux-arm64-2026-11-19/orbstack-suite.json)

The physical Pi has Erlang installed. I01 requires a host without BEAM, so the full reference run used a fresh Ubuntu 26.04.1 ARM64 guest under KVM on the Pi. It ran kernel `7.0.0-43-generic` and bubblewrap 0.11.1. The guest executed the ARM32 positive control on the physical CPU, exposed delegated CPU, memory and PID controllers, and had no BEAM installation. The qualification commit `3a9b2fc57b0d5a391d8a97d672a16bcead4c4d62` included the target-aware verification harness and the two ARM64 workflow records. Its runtime input digest matched 0.1.0.

The cold build reached the driver's 30-minute deadline before tests began. A second attempt stopped during preparation when a cache archive was truncated. Neither attempt produced a conformance verdict for the runtime. The next attempt copied the native ARM64 Cargo cache with per-file checksum comparison. The driver still invoked both release builds, doctor and the workspace suite on the guest.

The completed run recorded **3,073 passed tests, one failure and 18 ignored** across 117 test summaries. The three executable hashes matched before and after the suite. Doctor reported ready. The vendor-name scan found zero hits, and both real-agent evidence checks passed on ARM64. The gate evaluator used the current public Linux clause selection, which is labeled `linux-x86_64-stable`. The measured build target was `aarch64-unknown-linux-gnu`. [Conformance results and artifact digests](results/linux-arm64-2026-11-19/pi-kvm-conformance.json)

| Outstanding check | Measured result | What would close it |
| --- | --- | --- |
| K51 journal summary time | The 7,145,825-byte, 13,108-frame journal took 130.59 ms. Three isolated runs on the Pi guest took 128.77–132.45 ms. The budget is strictly under 50 ms. Three runs on the faster OrbStack ARM64 machine took 13.66–22.74 ms. | Meet the budget on a host that also passes the full ARM64 release suite. [K51 timings](results/linux-arm64-2026-11-19/k51.json) |
| K17 warm startup in the Ubuntu KVM guest | Added p95 startup reached 1,869.9 ms for plain-session file operations, 1,175.7 ms for the plain-session spawn tree and 990.4 ms for a delegated-scope no-op. All cells had 30 valid launches per arm. | Meet the 500 ms startup ceiling for every workload and session on the proposed stable host. The physical Pi and OrbStack runs are separate measurements. [Guest K17](results/linux-arm64-2026-11-19/pi-kvm-k17.json) |
| S01.2 foreign-ABI baseline coverage | The acceptance map requires an R21 live test that compiles only on x86_64. The ARM64 run passed both D2 observer checks, which exercise observation without the baseline policy. | Retain live ARM64 evidence for the baseline denial and bind it to the ARM64 clause while preserving the x86_64 check. [S01.2 acceptance map](../../specs/jail-v1/acceptance-map.toml) |
| I01.3 clean suite | The BEAM and PATH absence checks passed. The failed K51 test made the suite exit 101. | Finish a clean full run after resolving K51. |

Full local records are under `evidence/arm64-pi-2026-11-19/`. The final driver output is in `pi-kvm-qualified/`, with the two earlier attempts in `pi-kvm-strict/` and `pi-kvm-retry/`. The raw K17 launches and the private qualification Git bundle are in the same evidence directory. After collecting the records, the disposable KVM guest was shut down and its disk was removed. The physical Pi had 7.5 GiB free, SSH and Tailscale were active, and the memory controller was available.

The stable release stays scoped to its published x86_64 configuration. After a successful ARM64 qualification, a new stable candidate would need an ARM64 native release stage, a publisher and installer that include the qualified target, production signing, and verification of the public ARM64 installation. The private installation used a test key.
