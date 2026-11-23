# ARM64 stable qualification, 23 November 2026

**The Linux ARM64 build at `433e794bc09a` passed the complete release-conformance run, and is the recorded ARM64 tested run. K17 is not confirmed, so ARM64 is not yet a stable target.** The suite on the M5 Pro guest passed 3,084 tests, failed none and ignored 18 across 117 test binaries. No gate fails. Of the 110 gates, 65 pass and 7 pass with a recorded limit. The other 38 are macOS requirements and macOS-lane rows that the Linux scope reports as unsupported or elsewhere, and one credential check. The seven live checks open on 22 November passed. [Qualification record](results/linux-arm64-stable-2026-11-23/qualification.json) · [Suite log](results/linux-arm64-stable-2026-11-23/test.log) · [Evaluator verdict](results/linux-arm64-stable-2026-11-23/gates.txt)

## What ran

`cargo xtask conformance --linux-release` drove the guest from a clean checkout of `433e794bc09a9f774d7d421bf7d0b94482f2a9a2`, through a forwarded SSH port. It copied the source into a fresh run directory, built the release workspace and every test binary, ran the I02 vendor-name scan, `doctor --json`, the plain-session smoke leg and the I01 probe, and then the suite with `UKAI_CONFORMANCE=1` and `UKAI_RELEASE_EVIDENCE=1` on the system PATH alone. It checked the three executable hashes again afterwards. No test was left out.

The build-input digest is `sha256:0da6ea53bcb2f25c2094adf95ddc5e13ace97c688222b881d17e8cbbd1404c92`, which is also the digest of the retained 22 November candidate and of the x86_64 reference run. The tested `ukai-jail` has SHA-256 `b01c07d5a378bce363d1df11e5b5ed501cdabd38ab013ade0cd6452aec1d66ad`. The guest ran Ubuntu 26.04.1 LTS, kernel `7.0.0-43-generic`, and bubblewrap 0.11.1 on four native ARM64 vCPUs of an Apple M5 Pro under QEMU HVF, with local SSD storage. It carries the foreign-ABI prerequisites of [the 19 November record](arm64-remediation-2026-11-19.md): the `binutils-arm-linux-gnueabihf` assembler and two static BusyBox controls under `/usr/local/lib/ukai-conformance`. The guest had also updated its own C library to glibc 2.43-2ubuntu2.7 at 12:56 UTC, before any of the complete runs. Doctor reported ready, and all 21 expected capabilities matched the reference manifest. [Doctor record](results/linux-arm64-stable-2026-11-23/doctor.json) · [Host manifest](results/linux-arm64-stable-2026-11-23/host-manifest.txt) · [Executable check](results/linux-arm64-stable-2026-11-23/binaries-check.txt)

## The seven checks that were open

| Clause | Case | Test | Result |
| --- | ---: | --- | --- |
| F02.3 | 36 | `f02_mount_replacement_of_a_protected_git_is_denied` | Passed |
| S03.4 | 14 | `s03_each_outer_boundary_reversal_fails_and_changes_nothing` | Passed |
| S03.5 | 46 | `s03_the_outer_boundaries_cannot_be_reversed_inside_agent` | Passed |
| N05.8 | 8 | `n05_child_path_and_mount_changes_cannot_redirect_the_bridge` | Passed |
| R05.2 | 19 | `r05_same_uid_tampering_is_outside_local_evidence_assurance` | Passed |
| R05.3 | 42 | `r05_forging_records_mid_run_is_outside_local_evidence_assurance` | Passed |
| K05.1 | 25 | `j4_clone_untraced_is_a_gap_in_none`<br>`audit4_compat_abi_listener_and_untraced_clone_route_to_their_gaps` | Passed |

Each passed in the complete log, and each also passed on the retained executable `7383cbe3e27784f15282a0e5e048006be3cb2d1ca561ccb5ca7d13314005f14c` in a focused strict run on the same guest. [Focused log](results/linux-arm64-stable-2026-11-23/seven-open-checks-on-retained-candidate.txt)

Seven gates pass with a recorded limit, the specification's named gaps that the x86_64 run also carries: X05 (X05.4), S03 (S03.2), L03 (L03.6), R03 (R03.6), R06 (R06.3), C01 (C01.6), K17 (K17.2). One of them is K17.2, which the evaluator credits from a recorded run of another host. Its verdict therefore says nothing about K17 on this one, which a later section covers.

## Two earlier attempts

The first complete run passed 3,079 tests and failed 3. The saved guest lacked two prerequisites that the foreign-ABI checks refuse to skip without in strict mode, the cross-binutils assembler and the BusyBox controls. Earlier ARM64 runs on this guest had selected their tests explicitly, so the gap had not surfaced. Provisioning followed the 19 November record. The two Debian `busybox-static` packages of version `1:1.37.0-6+b9` match the hashes in Debian's trixie package index, and their executables match the hashes the test fixture pins.

The second complete run passed 3,081 tests and failed one, `j4_d2_a_foreign_abi_call_without_a_baseline_is_a_gap`. That is the subject of the next section. The backend, the kernel and the source were the same in both attempts. Their bundles are retained with the raw evidence in `evidence/arm64-stable-20261123.NZ2buZ/`.

## The test that needed a rule

That test needs the CPU to execute an ARM32 program, so that the observer can be seen recording its calls as foreign-ABI gaps. This kernel refuses the ARM32 executable before entry, so in strict mode the test could only fail here. S01.2 and R01.8 already accept a 64-bit-only kernel once the all-CPU refusal control proves it, and the acceptance test for the R01.8 receipt branches on that control. [R01.8 review](arm64-r018-qualification-2026-11-19.md)

This test, which no acceptance clause requires, now follows the same rule. Once the control proves that the kernel refuses ARM32 on every online CPU, there is no foreign call to make, and the test says so. The control requires the two hash-pinned static controls, a native execution that succeeds on each CPU, an ARM32 `execve` that returns `ENOEXEC` under `strace`, and a kernel that refuses the Linux32 personality. With one control binary hidden, the test fails. A compat-capable host still runs the original test, and x86_64 is unchanged. [Test and control](../../../crates/ukai-jail/tests/observer_j4_linux.rs) · [Control](../../../crates/ukai-jail/tests/fixtures/arm64_exec_control.py)

## Performance is not confirmed

K17 allows at most 100% median post-start file-operation overhead in each session. It was measured seven times on 23 November and passed four of them. With the same guest image and the same executable, a run passes and the next fails, so no single measurement is recorded as the result. [All seven measurements](results/linux-arm64-stable-2026-11-23/k17-measurements.json)

| Run | Guest glibc | Executable | Overhead, plain | Overhead, delegated | K17 |
| --- | --- | --- | ---: | ---: | --- |
| 1 | 2.43-2ubuntu2.7 | 23 November build | 103.55% | 103.86% | Failed |
| 2 | 2.43-2ubuntu2.7 | 23 November build | 104.49% | 100.32% | Failed |
| 3 | 2.43-2ubuntu2.4 | 22 November build | 88.94% | 82.24% | Passed |
| 4 | 2.43-2ubuntu2.7 | 22 November build | 97.37% | 97.10% | Passed |
| 5 | 2.43-2ubuntu2.4 | 23 November build | 99.16% | 96.41% | Passed |
| 6 | 2.43-2ubuntu2.4 | 22 November build | 100.54% | 98.12% | Failed |
| 7 | 2.43-2ubuntu2.7 | 23 November build | 96.69% | 97.49% | Passed |

The passing runs measured 88.94% to 99.16% in the plain session and 82.24% to 97.49% in the delegated one. The failing runs measured 100.54% to 104.49% and 98.12% to 103.86%. Every run kept all six startup results far below the 500 ms limit.

The runs measured two executables, the 22 November build and a build of 23 November. Neither is the executable of the recorded run, which was built afterwards from the same build inputs and differs only in the revision it names.

Three explanations were tested and set aside. The executable is not the cause: the two builds behave alike, and they share one build-input digest. The guest's C library is not the cause: the guest updated itself from glibc 2.43-2ubuntu2.4 to 2.43-2ubuntu2.7 at 12:56 UTC, half an hour after it booted, and passes and failures occur with either version. This agent's own activity raised the first measurement, which ran while it compiled, and that run is listed with the others. That leaves the host, which these runs do not isolate. The earlier records of the same image and the same executable measured 79.14% and 83.16% in the plain session on 22 November. Today the Mac's one-minute load was between 3.6 and 5.5 when the measured runs started, and a sample taken among them showed three web-content processes at full CPU, the window server and this agent's own interface busy. K17 compares an observed run with a direct one, and that comparison depends on how promptly the guest's tracer and tracee threads are scheduled.

K17 therefore needs a measurement on a quiet host before ARM64 becomes stable.

## What this changes

The freeze file records this run as `[tested_aarch64]` beside the x86_64 `[tested]` table, and `cargo xtask freeze --check --target aarch64-unknown-linux-gnu` passes. A stable release still ships x86_64 alone: `arm64_stable_version` in [release.json](../../../crates/ukai-jail/dist/release.json) stays unset until K17 is confirmed on a quiet host, and the publisher requires that coordinate before it will ship an ARM64 archive as stable. The Raspberry Pi and OrbStack measurements remain separate records for other configurations. [22 November supervision run](arm64-supervision-2026-11-22.md) · [20 November gate review](arm64-gate-review-2026-11-20.md)
