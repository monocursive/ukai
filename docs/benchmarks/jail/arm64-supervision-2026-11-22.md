# ARM64 process supervision and file observation, 22 November 2026

The Linux ARM64 build at `2f58d7cde8a910fc527128813952eb2d8e0b661c` passed all six outstanding process-supervision cases and both outstanding file-observation cases. The scored suite on the M5 Pro guest passed 2,979 tests, failed zero and ignored 18. The evaluator still requires seven live results across five release gates. ARM64 remains a preview. [Qualification record](results/linux-arm64-supervision-2026-11-22/qualification.json) · [Scored suite](results/linux-arm64-supervision-2026-11-22/scored-suite.txt)

## What the receipts establish

| Gate | Evaluator verdict | What passed |
| --- | --- | --- |
| L01 | Pass | An operator stop after the supervisor loses track of the process group produces an unknown tree outcome. |
| R06 | Pass with limits | When the supervisor detects that the target or a descendant left its group, it records lost integrity and retains the relevant state. Successful verification applies only to the registered group. |
| O06 | Pass | If a directory descriptor changes while a call is observed, the observer withholds the attribution. Each measured pathname change produced a literal snapshot or a counted gap. |
| K30 | Pass | The observer retains a resolved directory name only when the observations agree. |

A focused run passed all 48 tests mapped to the 28 clauses in these four rows. The broader run included the same checks and all the cases selected in the 20 November review. Both runs used strict conformance mode. The guest ran Ubuntu 26.04.1 LTS, kernel `7.0.0-43-generic` and bubblewrap 0.11.1 on four native ARM64 vCPUs with local SSD storage. All six driver checks passed. [Focused test log](results/linux-arm64-supervision-2026-11-22/supervision-and-observation.txt) · [Previous gate review](arm64-gate-review-2026-11-20.md)

## Performance and remaining evidence

K17 passed with its existing limits. Across 540 valid measured launches and 18 warmups, there were zero exclusions. The worst added p95 startup was 48.53 ms against a strict 500 ms limit. Median file-operation overhead was 83.16% in the plain session and 80.60% in the delegated session, each within the 100% limit. [K17 replay](results/linux-arm64-supervision-2026-11-22/k17.json)

The broader run selected tests explicitly. The evaluator reported missing live results for F02.3, S03.4, S03.5, N05.8, R05.2, R05.3 and K05.1. Those are cases 8, 14, 19, 25, 36, 42 and 46 in the previous review. The current publication scope is `linux-x86_64-stable`. An ARM64 release freeze remains open.

## Exact ARM64 candidate at 479584c0e

A fresh build on the M5 Pro reproduced the earlier executable at this revision. Its SHA-256 is `7383cbe3e27784f15282a0e5e048006be3cb2d1ca561ccb5ca7d13314005f14c`. All 21 expected doctor capabilities matched the reference manifest. Five focused controls passed, and the `tool` and `none` profiles both ran a command to completion in an ordinary login session.

K17 recorded 540 valid measurements, 18 warmups and zero exclusions. The largest added p95 startup was 64.26 ms against a 500 ms limit. Median file-operation overhead was 79.14% in the plain session and 84.34% in the delegated session, within the 100% limit.

A separate fresh Ubuntu ARM64 VM installed and upgraded a private test-signed archive. Both installations matched the candidate hash. The installer rejected a corrupted archive and an invalid signature. A restored copy of the reference guest booted and verified the candidate and its three companion binaries.

All seven live cases above remain open for this executable. Stable qualification still requires a complete passing ARM64 conformance record tied to these bytes and a tested ARM64 freeze. [Exact candidate record](results/linux-arm64-supervision-2026-11-22/exact-candidate.json)
