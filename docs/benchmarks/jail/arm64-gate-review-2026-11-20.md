# M5 ARM64 release gate review, 20 November 2026

**4 of the 13 open gates closed.** The release evaluator passed C01, C02, F04, S02. Of the 21 previously missing checks, 6 passed and 15 remain unexecuted. The incomplete verdict keeps the release freeze unrecorded.

The test guest ran Ubuntu 26.04.1 LTS 7.0.0-43-generic under HVF on the M5 Pro, using four native ARM64 vCPUs, 6 GiB of memory and local SSD storage. The candidate was `a6cd7dc2291391e96edfc37c86debdcd4f88576d`, the same revision as the preceding R01.8 run. All release inputs and the four release executables were hash-checked. All four executables also matched the previous candidate byte for byte. The scored workspace run had **2,971 passes, 0 failures and 18 ignored tests**. The complete map reported 9 failing rows. [Case-level results, supporting tests and log digests](results/linux-arm64-gates-2026-11-20/qualification.json)

## Review of the 21 missing checks

The case numbers are the stable IDs from the original 73-case review. A pass means the evaluator received the result of the mapped live test. Open cases still need their specified live evidence. [Previous qualification](arm64-r018-qualification-2026-11-19.md)

| Case | Acceptance clause | What the check must demonstrate | M5 result |
| ---: | --- | --- | --- |
| 6 | N05.7 | After one successful connection, the bridge must refuse an endpoint with a different identity. The original receives only the first request and the replacement receives none. | Passed |
| 7 | N05.7 | If the endpoint changes before the first connection, the replacement must receive zero connections. | Passed |
| 8 | N05.8 | Changes that the child attempts to make to its path or mount view must leave the approved bridge destination intact. | Open |
| 14 | S03.4 | Attempts to undo the outer namespace, mount and network boundaries must fail, with their effects still enforced afterward. | Open |
| 16 | C01.1 | Replacing a read-only credential source after staging must prevent target startup. The replacement must never be bound. | Passed |
| 17 | C02.1, C02.4 | After normal exit, private vendor state must be removed while all external file and directory canaries remain intact, including when the state contains links. | Passed |
| 19 | R05.2 | Local policy bytes that a same-user uncontained process can change must carry no protection claim. | Open |
| 20 | R06.2 | When a descendant leaves the tracked group after its parent exits, the supervisor must record lost integrity and preserve the group. | Open |
| 21 | R06.4 | A short-lived descendant that leaves the group must still be classified from its zombie identity before it is reaped. | Open |
| 22 | L01.2, R06.4 | When the original group identity is lost, the supervisor must report an unknown tree on termination and leave the replacement group untouched. | Open |
| 23 | R06.1 | A target that leaves and exits immediately must still produce lost integrity, without a fabricated verified exit. | Open |
| 24 | L01.2, R06.1 | If a live target leaves the group, the supervisor must give an unknown tree outcome on termination and must not claim verified settlement. | Open |
| 25 | K05.1 | A child outside observer coverage in the uncontained profile must produce a named descendant gap in the live record. | Open |
| 31 | O06.2, K30.3 | If a directory descriptor changes identity during an observed call, the trace must not attribute the call to either directory without evidence. | Open |
| 32 | O06.5 | A changing pathname must be reported as a literal snapshot or a counted gap. The two outcomes must account for every operation. | Open |
| 36 | F02.3 | The protected repository object must retain its original identity and contents when mount replacement is attempted. | Open |
| 37 | F04.2 | If the workspace identity changes after pinning and before the mount handoff, the launch must refuse and the target marker must be absent. | Passed |
| 42 | R05.3 | Changes to live local receipt, trace and state files must carry no protection claim or change the actual run outcome. | Open |
| 44 | R06.2, R06.5 | After detecting a descendant outside its tracked group, the supervisor must retain both group and vendor state. | Open |
| 45 | S02.1, S02.3 | Inside the private process view, namespace-entry requests on visible descriptors must be denied, and the host supervisor must be absent. | Passed |
| 46 | S03.5 | Attempts to undo the outer cgroup, Landlock, seccomp and no-new-privileges restrictions must leave those restrictions in effect. | Open |

## Supporting checks and their limits

The contained tool and agent both ran with zero effective capabilities, no-new-privileges set, seccomp active, and separate PID, mount and network namespaces. The tool profile mounted the nested .git directory read-only. The first supplemental probe applied the tool rule to the agent profile and failed. After checking §9.1, the corrected probe verified the agent’s protected config file was read-only while its parent directory remained writable. A neighboring workspace write succeeded in both profiles. The agent also saw its proxy directory as read-only. These observations establish ordinary enforcement. The open F02, N05 and S03 clauses additionally require evidence under attempted boundary changes. [Filesystem requirements, §9.1](../../specs/jail-v1.md)

An ordinary uncontained run emitted an unprotected receipt. A separate observation run produced a saved trace and control transcript bound to its final receipt. The validator rejected a changed receipt copy and out-of-order control messages. R05 still calls for measuring the effect of changes to live local records.

The suite also exercised integrity loss on unreadable target and orphan identities, cleanup retention, classification of an untraced child from recorded inputs, and revalidation of entry and exit arguments. These checks do not supply the live migration and observer-race observations required by L01, R06, K05, O06 and K30. The missing cases preserve the distinction between what the supervisor can infer and what the tested kernel actually did. [Supporting checks](results/linux-arm64-gates-2026-11-20/qualification.json)

### Process supervision follow-up

Six live controls on the M5 used a byte-identical copy of the candidate. With observation on and off, an operator stop while the target was alive produced signal 15 and cause `operator_signal`. In four runs the target exited with code 23 while its child was still alive. The intermediate receipt still showed `enforced` with no tree verdict. After the child ended, Ukai preserved exit 23, verified the registered group was empty and removed it. An unrelated process survived every run. The first probe expected an operator signal sent after the target exited to become its cause. Sections 6.4 and 8.1 preserve the target’s outcome during descendant cleanup. The corrected controls verified both signal timings.

A separate native test build injected a membership-read error while collecting an ordinary child's exit. At settlement, healthy subsequent reads preserved the recorded loss, with no tree verdict or verification timestamp. Its clean control verified the same child exit and an empty registered group. The six mapped L01/R06 live cases remain open. [Supervision results and receipt digests](results/linux-arm64-gates-2026-11-20/supervision.json)

## K17 and freeze

The replay used the existing strict startup limit of 500 ms, inclusive file-overhead limit of 100%, and guest-load cutoff of 3. It recorded 540 valid measured launches, 0 exclusions and 18 warmups. [K17 measurements](results/linux-arm64-gates-2026-11-20/k17.json)

| Session | Worst added startup, p95 | Median file-operation overhead |
| --- | ---: | ---: |
| plain | 50.39 ms | 88.36% |
| scope | 32.62 ms | 90.05% |

Remaining gates are **F02, K05, K30, L01, N05, O06, R05, R06, S03**. The evaluator uses the existing `linux-x86_64-stable` publication scope. The read-only freeze check found no tested run for this candidate. Raw results are retained in `evidence/arm64-gate-review.UNJLnn64/`.
