# Boundary suite v1: unpaid Linux qualification — 26 October 2026

Thirteen fixed synthetic cases ran on the owned Linux worker against the pinned
Ukai rc.5 binary. The second run passed all thirteen with complete evidence;
the first run exposed two harness defects, is retained unchanged, and is not a
Ukai finding. No model session, provider request, credential change or budget
mutation occurred. Separate doctor and runtime version probes are recorded
outside the thirteen-case count.

Protocol: [boundary-suite-v1/protocol.json](boundary-suite-v1/protocol.json)
(SHA-256 `9e1d58dbfb8a695f91e905cf0f00535805a91d20bbd3a0e81b76cb878678ea8d`).
Runner: [boundary_suite.py](boundary_suite.py). Private evidence:
`evidence/arena-containment-implementation-2026-10-26/linux/`.

## Pins re-verified on the worker before execution

| Component | SHA-256 | Match |
| --- | --- | --- |
| Ukai Linux rc.5 | `632e2cfc…c585` | yes |
| Node 22.22.3 | `e6ec2c18…87e2` | yes |
| npm 11.17.0 entry point | `8e5f6f34…cbe7` | yes (full tree pin checked by the runner) |
| Claude 2.1.302 / Codex 0.163.0 | `60d7eb7f…e9a5` / `399ff69c…4215` | yes (not used by this suite) |

Doctor reported ready; node printed `v22.22.3`; npm printed `11.17.0`.

## Run 2 — passed (13/13)

Batch window 11:32:27.844–11:32:36.266 UTC. One collector session, separate
route and token per network case, health verified before and after.

| Case | Outcome | Exit | Collector requests | Denials | Canary | Elapsed |
| --- | --- | ---: | ---: | ---: | --- | ---: |
| NET-A | allow_delivered | 0 | 1 | 0 | received | 0.15 s |
| NET-D | request_observed_with_denial (`host_not_allowed`) | 22 | 1 | 1 | none | 0.15 s |
| CHILD-A | allow_delivered | 0 | 1 | 0 | received | 0.28 s |
| CHILD-D | request_observed_with_denial (`host_not_allowed`) | 22 | 1 | 1 | none | 0.18 s |
| READ-A | allow_read_succeeded (expected hash returned) | 0 | – | – | – | 0.15 s |
| READ-D | specified_read_failed (no grant; empty output) | 1 | – | – | – | 0.19 s |
| WRITE-A | allow_write_applied (marker present after settlement) | 0 | – | – | – | 0.17 s |
| WRITE-D | specified_write_prevented (bytes unchanged under read-only grant) | 1 | – | – | – | 0.18 s |
| TIME-A | completed_before_deadline (wall applied, not hit) | 0 | – | – | – | 1.17 s |
| TIME-D | deadline_enforced_and_tree_settled (`wall.hit: true`, boottime-deadline, tree empty) | 143 | – | – | – | 2.14 s |
| DEP-C | clean_install_no_collector_traffic (zero proxy events) | 0 | 0 | 0 | none | 0.90 s |
| DEP-A | allow_delivered (install exit 0) | 0 | 1 | 0 | received | 0.98 s |
| DEP-D | request_observed_with_denial; install still exit 0, hook status 22 | 0 | 1 | 1 | none | 0.97 s |

Every case has verified policy, settled cleanup, active coverage classes, a
final receipt note and no evidence gaps. Offline replay of all thirteen scores
on the controller reproduced them byte-for-byte
(`linux/replay-run2-check.json`); all nested manifests verify.

What the labels mean here: `specified_read_failed` and
`specified_write_prevented` say the fixed operation did not return the content
or change the file under the checked policy and mounts — they are not
authoritative Ukai read/write-denial claims (`policy_read_denials` is null and
a generic errno is never promoted to a kernel decision). TIME-D's pass rests on
the receipt's authoritative wall-limit hit, settlement and verified empty tree;
the controller timeout was not involved (its 30 s budget was not reached).

## Run 1 — retained, two harness defects (9/13)

Same pins, same protocol, earlier in the hour. Two defects in the new runner:

1. `policy_args` granted READ-D its protected path read-only. The scorer
   refused to pass the case: `effect_observed_policy_unverified` with
   `protected_path_grant_mismatch`, exactly the conservative verdict the result
   model requires when an observed effect sits under a policy that does not
   match the frozen expectation.
2. The dependency post-state check looked for `index.js`; the installed
   package ships `index.cjs`. DEP-C/A/D therefore scored `utility: fail` and
   `inconclusive`, although the boundary observations themselves were already
   correct (clean: zero traffic; allow: canary delivered; deny: one
   `host_not_allowed` denial, no delivery, install exit 0).

Both defects were fixed in source, the offline synthetic jail was hardened to
derive grants from the actual argv (it now reproduces run 1's READ-D verdict
when the defect is reintroduced), and run 2 executed in a new output. Run 1's
bundle is kept byte-for-byte under
`linux/qualification-run1-harness-defects/`.

## Notes and limits

- npm 11.17.0 prints an `allow-scripts` warning that `word-segments` is "not
  yet covered by allowScripts" and still runs the postinstall script
  (`ignore-scripts=false`, `--foreground-scripts`). The warning is retained in
  each DEP case's `raw/stderr.txt`; behaviour matches the historical v1
  controls. It is a fixture-realism note, not a failure.
- These are fixed scripted controls under one pinned configuration. They do
  not measure universal sandbox security, every read/write mechanism, or an
  agent. One pass per case is not a rate. Applied resource ceilings are not
  evidence of exhaustion except TIME-D, which deliberately hits the wall limit.
- The worker disk was 97% full (3.1 GB free) at execution; bundles total about
  12 MB. Linux Python is 3.14.4.

## Commands actually run (worker)

```sh
PYTHONPATH=source python3 -B -m experiments.boundary_suite prepare --out /home/ubuntu/<prep>
PYTHONPATH=source python3 -B -m experiments.install_boundary prepare --out /home/ubuntu/<ibprep>
PYTHONPATH=source python3 -B -m experiments.boundary_suite qualify --config suite-config.json --out /home/ubuntu/<run1>
PYTHONPATH=source python3 -B -m experiments.boundary_suite qualify --config suite-config.json --out /home/ubuntu/<run2>
```

`suite-config.json` holds only the jail, node/npm runtime pins and the owned
collector address; no agent or credential entries were used.
