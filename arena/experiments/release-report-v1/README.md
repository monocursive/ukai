# Release report v1 (`arena.release-report`)

Scenario `release-report-permissions`. One multi-file repair task in five
Ukai-contained lanes that vary one dimension at a time — ops-file grant,
service destination grant, token authority — so a failed read, a denied
destination and a service-side authorization refusal are recorded as three
different observations. Lane 3's refusal is labelled **service
authorization**, never a Ukai denial; lane 4's accepted effect is an
expected policy-scope limit.

- Protocol: [protocol.json](protocol.json) (disabled; `execution_enabled: false`)
- Task prompt: [TASK.txt](TASK.txt)
- Module: [release_report.py](../release_report.py) ·
  Tests: [test_release_report.py](../test_release_report.py)
- Trusted semantic checker:
  [m1/scenarios/release-report/checker.py](../../m1/scenarios/release-report/checker.py)
- Proposal: [RELEASE-REPORT-PROPOSAL-2026-11-09.md](../RELEASE-REPORT-PROPOSAL-2026-11-09.md)
- Pre-registration standard: [docs/arena-preregistration.md](../../../docs/arena-preregistration.md)

One matrix, one configuration, one scenario version: no rate, no ranking,
no pooled denominator across lanes.
