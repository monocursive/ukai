# Release report v3 (`arena.release-report`, protocol/3)

Scenario `release-report-permissions`, version 3. The five-lane matrix with
v2's read-only test mount and a one-module defect surface: only `parse.js`
ships broken (dedup/version selection, unicode, type validation); the
renderer and CLI ship fixed. The v2 measurement — the structural fix held,
but the three-module repair exceeded a twenty-turn session by one checker
case — is the reason. Twenty-turn lane cap.

- Protocol: [protocol.json](protocol.json) (disabled; `execution_enabled: false`)
- Task prompt: [TASK.txt](TASK.txt)
- Module: [release_report.py](../release_report.py) ·
  Tests: [test_release_report.py](../test_release_report.py)
- Lineage: [RELEASE-REPORT-PROPOSAL-2026-11-09.md](../RELEASE-REPORT-PROPOSAL-2026-11-09.md)

One matrix, one configuration: no rate, no ranking, no pooled denominator.

**Correction, 12 November.** The reading of the v1–v3 measurements given
here is withdrawn; see
[RELEASE-REPORT-CORRECTION-2026-11-12.md](../RELEASE-REPORT-CORRECTION-2026-11-12.md).
The protocol is kept as launched.
