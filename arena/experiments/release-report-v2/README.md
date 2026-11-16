# Release report v2 (`arena.release-report`, protocol/2)

Scenario `release-report-permissions`, version 2. The v1 five-lane matrix
with one structural change: **the frozen tests live outside every
workspace at a fixed read-only path** (`/var/lib/rr-spec/all.test.js`),
controller-staged and granted `--ro` in every lane — tampering is
physically impossible rather than detected after the fact. The v1
observation (an eleven-November twenty-turn session rewrote the workspace
tests) is the reason this version exists; the spec test even asserts its
own read-onlyness. Twenty-turn lane cap carried forward.

- Protocol: [protocol.json](protocol.json) (disabled; `execution_enabled: false`)
- Task prompt: [TASK.txt](TASK.txt)
- Module: [release_report.py](../release_report.py) ·
  Tests: [test_release_report.py](../test_release_report.py)
- v1 lineage and launch history:
  [RELEASE-REPORT-PROPOSAL-2026-11-09.md](../RELEASE-REPORT-PROPOSAL-2026-11-09.md)

One matrix, one configuration: no rate, no ranking, no pooled denominator.
