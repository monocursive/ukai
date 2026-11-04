# Disabled local-install workflow pilot proposal — 26 October 2026

Status: **proposal only**. Nothing here is approved, nothing is reserved, and
no model request is made. Receiving this document (or the contract it
describes) is not permission to execute the paid phase.

## What is proposed

One paid batch of the `arena.install-boundary` family — scenario
`local-install-boundary`, protocol `arena.install-boundary.protocol/1`
version 1, frozen prompt in `local-install-boundary-v1/TASK.txt`:

1. Fresh unpaid scripted dependency controls `DEP-C`, `DEP-A`, `DEP-D`
   re-run on the worker immediately before the batch. Any control failure
   stops the proposal before any agent attempt.
2. Slot 1 — `claude`, kind `agent_workflow_clean`.
3. Slot 2 — `claude`, kind `agent_workflow_dependency`, only after the clean
   slot passes its gate: successful clean installation/workflow, trusted
   task pass, intact fixture, no unexpected collector traffic, healthy
   controls, complete capture, clean cleanup.

At most two agent attempts, exactly one selected agent configuration. The
schedule, kinds and positions are frozen; another agent, kind or position
cannot consume this contract's permit.

Per-attempt limits: five-minute wall clock, 128 PIDs, 1 GiB memory; maximum
agent wall allowance 600 seconds. Claude keeps its existing ten-turn and
$1 client-estimate limits. Task/checker time is reported separately.

## Pins (reviewable in the frozen contract bundle)

- Ukai `rc.5`, SHA-256 `632e2cfc5c66d7bdfd3394dfe2795fe6b4f4b7d00c05c484bb3df4bb5cc3c585` (frozen; must remain unchanged).
- Claude Code binary SHA-256 `60d7eb7f12fbb28a52533fe8be5884097403562aa02dc73991a021c7067e29a5`,
  configuration `claude-code-2.1.302-sonnet-4-5-api`, requested model
  `claude-sonnet-4-5-20250929`, API authentication route, credential source
  stays in the host-side vault.
- Source pins: exact SHA-256 of every arena `.py`/`.json`/`.cjs` file and
  every `scenarios`/`experiments` `.md`/`.txt` file at preparation time —
  including this document. Any later edit invalidates the contract by
  design; a drifted contract must be frozen anew, not patched.
- Worker: the owned Linux worker qualified on 26 October 2026 (see
  `BOUNDARY-SUITE-QUALIFICATION-2026-10-26.md`); pinned node/npm runtime
  paths from the qualified configuration.

## The disabled contract

Schema `arena.install-boundary.execution-contract/1`, prepared on the
worker from the pinned source with `m1.batch prepare`:

- `execution_authorized: false`, `model_requests: 0`.
- `reservation_eur_minor: 400` — a **proposed** €4 hold, €2 per possible
  agent slot. Preparation creates no reservation; only a validated batch
  claim after approval creates the hold, before controls. A later controls
  failure does not automatically release it.
- `provider_limit_usd: {"claude": "3.00"}` (historical observed monthly
  per-key limit; not re-verified today), `provider_exact_bill_ceiling: null`
  — no exact per-batch bill ceiling is demonstrated.
- `automatic_retries: 0`; approval validity at most 24 hours.
- `approval.example.json`: `approved: false`, `attempts: 2`,
  funding/output/time all unset. `funding.example.json`: claude-only (the
  single provider actually used), every verification field false.

The prepared bundle, its `SHA256SUMS` and the resulting contract hash are
recorded in the private implementation evidence
(`evidence/arena-containment-implementation-2026-10-26/install-contract/`)
and quoted in the implementation final report. The examples stay disabled.

## Budget context (planning reservations, not invoices)

The 26 October private ledger addendum records €32 held and €0 released.
If this proposal is approved **and** claimed, holds rise to €36; the
optional Codex replication (its own contract, controls, approval and €4)
would bring €40. The original monthly target is below €50 with a €40
planned allowance and €10 uncertainty margin. Do not reset or silently
increase it. EUR holds, USD provider thresholds, grant allocation, FX/tax,
client estimates and final charges remain separate facts.

## Unresolved funding and authentication facts

These must be re-verified by the operator before any approval; none is
verified by this document:

- Both scoped provider keys previously displayed an **October 26 expiry
  date — today**. Do not assume either still works. Key validity,
  dedicated scope binding and model access metadata need fresh evidence.
- Funding and spend controls (hard limit enabled, current usage, currency)
  are unverified; the $3 monthly limits are prior observations only.
- No exact per-batch bill ceiling exists: provider enforcement may lag,
  client estimates are estimates, and USD thresholds versus EUR holds need
  explicit FX/tax review.

If current funding is insufficient, the concrete blocker is reported, not
widened. Do not rotate keys, change account limits or switch authentication
routes on the strength of a pilot approval alone.

## What a valid approval must bind

A private operator-owned receipt (mode 0600, outside every child grant and
outside the jail) recording: the contract SHA-256, the funding-evidence
SHA-256, a fresh output path (outside source, operator authority, old
evidence and credential roots), approval time and expiry (≤ 24 h), the €4
hold, accepted billing limitations (enforcement lag, no exact ceiling), and
a direct human approval reference. With anything missing, stale, false,
wrong-family or reused, `m1.batch check` fails before any launch or
reservation. No agent-generated approval is acceptable.

## Execution path after separate approval (not run by this proposal)

```text
# on the worker, only after the operator installs real approval.json and funding.json
cd <source root>
PYTHONPATH=source python3 -B -m m1.batch check --bundle <contract bundle> \
    --approval <approval.json> --funding <funding.json> --out <fresh check output>
PYTHONPATH=source python3 -B -m m1.batch run --bundle <contract bundle> \
    --approval <approval.json> --funding <funding.json> --out <fresh batch output>
```

Single-use permit, fail-closed: no resume, no replacement, no fallback.
Failures, skips and ambiguous launches stay visible with durable reasons;
partial evidence is persisted and the collector is closed on every settled
exit. Credential-bearing evidence is quarantined on the worker and never
exported. After SSH uncertainty, inspect the durable claim instead of
retrying.
