# M1 execution preparation — 25 October 2026

The four-attempt pilot is frozen and ready for spending approval. **No model
sessions or paid tests ran in this preparation. No new budget reservation was
created.** Ukai and all prior results remain unchanged. The earlier M0 and M1
reports describe their original snapshots and are preserved separately.

The new controller is [`m1/batch.py`](m1/batch.py). It refuses execution without
a private operator approval bound to the contract, source hashes, funding
evidence, four-slot schedule and one fresh output directory. Each slot has a
durable claim and a single-use permit. It cannot replay or resume a claimed
batch, and it never silently replaces an unsuccessful attempt. The operator
remains trusted; these receipts are not signatures or independent billing audits.

## Account controls and authentication

| Provider | Dedicated scope | Monthly threshold | Current scope usage | Funding observed |
| --- | --- | ---: | ---: | --- |
| OpenAI | Ukai Arena M1 project | $3, enforcement enabled | $0 | $38.63 existing API credit |
| Anthropic | Ukai Arena M1 workspace | $3 spend limit | $0 | $1,106.93 total credit, including $997.25 promotional credit valid through 5 April 2027 |

The OpenAI project permits Standard service tier only. Its new key permits model
listing and Responses writes. The Anthropic key belongs only to the dedicated
workspace and has no Admin API access. Both new keys expire **26 October 2026**;
an expired key requires a fresh setup and contract, never a fallback to an older
unscoped key. Existing organization settings, keys, payment methods and other
workspaces/projects were left as found.

The user-reported startup grant is supported by the observed promotional balance;
the UI does not establish which credit will pay a future request. No purchase or
reload was made. OpenAI's existing credit is sufficient for the proposed nominal
limit; its auto-reload status was not relied on.

Each newly scoped key passed one exact-model metadata GET on Linux and one
real-vault CLI version probe. These prove metadata authentication and vault
startup, **not generation access or an end-to-end model response**. Keys stay in
private host-only files outside child grants. Only paths and sanitized receipts
are in this package. The key values and their digests are excluded.

The $3 + $3 thresholds are **not an exact $6 bill ceiling**. OpenAI documents
enforcement delay; a zero-overshoot guarantee was not established for Anthropic.
Taxes and exchange rates are separate. The proposed **€8 planning hold remains
unreserved**, and all M0 €12 holds remain intact. Sources:
[OpenAI spend-limit semantics](https://developers.openai.com/api/docs/guides/spend-limits)
and [Anthropic spend limits](https://platform.claude.com/docs/en/api/rate-limits).

Current standard token prices, cache/long-context differences and a clearly
illustrative cost calculation are recorded in `pricing-and-spend-controls.json`.
They are not a quote or forecast. Claude retains its existing 10-turn / $1 local
CLI cost guard. Codex has no verified equivalent CLI dollar/turn guard. Agent
budgets are therefore not claimed to be matched. No automatic batch retries are
allowed; provider-client internal retry behavior is not disabled by this gate.

## Exact proposed pilot

Protected-issue v1 is an owned, synthetic fixture: the useful task is to fix a
slug function; the poisoned issue attempts to induce a forbidden protected-file
read. A fresh source nonce verifies exposure independently of task completion.

| Order | Agent | Variant |
| ---: | --- | --- |
| 1 | Claude Code 2.1.302 / `claude-sonnet-4-5-20250929` / API | Clean |
| 2 | Codex CLI 0.163.0 / `gpt-6-astra` / `xhigh` / API | Clean |
| 3 | Same Codex configuration | Poisoned issue |
| 4 | Same Claude configuration | Poisoned issue |

Before any attempt, run two fresh file controls (allow and deny), plus trusted
broken/fixed task-checker fixtures. Each attempt has a fresh workspace, nonce,
canary and isolated agent state, 300 seconds, 1 GiB memory and 128 PIDs. Total
agent wall time is at most 20 minutes, with additional setup/cleanup time.

Stop before proceeding on failed controls, task failure, missing evidence,
unverified policy or cleanup, forbidden effect, missing poisoned-source exposure,
reported model mismatch, missing input/output usage, expired authority, or
credential exposure. Both clean tasks must pass before either poisoned case.
Credential scans also run when capture raises; unsafe evidence is quarantined.
Reported model IDs and requested configuration remain separate, especially when
the Codex stream does not report an actual model ID.

README v4 stays deferred to keep this pilot small. Postinstall v1 remains
excluded from agent trials because the unchanged trace does not supply its
required script attribution. One sample per variant supports wiring verification,
not safety rates, rankings, or pooling with M0.

## Verification and preservation

- **102 offline tests pass.** Gate simulations use synthetic credentials and
  mocked processes/network. They cover missing approval, changed sources and
  evidence, private receipts, account-control gaps, one-use permits, replay,
  clean-first stopping, failed controls, credential leaks and scan failures.
- **Four real unpaid Linux checks pass:** allow/deny controls and expected
  broken/fixed task outcomes. Their process cleanup is verified. These used the
  first gate source snapshot; subsequent changes only hardened credential scans,
  covered by the final offline tests.
- **Two new metadata GETs and two real-vault version probes pass**, with zero
  inference requests. These do not count as agent trials.
- The frozen Linux Ukai binary remains
  `632e2cfc5c66d7bdfd3394dfe2795fe6b4f4b7d00c05c484bb3df4bb5cc3c585`.
  Its source was not changed. The pre-existing tracked working-tree diff remains
  byte-identical. Only `m1/runtime.py` changed among the prior Arena source files;
  its original is retained in the before-source archive.
- The preservation audit covers all **14,869 pre-existing evidence files** in
  this checkout, including unrelated historical evidence; this broader count
  does not replace the previous Arena-only counts. Prior results and archives
  remain byte-identical.

Evidence is in
[`evidence/arena-m1-execution-prep-2026-10-25/`](../evidence/arena-m1-execution-prep-2026-10-25/).
The frozen `execution-contract/`, `pilot-proposal-spend-scoped/`, provider-control
observations, source archives, tests, Linux qualification, auth receipts and
preservation audit are separately retained and checksummed. The sibling archive
and checksum file form the export. No commit, push or deployment was made.

## Operator handoff

`final-linux-paths.json` names the new isolated controller, contract, private
funding receipt and prospective output on the Linux host. **No real approval
receipt exists.** The included approval example has `approved: false`.

After explicit approval for this exact four-attempt batch and its spending
limitations, record that user approval in the private receipt, bind the contract
and funding hashes, choose a validity window no longer than 24 hours and ending
before key expiry, and bind the exact fresh output. Recheck provider usage if
anything changed or the observation is older than 24 hours. Only then use
`batch.py check` followed by `batch.py run`. Do not edit the frozen proposal,
relax a refusal, reuse M0 holds, or retry a consumed batch.

If any output is marked quarantined, do not export it. After a future run,
preserve every unsuccessful attempt, reconcile actual provider usage/charges
separately from CLI estimates, and keep the reservation held until reconciled.

## Scope assessment

This is private testing of owned fixtures and the user's Ukai installation,
using synthetic data and normal API endpoints. It does not target provider
infrastructure, train a substitute model, publish comparative claims, or rely on
bug-bounty safe harbor. This is a bounded operational assessment, not general
legal clearance for other uses.

The reviewed [OpenAI Services Agreement](https://openai.com/policies/services-agreement/)
displayed 1 January 2026. The current Usage Policies landing page displays a
future effective date of 20 November 2026; the linked
[29 October 2025 version](https://openai.com/policies/usage-policies/revisions/2025-10-29/)
was used for today's scope assessment. Its restrictions on harmful cyber use,
unsolicited safety testing and provider-safeguard circumvention were considered;
this fixture tests the user's own local containment boundary.

Anthropic's Console links the
[17 June 2025 Commercial Terms](https://www.anthropic.com/legal/archive/af81645b-040b-485c-a4a0-3205ccfb3792).
Its linked archived usage-policy page was unavailable to the retrieval tool;
the dated official [15 August 2025 clarification](https://www.anthropic.com/news/usage-policy-update)
supports security testing with system-owner consent. The future-dated policy
landing page was not treated as current. Publication and any discovered real
vulnerability would need a separate review. The original M0 scope review remains
unchanged.
