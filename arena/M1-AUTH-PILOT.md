# M1 real authentication and small pilot — 25 October 2026

**Both API credentials are configured. Exact model metadata and real-vault
CLI startup passed for Claude and Codex. No inference or paid tests ran.**

## Authentication evidence

- Located an existing private Anthropic API credential in the Mac's expected
  Ukai credential store. A fixed `GET /v1/models/claude-sonnet-4-5-20250929`
  returned HTTP 200 with that exact model ID and active lifecycle.
- Installed that credential over encrypted SSH stdin in a new, mode-0600
  host-only file on the existing Linux worker. No credential value appeared in
  an argument, transcript, repository file, hash record or exported artifact.
  No previous credential file was overwritten.
- Created a separate M1 Claude API profile: `ANTHROPIC_API_KEY`, `x-api-key`,
  host-side vault, exact native executable binding, only `api.anthropic.com`,
  fresh attempt state. The original Claude subscription route remains the
  default for its original configurations; M0 profiles and results are intact.
- A real-vault `--version` probe inside the unchanged pinned Ukai binary passed.
  It reported Claude Code 2.1.302, never-staged credentials, zero provider
  requests, verified empty process tree and complete state cleanup. A scan
  found no credential bytes in its evidence.
- A separate metadata GET from the Linux host also returned HTTP 200 for the
  exact pinned model. The Claude setup made two authenticated metadata GETs,
  one local and one on Linux, and **zero inference requests**. The metadata
  request validates provider acceptance of the API key; the CLI version probe
  validates the vault/profile path. Neither is a paid end-to-end agent run.
- The user supplied a local RTF file containing an OpenAI API key. Its permissions
  were restricted to mode 0600, and the key was extracted in memory into a new
  private credential file outside the repository. It was installed on Linux via
  encrypted SSH stdin into a new mode-0600 host-only file. Neither key contents
  nor a key digest were retained in evidence.
- One metadata GET from Linux returned HTTP 200 for exactly `gpt-6-astra`.
  A separate real-vault `--version` probe passed with Codex CLI 0.163.0, zero
  provider requests, never-staged credentials and verified cleanup. Its evidence
  scan found no key bytes. The requested reasoning setting remains `xhigh`;
  generation and reasoning acceptance have not been tested.
- Across both agents: **three metadata GETs, two real-vault CLI version probes,
  zero model sessions and zero inference requests**. No saved Codex login was
  copied. Read-only model metadata acceptance does not prove generation access,
  quota, funding, spend limits or an end-to-end agent run through the vault.

The user then clarified that they have ChatGPT plan access. `codex login status`
confirmed **Logged in using ChatGPT** on this Mac. That plan is usable by the
normal Codex CLI; it does not provide API billing credits. The documented
subscription automation path uses a token-bearing login cache, which is not
qualified for the Arena's host-vault-only rule. No cache was copied or token
contents inspected by the controller. A subscription-candidate plan is retained
separately as `pilot-proposal-v2/`. The user subsequently chose to provide an
OpenAI API key; the current proposal uses that configured API route. A separate
API key is an Arena route choice, not a general Codex
subscription requirement.

References: [Codex sign-in methods](https://learn.chatgpt.com/docs/auth#openai-authentication)
and [managed account authentication](https://learn.chatgpt.com/docs/auth/ci-cd-auth).

The user's startup grant is recorded as user-reported funding context only.
The API key's grant allocation and remaining balance are unverified. API
estimates, actual charges and M0 subscription reservations remain separate.

The provider's Models APIs are read-only metadata endpoints:
[Anthropic model metadata](https://platform.claude.com/docs/en/api/http/models/retrieve),
[OpenAI model metadata](https://developers.openai.com/api/reference/resources/models/methods/retrieve).
Anthropic's API-key header is documented in its
[authentication overview](https://platform.claude.com/docs/en/api/overview).

## Proposed pilot, not authorized

The frozen plan is in
[`pilot-proposal-both-configured/PILOT.md`](../evidence/arena-m1-auth-pilot-2026-10-25/pilot-proposal-both-configured/PILOT.md)
and its machine-readable `plan.json`.

| Order | Configuration | Protected-issue v1 variant |
| --- | --- | --- |
| 1 | Claude Code 2.1.302 / Sonnet 4.5 / API | Clean baseline |
| 2 | Codex CLI 0.163.0 / GPT-6 Astra / xhigh / API | Clean baseline |
| 3 | Same Codex configuration | Poisoned issue |
| 4 | Same Claude configuration | Poisoned issue |

Two fresh file controls precede the four attempts. Each agent gets one clean
and one poisoned sample. Both clean tasks must pass before any poisoned case.
The order is seeded and reversed between blocks. Every attempt gets fresh
state, workspace, nonce and canary. No automatic retries or replacements.

Proposed reservation: **€8 total, €2 per attempt**, with **€0 newly reserved**.
This is a planning hold, not a provider-enforced cap. Maximum agent wall time
is 20 minutes (four × 300 seconds). Codex has no verified Claude-equivalent
turn/dollar ceiling; the plan does not claim matched budgets. All M0 €12 holds
remain untouched.

README v4 is deferred to keep this first pilot small. Postinstall v1 is excluded
from agent trials because its required script attribution cannot be established
from the unchanged trace. Its successful scripted controls remain preserved.
There will be no ranking, combined safety score or pooled M0/M1 rate from this
one-sample-per-variant pilot.

## Code and remaining gates

`m1/auth_setup.py` supports a fixed metadata GET, a pinned CLI version
probe, or installation of one selected credential via SSH stdin into a new
mode-0600 host-only file. Redirects, arbitrary endpoints, raw response bodies and automatic retries
are excluded. The new API route is explicit in the M1 runtime, with a distinct
Claude configuration ID. `m1/pilot.py` emits only a disabled proposal. The paid
execution function still refuses before credentials, staging or subprocesses.

87 local tests pass, including API/subscription separation, exact vault/header
binding, credential permissions, no response-body leakage, model-ID matching,
plan immutability, canary freshness and the unchanged paid-execution lock.

Remaining before any pilot execution: confirm the funding/terms/spend boundary
for both API routes, explicitly authorize a bounded batch, and bind that exact
approved plan into the currently disabled execution gate. Model generation
access and an end-to-end provider request through the vault remain untested.
Neither this setup nor the proposal authorizes paid execution.

Private evidence: `evidence/arena-m1-auth-pilot-2026-10-25/`. All 3,347
pre-existing Arena artifact files remain unchanged. The only existing Arena
source updated is `m1/runtime.py`; its prior version remains in the immutable
integration archive. Ukai's existing working-tree diff and Linux binary hash
are unchanged. All earlier authentication bundles and pilot proposals are
retained separately. The complete evidence and final source snapshot are in
`evidence/arena-m1-auth-pilot-2026-10-25.tar.gz`, with a sibling checksum file.
No commit or push was made.
