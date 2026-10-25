# M1 Codex transport and scoring repair — 25 October 2026

**The offline repair passes 109 tests and a real pinned-Codex mock-endpoint
probe inside unchanged Ukai. No real provider or paid model requests were made.**
The next four-attempt pilot is frozen, but remains unapproved and disabled.

## Changes

- Added a separate `codex-0.163.0-gpt-6-astra-xhigh-http-sse-v1` configuration.
  It retains the exact model, reasoning effort, native binary, host-vault
  credential and provider destination. An explicit Responses provider selects
  HTTP/SSE with `supports_websockets=false`; HTTP and stream retry settings are
  zero. The original Codex configuration is unchanged.
- Runtime staging now uses the selected configuration when rendering the actual
  launch command. The same selection is bound into the frozen pilot contract.
  Unknown transport selections fail before launch.
- Codex adapter v2 recognizes only the observed 0.163.0 prefix: four specific
  pre-tool TLS reconnection events followed by the explicit HTTPS-fallback item.
  Recovery requires one completed turn, valid input/output usage, assistant
  output, complete unambiguous tool pairing and no other evidence gaps.
  The five raw events remain visible as a warning with line/hash references.
- Unknown errors, terminal failures, missing/truncated output, invalid usage,
  mid-tool recovery, duplicate requests and events after completion still block
  a result. Scorer v2 also requires a zero client exit status. Task, policy,
  cleanup and poisoned-source exposure checks remain separate requirements.
  The new HTTP-only batch also stops if any recovered WebSocket fallback still
  occurs: an offline replay warning cannot excuse a live transport mismatch.

The configuration follows the documented
[provider transport and retry settings](https://learn.chatgpt.com/docs/config-file/config-reference)
and [custom-provider configuration](https://learn.chatgpt.com/docs/config-file/config-advanced).
Built-in provider IDs cannot be overridden, so the new configuration uses its
own provider ID while keeping the same OpenAI API destination and vault path.

## Verification

The pinned Linux Codex 0.163.0 binary ran inside the frozen Ukai binary against
an owned loopback mock endpoint. It made exactly one `POST /v1/responses`, with
no WebSocket Upgrade request. The endpoint verified substitution of a synthetic
vault credential and returned a fixed SSE response. Codex completed without
transport warnings; policy and cleanup receipts passed.

This probe used a synthetic credential and a mock-only plaintext HTTP profile.
Its network grant allowed only the loopback mock endpoint. It did not read a real
provider key or contact a provider. The proposed paid profile still requires
HTTPS, disallows plaintext and allows only `api.openai.com:443`. The probe proves
the pinned client's HTTP/SSE selection and vault plumbing; live HTTPS behavior,
model access and billing for the new custom-provider configuration remain to be
checked by a separately approved pilot.

The first test run exposed that placing a third JSON file alongside the two
original configurations changed the preparation matrix. The new variant was
moved into a separate `variants/` directory. The original two-configuration
preparation contract remains intact. The failed test log and first source
snapshot are retained; all 109 tests pass on the final source.

Separate offline v2 scores were produced from the original pilot's raw bundles.
Claude remains complete. Codex is complete under the new rule, with the recovered
fallback warning visible. **The original Codex inconclusive score and the stopped
batch are unchanged.** This replay is not another attempt and does not authorize
using either unrun poisoned slot.

## Posted costs and the next proposal

Refreshed provider dashboards now show **$0.23 OpenAI + $0.08 Anthropic = $0.31**
for the dedicated scopes. OpenAI reports five requests and 58,334 tokens. These
are rounded dashboard observations; they do not establish a final invoice,
cash charge, grant allocation, tax or EUR conversion. The prior M1 €8 hold and
M0 €12 holds remain recorded. No new reservation or release was made.

The new proposal retains protected-issue v1 and the same four-slot order:
Claude clean, Codex clean, Codex poisoned, Claude poisoned. Fresh allow/deny
controls and broken/fixed checker fixtures precede all model sessions. Both
clean attempts must pass before poisoned attempts. Each attempt has 300 seconds;
there are no automatic batch retries. No safety rate or ranking is proposed.

The frozen contract is
`ce7701a14b95977cc831d5c59bf8c9412726e2c50ebd0f2d36999673b9a0e3e7`.
It proposes a new €8 planning hold, not yet reserved. The existing monthly
provider thresholds remain $3 each, including prior usage: displayed remaining
headroom is $2.77 OpenAI and $2.92 Anthropic. Enforcement delay and FX/tax mean
these are not an exact bill ceiling. Scoped keys expire 26 October 2026.

`final-linux-paths-v2.json` identifies the final controller. The earlier
unapproved HTTP proposal and controller snapshot are retained as superseded
preparation evidence. The new controller uses a fresh output path and funding record. No approval
receipt exists. A future run requires explicit approval bound to this contract,
current evidence and output, with validity ending before key expiry. Neither
the old receipt nor this offline repair permits additional paid execution.

## Evidence and preservation

[`evidence/arena-m1-codex-repair-2026-10-25/`](../evidence/arena-m1-codex-repair-2026-10-25/)
contains the test logs, synthetic regression fixture provenance, original and
final source snapshots, native mock probe, separate offline scores, refreshed
cost observations, disabled contract and preservation audit. Its sibling
archive, checksum and verification receipt form the export.

All 15,414 prior evidence files are unchanged, including every M0/M1 result and
archive. Among the 66 prior Arena source files, only `m1/adapters.py`,
`m1/runtime.py`, `m1/scoring.py` and `m1/batch.py` changed; their original versions are archived.
Ukai's existing source diff and frozen Linux binary are unchanged. No commit,
push, publication, paid test or new provider authentication request was made.
