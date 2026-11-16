# Ukai Arena pre-registration format

8 November 2026 · Direction document, extending the
[containment](arena-containment-spec.md), [twin-exposure](arena-twin-exposure-spec.md)
and [reader program](arena-reader-program.md) specifications. Historical
protocols, scores, evidence archives and the pinned Ukai binary remain
unchanged. This document invents nothing new: it writes down, as a reusable
checklist, the discipline the existing families already follow, so that
future families — and eventually external runners — can be pre-registered
the same way, and so a reader can tell a pre-registered result from a
post-hoc story.

## 1. The rule

No paid slot runs under a protocol that was not frozen, hash-pinned and
disabled-before-approval first. Every claim is drafted — with its
falsifier — before the first session exists. Counting rules and
denominators are fixed before any result can influence them. A protocol
that changes after its batch was claimed is a new protocol, and the
contract's source pins make that drift visible rather than negotiable.

Pre-registration is what makes a stopped batch publishable and a null
result valuable: the protocol, not the outcome, is what the reader can
audit.

## 2. Required elements

A family is pre-registered when all of the following exist **before
approval**, in machine-readable form where an artifact says so:

| # | Element | Artifact | Rule |
| --- | --- | --- | --- |
| 1 | Identity | protocol JSON | family, scenario, version, experiment class, `status: prepared_not_authorized`, `execution_enabled: false` |
| 2 | One distinct uncertainty | protocol `purpose` | one sentence, mapping to a decision a reader can make; a family that answers no stated uncertainty does not run |
| 3 | Pins | protocol + contract | every binary by SHA-256; paired baselines (protocol and prompt hashes); worker; source pins at freeze time — any later edit invalidates the contract |
| 4 | Frozen schedule | protocol `schedule` | fixed slots in fixed order; another agent, kind or position can never consume the permit |
| 5 | Lane difference proofs | structural-difference / lane-configuration records | every deliberate difference between lanes is enumerated and proven; anything else blocks the family |
| 6 | Fresh controls | protocol `controls` | unpaid controls re-run on the batch's own collector session; a qualification that cannot be unpaid runs as the batch's first slot, and its failure stops the batch |
| 7 | Budget | protocol `budget` + contract | proposed hold, per-slot amount, ledger context, cost estimate labelled as a CLI estimate and never a bill; exceeding a target is an explicit operator decision, never a default |
| 8 | Counting rules | protocol `counting_rule` | what counts as a sample; what never enters a denominator (injection attempts, qualification slots); one pair/quad per configuration; no pooling across batches |
| 9 | Result vocabulary | protocol `result_rules` | every terminal named before the run — including the *unverified* terminals, because missing evidence is never a passing result — and the recorded-outcome-versus-stop distinction stated |
| 10 | Stop rules and states | protocol `stop_rules` + `state_transitions` | every way the batch can die, written before it can die that way; unused slots stay visible |
| 11 | Intended claim shape | proposal document | the register entry drafted before measurement, with evidence, scope, observation level, exclusions and a *falsified-if* — the C11/C12 pattern, not a promise of a result |
| 12 | Interpretation limits | protocol `interpretation_limits` | what the record can never say, including the neutrality clause: the thing rated is a configuration, never a model, never a vendor, never a product |

## 3. Publication order

1. The protocol and proposal are frozen (their hashes enter the contract).
2. The disabled contract exists with `execution_authorized: false` and
   `model_requests: 0`; preparation creates no reservation.
3. Only an explicit, time-boxed operator approval admits a batch claim;
   the hold is created before controls, and a failed control does not
   silently release it.
4. Results — completed, stopped, failed or quarantined — stay public with
   their protocols. Stopped batches keep their intended claim shapes
   labelled as not measured.
5. The founder's own losses publish first. A lab that grades its own
   product publishes that product's failures before its wins, or it is
   not a lab.

## 4. Reader's audit

A reader verifying that a result was pre-registered checks, in order:
the published protocol hash predates the batch claim; the contract's
source pins cover the protocol and proposal as frozen; the claim in the
register matches the intended shape drafted before the run (drift is
visible, and additive rescoring never rewrites an original); the
denominators in any sentence match the frozen counting rules; and the
sentence's exclusions survive contact with the record. If any link is
missing, the result is unpublished work, not evidence.

## 5. Worked examples already in the repo

- `arena/experiments/twin-exposure-v1/protocol.json` plus the 27 October
  disabled proposal → measured 1 November as claim C10, one complete pair.
- The s1ngularity replay: protocol and intended claim shape written before
  its approved batch; the batch **stopped**, and C11 keeps the intended
  shape explicitly unmeasured — pre-registration surviving a failure.
- `arena/experiments/twin-exposure-vendor-v1/protocol.json` plus the
  7 November disabled proposal: the four-slot vendor lane with a paid
  qualification slot, a lane-configuration difference record, an
  unverified-outcome terminal, and a pre-registered claim shape whose two
  possible outcomes were both declared useful before any run.

## 6. Non-goals

This format does not introduce rates, rankings, leaderboards or pooled
numbers — the standing stop-list governs (no new injection variants, no
model rankings). It does not authorize anything: every family still needs
its own protocol, its own approval, and the single-use execution gate.
External protocols and signed bundles arriving from other runners are a
later, separate specification.
