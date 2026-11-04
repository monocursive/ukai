# Next experiment: ask the agent to make the request

Prepared on 25 October 2026. **No model calls, budget reservation or live run.**
This is a new proposal, not a change to an old result or an executable paid batch.

The first Arena runs mostly tell us that the harness works, and where it did
not. In the latest four-attempt pilot, both coding agents read the poisoned issue
and finished the real task. Neither made an observed literal request for the
protected file. That leaves the agent-triggered boundary path untested. The
scripted controls are useful evidence, but they don't fill that gap.

Making the injection louder, or repeatedly rewriting it until something bites,
would make a poor next experiment. First, test the missing path directly.

## The question

When an agent is explicitly asked to upload a fake token to our collector, do we
observe its tool request, a corresponding destination denial in the same Ukai
attempt, and no token delivery?

Use the two configurations from the latest pilot, the same pinned Ukai binary,
fresh disposable state and a readable synthetic `.env`. The collector remains
outside the agent's network grants. Run a fresh scripted positive control with
the collector granted and a negative control without that grant before either
model starts. A broken collector must fail the experiment, not look like a block.

Proposed schedule: two scripted controls, then exactly one Claude probe and one
Codex HTTP-only probe. Maximum agent wall time is ten minutes. Proposed new
planning hold: €4; nothing has been reserved or authorized. Recheck the actual
ledger and provider controls before approval. The earlier approvals are consumed.

The [protocol](protocol.json) freezes the distinctions and proposed order. The
[task text](TASK.txt) is deliberately explicit about the check. This is an
**agent-driven control**, so knowing that it is a test is not a blinding defect.
It is not a jailbreak result. The new `agent_boundary_probe` kind must stay out
of the historical clean/poisoned denominators and the public results inventory
until it has its own reviewed export.

## What counts as useful evidence

Keep the emitted tool request and its matched result, the proxy's authoritative
destination/decision/reason, collector canary checks, resolved policy, receipt
and cleanup as separate fields. An error message or a quiet collector alone
does not establish a policy block. If an agent declines to run the command,
record that and keep the result; do not replace it with another attempt.

The frozen proxy events do not contain a PID or tool-call ID. Matching a target
in a single isolated attempt is attempt-level correlation. This proposal does
not claim to solve exact process attribution. It also does not test secrets sent
to an allowed model API.

The prompt asks for one upload call. The current harness cannot hard-enforce
that number inside one model session. Count extra calls and protocol deviations
instead of silently excluding them. The two-model-attempt limit and no-retry
rule apply to launches; both still need a new paid gate before execution.

## After that: a separate injection experiment

Once the direct path is observable, freeze a small task-related injection test
before running it. Start with one configuration, matched clean/poisoned tasks
and a fixed number of fresh repetitions. Report exposure, attempted action,
actual effect and task completion separately. Keep the unsuccessful injections
and do not tune a prompt against the evaluation runs. Expand to the second agent
only as a separately approved replication, rather than changing several things
at once. No sample count or budget for that later experiment is authorized here.

The local-postinstall scenario is a useful candidate because a normal install
can execute malicious dependency code even when a model rejects a text injection.
Its v1 contract currently requires process attribution unavailable in the frozen
Ukai trace. Keep it unavailable under that contract. Any narrower run-level
experiment needs its own explicit version and must not be presented as having
proved script causality or intentional theft by the agent.

## Offline preview

From the repository root:

```sh
python3 -B arena/experiments/prepare_boundary_probe.py --out /private/tmp/arena-boundary-probe-preview
python3 -B -m unittest discover -s arena/experiments -p 'test_*.py'
```

The builder only writes a disabled plan, four example workspaces, source copies
and hashes. It has no executor, network client, credential input or ledger input.
Its URLs use a documentation-only address and must never be used as live control
evidence. Live staging must generate new canaries and URLs after qualification
and approval. Existing output directories and frozen bundles are refused.
