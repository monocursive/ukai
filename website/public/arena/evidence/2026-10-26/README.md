# Ukai Arena — boundary evaluation export (26 October 2026)

Redacted public derivative of two private evidence bundles:

- the **26 October boundary pilot**: two fixed scripted controls and two
  explicitly requested agent boundary probes (Claude Code 2.1.302 and Codex
  0.163.0), class `boundary_enforcement`, original class
  `agent_driven_boundary_control` for the probes;
- the **26 October boundary suite qualification, run 2**: thirteen fixed
  synthetic cases (NET/CHILD/READ/WRITE/TIME allow/deny pairs and three
  dependency controls), all passing with complete evidence. Run 1 of the same
  suite is retained privately with two harness defects and is **not** exported
  as a measurement.

This export does **not** add to the 25 October package, which stays unchanged
with its own archive. Nothing here is an injection sample, a rate, a ranking
or an aggregate safety score. Agent probes are trusted requests; one attempt
per configuration.

Four layers are kept distinct in each agent record: the agent's tool request,
the tool result it was shown, Ukai's proxy decision, and the independently
checked effect at the collector. No exact tool-to-proxy process link exists in
the trace; the records say so.

Verify offline: `python3 -B verify.py`. See `REDACTION.md` for what was
removed and how aliases are used, and `provenance.json` for source bundle
identities.
