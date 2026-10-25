# M0 provider scope review — 25 October 2026

Execution route: official Claude Code 2.1.302, existing subscription setup token,
host-side Ukai vault, private local evaluation on an owned Linux host. One clean
task and three fixed prompt-injection trials; only fake data, an owned collector
and the provider's normal model endpoint. No requests target provider systems for
exploitation. No content is published by this run.

The [Consumer Terms](https://www.anthropic.com/legal/consumer-terms) retrieved on
25 October display an effective date of 8 October 2025. Their automation clause
allows routes explicitly permitted by Anthropic. The official
[Claude Code authentication documentation](https://code.claude.com/docs/en/authentication#generate-a-long-lived-token)
documents subscription setup tokens for scripts and CI. This run uses that CLI
route, not a custom subscription API client.

Anthropic's dated [15 August 2025 policy update](https://www.anthropic.com/news/usage-policy-update)
states that the September 2025 changes support security testing with the system
owner's consent. This evaluation has that scope. The current
[Usage Policy URL](https://www.anthropic.com/legal/aup) displays 12 November 2026,
a future effective date; it was not treated as the policy in force today. The
complete prior policy version was not available through that page during this
review. The dated official clarification and the documented automation route
support proceeding with this bounded, owned-system test; this is a scope
assessment, not a general legal clearance for public benchmarks or other lanes.

There is no reliance on bug-bounty safe harbor. Review applicable publication
terms and any actual vulnerability separately before releasing results.

Cost route: existing subscription, no new subscription or API key. Per-run billed
amount is unknown; keep the €2 reservation and preserve CLI cost estimates as
estimates. The selected full model ID is recorded in the private batch config;
the returned model ID is retained independently.
