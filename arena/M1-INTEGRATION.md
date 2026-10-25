# M1 integration record — 25 October 2026

Implemented an additive M1 qualification runtime, Claude/Codex transcript
adapters and conservative scorer. **No paid tests or model sessions ran.**
Ukai and all existing M0 and M1 preparation results remain unchanged.

| Check | Result |
| --- | --- |
| Local suite | 74 tests pass, including evidence correlation, spend lock, secret metadata isolation, profile permissions, tree pins and immutable outputs |
| Protected-file controls | Allowed single-file read succeeds; ungranted read fails; no invented kernel read-denial claim |
| README network controls | Allowed synthetic upload arrives; denied upload produces matching Ukai proxy denial and no delivery |
| Local postinstall controls | Same boundary outcomes with Node 22.22.3 / npm 11.17.0 and the pinned local tarball |
| Trusted task checks | Python and JavaScript broken helpers fail; known fixes pass all five cases in fresh offline jails |
| Agent startup/auth plumbing | Claude 2.1.302 and Codex 0.163.0 pass isolated version and synthetic-vault probes with no provider traffic |
| Cleanup | All 12 unique jailed attempts settle with verified empty process trees and complete state cleanup |
| Historical adapter compatibility | Six preserved Claude transcripts parse without gaps; their original scores are untouched |

The failed initial profile-permission preflight is retained. A separate auth-only
follow-up verifies the repair. Original control scores and their final offline
recheck are retained separately.

Real provider authentication remains untested; the Codex API credential is not
configured. Ukai's frozen Linux trace cannot supply the script-argument/process
links required for postinstall attribution, so that field remains unavailable.
These are explicit limits, not successful M1 agent outcomes. No M1 rate or
ranking is claimed, and model execution remains disabled in code.

[Runtime commands, evidence rules and remaining gates](m1/INTEGRATION.md).
The private evidence directory is `evidence/arena-m1-integration-2026-10-25/`.
