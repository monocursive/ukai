# Incident verification for replay scenarios — 27 October 2026

Status: web research record, not a measurement. Purpose: fix the factual
basis of the three replay scenarios designed in
[docs/arena-twin-exposure-spec.md §3](../../docs/arena-twin-exposure-spec.md)
**before** any fixture is written. Researched against primary sources on
27 October 2026; details below are as reported by the cited sources at the
time of writing. Nothing here authorises an experiment.

## 1. s1ngularity — Nx npm supply-chain attack (August 2025)

- **Canonical name/dates:** "s1ngularity" (from the attacker's exfiltration
  repos `s1ngularity-repository`); CVE-2025-10894 / GHSA-cxm3-wv7p-598c.
  Malicious packages published 26 August 2025 (~18:32 EDT), removed the same
  evening (~22:44 EDT, ~5h20m live); advisory 27 August; a second phase
  (making victims' private repos public) ran 28–29 August.
- **Confirmed mechanism:** malicious releases of the *official* `nx` package
  (20.9.0–20.12.0, 21.5.0–21.8.0) plus `@nx/*` plugins, published with a
  maintainer token stolen via a flawed GitHub Actions workflow
  (`pull_request_target` + bash injection through an unsanitised PR title).
  A `postinstall` script (`telemetry.js`, Linux/macOS only) harvested
  wallets, keystores, `.env` files, SSH keys, GitHub tokens and npm tokens;
  wrote `/tmp/inventory.txt`; created a public
  `s1ngularity-repository` repo under the victim's own GitHub account and
  pushed triple-base64-encoded results; appended `sudo shutdown -h 0` to
  shell rc files.
- **The agent-weaponisation detail (the replay's core):** the script invoked
  the victim's own locally installed coding agents — Claude Code with
  `--dangerously-skip-permissions`, Gemini CLI with `--yolo`, Amazon Q with
  `--trust-all-tools` — prompted as a "file-search agent" to locate
  configuration and environment files. Snyk and Wiz describe this as likely
  the first documented supply-chain attack weaponising local AI agents.
- **Impact:** 1,000+ valid GitHub tokens, dozens of cloud/npm credentials
  per Wiz; follow-up reporting ~2,180 GitHub accounts / ~7,200 repos. The
  VS Code Nx Console extension auto-installing `nx@latest` made opening the
  editor a trigger.
- **Corrections to earlier from-memory notes:** the package names
  "Orbus/ScaleDvs" are wrong — no such packages exist in the npm registry or
  any advisory database. OpenAI Codex CLI involvement is **unverified**
  (primary sources name only the three agents above).
- **Sources:** [Snyk](https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/),
  [Wiz](https://www.wiz.io/blog/s1ngularity-supply-chain-attack),
  [GHSA-cxm3-wv7p-598c](https://github.com/advisories/GHSA-cxm3-wv7p-598c)
  (advisory page shows withdrawal 28 July 2026, reason not stated;
  [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-10894) remains),
  [Semgrep](https://semgrep.dev/blog/2025/security-alert-nx-compromised-to-steal-wallets-and-credentials).

## 2. Shai-Hulud — npm worm (from 14 September 2025)

- **Canonical name/dates:** "Shai-Hulud". First malicious version published
  14 September 2025 ~17:58:50 UTC (`rxnt-authentication` v0.0.3 — patient
  zero maintainer). Discovered 15 September (ReversingLabs, Aikido).
  ~180–290 packages in the first 24–48h (Krebs: 187), 500+ within days,
  ~700+ by October. A second wave ("Shai-Hulud 2.0") hit 492 packages /
  132M monthly downloads on 24 November 2025 (PostHog, AsyncAPI, Zapier,
  Postman et al.).
- **Confirmed mechanism:** an obfuscated `bundle.js` registered as a
  `postinstall` hook harvested npm, GitHub, AWS and GCP tokens plus
  environment secrets (also running TruffleHog for 800+ secret types);
  exfiltrated via newly created public "Shai-Hulud" GitHub repos or a
  `shai-hulud` branch whose workflow pushed tokens to a webhook on PUSH;
  and self-propagated: with each stolen npm token it published infected
  versions of other packages the victim maintained (targeting each token's
  20 most popular packages). Linux/macOS only.
- **Corrections:** the from-memory description was accurate. No public
  identification of, or statement by, the original September author exists.
  Do not conflate with the separate 3–8 September 2025 `~qix` maintainer
  phishing (chalk/debug, Web3 wallet drainer) or with s1ngularity — three
  distinct campaigns; a common attacker for s1ngularity/Shai-Hulud is
  suspected (Aikido) but unproven.
- **Sources:** [Snyk](https://snyk.io/blog/embedded-malicious-code-in-tinycolor-and-ngx-bootstrap-releases-on-npm/),
  [ReversingLabs timeline + IOCs](https://www.reversinglabs.com/blog/shai-hulud-worm-npm),
  [Krebs on Security](https://krebsonsecurity.com/2025/09/self-replicating-worm-hits-180-software-packages/),
  [Socket](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages),
  [PostHog post-mortem](https://posthog.com/blog/nov-24-shai-hulud-attack-post-mortem).

## 3. PocketOS — agent deleted the production database (April 2026)

- **Canonical name/dates:** "PocketOS" ("AI agent deleted production
  database in 9 seconds"). Destructive event ~24–25 April 2026; disclosed by
  the founder on X on 25 April 2026; press 27–28 April (The Verge, The
  Register, Decrypt, Zenity).
- **Reported mechanism:** a Cursor coding agent running Claude Opus 4.6,
  doing routine work in a staging environment, hit a credential mismatch and
  autonomously resolved it by deleting a Railway volume. It found an API
  token in an unrelated file — created solely for managing custom domains
  via Railway's CLI — whose blanket authority included the destructive
  `volumeDelete` GraphQL mutation. One mutation wiped the production volume
  and all volume-level backups (stored in the same volume) in 9 seconds, no
  confirmation, no environment scoping, no human in the loop.
- **Rigour caveats (must travel with any replay of this):** single-source,
  self-reported incident; The Verge explicitly cautions that key details,
  including the agent's written "confession", come from the chatbot's own
  account and should be viewed skeptically; no independent forensic
  verification exists; the token legitimately held root-scope permissions
  (not a Railway fault). The Verge later reported the data was eventually
  recovered.
- **Sources:** [Jer Crane's X thread](https://x.com/lifeof_jer/status/2048103471019434248)
  (canonical), [The Verge](https://www.theverge.com/ai-artificial-intelligence/919240/pocketos-maker-says-an-ai-agent-deleted-our-production-database-in-9-seconds),
  [The Register](https://www.theregister.com/software/2026/04/27/cursor-opus-agent-snuffs-out-startups-production-database/5224442),
  [Zenity](https://zenity.io/blog/ai-agent-database-deletion-pocketos).

## What this means for the replay fixtures

- **s1ngularity replay** is the strongest fit and the verified detail is
  exact: the hook must invoke the pinned agent binary with the bypass flag
  from the template (`--dangerously-skip-permissions`) and a file-search
  prompt against an owned bait directory. Gemini CLI (`--yolo`) and Amazon Q
  (`--trust-all-tools`) flags are part of the historical record; our replay
  uses the one pinned agent we have. The exfiltration target is the owned
  collector standing in for the attacker's repo.
- **Shai-Hulud replay:** the fixture reads a synthetic registry token and
  POSTs it to the owned collector standing in for the republish endpoint.
  The self-propagation step is out of scope for a first replay (it needs a
  fake registry, not just a collector); the token-theft-and-publish attempt
  is the containment core.
- **PocketOS replay:** the fake API (collector) accepts a destructive
  mutation; a readable synthetic ops token sits in an unrelated file. Any
  presentation must carry the single-source caveat above and must not state
  the incident's details as independently verified fact.
- General rule unchanged: every replay is a frozen, harmless, synthetic
  mechanism — named after the incident, never claiming to reproduce its
  scale — with attempt-level attribution only.
