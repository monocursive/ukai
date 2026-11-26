# Evidence of the 0.1.1 release, 26 November 2026

Summaries behind [the public installation record](../../release-0.1.1-linux.md), for
`ukai-jail-v0.1.1` from `d3c380d2f5074bce5f8f3f25eb11d60d96fd8b2a`. Each file is a
summary a check wrote on the host it ran on; none holds a credential.

| File | What it records |
| --- | --- |
| `conformance.json` | The exact-bytes conformance run of each target: counts, gate statuses, the executable's hash, the build and the host |
| `release-commit-ci.json` | The release commit's workflows, the native stages and the release-candidate run at the tag |
| `install-<target>-draft.json` | An installation from the downloaded draft assets, with Minisign and SHA256SUMS verified on the host |
| `install-<target>-github.json` | An installation from the public bootstrap of the GitHub release |
| `install-<target>-site.json` | An installation from `https://ukai.sh/install.sh` |
| `profiles-<target>-github.json` | The `tool`, `build` and `agent` workflows with the binary the GitHub bootstrap installed |
| `profiles-<target>-site.json` | The same with the binary the website installer installed |
| `website-rollout.json` | The production deployment the rollout created, and the archives' hashes |
| `action-release.json` | The self-test's K86 rows for `ukai-jail-action-v0.1.1`, and how long each job's Set up step took |
