# Ukai Jail 0.1.0 for Linux x86_64

GitHub published the stable release on 2026-11-18 from
`8a80ed085430049e7cc6e6212d776b23039aea7c`. It includes one x86_64 GNU/Linux archive. The
qualification covers Ubuntu 26.04.1 LTS, kernel 7.0.0-31-generic,
bubblewrap 0.11.1, reference cgroup delegation and ptrace observation.
ARM64 users can explicitly select the rc.8 preview. The Mac VM has a separate
release. [Signed release](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0) · [Merged audit and fixes](https://github.com/monocursive/ukai/pull/55).

| Signed item | SHA-256 |
| --- | --- |
| x86_64 archive | `22e623e82770dabb5dbf85367237cde3bf7e659f901bd65f8e2d618e7b3d484f` |
| Installed executable | `b8275e61786ca91c55c55f0fca31e9ec09628c8f372416b8f8e2c22da1cb5987` |
| Public bootstrap | `377807dcc39a3cb5426521e2132ff525d872c400a4ada850030a215912e2be83` |

The publisher verified the production Minisign signature and downloaded all
seven public assets anonymously. Both public installers installed the release
twice in their own empty home on the reference host. Each verified its
embedded archive hash, installed the expected binary and release record, passed
`doctor --profile tool` and ran a contained `/usr/bin/true`. The receipts
confirmed an empty process tree and complete cleanup.

| Public installer | Receipt SHA-256 |
| --- | --- |
| GitHub release bootstrap | `0657bdee9e24d340064433419bc1ec656b1de0115bb2a2e6a5196c2943e877d6` |
| ukai.sh installer | `133e8f9cde583c030003f0a27627faf8995181275c846624dd0ee2faad38d226` |

The website-installed binary also ran the file-copy workloads under `tool` and
`agent`, and compiled and executed a C program under `build`. All three
produced the expected output, recorded enforced containment, and settled with
verified empty trees and complete cleanup. The website rollout updated
8 assets on the existing production site.

Strict conformance reported 3,075 tests passed, zero failed and 18 ignored.
The exact release commit passed [rust](https://github.com/monocursive/ukai/actions/runs/44385556768), [contracts](https://github.com/monocursive/ukai/actions/runs/44385556800), [fleet](https://github.com/monocursive/ukai/actions/runs/44385556715), [conformance](https://github.com/monocursive/ukai/actions/runs/44385556696), [release-candidate](https://github.com/monocursive/ukai/actions/runs/44396820732).
The runtime build-input digest is `sha256:81a2a1b453dd2c0427800235bc7148e5cd84f23d642319a726ffb543931e3def`. The [scoped Linux audit](../../security-audit-2026-11-18-linux.md) records the matching vendor workflows and performance measurements.
