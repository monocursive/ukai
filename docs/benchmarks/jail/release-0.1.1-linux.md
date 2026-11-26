# Ukai Jail 0.1.1 for Linux x86_64 and ARM64

GitHub published the stable release on 26 November 2026 from
`d3c380d2f5074bce5f8f3f25eb11d60d96fd8b2a`. It includes one GNU/Linux archive for each
target. The qualification covers Ubuntu 26.04.1 LTS with bubblewrap 0.11.1, reference
cgroup delegation and ptrace observation: on x86_64 with kernel 7.0.0-31-generic, and on
ARM64 with kernel 7.0.0-43-generic, measured in an HVF virtual machine on Apple Silicon.
The Mac VM has a separate release. [Signed release](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.1) · [ARM64 qualification](arm64-stable-qualification-2026-11-23.md) · [Rollout](https://github.com/monocursive/ukai/pull/60).

| Signed item | SHA-256 |
| --- | --- |
| x86_64 archive | `9bbf4b6e33b18f51bd2f85a30b4084ef1a38e8fe5237dbe5d10e1bba7d2bc72c` |
| aarch64 archive | `97d47720204fa89178fb7e8e1d9acde63d9668a43c2e131abb27ae6eb2364763` |
| x86_64 executable | `822370b6115f7ad9a4ce5f2814db3ba11caa08ddd6ea5ffe45c19077a0a029ef` |
| aarch64 executable | `e68781714a0019482ecfe2215915cfd66e85320b63b4dc7fa1b0aa8a2cc1684e` |
| Public bootstrap | `a080cf70524f2f3238acbd9cb6c6c9894f1df2c5812ef75c33eff93e2ee7b924` |

The publisher verified the production Minisign signature and downloaded all eight
public assets anonymously. The release-candidate workflow built both archives twice, on
the commit and again at its tag ([45805675986](https://github.com/monocursive/ukai/actions/runs/45805675986),
[45817041270](https://github.com/monocursive/ukai/actions/runs/45817041270)), and the
archives were byte for byte alike. The exact commit passed
[rust](https://github.com/monocursive/ukai/actions/runs/45805516352),
[contracts](https://github.com/monocursive/ukai/actions/runs/45805516661),
[fleet](https://github.com/monocursive/ukai/actions/runs/45805516582) and
[conformance](https://github.com/monocursive/ukai/actions/runs/45805516523).

## Conformance of the bytes that ship

Strict conformance ran on each host with the executable extracted from that host's
staged archive substituted for the one the driver builds (`--jail-binary`), so the
recorded hashes and `doctor --json` describe the bytes that ship. Each run passed 3,086
tests in 117 test binaries, with zero failed and 18 ignored: x86_64 in
`20261126T113356Z-d3c380d2f507`, aarch64 in `20261126T112311Z-d3c380d2f507`. In the
Linux lane of each run, 65 gates pass, 7 pass with limits, 2 pass with a part the
release scope does not support, 21 are unsupported by that scope, 1 needs live
credentials and 14 lie in other lanes; none failed. The
[tested freeze](../../specs/jail-v1/milestone-1-freeze.toml) records both runs.

The first ARM64 run of those bytes was refused, as it should have been: a later
`cargo test` had relinked its own artifact over the substituted executable. The driver
now replaces that artifact too, and the run was repeated.

K17 passed with limits in both runs. On ARM64 its margin is narrow, and it fails under
host load: the [26 November record](arm64-k17-2026-11-26.md) passed five replays in a
row on the executable of the 23 November run, with a narrowest margin of 1.57 points.

## Public installs

| Host | Installer | Receipt SHA-256 |
| --- | --- | --- |
| x86_64 | draft assets, Minisign and SHA256SUMS verified on the host | `d41b59b95aad37f112eaff2e08f7daa5a6545b445ad2350fc08c68ecbe86bb2a` |
| x86_64 | GitHub release bootstrap | `ef2f358246ff1d87cec6302403dd66ace414752fa08424f71477ca3c7c93b71b` |
| x86_64 | ukai.sh installer | `b9e0b2bd1dc7bcd808b658a5c4d2b8f36c076fe003b4377be5b852bd4c68d5df` |
| aarch64 | draft assets, Minisign and SHA256SUMS verified on the host | `397e09263c533722f934477e4cd311977216c5a86cc6475e5387e235fb2e593b` |
| aarch64 | GitHub release bootstrap | `b09036f0a54b5a3b523323404348441285c0562cfb953b7b7750d59671fa7c56` |
| aarch64 | ukai.sh installer | `0514feb0313b27e7b33aadafa9f417c7e5d8ca4600402369dedeeb11a6243d92` |

Each installed the release twice in its own empty home, with Minisign absent. Each
downloaded bootstrap was byte for byte the signed one. Each install verified the
archive's embedded hash, installed the expected executable and release record, passed
`doctor --profile tool` and ran a contained `/usr/bin/true` whose receipt showed an
empty process tree and complete cleanup.

With the binary each public installer put in place, GitHub's and the website's, the
`tool` and `agent` profiles ran a file-copy workload and `build` compiled and ran a C
program on each host: twelve runs, all with enforced containment, a verified empty tree,
complete cleanup and no gaps. [Evidence](results/linux-release-0.1.1-2026-11-26/).

The website rollout updated 8 assets of the existing production site (deployment
`32aff42b`). The served pages and installer were compared byte for byte with the
prepared ones. The rollout also repaired two passages the 0.1.0 rollout had left
pointing at the rc.8 preview: the guide's offline-installation paragraph, and the
licence links of the guide and roadmap pages.

## The action's first tagged release

[`ukai-jail-action-v0.1.1`](https://github.com/monocursive/ukai/tree/ukai-jail-action-v0.1.1)
is one parentless commit, `5750cc6eb6a6cbe1816d626b134cf2b6dd6161b2`, on the `action`
branch, holding only `action/` and the signed installer of the rollout. The self-test's
`release-tag` job fetches the action at that tag on both images
([45828127982](https://github.com/monocursive/ukai/actions/runs/45828127982), row K86).
It installs exactly release 0.1.1 through the installer beside it, the build's revision,
inputs and executable are those the freeze file records, and the job's "Set up job"
took one second on each image for the 15 files of 74,972 bytes.

## Notes

- Three of the four action self-test runs at the release commit on 26 November failed,
  including the one the tag push triggered
  ([45817041287](https://github.com/monocursive/ukai/actions/runs/45817041287)). Each
  failed on GitHub's listing of a run's artifacts lagging its own "finalized" reply, so
  a download right after an upload missed it; the action's own steps succeeded in every
  such job. The rollout waits before those downloads, and its two runs passed every job.
- The published executable answers `ukai-jail version` with `0.1.0`, the workspace
  version, which has not moved since the first commit; every release since rc.1 reports
  that number. The release record the installer writes beside it names 0.1.1, and
  upgrades and downgrades are decided on that.
- The runtime build-input digest is `sha256:0da6ea53bcb2f25c2094adf95ddc5e13ace97c688222b881d17e8cbbd1404c92`.
  The [scoped Linux audit](../../security-audit-2026-11-18-linux.md) describes the
  evaluated x86_64 workloads and remaining platform limits.
