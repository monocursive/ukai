# Installed Mac VM operations, 18 November 2026

The private Developer ID signed preview at `03456ef9236b6577735d8d9752bd8297caa311db` passed all four operational phases on the primary Apple Silicon Mac running macOS 27.0.1. The installed host binaries and guest image came from the previously measured native-v8 package. The final lifecycle check verified both the workspace detach and the installed file and helper pins. [Package identity](candidate.json), [cleanup](fault-final-lifecycle.json).

| Check | Observed outcome |
| --- | --- |
| Filesystem enforcement, receipt binding, unsupported policy | K109, K111 and K112 passed. [Gate results](gates-acceptance.json) |
| Credential source deletion | All 21 checks passed using a synthetic credential and the local plaintext witness. [Revocation results](source-watch-acceptance.json) |
| Warm reuse | Twenty service attempts and twenty installed-client attempts met their 1,000 ms budget. The maximum service connection-to-release time was 94.4 ms. The maximum client launch-to-first-write time was 342.2 ms. [Attempt review](warm-acceptance.json), [timing record](candidate.json) |
| Fault handling | All eleven lanes passed across nine groups, including both client suspension variants that failed on the earlier package. Offline replay recomputed 118 facts. Each individual group covers a subset of the matrix. The aggregate covers every required lane. [Fault replay](fault-replay.json) |

The operational run used synthetic credentials and made no provider calls. Its scope excludes Claude credential-exposure sampling and the K113 vendor workflow. The package still requires notarization, stapling and installed acceptance on the distributed bytes. Native macOS Endpoint Security is a separate backend. This run leaves its support status open.

The local evidence is under `evidence/production-2026-11-15/warm-vm-current/` in `guest-native-operational-admitted-03456ef92` and `guest-native-operational-control-admitted-03456ef92`. These directories contain the original per-attempt measurements, group outcomes and cleanup records. The [earlier qualification ledger](../../production-qualification-2026-11-15.md) identifies the image, source archive and installation used.
