# Ukai Jail 0.1.0-rc.4 publication — 21 October 2026

[Ukai Jail 0.1.0-rc.4](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.4)
adds interactive sessions (J14,
[jail-interactive-sessions.md](../../specs/jail-interactive-sessions.md)): a
run started from a terminal attaches it, `^C` and `^Z` reach the command, and
a launch profile can keep the agent's state per repository between runs. It
was published as a prerelease, not marked latest, following
[the release procedure](../../RELEASING.md).

## The release commit

| Fact | Value |
| --- | --- |
| Tag | `ukai-jail-v0.1.0-rc.4` (annotated) |
| Commit | `eb9b67b1853827624b75e6a1cd3aa76352f7f3ee`, the freeze commit |
| Build inputs | `sha256:893f85686e76cffeeb87f57c33ba27fe16685524d73676ec7b72c937e7c20d03` |
| Toolchain | Rust 1.98.1, optimized, clean, frozen |

Exact-commit CI on `eb9b67b18`, all successful: rust (39591417223, attempt 2;
attempt 1 was cancelled while the release-candidate workflow ran), contracts
(39591417216), fleet (39591417195), reference-host conformance (39591417187)
and the release-candidate build (39591435666).

The freeze was recorded with `cargo xtask freeze --doctor` from reference-host
conformance run `20261021T104601Z-f2387913d426` (Actions run 39586800374): the
first full PASS since J14 landed, 2874 tests passed, 0 failed, every gate
passing, with K11 and K27 on the clean-VM evidence for these inputs. Its
commit, `f2387913d`, differs from the freeze commit only in documents. `freeze
--check` passes: inputs_match_tree, revision_is_ancestor_of_head,
inputs_match_revision, frozen_inputs_unchanged_since_revision.

## What happened before conformance could pass

- **J14 was reviewed again after it merged.** Three independent reviews found
  a refusal after the persistent state was acquired that dropped its lease
  with the holder still recorded (a dead end for `gc`, which an agent could
  trigger), a jailed process that could take the terminal's foreground from
  the operator's shell after a relayed stop, and further terminal and state
  defects. All were fixed with tests that failed before and passed after
  (spec §8 items 17 to 29). The terminal fix stacks one more seccomp filter,
  pinned like the others, which answers `TIOCSPGRP` with `EPERM` inside the
  jail in terminal mode.
- **The bundled `claude` profile allows `platform.claude.com`** (spec §8
  item 30, the operator's decision): an interactive first launch of Claude
  Code 2.1.302 checks it during onboarding and exits when it is unreachable.
- **Two TLS advisories** published after rc.3 failed cargo-deny:
  RUSTSEC-2026-0382 (rustls-webpki, 0.103.15 to 0.103.16) and
  RUSTSEC-2026-0381 (webpki-roots, 1.0.9 to 1.0.10), both in what verifies
  the vault proxy's upstream certificates (`e598d06f7`).
- **The reference host's release build outgrew its bound.** The last passing
  build before J14 took 18 m 51 s of the driver's 20 minutes; J14's tests
  pushed it past. The driver now allows 30 minutes, inside a 75-minute job
  budget (`cccf5db30`; `xtask` is not a build input).
- **K11/K27 clean-VM evidence** was refreshed for these inputs:
  [release-preview-2026-10-21-rc4](results/release-preview-2026-10-21-rc4/README.md)
  (onboarding 67.4 s; the vaulted Anthropic key appears in none of the 81
  recorded files). The run made before the advisory fix is kept as
  [its superseded predecessor](results/release-preview-2026-10-21-rc4-before-advisories/README.md).

Every check in the procedure also ran locally on the tree before it was
pushed: macOS 1788 tests passed with 0 failed; the full Linux suite on the
reference host, run as conformance runs it, passed except K11/K27 before
their evidence existed; clippy, cargo-deny, I02, every contract validator and
the website build passed.

## Interactive Claude Code

The [interactive compatibility record](claude-code-interactive-2026-10-21.md)
(§6.3 of the J14 proposal) ran Claude Code 2.1.302 from the native installer,
with a setup token through the vault, over SSH on the reference host: 31 of
31 attempts met every condition, the run-4 hangup's terminal restore being the
stated exception, and a confirmation pass on the build with these inputs
(`cccf5db30`, binary `40621f6d…`) gave the same results. The setup token was
in none of the recorded files. It is the combination
[agent-compatibility.md](../../specs/jail-v1/agent-compatibility.md) marks
supported; `doctor` still reports every launch profile `experimental`.

## The signed candidate

Assembled locally from the workflow's two native stages with the production
release key (`release.pub`, created 10 October 2026). Both stages name the same
revision and inputs. `publish_release.py check` verified all eight assets and
the signature.

| Archive | SHA-256 |
| --- | --- |
| `ukai-jail-0.1.0-rc.4-x86_64-unknown-linux-gnu.tar.gz` | `c5ddd09e91e584e2f7ad98454f0fe38572dd3db75905e26b197b788e2e46b269` |
| `ukai-jail-0.1.0-rc.4-aarch64-unknown-linux-gnu.tar.gz` | `305d79aa1b826ad4d7aed209720c257df4cf6002e734bcbde3bd593487a9601d` |

## Native installation

On each native host, the SHA-256-pinned `bootstrap.sh` installed into an
isolated directory, with its own config and data directories and with a
`minisign` shim that always fails first on `PATH`. The guide's first command
then ran. This was done twice: from the signed candidate, and from the draft's
assets after they were downloaded and found byte-identical to the candidate.

| | Reference VPS | Raspberry Pi |
| --- | --- | --- |
| Host | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64 | Debian 13, Linux 6.18.50+rpt-rpi-v8, aarch64 |
| Bootstrap | installed 0.1.0-rc.4, exit 0 | installed 0.1.0-rc.4, exit 0 |
| Installed binary SHA-256 | `031e0ac5a42012fa45d1d9ca3212698e5dce5c43c80ef5790019c735f07803d6` | `0a9c88ff2e3e5e52a64e3144a38f9e32e5573f5667275dc3f2a7693851780623` |
| `doctor --profile tool` | ready; unavailable: `gpu_passthrough`, `nested_user_namespace` | ready; unavailable: `agent_inner_sandbox`, `apparmor_userns_restriction`, `cgroup_memory`, `cgroup_swap`, `gpu_passthrough` |
| First command | `hello from the jail`; settled, exit 0, tree empty, integrity verified | same |
| `tail --summary` | settled, survivors none (verified), 1 path opened for writing, network none | same |

## Publication

`publish_release.py draft` rechecked the gates (tested freeze, exact-commit
CI, live reference conformance, the remote tag), created the draft with
exactly eight assets and verified every downloaded asset.
`publish_release.py publish` rechecked the gates and draft bytes, published at
2026-10-21T11:59:46Z as a prerelease not marked latest, then downloaded all
eight public assets without authentication and verified their digests.

## Rollout

- The root `install.sh` is the reviewed `bootstrap.sh` byte for byte. Against
  the rc.3 installer it changes only the default version and adds the two
  rc.4 pins; the rc.1 to rc.3 and macOS VM pins are retained.
- `crates/ukai-jail/dist/release.json` names version `0.1.0-rc.4` and
  published tag `ukai-jail-v0.1.0-rc.4`.
- The README, guide, roadmap and release procedure link the rc.4 release; the
  README, guide and operating.md name the recorded interactive combination.

## Website and public installation

The website was deployed with `npm run deploy` (Cloudflare Pages project `ukai`)
from the rollout tree. `https://ukai.sh/install.sh` and
`https://ukai.sh/release.pub` were then fetched and are byte-identical to the
repository's `install.sh` (default `0.1.0-rc.4`) and `release.pub`; the home
page links the rc.4 release. This deploy also published the home page's
`#refusal` section (the 18 October launch demo, merged on 19 October), after
its claims were checked against its record and its quote corrected to the
recorded terminal (`400e70b79`).

On both native hosts, a new empty `HOME` (under `env -i`) ran the public command
exactly as published, then the guide's first command:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://ukai.sh/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
ukai-jail version --json
ukai-jail doctor --profile tool --json
```

| | Reference VPS (x86_64) | Raspberry Pi (aarch64) |
| --- | --- | --- |
| Public install | `Installed release 0.1.0-rc.4`, exit 0 | same |
| Build | `eb9b67b18`, clean, inputs `sha256:893f8568…` | same |
| Binary SHA-256 | `031e0ac5…`, as in the candidate tests | `0a9c88ff…`, as in the candidate tests |
| `doctor --profile tool` | ready | ready |
| First command | `hello from the jail`; settled, exit 0, survivors none (verified) | same |

The temporary homes were removed. The Apple Silicon installer path was not
exercised on a Mac for this release: its pinned VM preview is unchanged, and
`test_bootstrap.py` covers its selection.

## Open after this release

- `ukai-jail run --gate-fd 3 3<&-` (a gate descriptor the caller closed)
  aborts instead of refusing cleanly: the jail's own files can take the
  descriptor number before the channels are checked. Pre-existing; found by
  the J14 terminal fixes' harness.
- On the hosted macOS runner, `portable_proxy`'s
  `n04_header_overflow_refuses_at_the_32_kib_budget` timed out once (a 20 s
  read waiting for the proxy to close after its refusal) on `447d711d6`; it
  passed on the release commit and 25 times in a row locally.
