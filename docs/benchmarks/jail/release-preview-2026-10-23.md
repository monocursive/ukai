# Ukai Jail 0.1.0-rc.5 publication — 23 October 2026

[Ukai Jail 0.1.0-rc.5](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.5)
carries the fixes of the 22–23 October review for Linux:
- vault receipts claim only the binding they have;
- `gc` never reports a kill it did not make, and handles abandoned and
  never-started attempts honestly;
- the proxy keeps the attribution of requests it refuses after
  authentication;
- adopted operator channels are close-on-exec;
- `lifetime_boundary` works in policy files.

The same review's macOS work (J16–J18,
[jail-macos.md](../../specs/jail-macos.md)) is in the tree, but this Linux
preview does not ship it:
- native macOS execution is off by default and development-gated;
- J17 observation is off;
- every `--vm` run refuses;
- the release scope lists those clauses as unsupported.

It was published as a prerelease, not marked latest, following
[the release procedure](../../RELEASING.md).

## The release commit

| Fact | Value |
| --- | --- |
| Tag | `ukai-jail-v0.1.0-rc.5` (annotated) |
| Commit | `0fe655440db7fd0012257cbbbc7d7a790cd7eca1`, the freeze commit |
| Build inputs | `sha256:188328556e73ff58f3e8e47e54604f4bfa2a3fdb7cd9a3bc18bf53b9a379e140` |
| Toolchain | Rust 1.98.1, optimized, clean, frozen |

Exact-commit CI on `0fe655440` succeeded for every workflow:
- rust (39939889678);
- contracts (39939889630);
- fleet (39939889569);
- reference-host conformance (39939889758, attempt 2);
- the release-candidate build (39944314657, and 39948941308 for the tag push).

Conformance attempt 1 failed one test,
`j14_terminal_linux::k63_the_targets_bytes_reach_the_terminal_unchanged_and_in_order`.
Its read stopped after the terminal reset and before the `ukai-jail: settled`
line arrived. The test is unchanged since rc.4 and passed in the four other
conformance runs that day, so the job was re-run. Making the test wait for the
settled line is a follow-up.

The freeze was recorded with `cargo xtask freeze --doctor` from reference-host
conformance run `20261023T095544Z-4703d64c86dd` (Actions run 39935240597):
- the first full PASS since rc.4: 2995 tests passed, 0 failed, every gate
  passing;
- K11 and K27 used the clean-VM evidence for these inputs;
- its commit, `4703d64c8`, differs from the freeze commit only in the freeze
  file;
- `freeze --check` passes: inputs_match_tree, revision_is_ancestor_of_head,
  inputs_match_revision, frozen_inputs_unchanged_since_revision.

## What happened before conformance could pass

- **The review and its fixes.** On 22 October, six independent reviews of the
  uncommitted J16–J18 work found defects in Linux-reachable code and in every
  macOS slice. Three fix rounds followed, and the original reviewers then
  re-verified their findings. The Linux-visible changes:
  - vault receipts omit `binding` on Linux, keeping the rc.4 shape;
  - `gc` treats a kill that finds no target as a failed signal;
  - `gc --abandon` is macOS-only;
  - authenticated proxy refusals stay attributed, and the rest are counted
    as a `proxy_unattributable` gap;
  - adopted `--control-fd`, `--trace-fd` and `--gate-fd` are close-on-exec;
  - profiles, operator config and project config accept `lifetime_boundary`.
- **CI on the merge found what local gates had not run:**
  - the ES shim needed the macOS 27 SDK, so the build failed on the `macos-15`
    runner. `build.rs` now probes the SDK, and without these APIs the build
    reports `es_sdk_absent`;
  - a vendor-name hit (`std::io::Cursor`);
  - a release-scope test that expected only K rows;
  - four tests that had only run on macOS;
  - a spawn symbol (`posix_spawn_file_actions_addchdir`) that macOS 15 does not
    export.

  Each was fixed. The four Linux test fixes were run on the reference host
  before they were pushed.
- **K11/K27 clean-VM evidence** was refreshed for these inputs:
  [release-preview-2026-10-23-rc5](results/release-preview-2026-10-23-rc5/README.md).
  Onboarding took 62.9 s, and the vaulted Anthropic key appears in none of the
  81 recorded files.

Before the push, the macOS lane of the `rust` workflow also ran locally as CI
runs it: with an older SDK, in conformance mode, and the `gates
--linux-release` verdict. cargo-deny, I02, the contract validators and the
link check passed too.

## The signed candidate

Assembled locally from the workflow's two native stages with the production
release key (`release.pub`, created 10 October 2026). Both stages name the same
revision and inputs. `publish_release.py check` verified all eight assets and
the signature.

| Archive | SHA-256 |
| --- | --- |
| `ukai-jail-0.1.0-rc.5-x86_64-unknown-linux-gnu.tar.gz` | `33f397057c4d8996a01d60d382852223ac328075f2facd084b51a2068b5ce03e` |
| `ukai-jail-0.1.0-rc.5-aarch64-unknown-linux-gnu.tar.gz` | `2af9d2ef48ec12c4072822b6b6dca3cb867ee8fb0054c9e142d4e86a0221a752` |

## Native installation

On each native host:
- the SHA-256-pinned `bootstrap.sh` installed from the signed candidate into
  an isolated directory;
- the config and data directories were the installation's own, mode 0700;
- a `minisign` shim that always fails came first on `PATH`;
- the guide's first command then ran.

The draft's assets were then downloaded and found byte-identical to that
candidate.

| | Reference VPS | Raspberry Pi |
| --- | --- | --- |
| Host | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64 | Debian 13, Linux 6.18.50+rpt-rpi-v8, aarch64 |
| Bootstrap | installed 0.1.0-rc.5, exit 0 | installed 0.1.0-rc.5, exit 0 |
| Installed binary SHA-256 | `632e2cfc5c66d7bdfd3394dfe2795fe6b4f4b7d00c05c484bb3df4bb5cc3c585` | `31784fc530c537dc845e3d8c91403bbacd8f35a388fcdeb8d7c7e2751fd69dc5` |
| `doctor --profile tool` | ready; unavailable: `gpu_passthrough`, `nested_user_namespace` | ready; unavailable: `agent_inner_sandbox`, `apparmor_userns_restriction`, `cgroup_memory`, `cgroup_swap`, `gpu_passthrough` |
| First command | `hello from the jail`; settled, exited, tree empty, integrity verified | same |

## Publication

- `publish_release.py draft` rechecked the gates (tested freeze, exact-commit
  CI, live reference conformance, the remote tag), created the draft with
  exactly eight assets and verified every downloaded asset.
- After the operator reviewed the draft, `publish_release.py publish`
  rechecked the gates and the draft bytes.
- It published at 2026-10-23T12:02:48Z as a prerelease not marked latest.
- It then downloaded all eight public assets without authentication and
  verified their digests.

## Rollout

- The root `install.sh` is the reviewed `bootstrap.sh` byte for byte. Against
  the rc.4 installer it changes only the default version and adds the two
  rc.5 pins; the earlier pins are retained.
- `crates/ukai-jail/dist/release.json` names version `0.1.0-rc.5` and
  published tag `ukai-jail-v0.1.0-rc.5`.
- The README, guide, roadmap and release procedure link the rc.5 release. The
  interactive Claude Code record keeps naming rc.4, the build it ran on.

## Website and public installation

The website was deployed with `npm run deploy` (Cloudflare Pages project `ukai`)
from the rollout tree (`73dd18932`). `https://ukai.sh/install.sh` and
`https://ukai.sh/release.pub` were then fetched and are byte-identical to the
repository's `install.sh` (default `0.1.0-rc.5`) and `release.pub`.

On the reference VPS and the Raspberry Pi, `curl … https://ukai.sh/install.sh |
bash` in a fresh `HOME` installed rc.5 (revision `0fe655440`, the inputs above),
`doctor --profile tool` reported ready, and the guide's first command printed
`hello from the jail` and settled.
