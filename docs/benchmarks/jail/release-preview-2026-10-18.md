# Ukai Jail 0.1.0-rc.3 publication — 18 October 2026

[Ukai Jail 0.1.0-rc.3](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.3)
is the first Linux developer preview under the Ukai name. It installs
`ukai-jail` and adds the one-word agent launch (`ukai-jail claude …`), the
`credential set` and `credential rm` verbs, and the end-of-run summary.
It was published as a prerelease, not marked latest, following
[the release procedure](../../RELEASING.md).

## The release commit

| Fact | Value |
| --- | --- |
| Tag | `ukai-jail-v0.1.0-rc.3` (annotated) |
| Commit | `f95f2d3963bc8829ab08f8b320d43abbb9f220f8`, the freeze commit |
| Build inputs | `sha256:32e294a36c9d1dffd23ed2e9afc3ec8a87148e2b8cda26538d22737feffbaf89` |
| Toolchain | Rust 1.98.1, optimized, clean, frozen |

Exact-commit CI on `f95f2d396`, all successful: rust (39139968915),
contracts (39139969019), fleet (39139968884), reference-host conformance
(39139968881) and the release-candidate build (39139991150).

The freeze was recorded with `cargo xtask freeze --doctor` from reference-host
conformance run `20261018T144614Z-57439ebdbb23` (Actions run 39137393623), the
first full PASS after J12/J13 landed. `freeze --check` passes:
inputs_match_tree, revision_is_ancestor_of_head, inputs_match_revision,
frozen_inputs_unchanged_since_revision.

Two repairs were needed before conformance could pass:

- **K11/K27 clean-VM evidence.** OpenCode's free tier now refuses its own CLI,
  the pinned 1.18.32 included, so the evidence was refreshed with a vaulted
  Anthropic key: [release-preview-2026-10-18-rc3](results/release-preview-2026-10-18-rc3/README.md)
  (onboarding 66.6 s; the key appears in none of the 81 recorded files). The
  first attempt is kept as [its failed predecessor](results/release-preview-2026-10-18-rc3-doctor-home-failed/README.md).
- **K47.** The conformance driver never copied the three recorded attempts this
  J13 test replays, so it had failed in every hosted run since J13, hidden next
  to K11/K27. The driver now copies them (`57439ebdb`).

The reference host also needed space: the driver refuses to build with less
than 4 GiB free, so the inactive build caches of earlier kept conformance runs
were removed, keeping their logs and evidence.

## The signed candidate

Assembled locally from the workflow's two native stages with the production
release key (`release.pub`, created 10 October 2026). Both stages name the same
revision and inputs. `publish_release.py check` verified all eight assets and
the signature.

| Archive | SHA-256 |
| --- | --- |
| `ukai-jail-0.1.0-rc.3-x86_64-unknown-linux-gnu.tar.gz` | `9798ead7866a98456406456b2d9b13d7e881f265d24eb2b9674e4b602144029a` |
| `ukai-jail-0.1.0-rc.3-aarch64-unknown-linux-gnu.tar.gz` | `4b154f6b5f7b6d6d603c046813379d781c990705fe96ece446afe34587086a47` |

## Native installation

On each native host, the SHA-256-pinned `bootstrap.sh` installed into an
isolated directory, with its own config and data directories and with a
`minisign` shim that always fails first on `PATH`. The guide's first command
then ran. This was done twice: from the signed candidate, and from the draft's
assets after they were downloaded and found byte-identical to the candidate.

| | Reference VPS | Raspberry Pi |
| --- | --- | --- |
| Host | Ubuntu 26.04.1, Linux 7.0.0-31, x86_64 | Debian 13, Linux 6.18.50+rpt-rpi-v8, aarch64 |
| Bootstrap | installed 0.1.0-rc.3, exit 0 | installed 0.1.0-rc.3, exit 0 |
| Installed binary SHA-256 | `cbd87e7a2431676c639f4cfd36b3d1a0c1ec70cbb25b698b7956f6802246e953` | `ed82bd3a04c66118d0f0c75bb00422c79c9f0d58e573d19ed8e82c890630d798` |
| `doctor --profile tool` | ready; unavailable: `gpu_passthrough`, `nested_user_namespace` | ready; unavailable: `agent_inner_sandbox`, `apparmor_userns_restriction`, `cgroup_memory`, `cgroup_swap`, `gpu_passthrough` |
| First command | `hello from the jail`; settled, exit 0, tree empty, integrity verified | same |
| `tail --summary` | settled, survivors none (verified), 1 path opened for writing, network none | same |

## Publication

`publish_release.py draft` rechecked the gates (tested freeze, exact-commit
CI, live reference conformance, the remote tag), created the draft with
exactly eight assets and verified every downloaded asset.
`publish_release.py publish` rechecked the gates and draft bytes, published at
2026-10-18T16:09:36Z as a prerelease not marked latest, then downloaded all
eight public assets without authentication and verified their digests.

## Rollout

- The root `install.sh` is the reviewed `bootstrap.sh` byte for byte. Against
  the rc.2 installer it changes only the default version and adds the two
  rc.3 pins; the rc.1, rc.2 and macOS VM pins are retained.
- `crates/ukai-jail/dist/release.json` names version `0.1.0-rc.3` and
  published tag `ukai-jail-v0.1.0-rc.3`.
- The README, guide, roadmap and release procedure link the rc.3 release and
  show the `ukai-jail` commands. An `ouro-jail` from an earlier preview is left
  in place beside `ukai-jail`. The macOS VM preview keeps its `ouro-vm` command,
  and the website's home page says so to Mac visitors.

## Website and public installation

The website was deployed with `npm run deploy` (Cloudflare Pages project `ukai`)
from the rollout commit. `https://ukai.sh/install.sh` and
`https://ukai.sh/release.pub` were then fetched and are byte-identical to the
repository's `install.sh` (default `0.1.0-rc.3`) and `release.pub`; the home
page links the rc.3 release and shows Mac visitors the `ouro-vm` note.

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
| Public install | `Installed release 0.1.0-rc.3`, exit 0 | same |
| Build | `f95f2d396`, clean, inputs `sha256:32e294a3…` | same |
| Binary SHA-256 | `cbd87e7a…`, as in the candidate tests | `ed82bd3a…`, as in the candidate tests |
| `doctor --profile tool` | ready | ready |
| First command | `hello from the jail`; settled, exit 0, survivors none (verified) | same |

The temporary homes were removed. The Apple Silicon installer path was not
exercised on a Mac for this release: its pinned VM preview is unchanged, and
`test_bootstrap.py` covers its selection.
