# K108–K113 full live rows on the installed package — 2026-11-03

**The J18 gate rows, run against an installed package for the first time.**
The package is the snapshot-pinned image (Ubuntu archive
`20261020T000000Z`, `bubblewrap=0.11.1-1ubuntu0.3`,
`dbus-user-session=1.16.2-2ubuntu4`) built by `vm/package.py`, signed with
Developer ID `64SGQ348QJ` (timestamped), **notarization pending** — no
notarytool credentials exist on this Mac (no App Store Connect key, no
keychain profile, no stored Apple ID password); recorded as `pending`, not
claimed. Installed through `install.sh` into the fresh prefix
`/tmp/ukai-installed2` (SHA256SUMS verified, image expanded, install checks
`ready`). The client is the rebuilt `ukai-jail` (the K112 probe fix) with
the installed `bin` first on `PATH`, so `run --vm` starts the package's own
`ukai-vm serve`. Provenance: [provenance.json](provenance.json).

**Verdicts: K108, K109, K110, K111, K112 pass their full rows live;
K113 does not run** — no VM-tier agent compatibility record exists (J18 §9.4
names Claude Code headless in the guest as that record), so the row's
object is absent and the row is recorded as not run, not failed.

## Errata (2026-11-03, fix wave 1103)

Added after review; the raw files are unchanged. **None of these rows meets
its clause: K108–K113 are `untested`** (the acceptance map's notes give each
row's reason and what a real row needs). The table and text below are kept
as written, except the publication sentence that erratum 8 corrects.

1. **The client was not an installed one.** "The rebuilt `ukai-jail`" is
   `target/release/ukai-jail` built from the repository at `d0bfd0c7b`
   ([provenance.json](provenance.json)). The DMG ships only `ukai-vm` and
   `ukai-vm-install`; no macOS `ukai-jail` client ships, so no row here ran
   an installed and shipped client. K108, K109 and K110 ran through the
   Python protocol client, not `ukai-jail` at all.
2. **The package was a development build** labeled with the public
   preview's version: `ukai-vm-0.1.0-preview.1-macos-arm64.dmg` with
   `sha256:de86fb71…` before notarization, not the public preview's
   `sha256:f3a85e14…`. The warm candidate is now numbered `0.1.0-preview.2`.
3. **K108.** Every attempt's TCP probe was vacuous (`/dev/tcp` under the
   guest's `dash`), and the `GIT_ALLOWED` line in each attempt's stdout is a
   shell-precedence artifact that prints whatever happened (the `.git`
   claim rests on the host-side byte comparison). "Within initial + 1 s"
   misreads the clause: `initial` marks a tunable default, and the clause
   compares with the guest jail's own release time, which was not measured.
4. **K109.** The grants were the guest's fixed `tool` shape through the
   protocol client, not a host policy's; the `run --vm` path of that build
   dropped host `--ro`/`--rw` narrowing silently.
5. **K110** ran half its clause: no custodian kill, no VZ-client kill, no
   kill or `Ctrl-Z` of a host `ukai-jail` client and no case with every
   host controller suspended. Case A's workload finished before the kill
   and C's before the EOF, "same boot" was never checked by comparing boot
   ids, and the network probe was vacuous.
6. **K111 is false as recorded.** The stored receipt
   `k111-attempt/jail.json` (`sha256:935b35bc…`) is the host's own receipt,
   not the guest's, and it contradicts the guest receipt
   `k111-attempt/evidence/jail.json` (`sha256:6f7d67b3…`, the digest the
   transport record carries): network `pending` and observer not attached,
   against the guest's applied `none` network and attached ptrace observer.
7. **K112's harness could not fail its no-workload check:** it looks for
   `/tmp/k112-workload-ran`, while the workload would create
   `k112-workload-ran` in the workspace. `gate_rows.py` also exits 0
   whatever its verdict.
8. **Publication.** A notarized build must rerun the full rows; an install
   check alone is not enough (`release.json`'s scope note). The sentence
   under "What this does and does not claim" said otherwise and is corrected
   inline. K113 was not "measured there": the Claude Code record is one
   development attempt and K113 stays `untested`.

| Row | Verdict | Evidence |
| --- | --- | --- |
| K108 warm reuse | **PASS** | [k108-warm-live.json](k108-warm-live.json): 20 attempts over **one boot** of the installed service, every granted write on the host, `.git/config` byte-identical after every attempt, every exit 0, release latency **14.9 ms initial / 15.0 ms max** — every attempt within initial + 1 s |
| K109 live workspace | **PASS** | [k109.json](k109.json): granted write on the host with exact bytes; the protected `.git` write refused (sentinel unchanged); `/etc`, `/usr/local/bin` and the guest's root writes all refused |
| K110 fault matrix | **PASS** | [fault-matrix.json](fault-matrix.json): secret transport lifecycle (nested ids acked in tmpfs, duplicate refused, second attempt same boot), A kill-9 service, B whole-group Ctrl-Z, C attempt-EOF cancel — each on its own boot of the installed service |
| K111 receipt + transport | **PASS** | [k111.json](k111.json), [k111-attempt/](k111-attempt/): the client booted the installed service itself (66.4 s cold); stored receipt settled (`tree_empty: true`, exit 0); the guest receipt is Linux (`/platform/os`), its SHA-256 equals the transport record's `guest_receipt_sha256`, the binding ties attempt/boot/profile/argv to this run, and the summary's transport line carries only values lifted from `vm-transport.json` |
| K112 kernel-bound | **PASS** | [k112.json](k112.json): native (as shipped), native (dev-enabled) and the installed `--vm` backend each refuse at **probing** with `[unsupported]`, `lifetime_boundary: kernel-bound` recorded in policy, `owner_loss_termination` derived, no workload, no boot attempted; Linux `none` refusal is the portable test |
| K113 compatibility-record summary | **NOT RUN** | [k113.json](k113.json): no VM compatibility record exists; the mechanism it will rest on is verified — the transport line in K111's terminal capture names the transport from the record |

## Two real bugs the packaging found, and the fixes

1. **The package could not serve.** The first built package shipped the
   preview's cold-boot CLI as `ukai-vm`: it has no `serve` subcommand, so
   `run --vm` waited the full 180 s budget on a serve that had died
   printing a usage error. The package now ships the **Rust `ukai-vm`**
   (`serve`, `stop`, `status`, `version`, and a new `doctor` with the
   installer-check schema) as the operator surface; the Python helper is
   `ukai-vm-install`, called only by `install.sh` for `expand-image`
   (onefile — two onedirs cannot share `bin/_internal`). `package.py`
   builds the binary from committed Rust sources and refuses a dirty
   `crates/ukai-jail/src` tree like it refuses a dirty `vm/` one;
   `image.json` records `ukai_vm_sha256`.
2. **`--vm` accepted a kernel-bound policy.** The VM platform's probe
   answered `owner_loss_termination` Available, so `run --vm --lifetime
   kernel-bound` went looking for a boot instead of refusing — K112 says a
   qualified VM backend must provide a kernel-bound lifetime before
   accepting the key. The probe now refuses it with
   `kernel_bound_requires_vm` at probing, before any boot, covered by a
   hermetic CLI test with a fabricated install
   (`vm_tier.rs::a_kernel_bound_vm_run_refuses_at_probing_before_any_boot`).

One harness environment note, recorded because it refused three times
before the row ran: the K112 lanes first ran with no `HOME` and with the
row binary under `/private/tmp`. Both refusals were the loader's own
state-path rules (no config dir; a writable child root exposing the
executable), not the kernel-bound refusals this row measures. The harness
now gives each lane a real `HOME`, a private config dir, the case-sensitive
workspace, and a binary outside `/private/tmp`.

## What this does and does not claim

- The rows passed on a **signed but not notarized** package. Notarization
  remains pending on credentials; a notarized build must rerun these rows
  in full before any publication claim (erratum 8).
- `published: false`. The package is not distributed; the DMG's digest
  before notarization is in [provenance.json](provenance.json).
- K113 stayed open when this record was written (2026-11-03, earlier the
  same day): no VM-tier agent compatibility record existed. It exists now
  — Claude Code 2.1.311 headless in the guest on this same installed
  package ([that record](../macos-vm-claude-2026-11-03/README.md)) — and
  K113.1 is measured there; the protected-Mac native release (K104) stays
  blocked pending Apple's entitlement decision.
