# J18 live workspace share — containment probe and first live runs — 2026-11-02

**Development evidence only. No release gate is promoted; K109 stays
`untested` in the acceptance map until its full live row runs on a
qualified backend.** The entitlement-free VM tier is the macOS release
path while Apple's ES request (S9YJTLLH28) is pending; this measurement
builds its hardest piece: the live workspace share (jail-macos §6).

## Errata (2026-11-03, fix wave 1103)

Added after review; the raw files are unchanged, and the text below is kept
as written.

1. **The preflight's normalization probe could not fail.**
   `run.py::share_preflight` wrote its two probe files under the same name,
   both spelled with a precomposed `é`, so the second write always replaced
   the first and the probe reported `normalization_fold: true` on every
   volume. run-3's attempt record (`normalization_fold: true`, §2) is that
   constant, not a measurement. The containment probe's collision in §1 (a
   host NFD name, a guest NFC write) is a separate measurement and is not
   affected. The probe now writes distinct NFD and NFC names (`bfcf1f9d4`).
   Re-measured on 2026-11-03 with distinct names: the default APFS volume
   folds both case and normalization, and a case-sensitive APFS volume
   folds normalization only; no measurement file is retained for that
   re-measurement. So the recorded `true` matches what the corrected probe
   reports on a case-sensitive volume, and the disclosure below stands.

## 1. The containment probe

A minimal VZ transport ([probe/vzshare.swift](probe/vzshare.swift)) boots
the Ubuntu 26.04 cloud image with exactly one writable virtio-fs share and
runs an escape battery via cloud-init
([probe/battery.sh](probe/battery.sh), ownership follow-up in
[probe/battery3.sh](probe/battery3.sh)); the host side prepares sentinels —
a symlink and a hardlink that both point outside the share, a protected
`.git`, an NFD unicode name — and verifies what changed
([probe/verdict.json](probe/verdict.json)). Host: macOS 27.0.1 arm64;
guest kernel: Ubuntu 26.04 minimal.

| Route | Measured result |
| --- | --- |
| Symlink read/write, host-planted (target outside) | **Refused** — links resolve client-side in the guest VFS |
| Symlink write, guest-planted relative climb (`../../…`) | **Refused** — same mechanism |
| Write through a pre-existing hardlink to a file outside | **ESCAPED** — the outside sentinel changed |
| Guest write `.GIT/config` (host `.git` exists) | **ESCAPED** on a case-folding volume — landed in `.git/config` |
| NFC write onto an NFD host name | **Collided** (measured even on case-sensitive APFS) — disclosure, see below |
| Guest `..` traversal / rename climb | Stays in the guest VFS |
| `mknod` | Refused by the server |
| `mkfifo`, `user.*` and `com.apple.*` xattrs | Pass through to the host files (host-user-equivalent) |
| Modes | Map faithfully (guest 0755 = host 0755) |
| Non-root guest user writes | Succeed — the server authorizes every guest uid as the host user; **guest-side DAC is advisory inside the share** |
| `mount -o uid=,gid=` remap | Not supported by virtio-fs (measured refusal) |

Consequences, now encoded in the launcher's preflight
(`run.py::share_preflight`) and the guest controller:

- Symlinks anywhere in a live workspace: refused before boot (safe by
  construction, but the preview refuses them uniformly).
- Any regular file with `st_nlink > 1`: refused — the measured
  write-through escape. Directories' own link counts don't count.
- A case-folding volume: refused with the remedy (a case-sensitive volume;
  the K109 workspace below lives on one). Case folding bypasses every
  guest-side policy denial.
- Unicode normalization folding: **disclosed, not refused** — it only
  collides names that differ in decomposition, the protected segments are
  pure ASCII, so no denial can be bypassed; a future policy naming a
  decomposable protected path must refuse on it. Recorded in the attempt
  record as `normalization_fold: true`.
- The design consequence the spec records: inside the share, the guest
  jail's policy is the only write gate — which is §6's design.

## 2. The live runs (three, retained in [k109-runs/](k109-runs/))

All through `run.py --live-workspace --profile …`, real jailed workloads,
guest receipts verified by digest.

- **run-1** (`build`): completed with all denials, but the granted writes
  never reached the host — the guest controller's `run_command` had bound
  its workspace default at definition time, so the jail ran against the
  staged tmpfs while the share sat mounted. The bug (and its fix —
  call-time path resolution) is part of this evidence.
- **run-2** (`build`, fixed controller): granted writes still did not
  reach the host by policy — and exposed the real finding: the build
  profile's disposable-copy grant (`--rw` workspace, **no protected
  segments**) let the jailed workload write the operator's real
  `.git/config` through the share. The live share is not a disposable
  copy: both ends now refuse `build` with a live share
  (`live_share_requires_protected_profile`).
- **run-3** (`tool`, the supported shape): **the K109 row's claim, live.**
  Granted writes appear on the host (`from-guest.txt` created,
  `keep.txt` appended, `newdir/inner.txt` nested); `.git/config` denied
  and byte-identical afterwards; a write outside every grant denied;
  attempt `completed`, guest receipt verified, and the attempt record
  carries the share facts (`{case_fold: false, normalization_fold: true,
  symlinks: 0, multi_link_files: 0}`).

## What remains for J18

The warm service (`ukai-vm serve`) integration with the share, K108's
warm-reuse timing (second attempt within 1 s of guest release, 20 runs),
the run-mode NAT and credential plumbing, K110's fault matrix rerun, and
the release-image productization (prepare.py is not a pinned builder).
The guest-side `build`-profile guard ships with the next image build; the
host-side guard is active now and is what run-3 exercised.
