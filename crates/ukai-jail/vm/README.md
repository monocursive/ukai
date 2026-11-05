# macOS Linux VM preview

The [0.1.0-preview.1 release](https://github.com/monocursive/ukai/releases/tag/ouro-vm-v0.1.0-preview.1) runs
the published Linux ARM64 Jail in a disposable VM on an Apple Silicon Mac.
It does not execute macOS programs or change the native macOS backend's refusal.
The [11 October measurements](../../../docs/benchmarks/jail/macos-linux-vm-2026-10-11.md)
record the earlier prototype and its simultaneous-suspension failure. The current
custodian fixes that case; new package measurements are recorded separately.

Install with the [public Bash installer](https://ukai.sh/install.sh)
and follow the [Mac quickstart](../../../docs/guide.md#macos-vm-preview).
The released DMG is the exact signed, notarized, stapled package from the
[qualification record](../../../docs/benchmarks/jail/macos-vm-preview-package-2026-10-11.md).
Its embedded source and readme retain the pre-publication candidate wording;
current availability is recorded in the public release notes.

The released cold-boot preview (`run.py`) runs offline `tool` and `build`
commands. Each attempt gets two virtual CPUs, 2 GiB VM memory, a private 6 GiB
sparse disk, and the Linux jail's required 512 MiB memory, zero swap,
64-process and explicit wall-time limits. That preview has no VM network
adapter during an attempt, host directory sharing, credential forwarding,
interactive stdin or agent/provider integration; the warm service below is
a separate, unreleased design.
The `build` profile explicitly grants the disposable workspace copy read/write;
this grant is recorded in the Linux policy and receipt.

`prepare.py` downloads a dated Ubuntu 26.04 ARM64 image and the current public
Linux archive named by `jail.version` in `dist/release.json` (the published
`0.1.0-preview.1` DMG carries `0.1.0-rc.1`), checks embedded SHA-256 pins, and
prepares the guest.
The setup VM has NAT networking for Ubuntu package installation from an
immutable archive snapshot (`apt_snapshot` in `image.json`); the resolved
package versions and their digest are recorded in the image. It requires Python 3.11+,
Xcode command-line tools and `qemu-img` (only for image conversion). No host sudo,
SIP change, Endpoint Security permission or production signing key is used.
The helper is locally ad-hoc signed with Apple's ordinary virtualization
entitlement. The measured host is macOS 27.0.1; other versions are unqualified.

From the repository root:

```sh
python3 crates/ukai-jail/vm/prepare.py --out evidence/my-vm-image
mkdir -p /tmp/ukai-vm-workspace
printf 'hello\n' > /tmp/ukai-vm-workspace/input.txt
python3 crates/ukai-jail/vm/run.py \
  --image evidence/my-vm-image \
  --workspace /tmp/ukai-vm-workspace \
  --out evidence/my-vm-attempt \
  --profile tool --wall 30 -- \
  /bin/sh -c 'cat input.txt; printf "created in Linux\n" > output.txt'
```

Use new output directories for image preparation and every attempt. The image
directory is private trusted state: the launcher verifies its saved disk and
helper hashes before boot, and clones rather than boots the base disk.

The command is transported as a byte argv, never interpolated into a shell.
The example invokes a shell explicitly. Stdout/stderr are relayed; the command's
exit status is returned only after a verified Linux receipt and acknowledged VM
stop. Interruptions or incomplete evidence return 125. An interrupted run does
not invent a successful guest receipt.

Input transfer currently accepts regular files only: at most 5,000 files,
512 KiB per file and 32 MiB total. Symlinks, devices and FIFOs are refused.
`.git`, `target`, `node_modules`, `.venv`, `__pycache__` and `.DS_Store` are
excluded at every level. Empty directories are not preserved. The input
workspace is copied, never mounted or modified in place.

Results remain in `<out>/workspace/` for review and manual adoption. The
launcher never extracts guest tar paths or creates guest-provided symlinks.
`<out>/evidence/` holds the unmodified Linux receipt; `attempt.json` separately
records the Mac transport and VM termination. A transport record does not claim
native macOS enforcement. Normal runs discard the disposable disk. Abrupt
launcher death can leave a disk in its evidence directory; that is stored data,
not a resumed VM. Do not boot or reuse such disks.

## Lifetime design and checks

The Python launcher drives a sequenced heartbeat through the Swift VZ helper
and a virtio socket. The root-owned guest controller powers the entire guest
off after two seconds without a valid heartbeat. Before shutdown it writes
Linux `user.slice/cgroup.kill` and checks `cgroup.events` for an empty subtree.
The launcher also requires
timely acknowledgements and stops the VM if guest supervision fails. systemd
watches the guest controller independently. The child runs unprivileged inside
the existing Linux jail and cannot access the host control socket or controller.

The helper watches caller EOF and termination signals, and uses `VZVirtualMachine.stop`
for unconditional teardown. No VM state save, resume or restart path is exposed.
These mechanisms require fault measurements; merely booting a VM does not prove
owner-loss cleanup.

```sh
(cd crates/ukai-jail/vm && python3 -s -E -m unittest discover -p 'test_*.py')
python3 crates/ukai-jail/vm/check.py \
  --image evidence/my-vm-image --out evidence/my-vm-faults --repeat 3
```

The fault runner starts a live workload with six detached descendants. It
identifies the exact Apple VM service by its open attempt-disk descriptor, then
tests wall expiry, cancellation, launcher/helper death and stalls, simultaneous
launcher/helper death, and VM-service death and suspension/resumption. It
records the service's disappearance **before** emergency test cleanup.
That establishes loss of the tested VM's execution service; it is not a proof
against arbitrary kernel failures or every possible guest-resumption race.

The native C custodian owns the VZ client as an unreaped child and kills it
when the launcher's three-second lease expires. A pipe held only by the
custodian lets the VZ client detect custodian death. The launcher requires
custodian acknowledgements within 1.5 seconds and can terminate the exact VZ
client through `proc_signal_with_audittoken`, including after reparenting; PID
reuse cannot target a replacement process. The custodian uses continuous Mach
time, which includes host sleep. There is no automatic restart or VM resumption.

The fault matrix also checks custodian death/stall and suspension of each pair
of the three host controllers. Freezing all three simultaneously can still
retain VM resources until one resumes; the guest's independent lease kills the
workload. These are bounded empirical fault checks, not a universal kernel-owned
lifetime claim. Whole-host sleep/wake, kernel failure, arbitrary guest compromise
and nested execution in a macOS guest are not qualified. Native macOS acceptance
clauses and the public Linux release gates remain unchanged.

## Packaged preview

The DMG's operator surface is the **Rust `ukai-vm`** (`serve`, `stop`,
`status`, `version`, `doctor`) — the same binary `ukai-jail run --vm`
starts. `ukai-vm version` and `doctor` report `UKAI_VM_PACKAGE_VERSION` when
the build sets it (`package.py` sets it from `release.json`'s
`vm.candidate_version`), and `<crate version>-dev` otherwise.
`ukai-vm-install` is the installer's helper (the preview's
`expand-image`/`doctor`/`version` verbs); only `install.sh` calls it.
Consumers do not need Python, Swift, Rust or Homebrew. The signed DMG
contains an offline installer with a pinned SHA-256 manifest, the signed
VZ client/custodian, the compressed snapshot-pinned guest image, licenses
and this source. The installer uses a per-user version directory and never
needs sudo. The current `install.sh.in` copies the manifest and payload
first and checks the copy it installs: the manifest's own digest, no
non-regular payload entry, a payload file list equal to the manifest's, and
every listed digest, so an unlisted file refuses; a refused install removes
the directories it created. The manifest carries no modes, so the
installer sets them: directories 0755, files 0755 where the volume's file
is executable and 0644 otherwise; no world-writable, setuid, setgid or
sticky bit installs. Read [PREVIEW.txt](PREVIEW.txt) for installation, command
examples and limits. Apple Silicon / macOS 27+ is the package's minimum;
measured execution is on macOS 27.0.1. Intel Macs and native macOS
workloads are not included.

Build from a trusted prepared image whose seed hash and every source hash
recorded by `prepare.py` match the committed `vm/` tree. The current
`package.py` builds what one committed revision holds: it refuses when the
tree differs from HEAD anywhere under the jail's build inputs (the ones
`build_provenance.rs` names) or the archived source paths: a change staged
or not, an untracked or ignored file (Python bytecode excepted), an index
entry marked assume-unchanged or skip-worktree, or a file whose bytes are
not HEAD's blob. It checks again after the build. It builds `ukai-vm` with
`cargo build --release --locked` from the repository root into an explicit
`--target-dir` (a fresh one under `--out` by default), in a scrubbed
environment: only `HOME`, `PATH`, `USER`, `LOGNAME`, `TMPDIR`,
`RUSTUP_HOME`, `CARGO_HOME` and the three `UKAI_*` variables below reach
cargo, so a shell's `RUSTUP_TOOLCHAIN`, `RUSTFLAGS` or other `CARGO_*`
setting never does, and rustup takes the toolchain from
`rust-toolchain.toml`. Before building it records `rustc -vV` and
`cargo -V` in `package.json` and refuses unless both report that file's
exact release. It sets `UKAI_BUILD_REVISION` to HEAD,
`UKAI_BUILD_DIRTY=false` and `UKAI_VM_PACKAGE_VERSION` to the candidate
version, and refuses a binary whose `version` reports anything else. It
records the revision as
`source_revision` in `package.json` and `image.json`, and
`preview-source.tar.gz` holds the workspace at that revision: the Cargo
files, the toolchain pin, every crate and the build inputs outside
`crates/`, meant to be enough to rebuild `ukai-vm`, the VZ client, the
custodian and the installer helper. No rebuild from such an archive under
the pinned toolchain has been verified: the fix wave's one rebuild check
of an archive probably ran under rustc 1.96.0, not the pin. The
`0.1.0-preview.2` candidate built on 2026-11-03
and the published `0.1.0-preview.1` were built by the earlier script: no
`source_revision`, and a source archive of `crates/ukai-jail/vm` only. No
package has been built with the current script yet. A Developer ID
Application identity must be available in Keychain:

```sh
uv venv --python 3.13 evidence/vm-build-env
uv pip sync --python evidence/vm-build-env/bin/python --require-hashes \
  crates/ukai-jail/vm/requirements-build.txt
evidence/vm-build-env/bin/python crates/ukai-jail/vm/package.py \
  --image evidence/my-vm-image --out evidence/my-vm-package \
  --jail-archive evidence/my-vm-image/cache/jail.tar.gz \
  --identity 'Developer ID Application: YOUR ORGANIZATION (TEAMID)'
```

`package.py` signs all Mach-O runtime files with hardened runtime, and grants
only the VZ client `com.apple.security.virtualization`. Notarization is the
one step that needs the operator's Apple credentials, so it is its own
script — `notarize.py` submits and waits, staples, validates the staple,
runs `spctl --assess`, records every step's raw output, and only after all
checks pass writes the submission id into `package.json` (a rejected,
failed or timed-out submission keeps `notarization: pending` and exits
non-zero). It submits only the DMG bytes `package.json` recorded before
notarization, so a stapled or otherwise changed DMG is never resubmitted,
and refuses once `package.json` records a notarization. Each run writes its
own record exclusively (`notarization.json`, then `notarization.2.json`, …),
and `notarytool log` is fetched for every submission id Apple returned,
accepted or not. Credentials arrive only as arguments, and the value of
every credential flag is redacted from the recorded argv and output:

```sh
python3 crates/ukai-jail/vm/notarize.py --package evidence/my-vm-package \
  --key ~/private_keys/AuthKey_<ID>.p8 --key-id <ID> --issuer <ISSUER>
  # or: --profile <keychain-profile from `xcrun notarytool store-credentials`>
```

A package build alone does not establish notarization, installation or
execution proof — the 2026-11-03 build is recorded notarization-pending
(no notarytool credentials on the build host), its installer contract
passed all five check_install cases of that day's script against the
shipped DMG
([installer-check/](../../../docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/installer-check/summary.json)),
and its development gate measurements, which leave K108–K113 `untested`,
are in
[docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/](../../../docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md).
The current `check_install.py` (schema `ukai.vm.installer-check/2`) has a
sixth case, `payload-extra`, which plants an unlisted payload file and
requires a refusal with nothing installed. Its `install` case passes only
when the installed `ukai-vm version` reports exactly the version the
installer names, never a `-dev` build, the installed tree is exactly the
manifest's payload, and every installed mode is the normalized one
(`installed-modes-normalized`). `summary.json` binds the manifest and
installer
digests, and the DMG's with `--dmg`. It has not been run against a package
yet.

Run the warm harnesses against the installed package (the binary the
package ships, not a repository build). A harness deletes its workspace's
contents and writes `.git/config` there, so it accepts only a dedicated
directory marked while empty (`harness.py mark`), never one that is or
contains the home directory, the repository or the current directory, nor
one inside the repository. Every output directory must be new: a rerun
into an existing one refuses rather than overwrite a previous run's
evidence.

```sh
python3 crates/ukai-jail/vm/harness.py mark <empty directory on a case-sensitive volume>
UKAI_VM_BINARY=~/.local/bin/ukai-vm python3 crates/ukai-jail/vm/warm_live.py \
  --image ~/.local/share/ukai-vm/0.1.0-preview.2 \
  --workspace <marked directory> --attempts 20 --out evidence/vm-warm \
  [--budget-ms 1000] [--ukai-jail <client>]
UKAI_VM_BINARY=~/.local/bin/ukai-vm python3 crates/ukai-jail/vm/fault_matrix.py \
  ~/.local/share/ukai-vm/0.1.0-preview.2 <marked directory> evidence/vm-faults \
  [case,case,...] [--ukai-jail <client>]
```

What the current harnesses do (code tested on this host with the VM and
its clients faked). On 2026-11-04 `capabilities.py`, `warm_live.py`,
`fault_matrix.py` and `gate_rows.py` also ran against a booted guest on the
spare Mac
([morning record](../../../docs/benchmarks/jail/results/macos-vm-live-2026-11-04/README.md),
[evening record](../../../docs/benchmarks/jail/results/macos-vm-probes-2026-11-04/README.md));
each record's provenance names the harness revision it ran.
`claude_vm_row.py` has not run on the current client: K113 needs a Claude
Code credential in the guest.

- **The binaries under test** are named, never assumed: `warm_live.py`,
  `fault_matrix.py` and `capabilities.py` take `ukai-vm` from
  `UKAI_VM_BINARY` (`warm_live.py` also from `--ukai-vm`) and refuse without
  it; `gate_rows.py` and `claude_vm_row.py` take the installed root and the
  `ukai-jail` client as arguments. Every record names each binary with its
  SHA-256, and its machine-read fields hold repository-, `$TMPDIR`- or
  `~`-relative paths, never an absolute host path. `--ukai-jail <client>`
  adds the real `ukai-jail run --vm` to
  `warm_live.py` (timed from exec to its workload's first write on the
  host) and to `fault_matrix.py`'s client cases.
- **The egress probe** (decision D9) is a python3 socket connect to an IP
  literal (`1.1.1.1:443`) with a short timeout, after a positive control in
  the same attempt that must connect to a loopback listener and be
  accepted. Its verdict is one tagged JSON line the host parses; a missing
  line, a failed control, a connection or two lines is never a denial. No
  probe uses `/dev/tcp`. A denial counts only if all of these hold: the
  probe's connect failed with `ENETUNREACH`, the jail's own errno (a
  timeout, `ECONNREFUSED`, `EHOSTUNREACH` or any other errno is
  inconclusive); the guest NAT adapter was attached; and on the same guest
  boot a route control succeeded, through a receipt bound to its own
  attempt: an `agent` attempt allowed exactly `1.1.1.1:443` asks its proxy,
  outside the jail's network namespace, for a CONNECT tunnel there, and the
  proxy answered 200, which it does only after reaching the target.
  Otherwise the result is inconclusive, never a PASS: an empty namespace
  with no route at all gives the same errno. `warm_live.py` always attaches
  the NAT adapter (it has no `--guest-nat` flag), and `capabilities.py`
  and `proxy_measurement.py` also record whether `1.1.1.1:443` answers from
  the host. The live phase therefore needs outbound access to
  `1.1.1.1:443`.
- **Receipts are bound.** A receipt backs a verdict only when its digest
  verified and it is bound to that attempt: attempt id, argv digest (in the
  binding and in the receipt), profile, serve boot and guest boot. K111
  gates every summary fact, and its workload writes a nonce marker
  (`row-k111-<nonce>`) that must reach the host exactly.
- **Refusals are outcomes.** Every harness `run --vm` runs with
  `LANG=C.UTF-8` (no `TERM`, `TZ` or `LC_*`), `--terminal detach`, one
  whole-second wall in 1–300 and `/dev/null` as standard input (commit
  `36592d114`; K111 and K113 run the client under `script(1)`, which gives
  it a pty and relays nothing from `/dev/null`). A `vm:not-measured`,
  `vm:not-carried` or `vm:owner-loss-not-provided` answer is parsed from
  the client's output and recorded as `REFUSED`, never `PASS`, and so is
  the client's standard-input refusal: `warm_live.py`'s verdict is
  `REFUSED` when the real client refused and every warm gate held, and
  K112 is `REFUSED` when a lane was refused for its standard input. Since
`GUEST_MEASUREMENTS` has the ten rows below, a `tool` or `agent`
real-client case with an explicit 1–300 s wall passes probing (the cases
pass `--limit wall`); the evening record's 20 real
`warm_live.py` attempts ran with `/dev/null` as standard input and exited 0.
The client's standard-input refusal under these harnesses is covered by the
harness's own tests only; its live acceptance is pending.
- **`fault_matrix.py`** has nine cases, each on its own boot: `secrets`,
  `client-kill`, `client-ctrl-z`, `serve-kill`, `custodian-kill`,
  `vz-kill`, `all-suspended`, `eof` and `serve-group-stop` (a 5 s stop,
  past the custodian's three-second lease). The client cases use a Python
  stand-in unless `--ukai-jail` is given. Every case but `secrets` runs a
  heartbeat workload (a leader and descendants beating into the live
  share), "same boot" compares boot ids, and each case records its verdict
  before any cleanup (`checked_at` ≤ `cleanup_started_at`).
- **`capabilities.py`** measures each requirement alone, by its own
  attempt, and records it under `measurements[<requirement>]` (`verdict`,
  `measured_at`, the attempt id) for `limit:wall`, `limit:pids`, `limit:mem`, `filesystem_containment`,
`network_none`, `tree_termination`, `closed_set_observation`,
`syscall_filter`, `protected_coverage:existing_and_root` and
`network_proxy`, and under `not_measured` what a probe leaves out.
Those entries are what a `GUEST_MEASUREMENTS` row cites; the 2026-11-04
evening run's are the table's ten rows.
- **K108's limit.** `warm_live.py` judges each attempt's
  `connect_to_released` time against `--budget-ms` (default 1000, the
  clause's initial 1 s). That time spans the whole host path, the guest
  jail's own release included, so it is an upper bound on the overhead the
  clause limits, not the guest jail's own release time. The path is the
harness's Python client, and the record says so. With `--ukai-jail`, the
real client is timed separately, from its exec to its workload's first
write visible on the host, which ends before the attempt settles.
- **K113's limit.** `claude_vm_row.py` judges on `ukai-jail tail
  --summary` alone and lists under `not_measured` the J18 §9.4 Linux-row
  conditions it does not measure: the A01 fixture, ten repetitions, the
  no-source refusal, revocation, six active classes and the credential use
  count.

## Preview transport contract

`ukai.vm.image-build/1` records the immutable prepared raw disk, seed and signed
helpers by SHA-256. A fresh APFS clone is used per attempt. Host-to-helper JSON
lines contain `write` (base64 guest bytes) or `stop`. The helper emits `owner`
with its audit token, boot/connection events, base64 `data`, and stop/error events.
The guest protocol accepts sequential `ping`, regular-file `put`, one `run`, and
`cancel`; it returns `ready`, exact-sequence `pong`, `put`, `running`, stdout/stderr,
regular `file` messages and `done`. No second run or general privileged command
is accepted. Limits and validation are enforced independently at both ends.

`ukai.vm.attempt/1` is a Mac orchestration record. Its guest receipt remains
`ukai.jail.receipt/1` with Linux platform and original enforcement evidence.
`ukai.vm.install-check/1` is only package/host prerequisite validation. These
records must not be substituted for each other or presented as native Mac proof.

Apple references: [Virtualization](https://developer.apple.com/documentation/virtualization),
[virtualization entitlement](https://developer.apple.com/documentation/virtualization/adding-the-virtualization-entitlement-to-your-project),
[unconditional stop](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop(completionhandler:)).

## J18: the warm service (development; no row passes)

`ukai-jail run --vm` is wired to the warm `ukai-vm serve`, but **no macOS
`ukai-jail` client ships**: the DMG carries only `ukai-vm` and
`ukai-vm-install`, so the client is built from source. A `run --vm`
refuses at probing, before any connection or boot, with exit 125, while
any requirement of its plan lacks a measured guest record. The probe
answers Available only for a requirement a measured guest record backs:
one table in the VM platform, `GUEST_MEASUREMENTS`, names the requirement,
the record and that record's own time, which becomes `measured_at`. Its
ten rows come from the
[2026-11-04 evening live phase](../../../docs/benchmarks/jail/results/macos-vm-probes-2026-11-04/README.md):
`limit:wall`, `limit:pids`, `limit:mem`, `filesystem_containment`,
`network_none`, `tree_termination`, `closed_set_observation`,
`syscall_filter`, `protected_coverage:existing_and_root` and
`network_proxy`, each measured by its own attempts in `capabilities.py` on
one warm boot of an image built from the guest sources at `6bd497076`
(development evidence: a source build on one M2 Pro host, not an installed
package, one run of each probe). This tree's `guest.py` has since added
only the staged export's refusal of directory links and unlistable
directories, which no probe exercised. A `tool` or `agent` plan with an explicit
wall of 1–300 s requires only those, so it passes probing; the profiles' own
walls (30 m, 2 h) are `vm:not-carried:limits.wall`. Every other requirement
answers `vm:not-measured:<requirement>`: `execution_boundary` (a required
`pids=64`, `mem=512MiB` or `swap=0`, the only values the guest carries, adds
it; another value or a required `cpu` ceiling is `vm:not-carried`) and
`credential_staging` (a launch profile that declares credentials) have no row.
The morning record of the same day
([record](../../../docs/benchmarks/jail/results/macos-vm-live-2026-11-04/README.md))
measured the first five on an image built from older guest sources and backs
no row now. No 2026-11-02 record states a time or measured its requirement
alone, and the TCP half of `network_none` was vacuous (`/dev/tcp` under the
guest's `dash`). `owner_loss_termination` always answers
`vm:owner-loss-not-provided`.

K108–K113 are `untested`. The 2026-11-02/03 measurements on the dev Mac
([installed-package rows](../../../docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md),
[Claude Code guest record](../../../docs/benchmarks/jail/results/macos-vm-claude-2026-11-03/README.md),
[2026-11-02 record](../../../docs/benchmarks/jail/results/macos-vm-warm-2026-11-02/README.md))
are development evidence: 20 attempts over one boot at 14.9–15.0 ms
host-observed release latency, live-workspace writes on the host with
`.git` untouched, four fault-matrix sections, one guest receipt verified by
digest, the kernel-bound refusal, and one Claude Code headless attempt. They
do not meet their clauses: the network probes were vacuous, K110 ran half
its matrix, K111's stored receipt contradicted the guest receipt, K113 is
one attempt against J18 §9.4's Linux-row conditions, and the rows ran a
client built from the repository. The acceptance map's notes say what each
real row needs. The package is Developer-ID-signed and snapshot-pinned
(`apt_snapshot` in `image.json`) but **not notarized** and not published.
The `macos-vm-development` publication scope in `dist/release.json` lists
K108.1–K113.1 as unsupported, and no capability is claimed beyond that.

The specified live workspace share exists as a measured development
capability (2026-11-02): `run.py --live-workspace --profile tool` attaches
one writable virtio-fs share of exactly the workspace, the guest controller
mounts it as the attempt workspace, and jailed writes appear on the host
with `.git` and every out-of-grant write denied. Its containment review —
symlinks safe client-side; pre-existing hardlinks and case folding refused
by the host preflight; guest-side DAC advisory inside the share — is
measured in
[docs/benchmarks/jail/results/macos-vm-share-2026-11-02/](../../../docs/benchmarks/jail/results/macos-vm-share-2026-11-02/README.md)
and specified in jail-macos §6. The `build` profile refuses a live share:
its disposable-copy grant has no protected segments. Since the 2026-11-03
fix wave the preflight also refuses a nested mount (an entry on another
device than the workspace) and any FIFO, socket or device node, none of
them measured through the share, and runs its folding probes in a fresh
private directory. The 2026-11-02 normalization probe wrote one precomposed
name twice and reported a fold on every volume; with distinct NFD and NFC
names the default APFS volume folds both case and normalization, and
case-sensitive APFS folds normalization only (re-measured 2026-11-03), so
normalization folding stays a recorded disclosure, not a refusal.

What `--vm` carries is fixed (decision D1): the profile (`tool` or
`agent`), the wall (whole seconds, 1–300), the argv, the network shape
(`tool`: none; `agent`: the proxy with the allow set) and vault-mode
credentials. Before any connection or boot, for every profile, the host
compares every other element of the policy snapshot with the snapshot those
inputs alone resolve to on the guest platform, and the first difference
refuses with `vm:not-carried:<field>`, the field spelled as the snapshot's
key path in lower case (`filesystem.deny_read`, `filesystem.read_only`,
`limits.mem`, `environment.bindings`, `terminal`, `lifetime_boundary`,
`launch.credentials.<id>.mode`, …). None is silently dropped:

- **Limits** follow the guest's fixed shape, pids=64, mem=512MiB, swap=0: a
  required ceiling must equal it, a preferred one may not be stricter, and
  storage, inodes and cpu ceilings refuse. A wall outside 1–300 whole
  seconds refuses as `limits.wall` (the `tool` baseline's 30-minute default
  included).
- **Environment.** The guest jail's environment is `LANG=C.UTF-8` with no
  `TERM` and no `TZ`; an operator environment whose admitted `LANG`, `TERM`
  or `TZ` differs (any terminal that sets `TERM`) refuses as
  `environment.bindings`.
- **Credentials.** Only vault mode crosses, without executable bindings or
  refresh, and with no vendor-state shape; a staged mode (`copy_rw`,
  `bind_ro`) refuses. An attached terminal refuses (`--terminal detach`).
- `build` refuses on the live share
  (`vm:build-profile-refuses-the-live-share`), and `--profile none` refuses
  at resolving. The kernel-bound key is preserved in the snapshot and
  requirements, derived as `owner_loss_termination`, and refused by this
  tier (the guest's wall is a deadline, not an owner-loss bound).
- **TLS-only rules** cross without their `:443`, so the guest jail applies
  them TLS-only; the canonical `host:443` spelling the 2026-11-03 build sent
  admitted plaintext HTTP there.

After the run, the guest receipt must also report the requested profile,
network mode, allow set and TLS-only set (compared as sets) and the
requested limits applied; otherwise no verified receipt is stored and the
attempt's integrity is `lost`. That check is a second wall, not the gate.
The 2026-11-03 build silently dropped several of these elements; the carry
rule above is the fix wave's code, tested at the CLI with a fabricated
installation and not yet on a booted guest.

The low-level `ukai-vm serve` protocol is a development interface, not a
full-policy execution interface. With `--live-workspace` it shares exactly
the workspace over virtio-fs; once requested, the share is mandatory, and a
guest whose share fails to mount refuses rather than falling back to a
staged copy: a guest booted with the virtio-fs device whose mount fails
powers off with `live_share_mount_failed`. The guest's `ready` and `session`
replies state `live_share`; the serve refuses a session whose `live_share`
differs from what it attached or is missing, so an image prepared from
older sources is refused and must be re-prepared. The share mounts
`nosuid,nodev`, not `noexec` (the jail decides what executes). NAT is
attached for proxied `agent` policies, whose allow set the guest jail's own
proxy enforces. Vault-mode values cross over vsock once per attempt into the
guest's tmpfs, through controller-owned directories and an `O_EXCL` file
owned by the workload account; credential ids that nest (`a` and `a/b`)
refuse before any guest traffic. The values come from the secrets the
supervisor staged and validated, and the guest's launch declaration is
generated from the snapshot and parsed back with the same loader: nothing
re-reads the operator's files or `UKAI_CONFIG_DIR`. The guest jail's
standard input is `/dev/null`, so `run --vm` refuses a standard input that
is a pipe, a file, a socket or a character device other than `/dev/null`,
before any contact with the VM (`invalid_config` at `preparing`,
remediation `configuration`):
"--vm: standard input is a pipe, and the guest jail's standard input is
/dev/null: nothing written to it would reach the target; run with
`</dev/null`, or without --vm". A terminal, `/dev/null` and a closed
descriptor pass (unit tests); the check runs after probing, so no run
reaches it while every plan has an unmeasured requirement. The mandatory share, the
`live_share` comparison, the mount
options, the secret staging and the nested-id refusal in this paragraph are
covered by unit and model tests only (stand-in guests and the guest
controller's model); none of it has run on a booted guest, and live
verification is pending.

The serve's `status` reports `warm` from the boot's start (the VZ client
alive and no stop requested) and `ready` once the guest's session handshake
completed and its kernel is known: only then does an attempt that connects
run on a booted guest. The harnesses wait for `ready` before their first
attempt; on 2026-11-04 they waited for `warm`, and the first attempt of each
warm run waited out the guest's 40 s boot.

Whether `run --vm` reuses a serving `ukai-vm` or spawns one, it checks the
serve's status the same way: a live share of exactly this workspace and, for
a proxied policy, the NAT adapter. It keeps the boot id that status
reported, and the attempt socket's `ready` must carry the same one, or the
run refuses: another serve replaced it; rerun. A spawned serve runs in its
own process group, and its standard error goes to a private file of its
own, created exclusively, then renamed `<data>/vm/serve.stderr` when the
serve answers or `<data>/vm/serve-failed.stderr` when it exits first; a
refusal quotes only its own serve's text (at most 2048 bytes), even when
two runs spawn at once. The serve, ready and prepared waits, the status
read and the `Prepare` write are bounded by the attempt's preparation
budget, and the serve's wait also by 180 s. This is covered by unit tests
against a stand-in serve script, not against a real serve.

**The attempt stop (decision D6).** One stop serves the guest's done,
cancel2, reset and the outer-wall backstop. The workload account's
infrastructure is three processes, learned at session open, before any
attempt of the boot runs: the user manager (the system manager's `MainPID`
for `user@<uid>.service`), its `(sd-pam)` helper (the account's one live
process in the manager's `init.scope` whose parent is the manager; a
manager without one is accepted, two fail the learning) and the session
bus (the user manager's `MainPID` for `dbus.service`, which the learning
starts, in that unit's reported `ControlGroup`). Each is checked against
`/proc` and pinned by pid and start time; if the learning fails, the guest
powers off with `infrastructure_unknown`. The stop kills every
`ukai-attempts.slice/attempt-*` cgroup and every cgroup under the user
manager that neither is nor holds `init.scope` or the bus's unit (walking
into their sub-cgroups), and kills by pidfd every other live process of
the account wherever it sits, after re-checking its start time. Killing
the attempt cgroup alone is not enough: the guest jail moves itself into
`user@<uid>.service/app.slice/ukai-jail-*.scope` and runs its workload in a
leaf directly under `user@<uid>.service` (the paths in the K111 and K113
guest receipts), so the earlier per-attempt kill reached an empty cgroup.
A zombie thread-group leader with a live sibling thread counts as live,
and its group is killed by pidfd. A bus that restarted during an attempt
is not the learned one, so the stop kills it; the next `busctl` activates
it again. The stop then requires those cgroups empty and no such process
left, re-killing within a 2.5 s budget: a stray it kills no longer fails
the stop (the audit lists it in `strays_killed`), and one that survives
the budget does, as does a cgroup that stays populated (the audit lists
its `members`). It bounds the supervisor reap at 1 s; every wait feeds the
guest watchdog. On failure the guest powers off with
`attempt_tree_unverified`. On a Linux development host running systemd 259
the learning found exactly `systemd --user`, `(sd-pam)` and `dbus-daemon`
(commit `6c1f11852`; no evidence file is retained), and on a booted guest
the 2026-11-04 stop audit's learning found one manager, one helper and the
bus in `session.slice/dbus.service`, and every stop it recorded found nothing to kill ([record](../../../docs/benchmarks/jail/results/macos-vm-live-2026-11-04/README.md)),
as did every stop the evening record reports
([record](../../../docs/benchmarks/jail/results/macos-vm-probes-2026-11-04/README.md)).
The stop's kill paths have not run on a booted guest.

Before it signals anything, the stop records what it finds: the cgroups
still populated (`populated_before_kill`) and the account's live processes
outside the infrastructure (`live_before_kill`). It runs after the guest
jail exited and verified its own tree, so either list non-empty means
something survived the guest jail; `strays_killed` alone cannot say so,
because `cgroup.kill` records nothing of what it ends. A warm attempt's
`done` carries the stop's report as `stop`, the serve relays it unchanged,
and `ukai-jail run --vm` settles nothing (the attempt ends unknown, with no
relayed outcome and no transport record) when `done` has no `stop` or any
of those three lists is non-empty. A clean stop's cgroups go in the
transport record as `guest_stop_boundaries`. `warm_live.py` requires a clean stop on every attempt. Booted guests
have sent the report: on 2026-11-04 the 16 probe attempts and 20 warm
stand-in attempts of the
[evening record](../../../docs/benchmarks/jail/results/macos-vm-probes-2026-11-04/README.md)
reported all three lists empty, and its 20 real `ukai-jail run --vm`
attempts settled, which the client allows only on such a report. A
non-empty list, and the client's refusal of it, are covered by unit and
model tests only (stand-in guests and the guest controller's model). The attempt's staged
values and launch profile are removed at every stop and poweroff. The
named poweroffs new in this wave are `attempt_tree_unverified`,
`attempt_files_not_cleared`, `infrastructure_unknown`,
`live_share_mount_failed`, `launch_profile_unstageable` (a launch profile
name already present, a link included, or an unwritable directory: never
written through) and `launch_without_toml`; the serve names a guest that
powered itself off from its console (`guest poweroff: <reason>`).

Beyond the 2026-11-04 stop audit's clean stops (which killed nothing), none
of the attempt stop's kill paths or the named poweroffs above has run on a
booted guest. They are covered by unit and model tests, plus real-`/proc`
tests of the pidfd kill and the zombie-leader read on a Linux host
(`test_guest_warm.RealProcTests`, skipped elsewhere), and live
verification is pending.

The service holds an exclusive runtime lock before removing stale sockets. It
copies the installed artifacts to a private boot directory and verifies the
copies before executing them. The `run --vm` client hashes nothing itself:
it checks that `image.json` is `prepared` and refuses a serve status or a
`ready` whose disk, helper, custodian or seed digest differs from it. A boot has one session handshake. Each attempt
resets its directories, stages files, releases, relays output and returns its
receipt. Client EOF cancels only that attempt; an unacknowledged cancellation
ends the service. The custody heartbeat validates acknowledgement bytes and
uses a continuous-clock deadline. Both lease holders restart their window
after a wake gap (their own suspension, more than 0.5 s between loop
turns): the serve resets its acknowledgement baseline, and the custodian
reads the pending heartbeats before it judges its 3 s lease. By the
serve's tests and `test_custodian.py` (a stand-in VZ client, no VM), a stop
of the whole group longer than 3 s no longer ends the VM, and a caller that
is really gone still does. A failed or refused boot keeps its directory
(`<data>/vm/vm-*`: console, copied image, nvram) as evidence; only the
newest three are kept (`KEPT_BOOT_DIRS`), and older ones are removed when a
service starts and whenever it keeps a new one. Control requests,
handshakes, writes and shutdown have bounds. No live VM lifecycle claim follows from these unit tests.

The `bound_receipt` frame keeps the original guest jail receipt bytes and
carries a separate controller binding: host attempt/boot, guest attempt/boot,
profile and canonical argv digest. The host checks the digest, these bindings,
containment, namespace boundary, cleanup, required limits and errors before
storing `evidence/jail.json` and `evidence/vm-binding.json`. A receipt without a
binding refuses. These are **guest-reported facts checked for consistency**,
not independent host attestation of the guest kernel. The transport summary
labels that provenance and does not reuse the host receipt's boundary as a
guest measurement. Record-write failures cannot produce a successful outcome.

The guest's `done` exit status must equal what the verified guest
receipt's outcome means (`exited` with code c gives c, `signaled` with
signal s gives 128 + s), or the attempt's run event is unknown and no
transport record is written; a signaled outcome is relayed as signaled.
`Prepared.staged_secrets` must list exactly the credential ids sent, each
at `/run/ukai-vm/credentials/<id>`. After the run the host derives the
policy snapshot the guest jail resolves for this attempt (the share mount
`/mnt/workspace` as workspace, the fixed guest limits and the wall, the
crossing allow rules, the generated launch declaration, `LANG` only) and
refuses a guest receipt whose `policy.digest` differs. Nothing checks the
guest jail's version before the run: that would need it pinned in
`image.json`, and it is not, so a guest jail of another version still runs
the attempt and only its receipt is refused. These checks are covered by unit tests against stand-in guest replies (the
policy prediction against the real supervisor's plan for `tool`, `agent` and
`agent` with a vault credential). Against a booted guest they have run only
for `tool` attempts that exited 0: the 20 real attempts of the
[evening record](../../../docs/benchmarks/jail/results/macos-vm-probes-2026-11-04/README.md),
each settled with its guest receipt verified. The signaled branch, `agent`
and a vault credential have run only against stand-ins.

Once the guest receipt is verified and the guest's `done` agrees with it,
the settled host receipt takes `platform.kernel`, `platform.arch`,
`exec_observed`, `applied` (except its `terminal`), `observer` and
`coverage` from it, and `outcome.cause` when the host recorded no cause of
its own; `lifetime.native.details` names it: `guest_receipt`
(`evidence/jail.json`), `guest_receipt_sha256` and `guest_carried` (those
seven fields; decision D5). The summary of a `--vm` attempt is the host
receipt's own summary plus the transport line, once the chain the host
receipt names holds: the guest receipt in `evidence/jail.json` hashes to
both the digest `vm-transport.json` records and the host receipt's
`guest_receipt_sha256`. A broken link is an error; so is a host receipt
that names a guest receipt while `vm-transport.json` is absent. A host
receipt that names no guest receipt (the K113 record predates D5) is
summarized as itself. The summary counts nothing from the host journal,
and `run` and `tail --summary` print the same lines. This is tested in unit tests on the recorded K113 attempt and receipts
derived from it, and on 2026-11-04 `ukai-jail tail --summary` printed the
host summary and the transport line for one of the evening record's 20 new
attempts (by hand, not by a test).

From the repository root, build and run the stand-in tests without a VM:

```sh
export RUSTUP_TOOLCHAIN=1.98.1
cargo build -p ukai-jail --bins --offline
cargo test -p ukai-jail --test vm_tier --offline
cd crates/ukai-jail/vm
python3 -s -E -m unittest discover -p 'test_*.py'
```

`python3 -s -E -m unittest test_guest_warm` is the focused guest suite; `-I`
removes this directory from Python's import path and is not its invocation.
`test_warm_service.py` uses synthetic, nonbootable images and stand-in
custodian/VZ processes. It exercises two attempts, a fragmented 100 KB export,
EOF cancellation, the lease, stop/idle/signals, helper death, locking and
status output. `UKAI_VM_TEST_BINARY` can select an older binary for regression
replay. Rust tests cover the receipt gate, output sinks, export traversal,
frame bounds, record failures, policy refusal and CLI lifetime persistence.
`test_guest_main.py` drives the guest controller's `main()` over
`guest_harness.py`: a socketpair for the vsock, a scripted stand-in for the
Linux jail, a virtual clock, and a model of the kernel's cgroup and `/proc`
files taken from the K111/K113 guest receipts. Its docstring lists what the
model cannot show, which is the live phase's to measure: where the real
jail's scope and leaf land, that `cgroup.kill` ends the real tree and the
next attempt still gets its scope, that the learning finds exactly the
manager, its helper and the bus on the image through the real `systemctl`
calls, a real cancel inside `WatchdogSec=4`, the guest kernel's
zombie-leader behavior (the model's two facts were measured on kernel
7.2.12), the virtio-fs detection and mount options on a real kernel, and
the staged files' real owners.
`test_custodian.py` compiles `custodian.c` and suspends it past its lease
against a stand-in VZ client; it never boots a VM.

## What remains

Before any J18 row can pass: a shipped and installed macOS `ukai-jail`
client; a live phase that re-measures every guest requirement with real
network probes (a socket connect to an IP literal, with a positive control)
and fills `GUEST_MEASUREMENTS` from the records it produces (five
requirements so far; `capabilities.py` now also has probes and judges for
`tree_termination`, `closed_set_observation`, `syscall_filter`, protected
coverage and `network_proxy`, but none of them has run on a booted guest,
so none is measured); the full K110
matrix (custodian, VZ-client and host-client kills, `Ctrl-Z` of the client,
every host controller suspended) with long-running workloads and compared
boot ids; the K111 receipt fix (decision D5, now in the code) shown on a
live run, with every host field compared with the guest receipt; the
attempt stop and the mandatory share (D6, D7) run on a booted guest, the
learned infrastructure confirmed on the image; a VM-tier compatibility record
that meets J18 §9.4's Linux-row conditions (K113); a package built by the
current `package.py` and checked by the current `check_install.py`; and
notarization, followed by the full row rerun on the stapled DMG before
publication. The harnesses for most of this exist in code (above); none
has run live. These stand-in checks do
not establish a release, signed-package qualification or production
readiness.
