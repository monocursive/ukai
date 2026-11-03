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

The first scope is offline `tool` and `build` commands. Each attempt gets two
virtual CPUs, 2 GiB VM memory, a private 6 GiB sparse disk, and the Linux jail's
required 512 MiB memory, zero swap, 64-process and explicit wall-time limits.
There is no VM network adapter during an attempt, host directory sharing,
credential forwarding, interactive stdin or agent/provider integration.
The `build` profile explicitly grants the disposable workspace copy read/write;
this grant is recorded in the Linux policy and receipt.

`prepare.py` downloads a dated Ubuntu 26.04 ARM64 image and the current public
Linux archive named in `dist/release.json` (`0.1.0-rc.2`; the published
`0.1.0-preview.1` DMG carries `0.1.0-rc.1`), checks embedded SHA-256 pins, and
prepares the guest.
Only that setup VM has NAT networking, for Ubuntu package installation. Package
versions are recorded inside the guest; apt repositories are not snapshot-pinned,
so this is not a reproducible release-image builder. It requires Python 3.11+,
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
starts. `ukai-vm-install` is the installer's helper (the preview's
`expand-image`/`doctor`/`version` verbs); only `install.sh` calls it.
Consumers do not need Python, Swift, Rust or Homebrew. The signed DMG
contains an offline installer with a pinned SHA-256 manifest, the signed
VZ client/custodian, the compressed snapshot-pinned guest image, licenses
and this source. The installer uses a per-user version directory and never
needs sudo. Read [PREVIEW.txt](PREVIEW.txt) for installation, command
examples and limits. Apple Silicon / macOS 27+ is the package's minimum;
measured execution is on macOS 27.0.1. Intel Macs and native macOS
workloads are not included.

Build from a trusted prepared image whose seed hash and every source hash
recorded by `prepare.py` match the committed `vm/` tree. Uncommitted changes
there stop the build — as do uncommitted changes under
`crates/ukai-jail/src`, whose committed sources build the packaged
`ukai-vm`. Only committed files are archived as the preview source. A
Developer ID Application identity must be available in Keychain:

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
runs `spctl --assess`, records every step's raw output in
`notarization.json`, and only after all checks pass writes the submission
id into `package.json` (a rejected or failed submission keeps
`notarization: pending` and exits non-zero; the script refuses to run
twice). Credentials arrive only as arguments and never enter the record:

```sh
python3 crates/ukai-jail/vm/notarize.py --package evidence/my-vm-package \
  --key ~/private_keys/AuthKey_<ID>.p8 --key-id <ID> --issuer <ISSUER>
  # or: --profile <keychain-profile from `xcrun notarytool store-credentials`>
```

A package build alone does not establish notarization, installation or
execution proof — the 2026-11-03 build is recorded notarization-pending
(no notarytool credentials on the build host), its installer contract
passed all five check_install cases against the shipped DMG
([installer-check/](../../../docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/installer-check/summary.json)),
and its gate rows are in
[docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/](../../../docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md).

Run the warm harnesses against the installed package (the binary the
package ships, not a repository build):

```sh
UKAI_VM_BINARY=~/.local/bin/ukai-vm python3 crates/ukai-jail/vm/warm_live.py \
  --image ~/.local/share/ukai-vm/0.1.0-preview.2 \
  --workspace <case-sensitive volume> --attempts 20 --out evidence/vm-warm
UKAI_VM_BINARY=~/.local/bin/ukai-vm python3 crates/ukai-jail/vm/fault_matrix.py \
  ~/.local/share/ukai-vm/0.1.0-preview.2 <case-sensitive volume> evidence/vm-faults
```

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

## J18: the warm service (`run --vm` is the macOS release path)

The K108–K113 rows ran their full live evidence on an **installed package**
on 2026-11-03
([record](../../../docs/benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md)):
warm reuse (20 attempts over one boot, 14.9–15.0 ms release latency), live
workspace grants and denials, the K110 fault matrix, the guest Linux
receipt verified by digest with the summary's transport line lifted from
the transport record, and the kernel-bound key refusing in every lane
before any boot. K113 ran through the tier's compatibility record: Claude
Code 2.1.311 headless in the guest, the operator's OAuth token through
the vault (substituted in flight by the guest proxy, in no exported byte),
its task's file landing on the host through the share
([record](../../../docs/benchmarks/jail/results/macos-vm-claude-2026-11-03/README.md);
harness `vm/claude_vm_row.py`). The package is Developer-ID-signed and
snapshot-pinned (`apt_snapshot` in `image.json`) but **not notarized** —
no notarytool credentials on the build host — and not published; those,
with a notarized-build rerun of the rows, remain what a release claim
still needs, with staged credential modes. The earlier development measurements (one boot at 12.5 ms, the
guest capability suite — wall, pids, memory, containment, network_none,
workspace — NAT with egress denied, proxied agent policies, vault-mode
substitution) are in the
[2026-11-02 record](../../../docs/benchmarks/jail/results/macos-vm-warm-2026-11-02/README.md).
The `macos-vm-development` publication scope in `dist/release.json` names
what stays unsupported (K113.1) and no capability is claimed beyond it.
the unsupported clauses (K108.1–K113.1) and no capability is claimed.

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
its disposable-copy grant has no protected segments.

The refusals that remain are named: the `build` profile on a live share,
staged credential modes (`copy_rw`/`bind_ro`), deny-read staging, walls
outside the guest grammar, custom limit ceilings below the guest's measured
floor, case-folding workspaces, and `--lifetime kernel-bound` — preserved in
the snapshot and requirements, derived as `owner_loss_termination`, and
refused by this tier (the guest's wall is a deadline, not an owner-loss
bound) before any boot. Resource, environment, filesystem and observation
policies are not silently dropped: there is no permitted CLI release path
until all requested elements can be applied and measured.

The low-level `ukai-vm serve` protocol is a development interface to the offline
preview's fixed `tool`/`build` command, with copied inputs and exported outputs.
It is not a full-policy execution interface. It never updates the input
workspace in place. Run-mode NAT, agent/provider integration, credential
injection and interactive stdin are absent. Vault values are refused by both
the service and guest controller; they are not transported or staged.

The service holds an exclusive runtime lock before removing stale sockets. It
copies the installed artifacts to a private boot directory and verifies the
copies before executing them. A boot has one session handshake. Each attempt
resets its directories, stages files, releases, relays output and returns its
receipt. Client EOF cancels only that attempt; an unacknowledged cancellation
ends the service. The custody heartbeat validates acknowledgement bytes and
uses a continuous-clock deadline. Control requests, handshakes, writes and
shutdown have bounds. No live VM lifecycle claim follows from these unit tests.

The `bound_receipt` frame keeps the original guest jail receipt bytes and
carries a separate controller binding: host attempt/boot, guest attempt/boot,
profile and canonical argv digest. The host checks the digest, these bindings,
containment, namespace boundary, cleanup, required limits and errors before
storing `evidence/jail.json` and `evidence/vm-binding.json`. A receipt without a
binding refuses. These are **guest-reported facts checked for consistency**,
not independent host attestation of the guest kernel. The transport summary
labels that provenance and does not reuse the host receipt's boundary as a
guest measurement. Record-write failures cannot produce a successful outcome.

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

Still unmeasured against a real VM: K108 latency, K109 live workspace behavior,
K110's full kill/suspend matrix, guest capability probes, policy translation,
real guest receipts and kernel guarantees. These checks do not establish a
release, signed-package qualification or production readiness.
