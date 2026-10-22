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
python3 -m unittest discover -s crates/ukai-jail/vm -p 'test_*.py'
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

`ukai-vm` bundles Python; consumers do not need Python, Swift, Rust or Homebrew.
The signed DMG contains an offline installer with a pinned SHA-256 manifest,
the signed VZ client/custodian, compressed pinned guest image, licenses and this
source. The installer uses a per-user version directory and never needs sudo.
Read [PREVIEW.txt](PREVIEW.txt) for installation, command examples and limits.
Apple Silicon / macOS 27+ is the package's minimum; measured execution is on
macOS 27.0.1. Intel Macs and native macOS workloads are not included.

Build from a trusted prepared image whose seed hash and every source hash
recorded by `prepare.py` match the committed `vm/` tree. Uncommitted changes
there stop the build, and only committed files are archived as the preview
source. A Developer ID Application identity must be available in Keychain:

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
only the VZ client `com.apple.security.virtualization`. Submit the resulting
DMG with `xcrun notarytool submit --keychain-profile <profile> --wait`, retain the
result, then `xcrun stapler staple` and `xcrun stapler validate` the accepted DMG.
Verify `spctl --assess --type open --context context:primary-signature <dmg>`;
compute the final DMG SHA-256 only after stapling. A package build alone does
not establish notarization, installation or execution proof.

Run the fault matrix against the installed frozen executable:

```sh
python3 crates/ukai-jail/vm/check.py \
  --image ~/.local/share/ukai-vm/0.1.0-preview.1/image \
  --executable ~/.local/bin/ukai-vm \
  --out evidence/vm-packaged-faults --repeat 1
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

## J18: the warm VM tier (`--vm`)

[jail-macos.md §6](../../../docs/specs/jail-macos.md) turns this preview into
the Mac's second tier. `ukai-jail run --vm` (macOS only) drives a **warm**
guest through two new programs in this crate:

- **`ukai-vm`** (`crates/ukai-jail/src/bin/ukai-vm.rs`, one binary, no Python
  runtime) is the per-operator host service. `ukai-vm serve` locates the
  installed preview artifacts exactly where `install.sh.in` puts them
  (`~/.local/share/ukai-vm/<version>/`, or `UKAI_VM_HOME`), verifies every
  image hash the way `run.py`'s `load_image` does, reuses the installed
  `custodian` and `vz` binaries **unmodified**, clones the base disk, boots
  once, and serves attempts until `ukai-jail vm stop` or an idle period
  (initial 10 min, on `mach_continuous_time`) ends it. It is a foreground
  process, not a launchd job.
- **`ukai-jail --vm`** selects `platform/macos/vm.rs`'s `VmPlatform` instead
  of native preparation. The policy resolves for the guest (`platform`
  `linux`); the boundary is the guest jail's pid namespace; the receipt is
  the guest's Linux receipt, digest-verified on the host and stored in the
  attempt directory beside `vm-transport.json`, a
  `ukai.jail.vm-transport/1` record naming the VM boot id, image digests,
  vsock port, the sockets, the host wall times and the receipt digest. The
  summary's one transport line renders from that record
  (`record::transport_line`), as the J15 action adds its host-setup line.

### The wire protocols

All frames are NDJSON, one object per line, defined once in
`src/platform/macos/vm/protocol.rs` and included **by path** from both ends,
so the host program and the jail cannot drift apart silently:

- `ukai.jail.vm-control/1`, on `<data-dir>/vm/control.sock`: `status` and
  `stop`.
- `ukai.jail.vm-attempt/1`, on `<data-dir>/vm/attempt.sock`, one connection
  per attempt: the host sends `prepare` (argv as base64, the profile, the
  wall, the ephemeral credentials), then one `put` per workspace file, then
  `run`; the service answers `ready`, `prepared`, `released`, `stdout`,
  `stderr`, `file`, `receipt` (bytes plus their SHA-256) and `done`.
  **The connection is the lease**: its end-of-file cancels that attempt in
  the guest. No timer is involved, so a host `Ctrl-Z` suspends the run
  without ending it (§6), and the guest jail's own wall deadline still ends
  a suspended-host attempt.

### The warm guest session

`guest.py` gains a warm session beside its unchanged single-run `run` op
(preview compatibility, one run per boot, poweroff at completion): the
host's `session` op opens it; per attempt the host sends `reset` (both
attempt directories are emptied and recreated), `secret` (each ephemeral
credential), `put` (workspace files), `run2` (the **same jail command** the
`run` op builds — see `guest.run_command`, shared by both, so the warm
design changes nothing about what the jail is asked to do), and, on the
lease's end-of-file, `cancel2`. After a `done` the controller clears the
staged secrets and waits for the next attempt; the VM stays up until the
host stops or the idle budget ends. The outer-wall backstop and `cancel2`
end the attempt tree with the same `cgroup.kill` + verified-empty sequence
the poweroff path uses (`kill_workload`), without the poweroff.

### Credentials (J18 §6)

Vault values cross **once per attempt** and are never written to the guest
disk. What was implemented, exactly:

1. The supervisor's staged vault values (`launch.vault`) are carried in the
   `prepare` frame's `secrets` entries (id + base64 value).
2. `ukai-vm` relays each one as a vsock `secret` op, holding the bytes in
   memory only.
3. The guest controller stages each value at
   `/run/ukai-vm/credentials/<id>` — **tmpfs**, mode 0600, directory 0700
   (`guest.stage_secret`; the jail's credential grammar names source
   *files*, J12 §3.5, so a file is what the attempt's sources can name).
4. The controller deletes the whole staging directory at the end of every
   attempt — completion, cancellation, wall backstop —
   (`guest.clear_secrets`), so no value outlives its attempt.

What is **not** implemented yet, because it needs the live guest and the
in-guest launch-profile path: generating the guest-side credential
declarations that point at those tmpfs sources and running the in-guest
proxy's placeholder replacement. The transport, staging and deletion above
are stand-in tested; that last wiring is not.

### Tests and what stays untested here

`tests/vm_tier.rs` (portable, both CI lanes) covers the policy key
(derivation, digest stability, the native `--vm` answer, the Linux `none`
refusal), the CLI grammar (`--lifetime`, `vm stop`, the Linux `--vm` usage
refusal), the transport record's shape and its one escaped summary line, and
the attempt/control protocols against scripted stand-in servers. The Python
side is `vm/test_guest_warm.py` (command parity between `run` and `run2`,
reset, ephemeral staging and its traversal refusals).

Not covered here, because it needs a booted VM (the preview fault matrix,
K108–K110): warm reuse latency, the live workspace share, every
kill/suspend case of the warm design, the EOF lease against a real
connection loss, the in-guest credential wiring above, and any receipt a
real guest jail produced. `ukai-vm serve`'s boot path itself (custodian
spawn, lease thread, disk clone) is likewise exercised only against a real
image on a qualified host.
