# K90 bootstrap-strip closure — 2026-11-02

**Development evidence only. NC01 is not accepted; no release gate is
promoted. The protected-Mac release run (K104) stays explicitly blocked.**
This measurement closes the launchd deputy class itself, not just the
`launchctl` vector, and re-validates the earlier fix in the same isolated
VM. The native default-off gate, entitlement, packaging, K95/K96 fault and
memory pressure tests and every other native release requirement remain in
place. Follows the [kickstart-fix
rerun](../macos-k90-kickstart-fix-2026-11-02/README.md) from the same day.

## Why a direct-client probe was needed

The morning fix denied executing `/bin/launchctl` in the profile — a
per-binary ban. The class-2 requirement is wider: *anything the workload
can make run outside its sandbox*. So the probe asks: can a launchctl-free
client reach the launchd control plane through the port every member
inherits?

Findings on this build (macOS 27.0.1/26A434 host, 27.0/26A428 guest; see
[provenance.json](provenance.json)):

- **The MIG surface is dead.** The published job subsystem
  (`launchd src/job.defs`, subsystem 400) is not served on the bootstrap
  port: hand-rolled `kickstart` requests (correct header/body/NDR/tight
  `c_string` packing, port descriptor for `j : job_t`) get the reply right
  destroyed instead of an answer — the kernel returns the send-once
  notification (`msgh_id 71`). `/bin/launchctl` imports no `vproc_mig`
  symbols at all.
- **The real client protocol is XPC.** `launchctl` calls
  `_xpc_pipe_interface_routine(pipe, routine, request, &reply, flags)`
  (resolvable via `dlsym`) over a pipe from
  `xpc_pipe_create_from_port(bootstrap_port, 4)` — **built from the
  inherited bootstrap port**. Kickstart is routine `0x2be` with a
  `{type, handle, name}` dictionary; the target parser maps `gui` → type 8
  (disassembled from this build's `/bin/launchctl`). A probe speaking this
  protocol from outside completes typed request/reply exchanges with
  launchd.
- Therefore the profile cannot be the class boundary: SBPL v1 has no
  filter for Mach sends to that port, so **any admitted executable can be
  a launchd client.** The foundation must not rest on a command name.

## The fix

[launcher.rs](../../../../crates/ukai-jail/src/platform/macos/launcher.rs)
(`ukai-jail __launch-macos`, the inside process that `sandbox-exec` execs)
now calls `task_set_special_port(TASK_BOOTSTRAP_PORT, MACH_PORT_NULL)`
immediately before `execve`, clearing the cached `bootstrap_port` global
too — fail closed: if the port cannot be replaced, nothing runs. Every
client then fails locally: `bootstrap_look_up` returns
`KERN_INVALID_NAME`, `launchctl` dies client-side (measured exit 141), and
the lazy XPC pipe answers `EPIPE` with no reply. The profile's
`(deny process-exec (literal "/bin/launchctl"))` stays as the second
layer, giving a clean `EPERM` for the obvious vector. The template digest
is unchanged (`b2ae082d…`); this fix lives in the launcher, not the
profile.

## Results

| Check | Result | Scope |
| --- | --- | --- |
| Direct client vs supervisor | PASS | Inside a real jailed run (production launcher, both custodians alive): `port=0`, lookup `kr=268435459`, interface `rc=32 reply=0` — no route. Outside: `kr=0` and a launchd reply (`reply=1 error=113`) — the control plane answered. |
| Direct client vs guardian | PASS | Same shape. |
| Deputy regression (launchctl kickstart × 2, load × 2) | 4/4 PASS | The morning rows stay green with the strip in place; all four outside controls reached the live custodian. |
| Defense matrix, exact pinned digest (host) | 18/18 pass | Including the new `class_2_direct_launchd_client_is_unreachable_through_the_launcher` row, which runs the direct client through the real launcher under the profile ([host-defense-matrix.log](host-defense-matrix.log)). |
| Sandbox profile suite (host) | 37/37 pass | Unchanged template digest. |
| Launcher unit tests (host) | 5/5 pass | |
| Guest isolation and cleanup | PASS | `guard()` on every entry; no test-owned processes or jobs remain; VM stopped and retained. |

## What this does not do

The mach-lookup allowlist design (jail-macos §4.10) presumes members hold a
bootstrap port; with the strip, the empty allowlist is structural — a
future admitted service requires a brokered design (for example a
guardian-side proxy) specified and measured before any entry is admitted.
The spike's other open findings (process headroom, the full SQLite build,
stop-path timing) and K104 remain open; K90.1 stays `untested`.
