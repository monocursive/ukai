# VM tier live phase on the spare Mac — 2026-11-04

**Development evidence from a source build.** The VM tier's harnesses ran
live on the user's spare Mac (Apple M2 Pro, 16 GiB, macOS 27.0.1). The
build came from source: `ukai-vm` and `ukai-jail` were built with
`cargo build --release --locked` at `0def15ea1`. `vm/prepare.py` prepared
the guest image on that host, and its helper and custodian are ad-hoc
signed. This run had:

- no Developer ID signature;
- no notarization;
- no package and no `install.sh`.

Nothing here ran an installed or shipped build, and no macOS `ukai-jail`
client ships. **K108–K113 stay `untested`**; this record promotes no row
(see the [acceptance map](../../../../specs/jail-v1/acceptance-map.toml)).
Hashes, toolchain and run times are in [provenance.json](provenance.json).

**What it changes in the code.** The five requirements that
[capabilities.json](capabilities.json) measured are now the
`GUEST_MEASUREMENTS` rows in `crates/ukai-jail/src/platform/macos/vm.rs`.
Every `tool` and `agent` plan also requires `tree_termination`, which has no
probe yet. So every `ukai-jail run --vm` still refuses at probing, before
any connection or boot, with `vm:not-measured:tree_termination`. This run
saw that refusal live, in [warm-live-2.json](warm-live-2.json) and
[gate-rows/k111.json](gate-rows/k111.json).

## Results

| Harness | Record | Verdict |
| --- | --- | --- |
| `capabilities.py` | [capabilities.json](capabilities.json) | **PASS**: wall, pids and memory limits, filesystem containment and `network_none` measured on one guest boot |
| `fault_matrix.py`, all nine cases | [fault-matrix.json](fault-matrix.json) | **FAIL**: 8 PASS, `client-kill` ERROR (its guest powered off with `live_share_mount_failed`) |
| `fault_matrix.py client-kill` | [fault-matrix-client-kill-rerun.json](fault-matrix-client-kill-rerun.json) | `client-kill` **PASS**. The file's `outcome` is FAIL because `matrix_outcome` passes only a complete matrix. Every case passed once across the two runs, but neither run passed the whole matrix |
| `warm_live.py` (as of `0def15ea1`) | [warm-live.json](warm-live.json) | **FAIL**: route control not reached; first attempt includes the boot; real client refused (`unsafe_state_path`, a harness bug) |
| `warm_live.py` (as of `a468b46a7`) | [warm-live-2.json](warm-live-2.json) | **FAIL**: the same two checks; real client refused at probing (`vm:not-measured:tree_termination`) |
| `stop_audit.py` (one-off, kept here) | [stop-audit/](stop-audit/), [stop-audit-2/](stop-audit-2/) | The guest's own attempt-stop audit on one warm boot (no verdict) |
| `gate_rows.py` | [gate-rows/rows.json](gate-rows/rows.json) | K109 harness verdict PASS, K111 REFUSED, K112 harness verdict PASS, K113 not judged |

The client cases used the Python stand-in client. `fault_matrix.py` got no
`--ukai-jail`, because `run --vm` refuses at probing; the record's `not_run`
says so.

## The measured requirements ([capabilities.json](capabilities.json))

One serve and one guest boot (`vm-eba793c5…`, kernel 7.0.0-38-generic) ran
seven attempts between 12:50 and 12:51 UTC. The first attempt paid for the
boot: 39.7 s from connect to ready. Each `measurements/<requirement>` entry
names its attempt, and each attempt's receipt digest and binding were
verified.

- **`limit:wall`**: the workload slept past a 5 s wall. It got SIGTERM
  (exit 143) with cause `wall_expiry`, and printed no later output. The
  guest jail's own deadline ended it, not the host's backstop. Release to
  done took 5.24 s.
- **`limit:pids`**: 61 forks, then `EAGAIN`. The receipt records `pids.max`
  as 64, applied and hit. The probe could not read `pids.current` or
  `pids.max` inside the jail and printed `null`.
- **`limit:mem`**: the workload allocated in 16 MiB steps up to 496 MiB,
  then got SIGKILL (exit 137) with cause `memory_oom`. The limits were
  `memory.max` 512 MiB and `memory.swap.max` 0.
- **`filesystem_containment`**: writes to `/etc`, `/usr/local/bin` and the
  guest's root were refused with `EROFS` and left nothing behind. These
  paths were not visible (`ENOENT`): `/etc/shadow`, `/root`, `/home/ukai`,
  `/var/lib/ukai-vm` and `/run/ukai-vm`. The controls, `/usr/bin/python3`
  and a workspace file, were readable.
- **`network_none`**: the probe's control connection succeeded first. Then
  egress to `1.1.1.1:443` failed with `ENETUNREACH`, and DNS did not
  resolve. On the same guest boot, NAT was attached, and an `agent`
  attempt's route control through the guest jail's proxy got
  `HTTP/1.1 200 Connection established` from `1.1.1.1:443`. The host itself
  reached the target in 18.2 ms.
- **Workspace** (not a requirement): the write reached the host with this
  run's bytes, and `.git/config` was not touched.

## The fault matrix

Each case ran on its own serve boot, and every verdict was taken before
cleanup.

- **`secrets`**: two ids (`api/token`, `nested/id/two`) were staged
  under `/run/ukai-vm/credentials`. A duplicate attempt was refused. The next
  attempt ran on the same serve and guest boot. The network denial came
  with a positive route control on the same boot.
- **`client-ctrl-z`**: the stand-in client was stopped (`TN`). The guest's
  beats continued, and the workload finished with exit 0. The next attempt
  ran on the same boot.
- **`serve-kill`, `custodian-kill`, `vz-kill`**: each was killed with two
  attempts open. The serve was gone within about 2.0 s, and the custodian,
  VZ client and VM within 0.02 s. Both attempts ended, their sockets went
  unanswered, and the workspace survived.
- **`all-suspended`**: the custodian, VZ client, serve and client were all
  stopped (`TN`). The guest's beats went quiet 9.76 s after the 10 s wall
  started, before any resume.
- **`eof`**: after an attempt-socket EOF, the beats went quiet, and the
  serve was warm afterwards with a known kernel.
- **`serve-group-stop`**: the serve's group was stopped for 5 s. The beats
  continued, the workload finished, and the next attempt ran on the same
  boot.
- **`client-kill`**: in the full run, the case's guest powered off with
  `live_share_mount_failed` (`"error": "OSError"`) before the attempt was
  released. The stand-in client was already gone at the kill, so the
  harness refused to signal a pid it could no longer identify (see
  [consoles/](consoles/)). The rerun about 14 minutes later passed: the client
  was killed (exit −9 within 8 ms), the beats went quiet, and the serve
  was warm afterwards.

## Warm reuse ([warm-live.json](warm-live.json), [warm-live-2.json](warm-live-2.json))

Each run made 20 attempts on one serve boot and one guest boot. In every
attempt:

- the exit was 0;
- the receipt was verified (digest and binding);
- the granted write reached the host;
- the `.git` write was tried and refused, and `.git/config` stayed
  byte-identical;
- the receipt recorded `network: none`.

Both runs fail the same checks:

- **The route control did not reach the target**: a timeout in
  `warm-live.json`, `HTTP/1.1 504 Gateway Timeout` from the guest's proxy
  in `warm-live-2.json`. Without a positive control, the per-attempt denial
  is not established, so `every_attempt_network_denied` is false. The
  capability run reached the same target through the same proxy on its
  own boot, 18 minutes before the first warm run. Why it failed here was not determined.
- **`k108_every_attempt_within_budget`**: the first attempt's
  connect-to-released time, 39.9 s and 40.0 s, includes the guest's boot.
  The serve's status says `warm` (helper alive, not stopping) while
  `kernel` is still `null`: the boot has started, but the guest is not
  ready yet. The 19 later attempts took 77.6–108.6 ms from connect to
  released, 50–60 ms from connect to ready, and 23.5–48.7 ms from prepare
  to released. This is not the clause's measure, which is relative to the
  guest jail's own release time; the record's `k108_measure` states
  what it measured instead.

In each run, two attempts used the real client, `ukai-jail run --vm`
(exit 125). They refused with `unsafe_state_path` in `warm-live.json`: the
harness created the shared data directory with a umask-dependent mode,
fixed in `a468b46a7`. In `warm-live-2.json` they refused with
`vm:not-measured:tree_termination` at probing.

## The guest's stop audit ([stop-audit/](stop-audit/), [stop-audit-2/](stop-audit-2/))

The serve deletes a cleanly stopped boot's directory, so the records above
keep no guest console. `stop_audit.py` ran attempts on one warm boot and
read the console while the boot was still live. It is a one-off script, not
a repository harness. Both versions are kept here; the provenance records
their hashes.

- The guest learned its infrastructure: one manager, one helper, and the
  session bus in `session.slice/dbus.service`.
- Before each attempt, the guest found `app.slice` empty
  (`workload_tree_empty`, `strays_killed: []`). After each attempt, it
  found both the attempt's own `ukai-attempts.slice/attempt-N` and
  `app.slice` empty, with `strays_killed: []`. That makes 8 stops for 4
  attempts in `stop-audit/` and 12 stops for 6 attempts in
  `stop-audit-2/`. Every attempt ran on the same guest boot, including the
  one after the wall kill.
- `stop-audit-2/stop-audit.json`'s parsed `console_events` lists 10 stops,
  not 12. On the same console line, a terminal reset sequence comes before
  the post-attempt stops of attempts 5 and 6. The script's parser needs a
  line to start with `UKAI_VM `, so it skipped those two.
  [stop-audit-2/console.log](stop-audit-2/console.log) has all 12.
- **Background descendants**: the workloads ran `( cmd & )`,
  `( setsid cmd & )`, or both. In each case:
  - the guest receipt says `exited 0`;
  - its `errors` holds `evidence_lost` ("coverage was lost by settlement in
    exec, fs.deny (entry_abandoned)");
  - the guest jail exited 1;
  - the stop that followed found nothing to kill.

  The host refuses any guest receipt with a non-empty `errors` list
  (`crates/ukai-jail/src/platform/macos/vm/image.rs`, "guest evidence or
  cleanup failed"). So under `run --vm` today, a workload that leaves a
  descendant behind cannot settle as a success. This is the guest's Linux
  jail (rc.5) at work. Whether a native Linux host records the same was not
  checked here. The first version of the script did not keep receipts.

## Gate-row harness ([gate-rows/](gate-rows/))

`gate_rows.py` expects an installed package root. It ran against the
source-built root instead: the prepared image, plus a copy of the built
`ukai-vm` at `<root>/bin/ukai-vm`.

- **K109** (harness verdict PASS): the granted write reached the host with
  its exact bytes. The `.git` write was refused, and its sentinel was
  unchanged. Writes to `/etc`, `/usr/local/bin` and the guest's root were
  refused and left nothing behind. The grants were the guest's fixed `tool`
  shape, driven by the Python client.
- **K111** (REFUSED): `ukai-jail run --vm` refused at probing with
  `vm:not-measured:tree_termination`. So no guest receipt, binding or
  transport line exists to check. [gate-rows/k111-attempt/](gate-rows/k111-attempt/)
  holds the refused attempt's host files, and
  [gate-rows/k111-tail-summary.txt](gate-rows/k111-tail-summary.txt) holds
  its summary.
- **K112** (harness verdict PASS): three lanes refused at probing with
  `[unsupported]`, with no workload marker and no boot:
  - native as shipped;
  - native dev-enabled;
  - `--vm`, with `vm:owner-loss-not-provided`.
- **K113**: `claude_vm_row.py` was not run. It needs a Claude Code
  credential in the guest, and the client refuses at probing anyway.

Both `--vm` refusals took about 18 s: 18.0 s for K111 and 17.8 s for the
K112 `--vm` lane, against 0.0–0.1 s for the native lanes. The probe runs
after `VmPlatform::new`, which hashes every image artifact, including the
multi-GiB `base.raw`. That cost was not timed separately.

## Host stability ([host-stability/](host-stability/))

Of five bootstrap boots on this host, three crashed and one failed on the
package archive:

1. **`prepare-1`** hit `boot_timeout`. Its guest journal shows SIGSEGV in
   `cloud-init-main`, `systemd-networkd`, `dbus` and `systemd-resolved`,
   plus an abort and an `Illegal instruction`. It shows no kernel oops. A
   release `cargo build` was running on the host at the same time.
2. **`prepare-2`** hit `boot_timeout` after `snapshot.ubuntu.com` answered
   `401 UNAUTHORIZED` for the `InRelease` of all three suites. Nothing
   crashed. The snapshot service then flapped between 401 and 503 for a
   while.
3. **`exp-A` and `exp-B`** ran side by side, each with the kernel console
   also on `hvc0` so its log would be captured. B also booted with
   `arm64.nopauth`, to test a pointer-authentication hypothesis.
   - A hit a guest kernel NULL-pointer oops in `bpf_prog_free_deferred` at
     60 s, and a second oops at 331 s. It reached `poweroff.target` but
     never powered off, and was stopped by signal.
   - B hit `Illegal instruction (core dumped)` during `apt-get update`,
     then a kernel oops with `pc : 0x0` at 98 s, then `boot_timeout`.

   `arm64.nopauth` did not help.
4. **`prepare-3`** ran alone, once `snapshot.ubuntu.com` had answered 200
   twice in a row for all three suites. It prepared the image used above,
   and its journal shows no crash.

The guest journals are 8 MiB each and are not committed (the store's limit
is 5 MiB). Each `guest-journal-messages.txt` keeps its journal's `MESSAGE`
fields and SHA-256.

The cause is not determined. These three were not told apart:

- the guest kernel (7.0.0-38-generic);
- Virtualization.framework on this M2 Pro;
- host load: two guests, or a guest and a build, at once.

The live runs' consoles carry only the guest helper's `UKAI_VM` events, so
they cannot show whether a kernel oops happened during those runs. Every
live boot reached ready except the first `client-kill` boot.

## What this does not show

- No row's clause is met; K108–K113 stay `untested`.
- No installed, signed, notarized or shipped build ran.
- No macOS `ukai-jail` client ships. The client cases used the Python
  stand-in, and the real client refused at probing.
- These requirements have no guest measurement, so every `tool` and
  `agent` plan refuses:
  - `tree_termination`;
  - `closed_set_observation`;
  - `syscall_filter`;
  - `protected_coverage:existing_and_root`;
  - `network_proxy`.
- No warm-reuse latency was measured against the guest jail's own release
  time.
- K113 did not run.
- This is one host, and the guest is not stable on it.

## Files

| Path | What |
| --- | --- |
| `provenance.json` | Source, build, host, image, harness hashes, run times, what is not committed |
| `capabilities.json`, `logs/capabilities.log` | The capability probe |
| `fault-matrix.json`, `fault-matrix-client-kill-rerun.json`, `logs/fault-matrix.log` | The matrix and the `client-kill` rerun |
| `consoles/` | The guest consoles the serve kept, for the boots it did not stop cleanly |
| `warm-live.json`, `warm-live-2.json` | Warm reuse, before and after the harness fix |
| `stop_audit.v1.py`, `stop_audit.py`, `stop-audit/`, `stop-audit-2/` | The stop audit's scripts, records and guest consoles |
| `gate-rows/` | `gate_rows.py`'s rows, K111's refused attempt and its summary |
| `image/` | The prepared image's `image.json` and bootstrap console and events |
| `host-stability/` | The failed bootstrap boots and the two console experiments |
| `logs/` | Host-side output of `prepare.py` and the run scripts |
