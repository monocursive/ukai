# J18 warm service with the live share — first live qualification — 2026-11-02

**Development evidence only. No release gate is promoted; K108–K113 stay
`untested` until their full rows run on a qualified package.** This record
is the warm `ukai-vm serve` running against a real prepared image with the
[live workspace share](../macos-vm-share-2026-11-02/README.md) attached:
twenty attempts over **one boot**, plus the fault matrix and the secret
transport, all on macOS 27.0.1 / Ubuntu 26.04 (image built by `prepare.py`
from this tree, ordinary virtualization entitlement only).

## Errata (2026-11-03, fix wave 1103)

Added after review; the raw files are unchanged, and the text below is kept
as written except that the two links to `run-vm-cli/` are now plain text
(erratum 6).

1. **Every TCP egress probe here was vacuous.** `capabilities.py`,
   `warm_live.py`, `fault_matrix.py` and `proxy_measurement.py` probe with
   `(echo > /dev/tcp/93.184.216.34/443)` under the guest's `/bin/sh`, which
   is `dash`. `dash` has no `/dev/tcp`, so the probe prints its refusal
   whatever the network allows. No egress claim rests on these records:
   not `capabilities.json`'s `network_none` (its DNS half, a `getent`
   lookup, is a real probe), not the per-attempt `network_denied` in
   `warm-live.json`, not [warm-nat.json](warm-nat.json)'s "outbound TCP
   still refuses" (which also records no guest NAT field), not the fault
   matrix, and not the proxy record's `tool_offline`.
2. **`GIT_ALLOWED` in `warm-live.json`'s stdout is a shell-precedence
   artifact.** The probe chains `… || echo net_denied 2>/dev/null && echo
   GIT_ALLOWED || echo git_denied`, which the shell groups left to right, so
   `GIT_ALLOWED` prints whichever branch the network probe takes; it says
   nothing about the `.git` write, a separate earlier command whose result is
   never tested. `protected_write_absorbed` is the constant
   `'[core]' == '[core]'`. The `.git` claim rests only on the host-side
   comparison `git_config_untouched`.
3. **The capability verdicts for `pids` and `mem` are loose.** The `pids`
   verdict requires only `spawned=` (any 32 processes), not a refusal at the
   limit; the stdout does show `Cannot fork`, but the verdict would pass
   without it, and that attempt ended in `evidence_lost`. The `mem` verdict
   accepts any exit 137 or `Killed`, which does not tell the cgroup limit
   from the VM's own OOM killer.
4. **The proxy record's two runs used two guests.** "The offline `tool`
   profile on the same guest" is refuted by the record: the agent run's boot
   is `vm-574c66b2…` and the tool run's `vm-b22ef488…`. Both runs' host
   receipts also say network `pending` (the K111 contradiction).
5. **Root copies.** The root [proxy-policy.json](proxy-policy.json) and
   [proxy_measurement.py](proxy_measurement.py) are byte-identical to
   [proxy-policy/proxy-policy.json](proxy-policy/proxy-policy.json) and
   [proxy-policy/proxy_measurement.py](proxy-policy/proxy_measurement.py).
   The root [vault-consumption.json](vault-consumption.json) is the **FAIL**
   run (`outcome: FAIL`, `injected_header: null`), written by the
   `fc503e780` version of `vault_measurement.py`, whose probe sent no
   placeholder; the PASS run is
   [vault-consumption/vault-consumption-PASS.json](vault-consumption/vault-consumption-PASS.json).
   These root files were committed on 2026-11-03 from the uncommitted tree,
   byte for byte.
6. **`run-vm-cli/` was never committed.** The "`ukai-jail run --vm` drives
   the warm service" section cites `run-vm-cli/` and its `vm-binding.json`;
   neither exists in the repository, so that recorded run has no retained
   evidence here.
7. **K108's criterion was misread.** "Initial + 1 s" below treats `initial`
   as the first attempt's latency. In jail-macos.md, **initial** marks a
   tunable default: K108 asks for a second attempt released within 1 s
   (initial value) of the guest jail's own release time. The latencies here
   are host-observed prepared-to-released times through the Python protocol
   client and were never compared with the guest jail's own release time.
8. **K108–K113 remain `untested`**, as the opening says, and these records
   used the Python protocol client or a client built from the repository;
   no macOS `ukai-jail` client ships. "What remains before a release" below
   is the 2026-11-02 list; the acceptance map's notes are current.
9. **Fix 1 below moved the kill to a cgroup the jail leaves.** The guest
   controller starts each jail in `ukai-attempts.slice/attempt-N`, but the
   guest jail then moves its supervisor to a scope under
   `user@1001.service/app.slice` and puts its execution leaf directly under
   `user@1001.service`: the K111 and K113 guest receipts of 2026-11-03 show
   both paths (the records here do not retain them). By the controller's
   code at the time, the per-attempt kill therefore reached an empty
   cgroup, and cancel and the outer-wall backstop did not reach the jail.
   Case C recorded only that the guest stayed warm and the next attempt
   ran; it did not check that the cancelled workload stopped. Fixed in
   `bfcf1f9d4` (decision D6): one stop kills every attempt cgroup and every
   cgroup under the workload account's user manager except its
   infrastructure, then verifies them empty, or powers the guest off with
   `attempt_tree_unverified`. That is covered by unit and model tests only;
   it has not run on a booted guest.
10. **Case B stayed inside the custodian's lease.** The 2 s stop of the
    whole group is shorter than the custodian's three-second lease, so the
    case did not test a longer stop, and fix 2 below is the serve's half
    only. By the custodian's code at the time (it judged the lease on the
    continuous clock before reading the heartbeats waiting in its pipe), a
    stop of the whole group longer than 3 s would have ended the VM on
    resume; that was not measured. Fixed in `7af4af5c1`: the custodian reads
    pending heartbeats before it judges the lease and restarts its window
    after a wake gap longer than 0.5 s. `test_custodian.py` covers it
    against a stand-in VZ client; it has not run on a booted guest.

## K108 warm reuse (20 attempts, one session)

[warm-live.json](warm-live.json) — `--live-workspace`, profile `tool`:

| Property | Result |
| --- | --- |
| One boot for all 20 attempts | `warm_reuse_one_boot: true` |
| Every granted write reached the host | 20/20 (fresh file per attempt, on-host) |
| Protected `.git/config` unchanged after every attempt | byte-identical each time |
| Every attempt's exit | 0, guest receipt bound per attempt |
| Release latency (prepare→released) | initial **12.5 ms**, max **12.5 ms** |
| K108 criterion (2nd attempt within initial+1 s) | **20/20** — margin ~80× |

## K110 fault matrix ([fault-matrix.json](fault-matrix.json))

| Case | Result | Notes |
| --- | --- | --- |
| Secret transport lifecycle | PASS | Two values (one nested id) acked at `/run/ukai-vm/credentials/…`, attempt completed, second attempt on the same boot; duplicate ids refuse at the serve before any guest traffic |
| A: `kill -9` the service mid-attempt | PASS | Attempt socket unanswered after, no VZ client left, workspace survives on host; stale sockets are swept by the next boot |
| B: Ctrl-Z (whole process group, 2 s) | PASS | Attempt completes after resume, guest serves another attempt; evidence retained if the service does die |
| C: attempt-socket EOF mid-run | PASS | Cancels only that attempt (the lease is EOF, §6); the next attempt runs on the same boot |

With [NAT attached](warm-nat.json) (`--guest-nat`), every workload's
outbound TCP still refuses — the adapter grants the workload nothing; the
jail remains the policy gate.

## Two real bugs the matrix found and the fixes

1. **The warm reset killed the user manager.** The preview's per-attempt
   kill targeted `user.slice`, which contains the lingered `user@1001`
   service whose cgroup delegation the jail needs: the first warm reset
   killed it, and the next jail refused with `limit:pids
   (cgroup_unavailable)`. The guest controller now runs each attempt in a
   dedicated delegated cgroup under `ukai-attempts.slice` (controllers
   enabled on the slice; the join happens before the jail execs via a
   waiting wrapper — the root controller performs the move, because the
   delegated user cannot authorize leaving the service cgroup), and the
   per-attempt kill never touches `user.slice` again.
2. **The lease clock saw a suspension as a lost acknowledgement.** The
   serve's 1.5 s ack budget on the continuous clock interpreted a 2 s
   Ctrl-Z as custodian loss on resume. An expiry can only be decided by
   code that is running: an unexplained wake gap now resets the baseline.

Also fixed on the way: the boot directory is retained as evidence when the
service fails (it was deleted, making every custody failure
undiagnosable); a dropped attempt cgroup no longer kills the next reset
(a vanished boundary is empty by construction); nested secret ids create
their directories; the first `ready` handshake gets a boot-scale deadline.

## Pre-release guest capability measurements

The vm README requires every capability measured on the prepared image
before it may be reported available; [capabilities.json](capabilities.json)
(harness: `capabilities.py`, same warm boot, live share, NAT attached) is
that suite:

| Capability | Measured |
| --- | --- |
| `wall` | The attempt ends at its 5 s deadline — `never` never printed, exit ≠ 0 |
| `pids` | The fork storm spawned in batches and was capped (EAGAIN at the limit), not run to the VM's ceiling |
| `mem` | Unbounded allocation was **OOM-killed at the cgroup limit** (exit 137) — the bound is kernel-enforced, which is the claim |
| `containment` | Writes to `/etc` and `/usr/local/bin` both refused |
| `network_none` | Outbound TCP and DNS both refused with the NAT adapter attached |
| `workspace` | The granted write reached the host with the expected bytes; `.git` untouched |

## Pinned-image manifest (built and verified)

`prepare.py` builds the hashed manifest: the setup script writes the
installed `bubblewrap`/`dbus-user-session` versions in-image and to the
console as `UKAI_PINNED` markers (with `UKAI_STEP` progress markers and a
full `sh -x` trace), and `image.json` records `guest_pinned_versions` plus
their `guest_pinned_digest`
([image13-manifest.json](image13-manifest.json)):
`bubblewrap=0.11.1-1ubuntu0.3`, `dbus-user-session=1.16.2-2ubuntu4`,
digest `26faa9a3…`. The parsing is unit-tested and the built image was
verified end to end against the warm service: three attempts over one
boot, every granted write on the host, `.git` protected, release latency
12.4–14.0 ms ([image13-warm-verify.json](image13-warm-verify.json)), and
the capability suite passes on it
([image13-capabilities.json](image13-capabilities.json)).

The earlier "bootstrap flake" was not a flake: the trace wrapper revealed
`cannot create /usr/local/share/ukai-vm/pinned-versions.txt: Directory
nonexistent` — the manifest edit had placed that write before the
`mkdir`, and `set -e` aborted the script silently. The seven failed
attempts' raw evidence is retained in
[image13-attempts/](image13-attempts/) (including the successful build's
console), and the ordering is fixed.

## `ukai-jail run --vm` drives the warm service (2026-11-03)

The CLI surface is live: `ukai-jail run --vm --profile tool --limit
wall=<seconds>s --workspace <case-sensitive dir> -- <command>` boots the
warm service with the live share (or reuses a running one sharing exactly
that workspace), runs the attempt, and settles through the verified-receipt
path. The recorded run (`run-vm-cli/`, against the pinned
image13; erratum 6): workload output relayed, the granted write on the host, the
protected `.git` denied (`Read-only file system`), **phase settled, exit 0,
`tree_empty: true`**, the guest Linux receipt bound
(`run-vm-cli/vm-binding.json`) and the transport record
written with `workspace_share: live-virtio-fs`. Refusals keep their named
remedies: the build profile on the live share, custom limit ceilings below
the guest's measured floor, case-folding workspaces, a running guest
sharing a different workspace, walls outside the guest grammar, deny-read,
and any network mode until the proxied policy path lands.

## Proxied network policy, live through the CLI (2026-11-03)

The J18 §6 network design is measured end to end
([proxy-policy/](proxy-policy/), harness `proxy_measurement.py`):
`ukai-jail run --vm --profile agent --allow-host api.github.com …` boots
the guest with NAT, the guest jail starts **its own qualified Linux
proxy**, the workload's environment carries the bridge, and:

- the allowed host answers through the proxy (`ALLOWED 200`),
- the denied host (`example.com`) refuses,
- the offline `tool` profile on the same guest still has no egress,

with the attempt settling (`tree_empty: true`, exit 0, transport record
written). The wire carries the canonical allow rules (`Prepare.allow_hosts`
→ guest `--allow-host`; the guest re-parses each with its own grammar and
refuses invalid spellings before any workload runs); a proxied policy
requires a NAT-attached guest — the service boots with the adapter and a
running guest without it refuses with the `ukai-vm stop` remedy; the
receipt rule accepts `proxy` alongside `none` (anything else refuses).

## What remains before a release

The warm service is now measured end to end with the share, but the
release still needs: the `run --vm` client wiring in `ukai-jail` (the
service and protocol exist; the CLI surface does not), the NAT+proxy
policy path (the adapter flag is measured; the proxied policy is the
guest's existing, already-qualified Linux machinery), vault-value
consumption by the guest jail (the transport is measured; the jail-side
binding stays refused), the pinned-image builder (apt is recorded, not
snapshot-pinned), and the full live gate rows on an installed package.
