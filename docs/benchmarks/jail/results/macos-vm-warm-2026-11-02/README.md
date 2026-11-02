# J18 warm service with the live share — first live qualification — 2026-11-02

**Development evidence only. No release gate is promoted; K108–K113 stay
`untested` until their full rows run on a qualified package.** This record
is the warm `ukai-vm serve` running against a real prepared image with the
[live workspace share](../macos-vm-share-2026-11-02/README.md) attached:
twenty attempts over **one boot**, plus the fault matrix and the secret
transport, all on macOS 27.0.1 / Ubuntu 26.04 (image built by `prepare.py`
from this tree, ordinary virtualization entitlement only).

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

## What remains before a release

The warm service is now measured end to end with the share, but the
release still needs: the `run --vm` client wiring in `ukai-jail` (the
service and protocol exist; the CLI surface does not), the NAT+proxy
policy path (the adapter flag is measured; the proxied policy is the
guest's existing, already-qualified Linux machinery), vault-value
consumption by the guest jail (the transport is measured; the jail-side
binding stays refused), the pinned-image builder (apt is recorded, not
snapshot-pinned), and the full live gate rows on an installed package.
