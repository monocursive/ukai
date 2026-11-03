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
path. The recorded run ([run-vm-cli/](run-vm-cli/), against the pinned
image13): workload output relayed, the granted write on the host, the
protected `.git` denied (`Read-only file system`), **phase settled, exit 0,
`tree_empty: true`**, the guest Linux receipt bound
([vm-binding.json](run-vm-cli/vm-binding.json)) and the transport record
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
