# VM tier probes on the spare Mac — 2026-11-04 evening

**Development evidence from a source build.** The VM tier's capability
harness ran live on the user's spare Mac (Apple M2 Pro, 16 GiB, macOS
27.0.1). `ukai-vm` was built with `cargo build --release --locked` at
`6bd497076`, and `vm/prepare.py` from that tree prepared a new guest image
on the host, with an ad-hoc signed helper and custodian. This run had:

- no Developer ID signature;
- no notarization;
- no package and no `install.sh`.

Nothing here ran an installed or shipped build. **K108–K113 stay
`untested`**; this record promotes no row (see the
[acceptance map](../../../../specs/jail-v1/acceptance-map.toml)). Hashes,
toolchain and run times are in [provenance.json](provenance.json).

**What it changes in the code.** The ten requirements that
[capabilities.json](capabilities.json) measured are now the
`GUEST_MEASUREMENTS` rows in `crates/ukai-jail/src/platform/macos/vm.rs`.
They replace the morning record's five
([macos-vm-live-2026-11-04](../macos-vm-live-2026-11-04/README.md)), which
were measured on an image built from older guest sources. A `tool` or
`agent` plan with an explicit wall of 1–300 s (`--limit wall=<n>s`)
requires only measured requirements now, so it passes probing. What still
refuses at probing:

- the profiles' own walls (30 m for `tool`, 2 h for `agent`), which the
  guest does not carry (`vm:not-carried:limits.wall`), and likewise a run
  without `--terminal detach` or with an environment beyond
  `LANG=C.UTF-8`;
- `execution_boundary`, which a required `pids=64`, `mem=512MiB` or
  `swap=0` ceiling adds (the only values the guest carries; another value,
  or a required `cpu` ceiling, is `vm:not-carried`);
- `credential_staging`, which a launch profile that declares credentials
  adds;
- the owner-loss bound (`--lifetime kernel-bound`, K112);
- any policy `--vm` does not carry (`vm:not-carried:<field>`).

With that table, a client built at `5a394456a` ran 20 real
`ukai-jail run --vm` attempts on one warm boot: each passed probing,
settled and exited 0 (below). These are the first `run --vm` attempts that
got past probing.

## Results

| Harness | Record | Verdict |
| --- | --- | --- |
| `capabilities.py` | [capabilities.json](capabilities.json) | **PASS**: all ten requirements measured on one guest boot |
| `route_diag.py` (one-off, kept here) | [route-diagnosis.json](route-diagnosis.json) | 8 of 8 route controls reached; the morning's route-control failure did not recur |
| `warm_live.py --ukai-jail` (client at `5a394456a`) | [warm-live.json](warm-live.json), [real-client-attempts/](real-client-attempts/) | **PASS**: every gate on 20 stand-in attempts, and 20 real `ukai-jail run --vm` attempts each exit 0, each reaching its workload's host write within the 1 s budget (exit time is not recorded) |

`capabilities.py` and `route_diag.py` used the Python stand-in client
(`harness.run_attempt`), not the `ukai-jail` client. `warm_live.py` used
both: first the stand-in, then the real client against the same serve.

## The measured requirements ([capabilities.json](capabilities.json))

One serve and one guest boot (`vm-6ef11360…`, kernel 7.0.0-38-generic)
ran every probe between 20:32:10 and 20:32:37 UTC. Each
`measurements/<requirement>` entry names its attempts and the start of the
first one. Each attempt's receipt digest and its binding to the attempt
were verified, and each check is a named entry under `facts`.

The five requirements the morning record also measured passed again on
this image:

- `limit:wall`;
- `limit:pids`;
- `limit:mem`;
- `filesystem_containment`;
- `network_none`.

These probes are the same as the morning's, so the morning README
describes them.

The five new probes:

- **`tree_termination`**: the workload started six kinds of descendant:
  - a normal child;
  - one that ignores SIGTERM;
  - one in its own session (`setsid`);
  - a double-forked daemon;
  - a stopped child;
  - one in its own process group.

  Each wrote heartbeats to the live share, read from the host. Two
  attempts were measured:

  - In the first, the target exited with code 0 while every member was
    still running. Members had beaten 12 times.
  - In the second, the guest jail's 5 s wall ended the tree (SIGTERM,
    cause `wall_expiry`). Members had beaten 25 times.

  The stopped member beat twice, then stayed frozen. In both attempts the
  host saw no beat in a 3 s window that opened 1 s after `done`. The guest
  controller's own stop found no populated cgroup, no live process and no
  stray to kill. The receipt's tree was empty. Cancellation was not
  measured: the harness has no mid-run cancel that goes through the guest
  jail (`not_measured.cancel`).
- **`closed_set_observation`**: the ptrace observer attached with the
  `linux-closed-v1` set and no gaps, and counted exactly:

  | Class | 1 round | 3 rounds |
  | --- | --- | --- |
  | `exec` | 6 | 14 |
  | `fs.write` | 1 | 3 |
  | `fs.deny` | 1 | 3 |
  | `net` | 1 | 3 |

  Granted writes reached the host, denied writes were refused, and the
  network namespace refused connects. A background descendant that
  outlived the target was counted too: `fs.write` 4, its one heartbeat
  plus the three background opens. **Not exercised**: that branch's loss
  path. The run lost nothing, so the check that a loss is named
  (`evidence_lost`) held vacuously. Also not measured: which operation
  each count is, because the trace stays in the guest.
- **`syscall_filter`**: inside a `tool` attempt's guest jail (Seccomp
  mode 2, NoNewPrivs 1, two filters matching the receipt), the probe made
  46 calls:

  - **35 denied**, among them: ptrace, the `process_vm_*` and `pidfd_*`
    calls, keyring calls, `perf_event_open`, the `io_uring` enter and
    register calls, mount-family calls, `chroot`, `unshare`, `setns`,
    clock and time setters, `clone3`, an untraced clone, a `CLONE_NEWUSER`
    clone, `TIOCSTI`, a seccomp listener, and AF_UNIX and AF_VSOCK
    stream sockets (under `agent`, below, an AF_UNIX control connected);
  - **11 controls** got the kernel's own answer: `eventfd2`, `uname`, an
    AF_INET socket, `TIOCGWINSZ`, a bad seccomp flag, and others.

  Not measured:

  - 11 calls the kernel refuses an unprivileged caller with `EPERM` before
    any filter, so a denial there cannot be told apart
    (`not_measured.kernel_eperm_first`);
  - 17 calls not probed (`not_measured.not_probed`).

  That a control's answer came from the kernel, unfiltered, is inferred
  from the kernel's documented behaviour, not traced.
- **`protected_coverage:existing_and_root`**: one attempt per profile.

  - **`tool`**: the receipt mounted these read-only:
    - the workspace's `.git` and `.ukai`;
    - a nested repository's `.git`;
    - a deep `.ukai`;
    - a worktree's `.git` file.

    Writes, renames, new files, directories and symlinks there were
    refused (mostly `EROFS`; `EBUSY` and `EXDEV` for renames of mount
    points), and the host copies were unchanged. A missing root `.ukai`
    could not be created. Look-alikes were created as controls:
    `.git-sibling`, `.ukaix`, `x.git` and `.github`.
  - **`agent`**: `.git/config` and `.git/hooks` were refused the same way,
    in the workspace and in a nested repository. The rest of `.git` stays
    writable, and a control file was created there.
- **`network_proxy`**: an `agent` attempt allowed one target, and the
  results were:

  - the allowed target through the proxy: `200 Connection established`;
  - another host, another port and loopback through the proxy: refused
    with `403`;
  - a direct connect: denied;
  - the loopback and AF_UNIX controls: connected.

  The receipt applied the proxy with exactly that target and counted
  every request.

**Development limits**:

- one source build on one host;
- one run of each probe;
- the guest jail is the published 0.1.0-rc.5 for aarch64.

## Route diagnosis ([route-diagnosis.json](route-diagnosis.json))

The morning record's `warm_live.py` route control failed twice, each time
after 20 attempts on one boot, while `capabilities.py`'s control on a fresh
boot reached the target. [route_diag.py](route_diag.py) asked whether the
guest's egress decays with attempt count or idle time. On one boot with NAT
it ran `agent` route controls to `1.1.1.1:443` and `8.8.8.8:443` at four
points:

- at boot;
- after 20 tool attempts;
- after 300 s idle;
- again right after.

Each control was paired with the host's own reachability check of the same
target. All 8 reached their target (`200 Connection established`). The
failure was not reproduced, and its cause is undetermined.

## The real client ([warm-live.json](warm-live.json))

`warm_live.py` booted one serve with NAT (`vm-bd7c8b5c…`, kernel
7.0.0-38-generic) and ran its 20 stand-in attempts and route control
there. Every gate passed:

- one serve boot and one guest boot;
- verified receipts;
- granted writes on the host and protected writes refused;
- the jail's network denial, next to a route control that reached
  `1.1.1.1:443` on the same boot;
- a clean guest stop on every attempt.

Stand-in connect-to-release took at most 107 ms.

Then, against the same serve and data directory, it ran 20 real
`ukai-jail run --vm --terminal detach --profile tool --limit wall=20s`
attempts, each `/bin/sh -c 'printf x > released-<tag>-<i>'` on the live
workspace, between 21:01:39 and 21:01:47 UTC. Every one exited 0, with no
refusal. From exec of `ukai-jail` to the marker file appearing on the
host took 249–481 ms. That span covers the client's start, probing, the
serve status check, the attempt up to the workload's write, and the share
making that write visible; it ends before the attempt settles.

[real-client-attempts/](real-client-attempts/) keeps the 20 attempt
directories the client wrote. A check of all 20 (not part of
`warm_live.py`) found:

- each host receipt `settled`, outcome `exited` 0, no errors;
- `lifetime.integrity` `verified`, `tree_empty` true;
- `guest_receipt_sha256` equal to the SHA-256 of `evidence/jail.json` and
  to `vm-transport.json`'s digest;
- `evidence/vm-binding.json` naming the host and guest attempt ids;
- one serve boot and one guest boot for all 20;
- the guest stop's boundaries in `vm-transport.json`;
- the same coverage in each: 2 `exec`, 1 `fs.write`, no gaps.

`ukai-jail tail --summary` on one of them printed the host summary plus
the transport line. Its duration read `0ms attempt (wall clock)`: without
a host journal, the summary subtracted the receipt's whole-second
timestamps, so it printed at a precision the record does not have. Over
the 20 receipts that gives `0ms` for the 11 whose two stamps share a second
and `1.0s` for the other 9. Since `3b31aad90` the summary prints `under 1s`
or `1s ±1s` for such stamps. The transport record's own `elapsed_seconds`
(0.28–0.33 s) is the host's measurement.

**Not shown here**:

- `agent` or any proxied run through the real client;
- credentials or a launch profile;
- a signaled or limit-hit outcome through the real client;
- an attempt whose guest stop found something to kill;
- an installed package.

## Files

- [capabilities.json](capabilities.json): the capability record (schema
  `ukai.vm.capabilities/2`).
- [route-diagnosis.json](route-diagnosis.json) and
  [route_diag.py](route_diag.py): the one-off diagnosis and its script.
- [warm-live.json](warm-live.json) and
  [real-client-attempts/](real-client-attempts/): the warm run with the
  real client, and the 20 attempt directories that client wrote.
- [image/](image/): the image manifest, the bootstrap console log and its
  event lines.
- [logs/](logs/): the console output of the build, the image preparation,
  the capability run, the diagnosis and the warm run.
