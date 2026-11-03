# Jail proposal: native-first macOS, defended custody and an optional warm VM (J16–J18)

Status: work in progress on `dev` (merged 2026-10-23), decisions of 2026-10-22 with the 2026-10-23 declared-set amendment and the 2026-11-01 native-first plan (§13);
J16–J18 are not supported or released. `dev` at `ae14865f8` was the
refusal-only baseline before this implementation was merged.
Current implementation: native execution is **off by default**. Setting
`UKAI_JAIL_MACOS_NATIVE=dev` enables development only; a native receipt records
`native_execution=dev`. Native credential, vault and vendor staging answer
`unsupported` and refuse. J17 is wired before release (`J17_OBSERVE=true`):
`macos-closed-v1` declares the exact ES notification set; loss-free attached
`exec` and `fs.write` coverage is active only over that set. Synthetic producer
receipts are tested; live development-VM smoke runs also attach and report the
declared set, without satisfying K105–K107 release qualification.
`ukai-jail run --vm` is wired to the warm `ukai-vm` service, but every
attempt refuses at probing, before any connection or boot, until a live
phase re-measures the guest: the probe answers Available only for a
requirement a measured guest record backs, that table is empty, and every
other requirement answers `vm:not-measured:<requirement>` (§6).
The [2026-11-01 measurement spike](../benchmarks/jail/results/macos-custody-spike-2026-11-01/README.md)
runs this implementation with live Endpoint Security in an isolated,
SIP-disabled development VM. It exposes a K90 class-2 blocker: an existing
launchd job can be kickstarted from the sandbox and signal either custodian,
including with the candidate `mach-bootstrap` denial. NC01 is not accepted.
J16 lacks the bundle, Info.plist, entitlements and `~/Applications` installer.
J18's K108–K113 are `untested`: the 2026-11-02/03 development measurements
on the dev Mac do not meet their clauses (§6). A policy element the guest
jail does not carry refuses with `vm:not-carried:<field>`, and no macOS
`ukai-jail` client ships: the VM package carries only `ukai-vm` and
`ukai-vm-install`, so the client is built from source. The spike records
K92/K93 results and process-limit adjustments; development measurements do
not complete the release rows (§4.12).
Apple's entitlement and the protected-Mac acceptance run (K104) remain
release gates, alongside completing and validating the implementation.
Sections below specify release requirements where they describe behavior
beyond those gates; they are not live acceptance evidence. Historical
prototype evidence is identified separately.
Decisions were settled on 2026-10-22 (§12). The proposal was written against
`dev` at `68512e1f1`, after
Apple Developer Technical Support answered code-level support case `22799543`
(the [question and answer](../benchmarks/jail/apple-lifetime-question.md)).
The [DTS follow-up relayed on 2026-11-01](../benchmarks/jail/apple-lifetime-question.md#notification-load-follow-up-relayed-2026-11-01)
resolves the notification-load question and qualifies the both-lost residual
below. It supplies guidance, not new live acceptance evidence, and waives no
stress test or release gate.

- **The direction.** Native macOS is the everyday path after qualification:
  familiar local tools, an ordinary terminal session and project-scoped
  permissions. The Linux VM is an explicit option for stronger lifetime and
  resource requirements. Complete one Claude workflow before expanding native
  compatibility (§13); this changes implementation priority, not release gates.
- **The reviews.** The draft was revised after two independent reviews, an
  adversarial review of the mechanisms and a consistency review against
  jail-v1, jail-v2 and J12–J15, and again after a third review of the
  revision.
- **The decisions.** The operator asked for the best and simplest answer to
  each open question, and §12 records them.
- **What it replaces.** This proposal replaces the lifetime design of
  [jail-v2](jail-v2.md) §8 (J11), and keeps its §8.1 containment design.
  K23–K26 move into J16.
- **Provisional names.** The milestone names J16–J18 and the row numbers
  K87–K113 follow J15's K76–K86.

Each claim says where it comes from:

- **measured**: a run whose evidence is in this repository;
- **by reading**: Apple documentation, SDK headers or published XNU source, not run;
- **DTS guidance**: Apple's support replies as relayed in the Q&A record, not run;
- **inferred**: argued from those, not observed.

Normative words follow jail-v2. **must** is a release gate. **initial** is a
tunable default that must be recorded. **candidate** is unproved until the
named measurement passes.

Apple's answer to "does macOS provide a supported, kernel-owned boundary that
stops every descendant once every userspace custodian is gone?" was:
*"No, nothing like this currently exists."* Apple's suggestion was to make the
custodians defend themselves against workload control. Each custodian holds an
`es_new_descendants_client`, which *"can defend itself from all child activity.
External events may still terminate it, but its children cannot."* So native
macOS cannot meet the Linux lifetime contract, and no amount of further work
changes that. This proposal stops trying to. It proposes two tiers and requires the receipt to state which boundary a
run had. The following table is the intended release contract; the current
implementation gates above remain in force:

| | Native tier (J16, J17) | VM tier (J18) |
| --- | --- | --- |
| Runs | macOS programs, natively | Linux arm64 programs in a guest |
| Start | per run, three ES clients (S, G, G′; four with J17) and one extra process; the single-client prototype was ready in 40–70 ms p50 (measured, development VM) | warm: the Linux jail's own start; cold: about 22 s (measured, preview) |
| Containment | Seatbelt (jail-v2 §8.1) | the Linux jail, unchanged, inside the guest |
| While a custodian lives | the tree ends on stop, verified (§4.5) | the tree ends on stop, verified (jail-v1) |
| If every Ukai process of the attempt is lost | **the tree may survive**, whatever the cause. Direct workload control must be denied; client bugs and workload-induced memory pressure are not excluded (§4.7). | the guest's own death chain ends it, as on any Linux host (§6) |
| Receipt's `lifetime.boundary` | `native_tree` | `pid_namespace` (a Linux receipt) |

The native tier is the intended default after qualification. Today the
default refuses; the development opt-in does not make it supported. A run
that needs a kernel-bound lifetime must use a supported Linux deployment or
the separate released VM preview within its documented limits. `run --vm`
in this tree refuses at probing until the guest is re-measured (§6).

## 1. Scope

Release targets (not all implemented):

- **J16, the native tier.** Seatbelt containment and two Endpoint Security
  custodians. Covers `tool`, `build` and `agent`, headless and in terminal
  mode, with J12 launch and J14 persistent vendor state. J17 observation is
  included in the first complete native Claude workflow; observation off
  remains an explicit policy choice, not its acceptance baseline.
  Includes receipts, `gc`, `doctor`, packaging with the entitlement, and the
  rows of §9.1.
- **J17, native observation.** Exec and filesystem-mutation evidence from a
  separate ES client (§5).
- **J18, the VM tier.** The released VM preview becomes a warm, shared-workspace
  backend selected with `--vm`. It also adds the policy key that requires a
  kernel-bound lifetime (§6).

The implementation order and additional workflow acceptance criteria are in
§13. Native remains off by default until qualification. There is no silent
fallback between native, VM and uncontained execution. A native Claude
workflow milestone does not remove the other compatibility obligations in §9.

Out of scope, each its own later work:

- `--profile none` on native macOS. It refuses (§4.10).
- Kernel-enforced `pids`, `mem` and `cpu` limits on native macOS. Explicit
  requests refuse as jail-v2 §8.1 says, and custodian-enforced limits are an
  open question (§11).
- Command rules and `learn` on native macOS. Both stay refused (jail-v2 §7.2
  and §8.1).
- Importing a Claude Keychain credential (north-star §4.5 leaves it
  unscheduled). A future vault path is specified in §4.11; native
  credential staging currently refuses.
- macOS guests in the VM tier, Intel Macs, and macOS before 27.
- Any private interface: coalition management, `task_get_fatal_port`, and
  `sandbox_check` on other processes.

## 2. Invariants kept

- **A missing required guarantee refuses** (north-star D12). The native tier
  never runs a policy that requires more than it has. From J18 on, that
  includes a kernel-bound lifetime (§6).
- **Nothing claims more than the evidence.** `tree_empty=true` needs the drain
  proof of §4.5, which requires the root to have entered the table and no
  detected stream gap. The pre-first-message limit remains disclosed (§4.4).
  Every other end is
  `tree_unknown`. The boundary value says on every receipt whether a kernel
  would have ended the tree without any Ukai process (§3.2).
- **Vaulted credentials never enter the sandbox** (J12 §3.5). The workload is
  also denied the Keychain (§4.10), because there the operator's tokens are
  one Mach lookup away. Current native credential staging, including vault,
  copy and bind modes, is unsupported and refuses before staging. The Linux
  staging contract is unchanged.
- **The jail configures no host** (jail-v1 §3, and north-star D9 in spirit).
  The native tier installs no launchd job, system extension or root helper,
  and needs no sudo or SIP change (jail-v1 §3.3). It does need Apple's ES
  entitlement in its signature, which is a property of the distributed binary,
  not of the host.
- **Linux is unchanged.**

## 3. The lifetime contract on macOS

### 3.1 What Apple confirmed, and what was measured first

Apple's answer settles the question that the native research lane left open.
The research had already shown that no mechanism within reach closes the gap:

- **Two reciprocal ES custodians** (2026-09-30 `macos_es_pair.c` prototype,
  development VM, `(allow default)` profile; not the J16 implementation):
  - **Either one killed:** the other emptied the seven-process fixture in 40
    of 40 trials.
  - **Either one stopped:** emptied in 40 of 40 trials, through a 750 ms
    heartbeat that this design replaces with the wall deadline (§4.6).
  - **Both killed:** the fixture was empty in 0 of 20 trials, and all seven
    processes survived.
  - **Fail-closed `AUTH_EXEC`:** a survivor still executed a new command in
    10 of 10 trials.

  Source: [reciprocal custody](../benchmarks/jail/macos-reciprocal-custody.md).
- **Debugger death** cleaned up attached targets, but later fork and spawn
  children survived (development VM,
  [kernel lifetime](../benchmarks/jail/macos-kernel-lifetime-2026-10-10.md)).
- **Inherited Mach exception ports** became dead handlers when their owner
  died, and execution continued (development VM,
  [Mach lifetime](../benchmarks/jail/macos-mach-lifetime-2026-10-10.md)).
- **launchd jobs, process groups and `NOTE_TRACK`** left descendants running
  or were refused, measured on this Mac
  ([native mechanisms](../benchmarks/jail/macos-native-mechanisms.md)).
  Coalition termination was found by reading not to kill. XPC lifetime and
  audit sessions left descendants running in the development VM
  ([native services](../benchmarks/jail/macos-native-services-2026-10-10.md)).

Apple's two-level architecture is the shape the reciprocal prototype already
has: a guardian and a ward, each with its own descendants client. The new
implementation changes the heartbeat, defense, startup and stop paths; the
prototype does not validate them. The release requirement is that one
surviving custodian can stop and verify the registered tree under §4.5's
conditions. Direct workload control of either custodian, including through
other services, must be denied. This does not establish immunity to client
bugs or workload-induced memory pressure. Loss of both custodians leaves the
disclosed possibility of survivors, whatever its cause; "external-only" is
not a proven property of the residual.

In the follow-up relayed on 2026-11-01, DTS confirmed that notification
overload drops messages, observable through sequence gaps, rather than
terminating a notification-only client. DTS also suggested delaying
`AUTH_EXEC` approvals for backpressure and configuring authorization deadlines
and a non-kill deadline-miss mode. That is guidance, not a measured result for
this implementation. The design retains notification-only custody during
execution and the separate fail-closed guard during teardown. K93 still
validates event handling and load; K96 still measures memory-pressure survival.

### 3.2 Owner loss, read from the boundary

The question "*if every Ukai process of this attempt is gone, does a kernel
still end the attempt's tree?*" is answered by `lifetime.boundary`, which
every receipt already carries. No new field is needed:

| `lifetime.boundary` | Answer | Why |
| --- | --- | --- |
| `pid_namespace` (Linux contained, and the VM tier's guest receipt) | Yes | The death chain ends in the namespace init, whose death kills the namespace (jail-v1 §9.3). That section also records a limit: during bubblewrap's start-up, before `prepared`, an attempt without an execution leaf can leave the namespace init and its helpers alive. No target instruction has run by then. |
| `supervisor_cgroup` (Linux `none`) | No | `none` keeps its accepted unknown lifetime after owner loss (jail-v1 §8.2), and its end is verified only for the registered boundary (jail-v1 §9.3). |
| `native_tree` (macOS native) | No | The tree ends only while a custodian lives (§4). |

The J13 summary line says the same in words (§4.8). A policy key that
*requires* a kernel-bound lifetime arrives with J18 (§6), the first milestone
in which a Mac can satisfy it. Until then, a team that needs it on a Mac uses
Linux.

### 3.3 Why not the VM alone

Every native mechanism is weaker than the VM boundary, but the VM is heavy for
everyday use:

- It runs Linux programs only, so Xcode, Mac-built native dependencies and
  macOS-only tools are excluded.
- A cold start took about 22 seconds in the preview.
- It holds memory while it is warm.

For the interactive laptop case that the adoption ranking puts first, the
native tier is what people will use. So the native tier must be honest about
what it is. The VM backend is wired but unqualified; the current
`run --vm` path refuses at probing, before any connection or boot (§6).

## 4. Native tier: defended custody (J16)

### 4.1 Design rules

These rules are the design. The rest of §4 applies them.

1. **While the workload runs, the kernel does the defending.** Seatbelt
   denies the workload every way to signal, suspend, debug or control a
   process outside its sandbox, and every way to start one (§4.7). No
   custodian holds an authorization subscription while the workload runs. A
   slow, stalled or busy custodian therefore weakens no denial. The one
   authorization subscription in the design belongs to the guardian's
   separate guard client, during a stop. There every answer is a denial, and
   a missed deadline denies without killing the client (§4.5).
2. **Two custodians, independent.** The supervisor is one. The other is the
   guardian: the same `ukai-jail` executable, started in its guardian mode.
   That mode is dispatched before any configuration, policy or I/O setup,
   and its code path is small, as Apple advises: libc, the ES shim and
   audit-token signalling (decision 2). Each custodian has its own
   descendants client and its own membership. Either one alone can end the
   tree and prove its end.
3. **Custody code reads fixed-size fields only.**
   - Custody streams carry `NOTIFY_FORK`, `NOTIFY_EXEC` and `NOTIFY_EXIT`, and
     nothing else. Observation has its own client (§5).
   - A custody handler reads only the event type, the sequence numbers, the
     audit tokens and the exit status. It never reads a path, argument,
     environment or any other variable-length field that the workload
     controls. This avoids parsing those fields on the custody path; it does
     not prove the absence of shared client bugs. Apple names client bugs as
     the main risk.
   - Exec is in the set because exec replaces the audit token's PID version
     (by reading, `ESMessage.h`). The prototype's reported 900-of-900
     count is observed, not recorded with a reproducible derivation; it is
     not acceptance evidence for this implementation. A custodian that
     missed an exec could no longer signal that member.
4. **After release, the custody path acquires nothing.** The custody path is
   the guardian, and the supervisor's handler and stop. It forks no process,
   opens no descriptor and allocates no memory. The membership table is
   preallocated for `kern.maxprocperuid` live members, and a slot is reused
   when its member exits. Exhausting process slots, file tables or memory
   therefore cannot block a stop. The guard's subscription at a stop is the
   one exception. If it fails, the stop proceeds unguarded and says so (§4.5).
5. **Identity is the audit token**, updated at every exec. Every signal goes
   through `proc_signal_with_audittoken`. A PID never goes through `kill(2)`.
6. **Growth is bounded.** Before it spawns the launcher, the guardian lowers
   its own `RLIMIT_NPROC` soft and hard limits to the operator's current
   process count plus `PROCESS_HEADROOM=1024`; neither inherited limit is raised.
   Preparation refuses if either inherited limit cannot provide that full
   allowance. A successful set is insufficient: kernel read-back must confirm
   both limits at the requested ceiling, or preparation refuses (including
   kernel clamping below the allowance). Only after this check does the
   guardian report the allowance it applied, in one `allowance` frame on B
   immediately before `ready` (§4.3 step 3). Every receipt from `prepared`
   on records that report (§4.8), never a value the supervisor computes
   itself, and the guardian record repeats it (§4.4).
   **Amended 2026-11-02** (measured in the 2026-11-01 spike: a default host's
   `kern.maxprocperuid` is 1333 and the guardian refused wanting 1376): when
   the full 1024 does not fit under the inherited ceiling, the allowance is
   the inherited ceiling itself — never raised, still kernel-bounded, and the
   membership table is sized for exactly that ceiling — provided the ceiling
   still clears the operator's snapshot by at least 128 processes; below that
   there is no room for a tree and preparation refuses, naming the numbers
   and the remedy (close processes or raise `kern.maxprocperuid`); that
   refusal comes before any `setrlimit`. The inherited ceiling is
   min(soft, hard), the lower of the inherited soft and hard limits. The
   clamped path lowers both limits to it (soft = hard = ceiling, so a member
   cannot raise its soft limit back up to a higher hard limit; neither is
   ever raised) and confirms both by the same kernel read-back as the full
   allowance. On both paths the limits are read again just before
   `setrlimit`, and preparation refuses if either has moved below the
   decided limit; a limit that rose after the decision is not refused, and
   both are still lowered to the decided limit. After `setrlimit` the
   kernel read-back must show soft and hard both exactly at the decided
   limit, or preparation refuses. **Corrected 2026-11-03 (fix wave 1103, D13):** the clamped
   path first shipped setting nothing and only re-reading the limits, so a
   member could raise its soft limit as far as the kernel lets a non-root
   process: min(hard, `kern.maxprocperuid`), measured on the development
   Mac ([record](../benchmarks/jail/results/macos-nproc-raise-2026-11-03/README.md)).
   Where the inherited soft limit already equals `kern.maxprocperuid` (that
   Mac's default: soft 10666 = `kern.maxprocperuid`, hard 16000) that gains
   nothing; where an operator's soft limit sits below it, a member could
   climb back past the reported ceiling. And the receipt recorded the
   supervisor's own plan, a separate process-count snapshot taken after the
   guardian's, not what the guardian applied. Both paths now lower both
   limits, the supervisor plans nothing, and the receipt records the
   guardian's `allowance` report as `process_limit`, `process_headroom` and
   `process_headroom_clamped`.
   On a clamped host a fork storm stops at
   the kernel's own per-UID ceiling instead of the headroom — the operator's
   session is already within the headroom of that ceiling, which is the
   protection the rule offers there. Every member inherits the limit, and
   none can raise it without
   root. XNU checks the per-user process
   count against the forking process's limit (by reading; candidate, K92). A
   fork storm stops at the headroom instead of exhausting the operator's
   session, and a stop has a bounded set to freeze.
7. **A stop freezes, kills and proves** (§4.5).
   - **Safety:** a stop never gives a false `tree_empty`. This follows from
     ES's delivery order alone.
   - **Liveness:** the stop finishes within its budget. This is a candidate,
     argued and then measured. A stop that runs out of budget is
     `tree_unknown`, and the guardian keeps working.
8. **The one residual is named.** If both custodians are lost, the next `run`
   or `doctor` says so (§4.9).

### 4.2 Processes and membership

```text
operator shell
  └─ ukai-jail                  supervisor · ES client S (custody)
       └─ ukai-jail (guardian)  own process group, terminal signals ignored · ES clients G (custody), G′ (guard, at a stop)
            └─ sandbox-exec ─exec→ Ukai launcher (new session, inside the profile, blocked) ─exec→ target
                 └─ the attempt's tree
```

**Members** are the launcher (the `sandbox-exec` child, under every later
token) and its descendants.

- **Client G.** Its scope is the guardian and its descendants, and the
  guardian forks only the launcher. So every process G reports, other than
  the guardian, is a member.
- **Client S.** Its scope also holds the supervisor and the guardian, and the
  supervisor starts no other process during an attempt. So every process S
  reports, other than those two, is a member.
- **Entry.** A member enters the table on the first event that names it,
  which is normally its fork event.

So a stop never signals a custodian.

**Order.** The guardian sits below the supervisor, not above it as in Apple's
sketch, because the supervisor has to stay the operator's foreground process
(§4.11). Defense comes from Seatbelt, which covers both custodians whatever
their order.

**The guardian's signals.** The guardian ignores `SIGHUP`, `SIGINT`,
`SIGQUIT`, `SIGTERM`, `SIGTSTP`, `SIGTTIN` and `SIGTTOU`, and runs in its own
process group. It acts only on pipe A's end (§4.3) and on the wall deadline.
The two custodians share a process name, so `killall ukai-jail` signals both.
Its default `SIGTERM` is an orderly stop: the supervisor stops the run, and
the guardian ignores the signal and ends the tree on A's end-of-file.
`killall -9 ukai-jail` kills both, which is the named residual (§4.6). The
guide says to stop a run with `^C` or a plain `kill` of the supervisor. Ignored dispositions
survive `posix_spawn` and exec, so the launch block carries
`POSIX_SPAWN_SETSIGDEF` and `POSIX_SPAWN_SETSIGMASK`. They restore those
signals to their default disposition and restore the supervisor's signal
mask. A signal the supervisor itself inherited as ignored, as under `nohup`,
stays ignored, as it would without the jail.

### 4.3 Start, prepared and release

The order follows jail-v1 §8.1. The target launcher is blocked inside the
final boundary before `prepared`.

1. **Client S.** The supervisor resolves the policy and prepares the attempt
   directory as on Linux. Before any other process of the attempt exists, it
   creates client S and unmutes every default-muted path and target path
   (`es_unmute_all_paths`, `es_unmute_all_target_paths`). It then subscribes
   the three custody events and reads `es_muted_paths_events` back.
   - Refuse if anything is still muted. ES mutes a default set at client
     creation, which is mostly authorization events, and that set "may change
     across macOS releases" (by reading, `ESClient.h`).
   - Apple advises against unmuting that set. It protects system daemons whose
     authorization events would otherwise stall, but a descendants client
     never sees a system daemon, and the custody clients hold no
     authorization subscription.
   - Refuse if client creation fails, naming the result code.
     `ERR_NOT_ENTITLED` (`es_not_entitled`) refuses with remediation
     `unsupported`; `ERR_TOO_MANY_CLIENTS` (`es_too_many_clients`) uses
     `retry`. These mappings apply to requirement checks in inspect and run.
2. **Spawning the guardian.** The supervisor creates:
   - the guardian record (§4.4);
   - pipe **A**, supervisor → guardian, and pipe **B**, guardian → supervisor;
   - the launcher's release pipe **R** and error pipe **E**, as on Linux.

   It spawns its own executable in guardian mode with only these inherited:
   - its standard descriptors;
   - the record and the guardian's ends of A and B;
   - the launcher's ends of R and E, which the guardian passes on and closes;
   - in terminal mode the relay's pty slave, and otherwise the child's end of
     each stdio relay. Under jail-v1 §8.3 a regular-file or socket stream is
     relayed: the launch block names a supervisor-owned pipe end in its
     place, and the supervisor keeps the operator's descriptor. The guardian
     passes each on and closes it;
   - the launch block, which holds the `sandbox-exec` argv, environment,
     working directory, standard-descriptor actions, the signal attributes of
     §4.2, and `POSIX_SPAWN_SETSID`. Every launcher starts a new session.
     The renderer escapes path bytes as SBPL literals in a fixed template,
     rejects values it cannot represent, and records the public parameters.
     It does not pass them through `sandbox-exec -D`.
   - the grace period.
3. **Clients G and G′.** The guardian creates its custody client G,
   unmutes it and checks it as in step 1, and subscribes the custody events.
   It also creates the guard client G′:
   - it sets and reads back `ES_DEADLINE_MISS_MODE_FAIL_CLOSED`;
   - it unmutes it, and mutes the guardian's own process (`es_mute_process`);
   - it subscribes nothing until a stop (§4.5).

   The guardian then lowers `RLIMIT_NPROC` (rule 6), sends `allowance` (the
   limit, headroom and clamp flag the kernel read-back confirmed), then
   `ready` on B. A handshake without exactly one `allowance` before `ready`
   refuses: `ready` without it, a second `allowance`, one that does not
   decode or carries values rule 6 cannot produce, or any other frame in
   their place. If any of this fails, it exits naming the failure, and the
   supervisor refuses.
4. **Launch.** The guardian calls `posix_spawn` once for `sandbox-exec`. It
   interprets nothing in the launch block: it turns the block into
   `posix_spawn` arguments and nothing else. It then closes its copies of R,
   E and every stdio source the block names (a standard descriptor passed
   through, a stdio relay's pipe end, or the pty slave), so that end-of-file
   means what it does on Linux (jail-v1 §8.3). A standard descriptor the
   block does not name, because its stream is relayed or a pty is attached,
   stays open in the guardian; no member inherits it. `sandbox-exec` applies the profile
   and executes the Ukai launcher, which is `ukai-jail`'s launcher mode,
   running inside the profile. The launcher:
   - marks its ends of R and E close-on-exec;
   - in terminal mode, takes the relay's pty slave as its controlling
     terminal (§4.11);
   - reports `blocked` on E and waits on R.
5. **Prepared.**
   - On `blocked`, the supervisor sends the launcher's current token from
     client S on A.
   - The guardian answers on B once client G's table holds that same token.
   - Both engines register the expected launcher root and known custodian
     tokens before replaying buffered handshake events in order. A buffered
     overflow or gap must remain an integrity failure, never be discarded.
   - Every requirement is then applied. The supervisor persists the
     `prepared` receipt and publishes `prepared`, and waits for `--gate-fd`
     if one was given (jail-v1 §8.1 step 6).
6. **Release.** The supervisor writes the release deadline frame on A, then
   `release` on R and closes its R write end. A stays open until stop. The wall deadline runs on the continuous clock
   (`mach_continuous_time`, which counts sleep), from release, on both
   custodians.
7. **Exec.** The launcher executes the target, exactly as the Linux launcher
   does. A failed exec arrives on E with its errno and keeps jail-v1's
   distinctions (`exec_error`, `ENOENT` and `EACCES`, a missing interpreter):
   the attempt is `refused`. A successful exec closes E, and the launcher's
   next `NOTIFY_EXEC` on client S confirms it. That event is counted, not read
   (rule 3), and its token is the target's identity.

**End-of-file on pipe A means stop.** The supervisor stops the tree by closing
its end. Its death closes it the same way, so a deliberate stop and a lost
supervisor run the same guardian path.

- **A and B.** Only the two custodians hold them. Each frame is a little-endian
  u32 length followed by at most 4096 bytes. Oversize or malformed frames are
  protocol loss; the guardian stops and the supervisor records guardian loss.
  Integers in a payload are little-endian.
  - **A** (supervisor → guardian): `launcher-token ` + the launcher's audit
    token (eight u32, step 5), and `release-deadline ` + the wall deadline
    (u64, an instant in continuous-clock nanoseconds; `u64::MAX` releases
    with no wall watchdog, step 6).
  - **B** (guardian → supervisor), in this order: `allowance ` + limit
    (u64) + headroom (u64) + clamped (one byte, 0 or 1), then `ready` (step
    3); `token-seen` (step 5); and at the stop `record ` + the guardian
    record's JSON (§4.4).
- **R and E.** The supervisor and the launcher hold them. The guardian holds
  them only until its spawn returns.
- **Close-on-exec.** Every pipe descriptor is close-on-exec, except the
  launcher's ends of R and E, which must survive `sandbox-exec`'s exec until
  the launcher marks them.

An inherited write end of A would delay the guardian's stop until the wall
deadline. K91 checks every descriptor of every member.

The target's outcome comes from client S's `NOTIFY_EXIT` wait status for the
target's token (by reading, `ESMessage.h`). There is no second source.

### 4.4 Membership and the guardian record

The guardian stop record is `guardian.json` in the attempt directory. The
supervisor creates it before spawning the guardian; GC uses the same name.
Once the handshake names the guardian, and before release, the supervisor
also persists the guardian's identity in `guardian-identity.json`, so `gc`
can establish the guardian dead even when both custodians are lost before
its record is written (K95).

Each custodian keeps a table of members, keyed by PID, that holds each
member's current audit token:

- **The first event naming a member** (§4.2), normally `NOTIFY_FORK`: the
  member enters with its token. A full table is an integrity loss. It cannot
  fill below the per-user process limit.
- **`NOTIFY_EXEC` of a member:** the member's token is replaced by the
  target's. If the target's user ID differs from the member's (a setuid
  program), the custodians can no longer signal it, and that is an integrity
  loss. The profile denies such programs (§4.7), so this is detection, not
  the defense. A changed group ID alone does not affect signalling, and is
  not an integrity loss.
- **`NOTIFY_EXIT` of a member:** the member leaves, and its slot is reused.
- **Any gap** in a message's sequence numbers (`global_seq_num` overall,
  `seq_num` per type) marks the stream `gapped` for the rest of the attempt.
  Per `ESMessage.h`, a jump in those numbers counts dropped messages (by
  reading). The checker accepts first values 0 or 1 and rejects a later
  starting value. The SDK does not promise the first-value baseline: a drop
  before the first delivered message that still fits 0/1 is indistinguishable.
  Contiguity after the first message cannot prove absence of that loss.
  Prototype contiguous sequences were measured; K93 still needs a live
  forced-gap run on this implementation.

The **guardian record** is a small file that the supervisor creates in the
attempt directory before it spawns the guardian. The guardian writes it once,
when its stop ends, and sends the same result on B:

- `drained`, or `not_drained` with the reason (`gap`, `integrity` or
  `budget`);
- counts and timestamps;
- its own token and the launcher's first token;
- the boot session (`kern.bootsessionuuid`);
- `process_allowance` (`limit`, `headroom`, `clamped`): rule 6 as the
  kernel confirmed it, the same values the guardian sent in its `allowance`
  frame before `ready` (§4.3 step 3). The supervisor rejects a record that
  omits it or disagrees with the frame, as it rejects a malformed one: one
  guardian applied one allowance, and the attempt then has no accepted
  guardian record;
- `sequence_start: "unverified"` on every record, disclosing the
  pre-first-message residual even when `drained` is true.

The guardian record has no stop trigger. Adding that evidence is a known
follow-up: after the deadline, a drained record alone cannot establish a
wall hit when the supervisor did not observe the trigger (§4.8).

The record is how `gc` learns how a stop ended once the supervisor is gone.
The workload cannot reach it: the attempt directory is outside every
child-visible root, and Seatbelt denies it.

### 4.5 Stopping the tree

A stop is triggered by target exit, an operator signal, the wall deadline, a
fatal error or a gap under strict evidence. The supervisor gives the jail-v1
§9.3 cooperative grace (`SIGTERM` to the target, initial 2 s), then closes A
and stops the tree itself. On A's end-of-file, the guardian runs its own stop
on its own table. It also starts one on its own when the wall deadline plus
the grace passes. The two signal the same identities, which is harmless, and
neither waits on the other.

A synchronization timeout is not a gap. The initial synchronization is a
bounded delivery wait; a timeout continues polling the stream. Root entry,
actual sequence/ring loss and identity integrity still govern the drain
verdict. Neither a successful wait nor a timeout establishes completeness.

The stop, per custodian:

1. **Guard (the guardian only).** Subscribe client G′ to `AUTH_SIGNAL`,
   `AUTH_PROC_SUSPEND_RESUME` and `AUTH_EXEC`, and deny every request it
   delivers.
   - Every request G′ delivers comes from a member: its scope is the guardian
     and its descendants, and it mutes the guardian.
   - Fail-closed mode denies a late or dropped answer, and never kills the
     client (by reading, `ESTypes.h`).
   - G′ is a separate client, so its load never gaps the custody stream on G.
   - From here on, no member can resume another, signal anything or exec, so
     every member's token stays stable.
   - If the subscription fails, the stop proceeds unguarded and records it.
2. **Freeze.** Send `SIGSTOP` to every member, and to each newly reported
   member on arrival. Repeat the sweep over the whole table every settle
   interval (initial 20 ms). A kernel-originated `SIGCONT` passes neither ES
   nor Seatbelt; one is sent, for example, to an orphaned process group that
   holds a stopped member (by reading, XNU). `ESRCH` for a member that has no
   exit event means an exec from before the guard is still unprocessed.
   Signal that member again with the new token when the exec arrives. The
   freeze ends when a full sweep finds every member stopped and no new member
   has arrived since the previous sweep.
3. **Kill.** Send `SIGKILL` to every member, and to each newly reported member
   on arrival.
4. **Drain.** The stop requires the root to have entered the table. An empty
   table without that root, including one that held only unrelated members,
   never proves drainage. Once the root entered, every recorded member must
   have its exit event, with no detected gap or identity integrity loss.

**Safety: the drain proof.** ES delivers a client's messages strictly
serially, in the order they were enqueued, and a fork's message is enqueued
inside the fork (by reading, `ESClient.h` and `ESMessage.h`). A process's fork
events therefore reach a client before its own exit event, because the exit
follows the end of the last thread. This argument requires the root to have
entered the table, replay of every buffered handshake event, no identity
integrity loss, and complete delivery from subscription onward. The engine
checks root entry and detected gaps, but cannot establish that last condition
before the first delivered message (§4.4). Its `drained` result is conditional
on that disclosed sequence-start residual; it is not proof of loss-free
subscription startup. Neither the settle interval nor a synchronisation
marker proves completeness. K92 still requires a live adversarial run;
synthetic root-registration and replay tests are component evidence only.

**Liveness: why the freeze ends** (a candidate, inferred; K92 measures it
with adversarial fixtures).

- After step 1, no member can resume a stopped one or exec. Signals,
  suspend/resume and exec are denied by ES, and `ptrace` and task ports by the
  profile (§4.7). The kernel's own `SIGCONT` is answered by the repeated
  sweeps.
- A stopped member cannot fork. It keeps its process slot, and rule 6 caps
  the slots. During the freeze, a fork needs a slot that only an exit frees,
  and each stop removes a running member without freeing one. So the running
  members can only become fewer.
- The kill then meets only forks that were in flight when the freeze ended.
- Without the guardian, step 1 is missing, and the supervisor's stop may then
  run out of budget against a workload that resumes itself. Safety is
  unaffected.

**Budget and settlement.** The budget is initial 5 s from the stop's start,
as Linux's §9.3.

- **`tree_empty=true`** needs one custodian that **drained**: the root entered,
  its table is now empty, with no detected stream gap or user change. This
  retains the disclosed unverified sequence start (§4.4). The supervisor settles from its own
  drain, or from the guardian's `drained` result on B within the budget. The
  other custodian's gap is recorded in its result and is not an integrity
  loss. The verification scope is `attempt_tree`.
- **Anything else** is `tree_unknown`. When no custodian could verify because
  of a gap or a user change, that is failed verification: it sets
  `lifetime.integrity=lost` and retains state, as on Linux (jail-v1 §9.3).
  The receipt then keeps its last nonsettled phase, and the control stream
  ends `unsettled` (jail-v1 §8.2).
- **A storm can cost the run its state.** An event storm the workload makes,
  if it gaps both custody streams, can therefore quarantine its persistent
  vendor state under J14 §4.9. This
  is decided, not accidental. **must:** K93 shows that ordinary heavy work
  does not gap, or this design is revisited before release.
- **After the budget**, the guardian keeps stopping for up to initial 60 s,
  then writes its record. A record that says `drained` lets `gc` verify the
  end later (§4.9).
- **The guardian's end.** The guardian exits after writing its record. The
  supervisor reaps it, and ends it by audit token first if it is stalled.

### 4.6 Losing a custodian

A lost or stalled custodian is recorded as on Linux. jail-v1 §9.3 records a
lifetime loss as a wrapper note with `fields.kind = lifetime`, and the
receipt gains an `errors[]` entry, code `custodian_lost` or
`custodian_stalled`, naming the custodian. When a custodian's loss starts the
stop, `outcome.cause` is `custodian_lost`.

| Event | Can the workload cause it? | Result |
| --- | --- | --- |
| Supervisor dies: crash or `SIGKILL` | Direct workload control must be denied (§4.7); client bugs and workload-induced memory pressure are not excluded | The guardian sees end-of-file on A, stops the tree and writes its record. The receipt stays at its last phase, as on Linux after a supervisor crash. `gc` verifies the end from the record (§4.9). |
| Guardian dies | As for supervisor death | The supervisor sees end-of-file on B and the guardian's exit, and stops the tree from client S, as Linux stops on the watcher's death. `tree_empty=true` stays possible from S's stream alone. Liveness is weaker without the guard step (§4.5). |
| Supervisor stalls (`SIGSTOP`, a debugger, a stopped terminal job) | Direct workload control must be denied; bugs or resource-induced stalls are not excluded | The guardian ends the tree at the wall deadline plus the grace, with cause `wall`. A stall alone is never taken as a loss. There is no heartbeat, so an operator's `Ctrl-Z` of the whole job does not kill the run. |
| Guardian stalls | As for supervisor stalls | At stop, the supervisor drains alone and then ends the guardian. The error is `custodian_stalled`. |
| A custody stream gaps | Yes, with an event storm | Detected. The stop proceeds, and the result is `tree_unknown` unless the other custodian drained. |
| A member changes user (a setuid program the profile missed) | Only through a gap in the profile | Integrity loss, so `tree_unknown`. K90 hunts for the gap. |
| A crafted program name or argument | No | Custody handlers never read variable-length fields (§4.1, rule 3). |
| ES ends the guardian for its stop-time authorization subscription | No (by reading): fail-closed mode denies a missed deadline and never kills the client (`ESTypes.h`) | Were it to happen, as "guardian dies". The supervisor holds no authorization subscription. |
| `killall ukai-jail` (`SIGTERM`) | No | An orderly stop. The supervisor stops the run, and the guardian ignores the signal. |
| **Both custodians die**, for example `killall -9 ukai-jail` | Direct workload control must be denied; simultaneous loss through client bugs or workload-induced memory pressure is not excluded | **The named residual, whatever its cause.** The tree may keep running. Nothing acts until the next `run`, `doctor` or `gc` (§4.9). |
| Host sleep | No | The wall deadline counts sleep (§4.3). K97 measures it. |
| Reboot or kernel panic | No | Every process ended. `gc` sees a new boot session. |

### 4.7 Defense: custody is exactly as strong as containment

Anything the workload can make run outside its sandbox, with the operator's
rights, can kill both custodians. It could also escape every other control.
And anything a system service starts at a member's request is not a
descendant, so it is outside every membership, and `tree_empty` would not
cover it. So the defense is not a separate mechanism. **Every path from the
sandbox to unsandboxed execution is a containment failure and a custody
failure at once.**

**Measured blocker, 2026-11-01; closed 2026-11-02:** in the isolated
development VM, sandboxed `launchctl kickstart` started a fresh preloaded job
outside the jail. That job successfully sent `SIGCONT` to each live custodian;
both outside positive controls also succeeded. The candidate
`(deny mach-bootstrap)` did not stop this route, and `launchctl load` was
denied in the corresponding controls. The cause: launchd's audit-token
sandbox checks cover only job creation and service lookup/registration, and
SBPL `(version 1)` has no filter for Mach sends to the inherited bootstrap
port, so no denyable operation names the kickstart route. Two layers now
close the class. First, the template denies executing the `/bin/launchctl`
client outright, after the exec grants; the rerun on template digest
`b2ae082d…` denied kickstart and load against both custodians with working
outside controls ([kickstart-fix
record](../benchmarks/jail/results/macos-k90-kickstart-fix-2026-11-02/README.md)).
Second — because a name ban is not a class fix — a direct-client probe
(measured the same day) showed the launchctl-free route: this build serves
no MIG job subsystem on the bootstrap port, and `launchctl`'s own client is
`_xpc_pipe_interface_routine` over a pipe built **from the inherited
bootstrap port**, reachable by any admitted executable. The launcher
(`__launch-macos`) therefore strips the inherited bootstrap port
(`task_set_special_port(TASK_BOOTSTRAP_PORT, MACH_PORT_NULL)`, fail closed)
immediately before the target exec: members hold no route to the launchd
control plane at all, for any client. Measured in the same VM against both
custodians: inside, `port=0`, local lookup failure, no XPC reply; outside,
the lookup succeeds and launchd answers the interface routine
([bootstrap-strip
record](../benchmarks/jail/results/macos-k90-bootstrap-strip-2026-11-02/README.md)).
Consequence for §4.10: the Mach allowlist is now structurally empty — a
member has no bootstrap port to look anything up through — so admitting a
future service requires a brokered design (for example a guardian-side
proxy), specified and measured before any entry is admitted. This is
development-VM evidence, not release acceptance; the remaining requirements
below must still be established on the release profile.

**must:**

- The shipped profile closes classes 1–4 below; classes 5–6 retain their
  resource and event-load requirements.
- K90 passes against that exact profile template.
- The receipt records the template's digest and the generated parameters:
  paths and the setuid list.
- A build whose template digest differs from the one K90 passed is not a
  release.

The SBPL rules belong to the backend evaluation, while the classes are the
requirement:

1. **Direct control of another process.** The denials:
   - Signals by every route: `kill`, `killpg`, `kill(-1, …)`, `sigqueue`,
     `proc_terminate`, `proc_signal_with_audittoken`, `pid_suspend`,
     `pid_resume`. Signals are confined to the sandbox, and the measured base
     is `(deny signal) (allow signal (target same-sandbox))`, under which 800
     of 800 workload attempts against both custodians returned `EPERM`.
   - Debugging and task ports, for **every** target, members included:
     `ptrace`, `task_for_pid`, and `task_name_for_pid` followed by control
     calls. Members included means a member cannot resume a frozen one by
     these routes either.
   - `memorystatus_control`, priority changes and `proc_rlimit_control` on
     non-members.

   Both custodians are also hardened-runtime binaries without
   `get-task-allow`, so a same-UID caller cannot obtain their task ports even
   without Seatbelt (by reading).
2. **Asking another process to run something.**
   - launchd job operations: `launchctl submit`, `bootstrap`, `kickstart`,
     `kill`, `bootout`, `load`.
   - LaunchServices (`open`, `lsopen`) and Apple Events (`appleevent-send`,
     `osascript`).
   - Mach and XPC services beyond an allowlist. `mach-lookup` is
     default-deny. An entry is admitted only for a service that cannot start,
     or keep running, code on the caller's behalf, and K90 probes each
     entry.
   - Unix-domain sockets of unsandboxed servers: tmux and screen, Docker, SSH
     `ControlMaster`, the VS Code CLI socket, language servers. Unix-socket
     connects are default-deny apart from named grants.
   - Loopback TCP other than the attempt's bridge ports: Docker's TCP API,
     inspector and remote-debugging ports, local development servers.
3. **Gaining another user.** macOS has no `no_new_privs`. The profile denies
   executing every setuid and setgid file in the readable roots, by path.
   - The system volume is sealed, so its set is fixed for each macOS build.
     It is enumerated once per build (`kern.osversion`) and cached.
   - Granted roots are scanned at preparation.
   - A member that changes user anyway is detected (§4.4).
4. **Leaving something for later.** Shell start-up files, launch-agent
   property lists and login items. The filesystem default-deny of jail-v2
   §8.1 covers these, and K90 checks that the obvious ones are denied.
5. **Resources.** Rules 4 and 6 keep a stop working through exhausted
   process slots, descriptors or memory, and bound the tree. Memory pressure
   can still lead macOS to kill processes. The custodians are small and the
   workload is large, but no priority is promised. K96 measures custodian
   survival under pressure the workload induces.
6. **Event load.** Notification-queue overload drops messages, observable as
   gaps in `seq_num` / `global_seq_num`, rather than terminating a
   notification-only client (DTS guidance, follow-up relayed 2026-11-01).
   This answers §11's question 1. It is specific to ES notification overload,
   not immunity to client bugs or system memory pressure. K93 remains a
   required implementation test of storms, gap handling, drain reporting and
   ordinary heavy builds; K96 retains the separate memory-pressure trials.

Same-UID processes outside any jail (the operator's other tools, an agent
that is not run under Ukai) can end both custodians. These are examples of
the "external events" Apple names, not the only possible causes of loss.
The boundary is `native_tree` because no supported kernel-owned death chain
remains once both custodians are gone, regardless of how they were lost.

### 4.8 What the receipt and the summary say

- `lifetime.boundary` is `native_tree`, with `verification_scope`
  `attempt_tree`.
- `applied.filesystem.mechanism` is `seatbelt_profile`, and the profile's
  digest is recorded (§4.7).
- `lifetime.native.details` (macOS) holds:
  - `custody: es_descendants`, `defense: seatbelt` and `native_execution: dev`;
  - `profile_digest` (64 lowercase hex digits for the template) and
    `profile_parameters`: read/write, read-only and deny roots, protected
    paths and `path_anchors` (the pinned ancestor literals), setuid exec
    denials and scan holes, the kernel setuid backstop,
    Mach services, Unix sockets, terminal slave and bridge ports. These are
    public parameters, never environment values or proxy secrets;
  - rule 6 as the guardian reported it in its `allowance` frame (§4.3
    step 3), in every receipt from `prepared` on: `process_limit` (the
    `RLIMIT_NPROC` soft and hard limit every member inherits),
    `process_headroom` (the allowance above the guardian's process-count
    snapshot) and `process_headroom_clamped` (true when the inherited
    ceiling stood in for the full 1024). The supervisor computes none of
    them itself;
  - `handshake_events_pending`, the pending handshake-event count;
  - per custodian (`supervisor`, `guardian`), one `result`: `drained`,
    `not_drained`, `lost` or `stalled`, plus `stream` (`contiguous`,
    `gapped` or `unknown`). `events` is an integer, not a per-event object;
    without a guardian record it is null and the guardian stream is
    `unknown`. An absent record never asserts continuity;
  - `stop`: the member count (`members`), budget (`budget_ns`), elapsed
    time (`elapsed_ns`) and `stop.phases`, the whole stop's six marks on
    the continuous clock in stop order (`requested`, `freeze_done`,
    `first_kill`, `result`, `guardian_record`, `settled`), each null where
    the mark did not occur. The guardian's own machine marks are in its
    record (`stop_phases`).
- `applied.syscalls` is null: the backend does not emit a separate syscall
  filter record. `applied.filesystem.protected_coverage` is
  `existing_and_root`; `all_descendants` is unsupported.
- For network mode `none`, `applied.network.mechanism` is
  `seatbelt-deny-network`: the profile emits `(deny network*)` with no
  production allows.
- The wall row is required and applied with mechanism
  `both-custodians-continuous-clock`; preferred resource ceilings remain
  unapplied. The final row records `hit=false` when settlement finishes
  before the deadline, `hit=true` on a confirmed expiry, or `hit=null` when
  the deadline elapsed without an observed trigger. The null case records
  limits coverage `degraded`, a null observed count and a
  `wall_hit_unobserved` gap. The guardian record has no stop trigger; adding
  it is a known follow-up. Elapsed time alone does not establish a hit.
- With observation on, `observer.backend=es_notify` and
  `observer.set=macos-closed-v1`; `attached=true` only after successful setup.
  `exec` and `fs.write` are active with counts over §5's declared set when no
  evidence was lost. Setup failure refuses before exec in either evidence mode;
  an unattached observer never permits a requested observed run.
  With observation off there is no audit attachment or count.
  Wrapper limit facts remain available without an audit observer or proxy.
  In the native settled receipt, `observer.sources.wrapper` is `supported`
  with known wall evidence (while `coverage.limits` is `active`); unknown wall
  evidence makes both `degraded` as above.
- `process.identity.kind` is `macos_audit_token`, with `pid`, `pidversion`,
  `boot_session` and the full token. Exec changes the token: the receipt
  carries the current target identity, republished on each later confirmed
  target exec. `target_process` is not retained inside native details: the
  producer moves that identity into the receipt's top-level `process`.
- [receipt-macos-native.json](jail-v1/examples/receipt-macos-native.json) is a
  hand-written illustrative development receipt with the product field
  shapes. Its identities, paths, counts, times and drainage are synthetic;
  it is not product output or live evidence. The example's guardian has no
  record (`not_drained`, `unknown`, null events); its illustrated verified
  end relies only on the supervisor. Missing evidence alone does not assert
  that the guardian was lost.
- The J13 survivors line names the custody, for example
  `survivors: none (verified · native custody, not kernel-bound)`. With the
  guardian lost, it adds `· guardian lost`. One lost guardian is a handled
  single-custodian failure, not the named residual: that is the loss of both
  custodians (§4.6). With `tree_unknown`, it says what is unknown, as on
  Linux. The summary is still computed from the receipt alone (K54).

### 4.9 gc and the next start

On macOS the owner is **both** custodians. `gc` retains an attempt whole while
either one lives (jail-v1 §14.2). A custodian is dead when its audit token no
longer matches, or when the boot session differs.

- **Proven refusal before preparation.** On the Mac host, native and VM-policy
  refusals can settle without a tree when the recorded supervisor is dead,
  the receipt is `refused` with boundary `pending`, integrity is not lost,
  process is null, `exec_observed=false`, and its nonempty errors are all at
  resolving/probing. `guardian.json` must be genuinely absent, not unreadable
  or corrupt. A missing process alone is insufficient. Ordinary `gc` or
  `gc --abandon` can finish managed-scratch cleanup and record `gc_finished`,
  without `gc_abandoned` because no tree was created.
- **The receipt proves tree death** (settled, `tree_empty=true`). As jail-v1
  §14.2: nothing is killed.
- **Same boot, guardian record `drained`.** The tree's end is verified by
  the guardian. `gc` records `gc_custody_verified` and permits cleanup, like
  `gc_terminated_orphan` on Linux. The receipt is left as written (jail-v1
  §14.2).
- **Same boot, no drain proof.** Once preparation may have begun, a missing
  record does not prove the guardian dead. Once the supervisor is dead,
  `gc` checks any probeable guardian identity and retains everything if its
  liveness is alive or unknown. Otherwise it attempts `SIGKILL` on the target
  recorded in the receipt
  (`process.identity`), by audit token. That does not signal a reused PID.
  `gc_killed_target` is recorded only when signalling succeeds; a stale token
  or ESRCH is a target-not-found failure, never a claim that it was killed. The tree's end is
  **not** verified, because the other descendants are in no record.
  - The attempt keeps `tree_unknown`.
  - Vendor-state cleanup and a J14 lease stay held, as for lost integrity on
    Linux. J14's visible throwaway fallback applies to later sessions.
  - To accept the unverified end, the operator runs
    `ukai-jail gc --abandon ATTEMPT`, but only once both custodians' deaths
    are established. Success records `gc_abandoned` and releases the lease
    and resources. If the guardian identity is absent, unreadable or corrupt
    and no pre-preparation proof applies, same-boot abandonment refuses with
    exit 1 and retains state. Reboot, then run `ukai-jail gc`; lost integrity
    can still require explicit abandonment after reboot.
- **New boot session.** Nothing of that boot is alive. `gc` proceeds as
  jail-v1 §14.2 does after a reboot. Lost-integrity attempts are kept in every
  boot there, and here too, until the operator abandons them.

Before doing anything else, `run` and `doctor` on macOS look for attempts of
this operator whose supervisor is dead and whose end is not verified. A
probeable guardian identity suppresses the warning unless its probe establishes
death; missing guardian identity requires recovery without assuming death.
The diagnostic names each attempt and an actionable recovery: `gc` or
`gc --abandon` when the guardian's death can be checked; reboot then `gc`
when its identity is absent or unreadable, with explicit abandonment after
reboot if lost integrity requires it. They never kill anything themselves:
killing is `gc`'s, as on Linux.

### 4.10 Requirements and containment on macOS

jail-v2 §8.1's filesystem, network and in-child path design stands. It is the
containment that §4.7 depends on. How the macOS platform answers each
requirement (`capability.rs`) behind the explicit development opt-in.
“Available when probes pass” describes a capability answer, not live proof
or a supported release:

| Requirement | J16 on macOS |
| --- | --- |
| `tree_termination` | Available when required probes pass, mechanism `es_descendants` (§4); boundary `native_tree`, with the sequence-start residual. |
| `filesystem_containment` | Available when probes pass, `seatbelt_profile`. |
| `syscall_filter` | Capability maps to `seatbelt_profile` operation denials when the probe passes; `applied.syscalls` remains null. No separate syscall-filter receipt is emitted. |
| `protected_coverage:*` | `existing_and_root` when probes pass; `all_descendants` is unsupported and refuses. No complete future nested-path coverage is claimed. |
| `network_none`, `network_proxy` | Available when the profile and loopback probes pass (below). |
| `credential_staging` | `unsupported`, including vault, copied/bound credentials and vendor staging; refuses before staging. |
| `closed_set_observation` | Available when the development gate is enabled and the observation client create/delete probe succeeds (`es_notify`); SDK absence, a disabled gate or entitlement refusal is reported honestly. Actual attachment before release is still required (§5). |
| `execution_boundary` | `unsupported`. There is no supervisor-owned resource boundary, so `none` and every explicit tree ceiling refuse. |
| `limit:wall` | Available when probes pass; custodians use the continuous clock. Live wall-expiry acceptance is outstanding. |
| `limit:pids`, `mem`, `swap`, `cpu`, `storage`, `inodes` | `unsupported`. An explicit request refuses, and a preferred value is recorded as not applied. |

**Path protection.** The native profile pins every ancestor of a protected
or `deny_read` path within each writable root, excluding the writable root
itself, with literal write denies. A writable root contained by another
writable root can itself be pinned. The guarded path also denies writes;
`deny_read` additionally denies reads. Thus rename, unlink and link of the
guarded path or its pinned parents are denied, while ordinary writes inside
unprotected children remain allowed. `profile_parameters.path_anchors`
is a sorted, deduplicated array of absolute strings for those ancestor
literals. Preparation refuses with `unsupported` when an existing guarded
regular file has more than one hard link, including a file inside a guarded
directory: an already-existing alias would escape a path-based denial.
`existing_and_root` covers the configured root suffixes and matching guarded
paths that exist at preparation; nested repositories created later at
unguarded paths are outside it; no future nested-repository or inode-wide
protection is claimed. These are implementation/component-test rules, not
live custody acceptance.

Changes and additions:

- **Profiles.** `tool`, `build` and plain `agent` may proceed only with the
  development opt-in and all required probes. A launch that needs native
  vendor/credential staging refuses before acquisition of managed or
  persistent vendor state. `none` refuses with
  remediation `unsupported`, because without a sandbox nothing defends the
  custodians.
- **macOS profile baselines** (`profiles.rs` is per-OS) record
  `observe = on` after J17 wiring, over `macos-closed-v1`. An explicit
  `--observe on` resolves to the same requirement. Requested attachment failure
  refuses before exec in both evidence modes; `observe = off` still runs
  without an observation client (§5). `build`'s memory ceiling stays preferred and recorded as not applied.
  The policy snapshot records these baseline values, never implicit choices
  (jail-v1 I02).
- **The bridge on a shared loopback.** The bridge keeps jail-v2's two ports,
  HTTP and SOCKS5, on ephemeral loopback ports. Each requires a per-attempt
  secret, carried in the child's proxy URLs (HTTP proxy authentication, and
  SOCKS5 username and password). The profile allows outbound loopback to
  those two ports only. This is a candidate. K99 measures each agent through its supported
  protocol and tests both bridge protocols independently. A connection is attributed to the attempt as soon
  as the secret verifies, even if HTTP Host/framing checks or the SOCKS
  command subsequently refuse, or the client disconnects. Before that proof,
  a refusal cannot safely become a workload event. Accepted connections refused
  before attribution, including proxy capacity, bridge relay capacity and
  upstream Unix-socket connect failure, contribute to `proxy_unattributable`.
  That gap has source `proxy`, class `proxy.net` and `lost_count` equal to the
  accepted connections refused before attribution; it is not a count of proven
  workload events or of events known to have been lost. Nonzero uncertainty
  makes proxy coverage `degraded` with a null observed count. Linux's private
  proxy path without a bridge secret retains its existing attribution.
  Transient interrupted/aborted accepts retry; persistent accept errors or
  fatal worker-spawn failures stop both bridge loops. Settlement records
  `proxy_stopped` from the first failure timestamp with degraded proxy coverage
  and a null count, never a silent complete interval.
- **DNS.** `com.apple.dnssd.service` is not in the Mach allowlist. A proxied
  child resolves through the proxy, and DNS is not an exfiltration channel.
- **Local preview, planned.** The complete Claude workflow needs an explicit,
  per-attempt loopback listener grant (§13.3 step 4). It is not supplied by
  the current bridge rules. Until its policy, containment and receipt support
  pass acceptance, local preview remains unsupported; the implementation must
  not enable general loopback access to make a development server work.
- **Keychain.** The Security server and the keychain files are denied. A
  sandboxed `security find-generic-password` fails (K100).
- **The Mach allowlist is structurally empty** (amended 2026-11-02). The
  2026-11-02 bootstrap-strip closure of §4.7's class-2 deputy route removes
  the inherited bootstrap port in the launcher before the target exec, so a
  member has no port to look any service up through: `(deny mach-lookup)`
  was already the measured baseline under which Node, Git and a shell run,
  and the strip makes it structural rather than advisory. The template's
  `mach_services` parameter and its allow rule are retained but inert.
  **Admitting a service now requires a brokered design, not an allowlist
  entry**: the member cannot reach launchd or any system server directly,
  so the only honest route is a guardian-side proxy — the guardian holds
  the bootstrap port, exposes an authenticated, named, attempt-scoped
  channel (for example over the existing attempt bridge), validates every
  request against a backend-evaluated admission list, and performs the
  lookup and relay itself. Any such broker needs its own §4.7-class threat
  review (the deputy argument applies to it in reverse), a receipt record
  of every admitted name, and a K90 probe row per entry before it ships.
  Until that design exists and passes, the allowlist stays empty and any
  request for a Mach service refuses with the named remedy.

### 4.11 Launch, credentials, terminal and state

- **Program resolution** (J12 §3.3):
  - **Mach-O programs**, with the same install-root grants.
  - **Group-writable directories.** J12's refusal also applies on macOS.
    Homebrew's `/opt/homebrew/bin` is
    group-writable by `admin` (observed, not recorded). Group- or
    other-writable install directories refuse on macOS, as on Linux; there
    is no group-membership exception. Directory-service membership cannot
    be proved complete. Homebrew's admin-writable prefix is a known refusal:
    install the agent in an operator- or root-owned directory that is
    neither group-writable nor other-writable (decision 6).
  - **No exec pins.** Linux's exec-by-descriptor pins (F5, F2) have no macOS
    equivalent, because there is no `fexecve`. The program is checked before
    release, and a swap by a same-UID process outside the jail is outside the
    threat model. This is a recorded limit.
- **Credentials** (J12 §3.5): native credential, vault and vendor staging are
  unsupported and refuse, including `ukai-jail claude`. The following is the
  future contract from decision 4, not implemented native credential use.
  - **The binding is weaker.** The bundled `claude` profile binds its
    credential to `@program`. On Linux, the seccomp mediator pins the
    connecting process (`vault/origin.rs`). ES has no TCP connect event, only
    Unix-socket and XPC connects, so the native binding can only reach the
    attempt: any member that holds the
    proxy secret can use the vaulted credential. It still never sees the
    value. The receipt's credential entry records `binding: attempt`.
  - **No Keychain.** The future vendor run must use a vault placeholder,
    with Keychain access denied (§4.10); no such run is claimed.
- **Terminal mode** (J14 §3) **uses J14's option (b), the pty relay**, on
  macOS. J14 kept the operator's terminal and made it safe with the PID
  namespace and a seccomp filter on `TIOCSTI`, `TIOCSETD` and `TIOCSPGRP`.
  macOS has no PID namespace. A member can still change its process group
  through `posix_spawn` attributes when the `setpgid` syscall is denied
  (measured), and nothing confines the group it names to the attempt
  (inferred). Seatbelt's filtering of those ioctls is unproven.
  - **How it works.** The supervisor allocates a pty and gives its slave to
    the launcher as controlling terminal in a new session. It copies bytes,
    window sizes and the stop relay between the operator's terminal and the
    master.
  - **What it closes.** The workload never holds the operator's terminal, so
    J14 §3.5's rows 1–6 and 10 are unreachable on every macOS release.
  - **What it costs.** J14 listed the costs: X05's byte equality does not
    hold for terminal runs, and raw mode, size propagation and end-of-file
    become jail code.
  - **Elsewhere.** Detached and non-terminal runs keep X05. Their launcher's
    new session has no controlling terminal, so `/dev/tty` fails, and the
    operator's terminal is out of reach there too.
  - **The receipt** records `applied.terminal.session: relay`.
- **Persistent vendor state.** Native vendor staging refuses before acquisition,
  even when the launch declares state without credentials. The
  intended J14 layout and lease integration remain acceptance work; a lease
  must be released only with a verified end or `gc --abandon` (§4.9).

### 4.12 Packaging and the entitlement

- **One entitled executable.** The supervisor and the guardian are both
  `ukai-jail`, the bundle's main executable,
  `Ukai.app/Contents/MacOS/ukai-jail`. It carries
  `com.apple.developer.endpoint-security.client`, authorised by the bundle's
  embedded provisioning profile.
- **The installer** places the bundle in `~/Applications` without sudo and
  links `ukai-jail` onto the `PATH`.
- **The bundle identifier** is the one request `S9YJTLLH28` names,
  `com.monocursive.ouroboros.jail`. It predates the rename, but a bundle
  identifier is not shown to users, so it stays rather than reopening the
  request.
- **Requirements.** macOS 27 or later (`es_new_descendants_client`, by
  reading), Developer ID, hardened runtime and notarization. No root, no TCC
  approval and no Full Disk Access: the descendants client removes those
  requirements (by reading, SDK).
- **Development VM:** the earlier VM was deleted on 2026-10-22. A fresh pinned
  clone, `ukai-custody-spike-20261101`, was used on 2026-11-01 under the
  [runbook](../benchmarks/jail/macos-development.md), without host shares,
  credentials or guest external networking. Its ad-hoc entitlement and
  disabled guest SIP permit development measurements only; the
  [spike record](../benchmarks/jail/results/macos-custody-spike-2026-11-01/README.md)
  retains provenance, failures, raw records and final VM state.
- **Release must** repeat every J16 row on a normally protected Mac, with the
  approved profile. **J16 cannot ship before Apple grants the entitlement.**

## 5. Native observation (J17)

**2026-10-23: declared partial set, operator decision.** J17 is wired into
native attempts, behind `UKAI_JAIL_MACOS_NATIVE=dev` and the ES entitlement.
The implementation and synthetic producer tests do not establish live ES
acceptance: K105–K107 remain untested live. No entitled native observation
run or performance measurement is claimed.

The supervisor starts a fourth ES client after custody is established and
before releasing the blocked launcher. It excludes the exact current audit
tokens of the supervisor, guardian and launcher; a new exec token is not
excluded. These exclusions are local to observation, not ES process mutes
that could hide a new image or instigated child. Ignored helper notifications
and unmodified CLOSE still participate in sequence checks. Observation has
no custody authority; its gaps do not by themselves invalidate custody's
`tree_empty` evidence.

The declared closed set is **`macos-closed-v1`**, following jail-v1 §11.2 and
§11.4's declared-set rule. The [published table](jail-v1/evidence/closed-set-macos.txt)
is generated from `observe/closed_set.def`, the same rows the C shim uses
for subscription and mute verification. A test requires byte equality.

- `exec`: `NOTIFY_EXEC`, emitting the observed image transition, not a claim
  to have read the original exec argument or syscall.
- `fs.write`: `NOTIFY_CREATE`, `RENAME`, `UNLINK`, `LINK`, `CLOSE` with
  `modified`, `TRUNCATE`, `SETMODE`, `SETATTRLIST`, `CLONE`, `COPYFILE`,
  `EXCHANGEDATA`, `SETEXTATTR`, `DELETEEXTATTR`, `UTIMES`, `SETOWNER`,
  `SETFLAGS` and `SETACL`.
  Clone/copy results retain source and destination; summaries count
  the destination as changed, and both sides of an exchange. NEW_PATH CREATE
  denotes ES-denied creation, with unknown syscall errno, not a successful
  creation or a Seatbelt-denial observation.

All these mutation notifications are subscribed: their callback work is
bounded fixed-size path copying with no filesystem lookup or dynamic
allocation. Individual write calls (`NOTIFY_WRITE`) are deliberately outside
the set: per-call delivery adds no path-modification evidence beyond modified
CLOSE and can flood the ring on write-heavy builds. Writes are represented by
modified CLOSE, including implicit closes at process exit. This matches Linux's
path-mutation granularity (`opened_for_mutation`, `truncated`). Ring overflow
remains real loss. This is a cost rationale, not a measured performance claim.
The installed 27 SDK event list was checked; the 26.5 build uses the explicit
`es_sdk_absent` path when the required descendants APIs are missing.

Outside the set are writes only through a memory mapping with no modified
close or other subscribed notification, and effects ES cannot attribute to
the descendants stream. Cloud materialization and File Provider updates
(`FILE_PROVIDER_MATERIALIZE`, `FILE_PROVIDER_UPDATE`) are outside the set.
A descendants client also receives instigated events: a read may trigger cloud
materialization whose event process is a provider daemon, not the workload.
These events therefore cannot establish workload content changes. Autonomous
OS effects are also outside the set. Mount/remount/unmount and generic fcntl
operations are not mutation results in this table; their effects without a
subscribed notification are outside it. mmap/mprotect notifications describe
mapping/protection, not proof that memory was subsequently written. These
exclusions alone never degrade coverage. Counts are delivered notification
results, not unique syscalls, bytes, file counts or content diffs.

`fs.deny` stays unsupported: Seatbelt denials are not ES events. Native `net`
stays unsupported; `proxy.net` comes independently from the bridge, including
its unattributable-refusal accounting. `learn` stays refused without fs.deny.

When attachment succeeds and no in-set evidence is lost, `exec` and `fs.write`
are active with observed counts. Sequence discontinuity, ring overflow,
invalid/truncated messages, worker failure, drain/delete failure and trace
refusal degrade the affected classes with named gaps and null counts. There
is no standing `uncovered_mutations` gap. The worker reports loss while the
attempt runs: strict evidence stops as `evidence_lost` (stop cause
`evidence_loss`); best-effort continues with degraded coverage. Loss found
only during final drain still fails strict evidence at settlement, without
inventing an earlier stop. Requested observation that cannot start (SDK absent,
not entitled or setup failure) refuses before exec in both strict and
best-effort modes with exit 125, `observer_unavailable`, stage `preparing`,
remediation `host_setup`, as the frozen jail-v1 attach contract requires.
`observe = off` creates no observation client. Custody and all other required
capabilities remain mandatory in either evidence mode. The `es_notify`
capability probe follows the same development gate as `es_descendants`: on
an SDK-capable build, an unset `UKAI_JAIL_MACOS_NATIVE=dev` returns
`native_development_disabled` without creating a client. SDK-absent builds
report `es_sdk_absent` without creating one. With the gate enabled, the probe
creates and deletes a real observation client; actual start is authoritative.
The worker checks stop between bounded batches and continues draining without
sleeping while a batch is full; it waits only after observing the ring empty.

The worker resolves the existing workspace through `F_GETPATH` before
creating ES, including symlink aliases and stored case. Missing or
non-directory roots refuse setup. Delivered paths are never looked up later.
Both global and per-type sequences may start at 0 or 1; a first value above
1 is a gap with unknown exact loss. Audit frames and gap notes carry
`sequence_start: "unverified"`: loss before the first delivery may remain
undetectable. Global and per-type losses are not added together. Ring-drop
counts are exact; overlapping sequence loss has a null count. Repeated
snapshots do not count a drop again.

Receipts name `observer.set=macos-closed-v1`. `version --json` announces
`observation.closed_set=macos-closed-v1` on SDK-capable macOS builds; an
`es_sdk_absent` build announces null. This describes build capability, not
host entitlement or the development gate's runtime setting. No schema change is needed. The native summary distinguishes
modified content, created entries and metadata changes; workspace-root changes
are named separately from entry counts. Rust and `summary_check.py` recompute
the synthetic supervisor-produced receipts. Their agreement is component
proof, not live acceptance or full-filesystem coverage.

## 6. VM tier: a warm guest (J18)

The released [VM preview](../../crates/ukai-jail/vm/README.md)
(`0.1.0-preview.1`, the public package) cold-boots a disposable Ubuntu guest
for every command. It copies inputs in and outputs out, and it is offline.
The J18 code on `dev` replaces it with a warm service, `ukai-vm serve`, that
`ukai-jail run --vm` starts and reuses. Its candidate package
(`0.1.0-preview.2`) is Developer-ID-signed but not notarized and not
published, and it carries only `ukai-vm` and `ukai-vm-install`: no macOS
`ukai-jail` client ships, so the client is built from source.

**Current behavior (fix wave of 2026-11-03).** The host-side gates below are
tested at the CLI against a fabricated installation (`vm_tier.rs`) and in
unit tests; the guest-side behavior (attempt stop, mandatory share, named
poweroffs) is covered by unit and model tests only. None of it has run on a
booted guest yet; live verification is pending.

- **Probe (D2).** `owner_loss_termination` always answers
  `vm:owner-loss-not-provided`: the guest's wall is a deadline, not an
  owner-loss bound (K112). Any other requirement answers Available only when
  the VM platform's one measurement table, `GUEST_MEASUREMENTS`, lists it:
  the requirement, the guest record that measured it inside the guest
  through the jail command `--vm` issues, and that record's own time, which
  becomes `measured_at`. The table is empty. The 2026-11-02 records state no
  time of measurement, and none of their verdicts measured its requirement
  alone: `wall` cannot tell the guest jail's deadline from the controller's
  `wall + 10 s` backstop, `pids` passes whatever the limit, `mem` passes on
  any OOM kill, containment measured writes but not reads, and
  `network_none`'s TCP half was vacuous (`/dev/tcp` under the guest's
  `dash`). So every requirement answers `vm:not-measured:<requirement>`
  (`missing_capability`, remediation `unsupported`), and **every `run --vm`
  refuses at probing, before any connection or boot,** with exit 125, until
  a live phase fills the table. A policy `--vm` does not carry answers its
  carry reason on every row but owner loss instead (remediation
  `configuration`).
- **What `--vm` carries (D1).** Exactly the profile (`tool` or `agent`), the
  wall (whole seconds, 1–300), the argv, the network shape (`tool`: none;
  `agent`: the proxy with the allow set) and vault-mode credentials. Before
  any contact, for every profile, the host compares every other element of
  the policy snapshot with the snapshot those inputs alone resolve to on the
  guest platform (the profile's baseline with the guest's environment, the
  allow set as spelled on the wire, a launch of the vault credentials only).
  The first difference refuses with `vm:not-carried:<field>`, the field
  spelled as the snapshot's key path in lower case: `filesystem.deny_read`,
  `filesystem.read_only`, `limits.mem`, `environment.bindings`,
  `launch.credentials.<id>.mode`, `terminal`, `lifetime_boundary`, and so
  on. The comparison names every snapshot field, so a new field does not
  compile until it is classified.
  - **Limits** follow the guest's fixed shape, pids=64, mem=512MiB, swap=0:
    a required ceiling must equal it, a preferred one may not be stricter (a
    looser one is met by the guest's), and any storage, inodes or cpu
    ceiling refuses. A wall that is not whole seconds in 1–300 refuses as
    `limits.wall`, the `tool` baseline's default 30-minute wall included.
  - **Environment.** The contained baselines admit `LANG`, `TERM` and `TZ`
    from the operator; the guest jail's environment sets `LANG=C.UTF-8` and
    neither `TERM` nor `TZ`. An operator environment that differs, such as
    any terminal that sets `TERM`, refuses as `environment.bindings`.
  - **Terminal and lifetime.** A snapshot with a terminal mode refuses as
    `terminal` (the remedy is `--terminal detach`); the kernel-bound key is
    not carried either (`lifetime_boundary`).
  - **Credentials.** Only vault mode crosses (a staged mode refuses as
    `launch.credentials.<id>.mode`), without executable bindings or
    `refresh`, and with no vendor-state shape of its own.
  - `build` refuses with `vm:build-profile-refuses-the-live-share`, and
    `--profile none` refuses at resolving.
  - **TLS-only rules** cross without their `:443`, so the guest jail records
    them TLS-only too. Before this fix they crossed in canonical `host:443`
    form, which the guest's grammar reads as an explicit port, one that
    admits plaintext HTTP (the K113 record's erratum).
  - **After the run** (the second wall, never the gate), the guest receipt
    must report the requested profile, network mode, allow set and TLS-only
    set (`applied.network.mode`, `allowed_hosts` and `tls_only`, compared as
    sets), and the requested limits applied: a required ceiling at its
    value, a preferred one at least as strict. Otherwise the host stores no
    verified receipt, and the attempt's integrity is `lost`.
- **Vault (D3).** Values come from the secrets the supervisor staged and
  validated for the attempt, exactly one loaded value per credential. A
  staged read-only bind, a staged secret no credential declares, or a
  declared credential with no staged value refuses. The guest's launch
  declaration is generated from the snapshot's `launch` group, with each
  source at the guest's tmpfs path `/run/ukai-vm/credentials/<id>`, and
  parsed back with the same loader before it is sent: it must reproduce the
  snapshot's credential declarations except for the source. Nothing
  re-reads the operator's TOML or `UKAI_CONFIG_DIR`, and every vault refusal
  comes before any contact.
- **Serve (D4).** Whether `run --vm` reuses a serving `ukai-vm` or spawns
  one, it then asks for its status. It refuses unless the serve shares
  exactly this workspace live and, for a proxied policy, has its NAT
  adapter. A spawned serve runs in its own process group, with standard
  input and output closed and standard error in `<data>/vm/serve.stderr`.
  One that exits before it answers is refused, quoting that file. The serve,
  ready and prepared waits are bounded by the attempt's preparation budget,
  and the serve's also by 180 s.
- **Receipt and summary (D5).** When the guest receipt verified and the
  guest finished, the settled host receipt takes `platform.kernel`,
  `platform.arch`, `exec_observed`, `applied` (except its `terminal`),
  `observer` and `coverage` from the verified guest receipt. Its
  `lifetime.native.details` gains `guest_receipt` (`evidence/jail.json`),
  `guest_receipt_sha256` (`sha256:<hex>`) and `guest_carried` (those six
  fields). The host keeps its own terminal record, a limit hit the host
  itself observed (its wall deadline) stays a hit, and `process` stays the
  host's. The summary of a `--vm` attempt (a host receipt naming the
  transport, with `vm-transport.json` present) reads the guest receipt and
  refuses it unless it hashes to the record's `guest_receipt_sha256`. It
  takes the same groups from it, counts nothing from the host journal
  (journal `absent`: the guest's journal is not exported), names the host
  receipt's digest, and prints the transport line itself, after its lines
  and before the receipt line. So `run` and `tail --summary` print the same
  lines; the JSON summary keeps its frozen shape, and the transport line is
  not one of its lines. Tested against the recorded K113 attempt; no
  `run --vm` has produced such a receipt yet.
- **Attempt stop (D6).** One stop serves the guest's done, cancel2, reset and
  the outer-wall backstop. It kills every `ukai-attempts.slice/attempt-*`
  cgroup, and every cgroup under the workload account's user manager except
  its infrastructure: `init.scope` and the `dbus.service` user unit
  (`session.slice/dbus.service` or `app.slice/dbus.service`). It then
  requires those cgroups empty and no live process of the workload uid
  outside the infrastructure, re-killing within a 2.5 s budget. The jail
  supervisor's reap is bounded at 1 s, and every wait feeds the guest
  watchdog. A failure powers the guest off with `attempt_tree_unverified`.
  The infrastructure set comes from what `prepare.py` installs; it has not
  been confirmed on a booted guest. The attempt's files (staged values and
  launch profile) are removed at every stop and every poweroff; failing to
  remove them at a stop powers off with `attempt_files_not_cleared`.
- **Mandatory share (D7).** A guest booted with a virtio-fs device whose
  mount fails powers off with `live_share_mount_failed` and never falls back
  to the staged workspace. `ready` and `session` state `live_share`, and the
  serve refuses a session whose `live_share` differs from what it attached,
  or that does not state it. An image prepared from older sources states no
  `live_share`, so it is refused and must be re-prepared. The share mounts
  `nosuid,nodev`, not `noexec`.
- **Named poweroffs** new in this wave: `attempt_tree_unverified`,
  `attempt_files_not_cleared`, `live_share_mount_failed`,
  `launch_profile_unstageable` (a launch profile name already present, a
  link included, or an unwritable directory: never written through) and
  `launch_without_toml`. The serve names a guest that powered itself off
  from its console (`guest poweroff: <reason>`).
- **Tests and their limits.** `test_guest_main.py` drives the controller's
  `main()` over `guest_harness.py`, a model of the kernel's cgroup and
  `/proc` files taken from the K111/K113 guest receipts. What the model
  cannot show is listed in `test_guest_main.py`'s docstring: that the real
  jail's scope and leaf land where the receipts say, that `cgroup.kill`
  ends the real tree and the next attempt still gets its scope, the image's
  real infrastructure set, a real cancel inside `WatchdogSec=4`, the
  virtio-fs detection and mount options on the real kernel, and the staged
  files' real owners. `test_custodian.py` compiles the custodian and
  suspends it past its lease against a stand-in VZ client.
- **Install errors.** A missing or invalid VM installation is a host
  prerequisite refusal: exit 125, `backend_unavailable` at `probing`,
  remediation `host_setup`, including `--profile none`. With native
  development enabled, `--lifetime kernel-bound` also refuses with
  `unsupported`, explaining that native macOS cannot provide it and VM policy
  enforcement of it is unavailable in this build; adding `--vm` is not
  offered as a working remedy.

**Evidence status.** K108–K113 are `untested` (§9.3, §9.4). The 2026-11-02/03
development measurements on the dev Mac
([warm record](../benchmarks/jail/results/macos-vm-warm-2026-11-02/README.md),
[installed-package rows](../benchmarks/jail/results/macos-vm-installed-2026-11-03/README.md),
[Claude Code guest record](../benchmarks/jail/results/macos-vm-claude-2026-11-03/README.md))
do not meet their clauses: their network probes were vacuous, K110 ran half
its matrix, K111's stored receipt contradicted the guest receipt (network
`pending` and observer not attached, against the guest's applied network and
attached observer; the D5 mirror above addresses it, untested against a
live run), K113 is one attempt against §9.4's Linux-row conditions,
and the "installed package" rows ran a client built from the repository.
The acceptance map's notes give each row's reason and what a real row needs.

The lifetime key is implemented in top-level profile files and operator and
project `[jail]` tables as `lifetime_boundary = "kernel-bound"`. It has the
same narrowing, canonical bytes and digest as the CLI; omission in a later
layer does not remove it, and an unknown value is `invalid_config` (exit 2).

The helper's orderly SIGTERM path now exits 0 during startup, idle,
preparation or running and removes its service socket; a previously recorded
custody/transport failure still exits 125. Synthetic helper tests establish
that distinction without booting a VM or qualifying `run --vm`.

The following are the backend's requirements; none is claimed until its
K108–K113 row passes:

- **Selection.** `--vm` on macOS.
- **The requirement.** J18 also adds a policy key that requires a
  kernel-bound lifetime (`lifetime.boundary` `pid_namespace`). It comes with
  a jail-v1 §6.3 narrowing row, a canonical-bytes update and a derived
  requirement name, `owner_loss_termination`. Native macOS reports it
  `unsupported` and refuses; this build's VM tier refuses it too, with its
  own reason, `vm:owner-loss-not-provided`. Linux `none` refuses. A future
  qualified VM backend must supply the kernel-bound lifetime before it can
  accept the requirement.
- **One warm guest per operator.** A per-user host program, `ukai-vm`, starts
  the guest on first use and stops it after an idle period (initial 10 min)
  or on `ukai-jail vm stop`. `ukai-vm` keeps the preview's separate custodian
  and VZ client processes, so the preview's fault model still applies, and
  K110 re-runs it for the warm design. It is not a launchd job.
- **Lifetime.** Each attempt is a normal Linux jail attempt in the guest.
  That chain is what the receipt's `pid_namespace` claims, and it holds
  whatever happens on the host:
  - **The host `ukai-jail` is lost.** The connection that carries the
    attempt closes, and the guest supervisor stops the attempt. The lease is
    end-of-file, not a timer, so a host `Ctrl-Z` does not kill the run.
  - **The host side is suspended.** This includes the preview's recorded
    residual, every host controller suspended at once. The guest jail's own
    wall deadline still ends the attempt. The serve and the custodian each
    restart their lease window after a wake gap (their own suspension), so
    a stop of the whole group longer than the custodian's 3 s lease no
    longer ends the VM by itself; the custodian reads the pending heartbeats
    before it judges the lease (unit-tested, not yet run on a booted guest).
  - **`ukai-vm` dies.** The VM service ends, and every guest process with it.
    The preview measured each of its kill cases once, and K110 repeats them.
  - **Per attempt**, the guest controller's one stop (D6, above) kills and
    verifies empty every cgroup the workload account's attempt can occupy:
    each `ukai-attempts.slice/attempt-*` cgroup and every cgroup under
    `user@<uid>.service` except the manager's infrastructure (`init.scope`
    and the `dbus.service` user unit), because the guest jail moves itself
    into `user@<uid>.service/app.slice/ukai-jail-*.scope` and runs its
    workload in a leaf directly under `user@<uid>.service`. It also requires
    no live workload-uid process outside the infrastructure. Its waits are
    bounded; a failure is the poweroff `attempt_tree_unverified`, and a
    watchdog poweroff during a cancel is a defect. This is covered by unit
    and model tests only, not yet on a booted guest.
- **The receipt** is the guest's Linux receipt. It is verified on the host by
  digest and stored as `evidence/jail.json` beside a transport record naming
  the VM and the host-side facts. The host's own attempt receipt never
  contradicts it: its settled form takes the guest's platform, exec
  observation, applied groups, observer and coverage, and names the guest
  receipt and the fields it took (`guest_receipt`, `guest_receipt_sha256`,
  `guest_carried`; D5, above). The summary prints the guest's applied facts
  plus one transport line from the transport record, as the J15 action adds
  its host-setup line.
- **Workspace.** A per-attempt virtio file-system share of exactly the
  workspace. Once a share is requested it is mandatory: a guest whose share
  fails to mount powers off with `live_share_mount_failed` and never falls
  back to the staged workspace, and the guest's `ready` and `session`
  replies state `live_share`, which the service compares with its own
  `--live-workspace` (D7, above; unit and model tests only, not yet on a
  booted guest).
  The guest jail then applies the policy's grants. Changing a
  running VM's share is by reading and a candidate. K109 measures it. Mac-built
  native dependencies, such as `node_modules` add-ons, do not run in the
  guest, and the guide says so.
  **Share containment review (measured 2026-11-02, Virtualization.framework
  virtio-fs on macOS 27.0.1 against an Ubuntu 26.04 guest, probe evidence
  under `docs/benchmarks/jail/results/`):**
  - *Safe by construction, and measured:* symlinks resolve client-side in
    the guest's own VFS — host-planted and guest-planted links, reads and
    writes, all refuse to touch anything outside the share; guest `..`
    traversal stays in the guest; `mknod` is refused by the server; rename
    "climbs" land in the guest's parent directories, not the host's;
    modes map faithfully (a guest `0755` is a host `0755`).
  - *Escapes the preflight refuses:* a **pre-existing hardlink** inside the
    workspace writes through to whatever host file it names (measured: the
    sentinel outside the share changed), and a **case-folding volume** maps
    a guest's `.GIT/config` onto the denied `.git/config`, bypassing every
    guest-side policy denial (measured). The launcher therefore refuses,
    before any VM boots, a live workspace containing symlinks or any file
    with more than one hard link, or on a case-folding volume (probed in
    place); the refusal names the remedy — a case-sensitive volume. Since
    the 2026-11-03 fix wave it also refuses a nested mount (an entry on
    another device than the workspace root, whose volume the probes never
    examined) and any FIFO, socket or device node (no workspace content,
    and their behavior across virtio-fs is unmeasured); the folding probes
    run in a fresh private directory that is removed afterwards. These
    are host-side facts, so only the host can check them. Unicode
    normalization folding only collides names that differ in decomposition
    — the protected segments are pure ASCII, so no denial can be bypassed
    through it; it is recorded as a disclosure, and a future policy naming a
    decomposable protected path must refuse on it. **Corrected 2026-11-03:**
    the 2026-11-02 normalization probe wrote one precomposed name twice and
    reported a fold on every volume. Re-measured on the development Mac
    with distinct NFD and NFC names, the default APFS volume folds both case
    and normalization, and case-sensitive APFS folds normalization only, so
    the disclosure stands.
  - *Disclosed, not blocked:* the server authorizes every guest uid as the
    host user, so guest-side DAC is advisory inside the share — the guest
    jail's policy is the only write gate, which is the design; `uid=`/`gid=`
    remaps do not exist for virtio-fs (measured refusal); fifos can be
    created and xattrs — including `com.apple.*` names — pass through to
    the host files, all equivalent to what the host user could do anyway.
- **Network and credentials.** An `agent` policy's guest has a NAT adapter,
  and the guest jail's own proxy enforces the allow set, as on any Linux
  host; a `tool` policy's network is none. A TLS-only rule (one every grant
  of which omitted its port) crosses without its `:443`, so the guest
  applies it TLS-only. Vault-mode credentials go
  from the supervisor's validated secrets to the guest supervisor over vsock,
  once per attempt, and are never written to the guest disk. Staged
  credential modes refuse with `vm:not-carried:<field>`.
- **Image.** The preview's pinned Ubuntu image first. A minimal kernel and
  init are a later optimisation. By reading, Apple's Containerization
  framework reports sub-second VM starts that way.

J18 has no external blocker: it needs only the ordinary virtualisation
entitlement that the preview already uses.

## 7. Alternatives considered

| Alternative | Why not |
| --- | --- |
| VM only | Heavy for daily use, and Linux programs only (§3.3). |
| Defend with ES authorization events for the whole run, as Apple suggests | Deadlines while the workload runs, and both custodians would hold authorization subscriptions. Seatbelt's denial is kernel-enforced with no custodian in the loop. The design uses one authorization subscription, held by one custodian during a stop, where every answer is a denial (§4.5). If Seatbelt's signal filter ever regresses, K90 shows it, and authorization events become the fallback. |
| Apple's optional third process, a full `es_new_client` defending against system-wide actors | Needs root, Full Disk Access and an installed component. The actors it adds defense against already hold the operator's rights outside every jail. |
| Fail-closed `AUTH_EXEC` | Measured: a survivor executed a new command after both clients were gone. |
| One custodian | One crash would leave survivors. Either one of two was enough in 40 of 40 kill trials. |
| A separate guardian executable with its own process name | A second entitled executable would probably need its own bundle and a second identifier on the pending entitlement request. The only thing it buys is surviving `killall -9 ukai-jail`, which is an explicit external kill. Plain `killall` is already an orderly stop (§4.2). |
| Binding a credential to its program at accept, by finding which member holds the connection's socket | More code for a check that is racy without a connect-time pin. The attempt-level binding is disclosed instead (decision 4). |
| A heartbeat between custodians | It would kill a run that the operator suspended with `Ctrl-Z`. Pipe end-of-file and the wall deadline cover the real cases (§4.6). |
| A shared-memory membership log, so `gc` could kill every recorded member after both custodians are lost | It gives no verified end, only a longer kill list. It costs sizing, torn writes and write-back on a copy-on-write file system. Cut in review. |
| A user LaunchAgent watchdog | It is an installed component, and it could only do what `gc` already does. Deferred (§11). |
| Starting `sandbox-exec` suspended and resuming it at release | The profile would apply after `prepared`, and exec errors would lose jail-v1's distinctions. Replaced by the launcher blocked inside the profile (§4.3). Found in review. |
| Coalitions, `task_get_fatal_port`, `sandbox_check` of other processes | Private or unsupported (§3.1). |

## 8. Contract changes, row by row

| Where | Change | Kind |
| --- | --- | --- |
| [jail-v2](jail-v2.md) §8 | J11's lifetime design and its sentence "Do not select a weaker native guarantee merely because these proofs need more work" are replaced by §4 for the native tier. K29 is replaced by K87–K104. K23–K26 move into J16; K24's bridge gains the per-attempt secret (§4.10). | Amendment (decision 1) |
| [jail-v1](jail-v1.md) §3.3 | The intended native contract requires verified custody under §4.5's root-entry and sequence assumptions, with the both-lost residual (§4.6); no live acceptance run or kernel-bound lifetime is claimed. | Amendment (decision 1) |
| jail-v1 L02, M01 | Intended native contract: each custodian lost alone ends the tree within a bound; both lost is the residual (K95). Execution is currently off by default; the development opt-in and all required probes are necessary. Native live clauses remain untested. | Row amendments (decision 1) |
| jail-v1 receipt schema | `lifetime.native.details` for macOS (§4.8), identity kind `macos_audit_token`, `applied.terminal.session` widened from the constant `caller` to `caller` or `relay`, and optional `credentials[].binding`. Linux vault receipts omit `binding`, retaining the rc.4 shape; a native macOS vault entry, if present, carries `binding: attempt` (a schema contract; native staging currently refuses). If present, `binding` is valid only on a macOS vault entry and only as `attempt`; an absent field remains valid. The field addition is optional. | Schema |
| jail-v1 §6.1, §14.2 | `gc --abandon ATTEMPT`, and macOS `gc` records `gc_custody_verified`, `gc_killed_target` and `gc_abandoned` (§4.9). | Addition |
| `profiles.rs` macOS baselines | `observe = on` over `macos-closed-v1` and a preferred `build` memory ceiling (§4.10). | Baseline |
| [jail-launch-and-summary](jail-launch-and-summary.md) §3.3 (J12) | The macOS group-writable rule (§4.11). | Amendment |
| jail-launch-and-summary §4 (J13), `ukai.jail.summary/1` | The survivors line names native custody (§4.8). | Addition |
| [jail-interactive-sessions](jail-interactive-sessions.md) §3 (J14) | macOS terminal mode is the pty relay (decision 3). X05 does not hold for macOS terminal runs. | Amendment |
| jail-v1 §6.1, §6.3 (J18) | `--vm`, `vm stop`, and the kernel-bound lifetime key with its narrowing row and requirement name (§6). | Addition |
| `crates/ukai-jail` | Default native refusal; development-gated preparation, guardian and launcher modes, and the ES shim. Credential/vendor staging refuses. J17 attaches the declared observer before release; strict startup failure refuses. | Implementation |
| `crates/ukai-jail/vm` | The warm service, guest controller, package builder and measurement harnesses exist; every `run --vm` refuses at probing until a live phase re-measures the guest, and K108–K113 stay `untested` (§6). | Implementation |
| Installer, [RELEASING](../RELEASING.md) | The Mac bundle, provisioning profile and notarization, and the protected-Mac release run. | Procedure |
| [roadmap](../roadmap.md), [guide](../guide.md) | Record Apple's answer and the two tiers, and explain the native boundary and `--vm`. | Guide |

## 9. Tests and records required before "supported"

### 9.1 J16 rows (native tier)

The fixture is the reciprocal prototype's: a normal child, a child that
ignores `SIGTERM`, a `setsid` child, a double-fork daemon, `posix_spawn`
group and session children, and the root. "Empty" means an independent
snapshot of every recorded birth identity, taken before any emergency cleanup.

| Row | Claim |
| --- | --- |
| K87 | Ends with both custodians alive: wall expiry, operator cancel and target exit each leave the fixture empty and settle `tree_empty=true`. |
| K88 | Supervisor `SIGKILL`: the fixture is empty within the budget, the record reads `drained`, and `gc` then records `gc_custody_verified`. Supervisor `SIGSTOP` past the wall deadline: the guardian empties the fixture at the deadline plus the grace, and `gc` retains the attempt while the stopped supervisor lives. `killall ukai-jail` settles `tree_empty=true` as an operator stop. |
| K89 | Guardian `SIGKILL`: the fixture is empty, the receipt carries `custodian_lost`, and `tree_empty=true` comes from client S. Guardian `SIGSTOP`: the receipt carries `custodian_stalled`, the supervisor drains alone and ends the guardian, and `tree_empty=true`. |
| K90 | Defense matrix, run against the exact shipped profile digest. Every attack of §4.7 classes 1–4 from inside the sandbox fails, against both custodians, against other members during a stop, and against the operator's other processes. Each attack has a positive control from outside the sandbox. Anything that runs is recorded. |
| K91 | Descriptors: only the custodians hold A and B. R and E are held by the supervisor and the launcher, and by the guardian only until its spawn returns. No member holds a copy of the guardian's standard descriptors or of a pty slave it passed on. Every descriptor of every member is listed. |
| K92 | Drain proof and freeze, with adversarial fixtures: many threads forking in parallel, members that `SIGCONT` each other, an orphaned process group holding a stopped member, a fork chain, and an exec loop. Each stop settles `tree_empty` with every exit observed, or `tree_unknown`, never a false `tree_empty`. The `RLIMIT_NPROC` headroom holds. The p50 and p95 stop times are reported. |
| K93 | Event load: a fork and exec storm, and a signal flood during a stop, either drain or produce a real sequence gap. A gap gives `tree_unknown` unless the other custodian drained, and the guard's load never gaps client G. No custodian is terminated by the system. **And** a parallel build of a large repository (named in the record) does not gap. |
| K94 | Exec and gate: a missing program, a non-executable file and a missing interpreter refuse with jail-v1's distinctions. With `--gate-fd`, owner death before release kills the blocked launcher, and no target instruction runs. |
| K95 | Both custodians `SIGKILL`ed, one by one and with `killall -9 ukai-jail`: the receipt never settles, and the next `run` warns. `gc` kills the target by token and reports `tree_unknown`. The lease stays held until `gc --abandon`. The test lists the survivors it found. |
| K96 | Memory pressure induced by the workload: whether each custodian survives is recorded over 10 trials. A custodian that dies is handled as K88 or K89. |
| K97 | Identity and clocks: forced PID reuse never signals a replacement. A wall deadline spanning a host sleep expires on the continuous clock. |
| K98 | Refusals before any workload process: no entitlement, the client limit reached, a custody event that stays muted after unmuting (injected in a development build), `--profile none`, an explicit `pids`, `mem` or `cpu` ceiling, and requested observation cannot attach (including `--observe on`) in both evidence modes. |
| K99 | Proxy: Claude Code and OpenCode each reach an allowed host through their recorded supported proxy protocol. Separate live fixtures exercise authenticated HTTP CONNECT and SOCKS5 with allowed-host enforcement. A missing or invalid secret, a denied destination and any ungranted loopback port fail. The credential entry records `binding: attempt`. |
| K100 | Keychain, DNS and Apple Events: a sandboxed Keychain read, a direct DNS query and `osascript` to System Events all fail. |
| K101 | Terminal relay: the operator's terminal is never a member's descriptor. `TIOCSTI`, `setpgid` and `TIOCSPGRP` from members reach only the relay pty. `^C`, `^Z` and window size behave as in J14, raw mode is restored after a killed agent, and the guardian is never signalled. The `SIGTERM` grace, `^C` and a shell `trap` reach the target (the dispositions of §4.2). In a detached run, `/dev/tty` fails. |
| K102 | jail-v1 §3.3's list: `/var` versus `/private/var`, case-insensitive APFS (`.GIT` against a protected `.git`), symlinks, bundles and dynamic libraries, and nested vendor sandboxes (an agent's own Seatbelt use inside the jail) recorded. Group- or other-writable install directories refuse, including Homebrew's admin-writable prefix, with remediation to an operator- or root-owned directory that is neither group-writable nor other-writable. |
| K103 | Costs: release latency and stop-to-settled time over 20 runs, p50 and p95, on the named Mac. |
| K104 | A protected Mac: every J16 row passes with SIP enabled and the approved provisioning profile, on the release build. |

K23–K26 of jail-v2 (the slice, network, receipts and the OpenCode A01 row)
are J16 rows, and K104 includes them.

### 9.2 J17 rows (native observation)

| Row | Claim |
| --- | --- |
| K105 | The A01 fixture's expected exec and in-set file-mutation events are present with observer.set `macos-closed-v1`; attached loss-free exec and fs.write are `active` with counts, while fs.deny and native net are `unsupported`. Live acceptance remains untested. |
| K106 | An observation-client gap marks the classes `degraded` and leaves custody streams and `tree_empty` untouched. |
| K107 | The J13 summary recomputes from a macOS receipt with `summary_check.py`. |

### 9.3 J18 rows (VM tier)

| Row | Claim |
| --- | --- |
| K108 | Warm reuse: a second attempt in a running guest is released within initial 1 s of the guest jail's own release time, over 20 runs. |
| K109 | Live workspace: writes granted by policy appear on the host. Writes outside the grants and the share are absent. |
| K110 | The preview's fault matrix, rerun for the warm design. Killing the host `ukai-jail` ends that attempt through its lease, and `Ctrl-Z` of it does not. Killing the custodian, the VZ client or `ukai-vm` ends the VM service and every attempt. With every host controller suspended, the guest's wall deadline ends the attempt. All are checked before any test cleanup. |
| K111 | The stored receipt is the guest's Linux receipt, verified by digest, and the summary's transport line comes from the transport record. |
| K112 | The kernel-bound key derives `owner_loss_termination`: native macOS and this build's installed `--vm` backend refuse with `unsupported`; Linux `none` refuses. A qualified VM backend must provide a kernel-bound lifetime before accepting it. |

All five are `untested` (§6, evidence status). A real row needs an installed
and shipped client, real network probes with a positive control, the full
K110 matrix and the K111 receipt fix.

### 9.4 Compatibility records (A-rows)

Each tier is supported for an agent only after its own record:

- **J16:** Claude Code interactive and headless, with the vaulted token, and
  OpenCode headless (K26).
- **J18:** Claude Code headless in the guest.

The pass conditions are those of the Linux rows, plus:

| Row | Claim |
| --- | --- |
| K113 | Each compatibility record's summary names its custody (native) or its transport (VM). |

K113 is `untested`. The 2026-11-03 Claude Code guest run was one attempt; a
J18 record must meet the Linux rows' conditions above (the A01 fixture, ten
repetitions, the no-source refusal, revocation mid-stream, observation on
with strict evidence and the summary's credential use count) on an installed
and shipped client, after the K111 receipt fix.

## 10. Costs

- **Native, per run.** Three ES clients (S, G and G′; four with J17) and
  one extra process. The single-client prototype's readiness, from helper launch through fixture
  registration, was 40–70 ms p50 in the development VM (measured). K103
  measures the real design.
- **Native, overall:**
  - Apple's entitlement.
  - A bundle-shaped install.
  - The pty relay's code.
  - A credential binding that reaches only the attempt.
  - A dependence on `sandbox-exec`, which Apple has deprecated without
    removing. Every Seatbelt-based tool shares that risk, and K90 on each new
    macOS release catches a regression.
  - A build that needs more than the process headroom of extra processes
    fails with `EAGAIN`. The headroom is recorded.
- **VM.** About 22 s cold start once per warm period (measured, preview). 2 GiB
  of memory configured per guest, and a 511.5 MiB DMG (measured).
  Shared-file performance is K109's to measure.
- **The residual.** If both custodians are lost, the tree runs until the
  operator runs `gc`. Even then only the target is killed, and its other
  descendants can survive. The boundary, the summary and `doctor` say so.
  External kills are one cause; client bugs and workload-induced memory
  pressure are not excluded. DTS's notification-overload answer does not
  establish an external-only residual.
  The pre-first-message sequence ambiguity (§4.4) is a separate residual.
  The VM backend refuses at probing until the guest is re-measured (§6);
  only the released preview has its own recorded, narrower contract.

## 11. Open questions

1. **Apple follow-up resolved (relayed 2026-11-01, decision 5).** DTS says
   notification overload drops messages with sequence gaps and does not
   terminate a notification-only descendants client. The
   [recorded exchange](../benchmarks/jail/apple-lifetime-question.md#notification-load-follow-up-relayed-2026-11-01)
   supports §4.7 class 6. It does not resolve client bugs, system memory
   pressure or the pre-first-message sequence ambiguity (§4.4). The guard's
   fail-closed deadline-miss mode remains separate from notification custody.
   K92, K93, K95 and K96 remain required, as do entitlement, packaging, K104
   and all other release gates. The reply is not evidence that any test passed.
2. **Seatbelt's future.** If Apple removes `sandbox-exec` or SBPL, the native
   tier loses its containment and its defense together. The fallback is App
   Sandbox for containment, which is unsuited to arbitrary programs, plus ES
   authorization events for defense. That would be a redesign, not a patch.
3. **Custodian-enforced limits.** The guardian could count members and poll
   memory footprints, and treat a crossed ceiling as a limit hit. The result
   would be racy, not kernel-enforced, so it would be reported as preferred,
   never required. This is deferred.
4. **Faster recovery.** A user LaunchAgent that runs `gc` on an orphaned
   attempt would shorten the residual's window. This is deferred, as in §7.

## 12. Decisions (2026-10-22; amendments 2026-10-23 and 2026-11-01)

The operator chose two tiers, and then asked for the best and simplest answer
to each remaining question. These are those answers:

1. **The contract is amended for the native tier** (§8: jail-v2 §8, jail-v1
   §3.3, rows L02 and M01). The native tier ships with boundary
   `native_tree` and the named residual. Apple says the alternative, a
   kernel-bound native guarantee, does not exist. Waiting for it would mean
   no native tier at all.
2. **One executable.** The guardian is `ukai-jail` in guardian mode, not a
   separate binary.
   - **Why.** A second entitled executable would probably need a second
     identifier on the pending entitlement request, which is the one change
     that could add delay with Apple.
   - **What it gives up.** A distinct process name buys only survival of
     `killall -9`, an explicit external kill. Plain `killall` is already an
     orderly stop (§4.2).
   - **Apple's advice holds.** Apple asks for minimal client code, and the
     mode dispatch keeps the guardian's code path small.
3. **The pty relay for macOS terminal mode.** Without a PID namespace, it is
   the only design whose safety does not rest on an unproven Seatbelt ioctl
   filter, and it is one design for every macOS release. Its cost, the relay
   code and X05's byte equality for terminal runs, is the one J14 had already
   accepted as its fallback.
4. **An attempt-level credential binding, disclosed** (`binding: attempt`).
   This is the future native vault contract. The current implementation
   refuses native credential/vendor staging, including `ukai-jail claude`.
   Linux vault receipts omit `binding`; the optional macOS field, when
   present, is only `attempt`. The socket-holder check is dropped because it
   would be racy without a connect-time pin (§7).
5. **Order, amended 2026-11-01 (§13).**
   - **First, a measurement spike in the development VM**, because these rows
     can still change the design: K92 (drain proof and freeze), K93 (event
     load and the heavy-build gap check), and K90's class 2 (deputies).
   - **Then the complete native Claude workflow, J16 with J17**, including
     credentials, persistent state, terminal behavior, project tools, recovery
     and performance. Development-VM evidence does not replace protected-Mac
     acceptance with the approved entitlement.
   - **Then expand native compatibility and complete J18.** J18 may progress
     independently while entitlement approval is pending, but its availability
     neither qualifies native execution nor silently substitutes Linux for Mac
     programs. This supersedes the previous J18-before-J17 implementation order.
   - **Apple (updated 2026-11-01):** §11's question 1 is answered in the
     relayed follow-up. Notification overload does not kill a notification-only
     client. The measurement spike, stress tests and release gates remain;
     the both-lost residual is not proved external-only.
6. **Install-directory rule, amended 2026-10-22.** The root+operator group
   exception was withdrawn because directory-service membership cannot be
   proved complete. Homebrew's admin-writable prefix refuses. Remediation:
   install the agent in an operator- or root-owned directory that is neither
   group-writable nor other-writable. The operator chose to keep this refusal;
   Linux is unchanged.

7. **2026-10-23: declared partial set, operator decision.** Native observation
   adopts `macos-closed-v1` (§5), defined by its exact published notification
   table. Out-of-set effects alone do not degrade exec/fs.write coverage;
   actual evidence loss does. J17 is wired before release and the baseline
   becomes observe on. Attachment failure refuses before exec in both evidence
   modes; best-effort applies only to loss after successful attachment. This
   amendment does not waive live
   K105–K107 acceptance, entitlement, packaging or performance gates, and
   does not change Linux's closed set or behavior.

8. **2026-11-01: native-first developer experience.** Complete the installed,
   authenticated Claude workflow in §13 before broadening the product claim.
   The default after qualification is native, with a visible `native_tree`
   boundary; the VM is explicitly selected for Linux-compatible work requiring
   a kernel-bound lifetime or hard resource limits. Neither tier is described
   as supported before its existing gates pass. Total custodian loss remains
   a disclosed residual regardless of cause.

## 13. Native-first implementation plan: one complete Claude workflow

**Status: planned, not accepted.** This is the operator's 2026-11-01 product
direction and implementation sequence. Every step and NC acceptance item below
is pending live qualification. Existing component code, historical prototypes
and the DTS reply do not count as completed steps. This section adds workflow
requirements; it does not replace K23–K26, K87–K113 or their acceptance-map
clauses. Writing this plan authorizes no release and records no new runtime
result.

### 13.1 Product target and first supported combination

A developer installs Ukai once, configures a credential once, enters a
repository and runs `ukai-jail claude`. Claude behaves like its normal terminal
application, keeps that repository's sessions, edits the granted checkout,
uses explicitly granted tools and destinations, and leaves an understandable
summary when the developer exits. The workload cannot expand its own grants.

The first qualification record names one Apple Silicon Mac and macOS 27+
build, one signed Ukai release candidate, one Claude Code native Mach-O
installer version, one Node/npm version, Git, and Terminal.app with zsh. Pin
binary and fixture digests; do not infer compatibility with other versions,
terminals, npm-installed Claude, Intel Macs or earlier macOS releases. Use a
Claude install directory satisfying §4.11's ownership and mode checks; the
Homebrew refusal remains. Broader support requires separate records.

Native runs Mac programs with defended custody. The optional VM runs Linux
programs with the guest's kernel boundary. A policy requiring kernel-owned
termination or hard resource limits must refuse native execution; it can run
only on a qualified backend providing those requirements. A Mac-only command
with those requirements remains unsupported. A backend choice must be visible
before execution, and neither a missing entitlement nor an unavailable VM
permits an uncontained fallback.

### 13.2 The reference journey

Create a versioned `macos-claude-workflow-v1` fixture under the jail benchmark
harness during implementation. It is a small Git checkout with a pinned npm
lockfile, one deliberately failing unit test, a small web page with hot reload,
and a documented edit that makes the test pass and changes the page. It also
has a workspace-local npm cache, a protected fixture path, and separate fake
secret and sibling-project sentinels outside the grants. No real unrelated
project or credential is used as an attack fixture.

The intended operator journey, after implementation and qualification:

1. Install the notarized package into `~/Applications`; the installer exposes
   `ukai-jail` on PATH. `doctor --profile agent` explains any missing capability
   before a workload starts. No developer environment variable, sudo, root
   service or SIP change is part of the supported path.
2. Run `claude setup-token` outside Ukai, then paste the value into
   `ukai-jail credential set claude-oauth`. Do not put it in a command argument,
   repository or recorded transcript. This is the chosen subscription flow;
   an API-key fallback needs its own compatibility record and must never be
   selected silently because this flow failed. Anthropic documents setup tokens
   and `CLAUDE_CODE_OAUTH_TOKEN`; interactive placeholder behavior on the pinned
   Mac build still needs measurement. [Authentication documentation](https://code.claude.com/docs/en/authentication)
3. Enter the fixture and run `ukai-jail claude`. Complete Claude's first-run
   onboarding and normal permission prompts. Confirm the selected credential
   identifier, workspace, backend and grants without exposing secret values.
4. Ask Claude to inspect `git status`/`git diff`, install the locked dependencies,
   fix the failing test, run the tests and edit the page. An operator-controlled
   launch configuration grants the required registry destinations and tool
   roots. Git inspection does not require granting writes to protected `.git`.
   Ship a reviewable starter configuration so this needs no manual Seatbelt
   editing: name the provider endpoints, `registry.npmjs.org:443` for the pinned
   fixture, read-only tool roots and workspace-local cache. Any extra destination
   must be justified and approved by the operator outside the workload; an
   install redirect or repository file cannot approve it.
5. Start the development server on the explicitly granted loopback port. The
   operator opens the printed URL in a host browser and observes the page change
   through hot reload, including its WebSocket connection. The workload does
   not receive permission to launch the browser through LaunchServices.
6. Exercise resize, paste and Unicode input; interrupt an operation with Ctrl-C
   without accidentally killing the guardian; suspend/resume using Ctrl-Z/fg.
   Exit Claude normally and confirm that its server and other descendants stop.
7. Run `ukai-jail claude --resume` and continue the same conversation without
   repeating credential setup or ordinary onboarding. A second checkout gets
   independent settings/history. Run a short headless counterpart with the same
   grants and vault. Any Claude permission flag is an explicit test/operator
   choice, never injected by Ukai.
8. In separate fault trials, kill or stall one custodian, then exercise the
   both-lost case. Check verified cleanup where possible and the explicit
   recovery path where it is not. These trials use the isolated fault harness;
   their survivors are recorded before emergency cleanup.

### 13.3 Implementation sequence and deliverables

Each step has a concrete exit condition. Build the workflow incrementally
behind the development opt-in; remove that requirement from a supported
package only after step 6. No individual successful demo enables native by
default.

1. **Qualify the custody foundation and align the contract.** Work in
   `src/platform/macos/{custody,guardian,es,boundary.rs,sandbox.rs}` under
   `crates/ukai-jail`, with the existing native harness. Re-create the disposable
   development VM per §4.12; run the K92/K93/K90-class-2 spike before relying on
   the design. Preserve K95 and K96 fault/pressure coverage. Save identities,
   sequence gaps, stop budgets and positive controls, and fix failures before
   adding workflow grants. Keep documentation tests and
   `jail-v1/acceptance-map.toml` aligned with the declared J17 design. K98 was
   clarified on 2026-11-01: requested observation that cannot attach refuses
   before exec in both evidence modes; successful attachment is permitted.
   The gate, mapping and regression checks preserve every other refusal and
   retain K98.1 as untested until full live qualification. **Exit:** NC01 plus the spike's required evidence;
   all other live gates remain pending until exercised on the release candidate.
**2026-11-01 progress:** the nine documentation failures and K98/K99 mapping
inconsistencies are repaired. The isolated spike ran, but the preloaded-job
`launchctl kickstart` escape still reached both custodians; the candidate
`mach-bootstrap` denial was insufficient. **2026-11-02:** the class is closed
— the template denies executing the `launchctl` client (digest
`b2ae082d…`, rerun 4/4 with outside controls), and after a direct-client
probe showed that `launchctl`'s own XPC client is built from the inherited
bootstrap port, the launcher strips that port before the exec; the same-VM
direct-client rows pass against both custodians, and the exact-digest
defense matrix passes its rows (§4.7). The same day's [compatibility
measurements](../benchmarks/jail/results/macos-compat-2026-11-02/README.md)
closed the spike's other three findings: rule 6 is amended (clamp-with-floor,
§4.1) and measured on a busy default-ceiling host; the whole stop path is
instrumented (`stop.phases`, §4.5's NC09/NC11 reconciliation: the machine's
stop is 20–74 ms, the guardian's record ≤330 ms, and the spike's 2.4–5.3 s
oracle interval is harness-side overhead); and the full SQLite source-tree
build passes under two explicit receipt-recorded grants (`/private/var/tmp`
for Apple tclsh8.5's TMPDIR-ignoring error files, and the workspace as an
exec root — the interim shape of step 4's workspace-helper review, whose
per-helper digest design remains required). K95/K96, full J17 loss trials,
credentials, packaging and K104 remain; NC01 stays open.
   K92's 25 bounded drain checks and K93's ten event-load checks pass in that
   VM, but default process-headroom compatibility, end-to-end stop timing and
   the full SQLite repository build remain unresolved. The four-configuration
   amalgamation build passes; the full source-tree configure fails in Tcl's
   subprocess error capture even with an explicit SDK and private temporary
   directory. It does not satisfy K93's ordinary large-repository requirement.
2. **Make installation and preflight reproducible.** Extend the packaging and
   installer under `crates/ukai-jail/dist` with §4.12's bundle, entitlements,
   provisioning, signing and notarization. Connect preflight to
   `macos/requirements.rs` and program resolution in `launch_profile.rs`.
   Detect unsupported OS/build, missing entitlement, invalid install roots,
   missing agent/tools and absent credential sources before workload release.
   Diagnostics must name the problem and a specific safe remedy. Test clean
   install, upgrade and removal in a disposable account; upgrades preserve
   credentials/state and removal does not silently delete them. **Exit:** NC02;
   no shipping until entitlement approval and K104.
3. **Connect vault, launch and persistent state.** Implement the native paths
   across `macos/boundary.rs`, `macos/bridge.rs`, `credentials.rs`,
   `credential_store.rs`, `launch_profile.rs` and the state/lease modules.
   Replace staging refusals only for paths whose complete lifecycle is tested;
   other staging modes remain refused. Adapt the native launch contract without
   weakening Linux's program-bound vault. The Mac proxy substitutes the token
   only at its approved provider destination and records `binding: attempt`:
   members able to use the authenticated proxy can use the credential, even
   though they never receive its value. Preserve per-workspace state leases,
   `.credentials.json` discard and contamination quarantine. Qualify both first
   launch and resume, expiry/revocation and source replacement; do not read the
   host Keychain or implement an undocumented refresh flow. **Exit:** NC03–NC05
   and the credential/state portions of the Claude compatibility record.
4. **Complete the local development loop and terminal.** Integrate
   `macos/relay.rs`, `stdio.rs`, `launcher.rs`, `sandbox.rs`, `bridge.rs` and
   `boundary.rs` with the launch profile. Grant only named read-only tool roots,
   the writable checkout/cache and reviewed network destinations. Keep policy
   narrowing and protected paths intact. Resolve the measured tool-environment
   and temporary-file compatibility failures. The current native profile only
   executes programs from read-only grants: workspace compiler wrappers were
   denied in the spike. Review how the chosen workflow runs repository-local
   scripts and generated helpers, with explicit policy, digest, receipt and
   narrowing semantics plus outside-workspace negative controls; do not
   silently make every writable path executable or run helpers outside custody.
   Add the preview listener described
   below as an explicit new capability, including policy/schema, canonical
   digest, receipt, documentation and negative-test changes before enabling it.
   **Exit:** NC06–NC08 and K90/K91/K99–K102 rerun against the resulting profile.
5. **Integrate observation, recovery and performance.** Use
   `macos/observe.rs`, `observe/run.rs`, `guardian/record.rs` and the shared
   summary/gc/state paths. The normal journey uses J17 observation on and strict
   evidence; requested attachment failure refuses before exec. Keep observation
   and custody loss distinct. Make the final summary and next-start diagnostic
   actionable, implement no automatic abandonment, and measure the budgets in
   §13.5. **Exit:** NC09–NC11, K103 and K105–K107 evidence.
6. **Qualify the installed release candidate end to end.** Run the complete
   journey and fault matrix on a SIP-enabled Mac with the approved profile,
   using the installed signed build without the development opt-in. Rerun every
   existing applicable release gate, including the OpenCode/K26 obligations;
   the Claude focus does not waive them. Publish the exact supported combination,
   evidence and limitations only after NC12 and the existing gates pass. Complete
   the explicit VM option separately under J18's own gates; do not broaden a
   native support claim to cover it.

**Preview listener design constraint.** The proposed grant permits a member
to bind/listen/accept on one operator-selected `127.0.0.1:port` for this attempt.
It permits responses on accepted connections, including hot-reload WebSockets;
it does not permit new outbound connections to other host services. No wildcard
interface, general localhost exemption, arbitrary Unix socket, Mach service or
inherited operator socket is granted. Other local processes can reach this
listener; it is not an authenticated private channel. A port conflict fails
visibly without selecting a different port or weakening policy. Record the
grant and enforce its absence on subsequent attempts unless selected again.
The backend evaluation must prove these rules can be separated on the supported
OS before committing to a policy spelling. If they cannot, this workflow stays
blocked pending a reviewed broker design; the server may not run outside Ukai
as an invisible workaround. This is a planned extension to §4.10, not a current
capability claim.

**Vendor compatibility constraint.** Use HTTP(S) proxying for Claude's provider
traffic. Anthropic currently documents authenticated HTTP(S) proxies and says
Claude Code does not support SOCKS. K99 was clarified on 2026-11-01 to separate
agent/version compatibility from live fixtures for both bridge protocols.
Allowed-host enforcement, missing/invalid-secret rejection, denied destinations
and ungranted-loopback rejection remain mandatory. K99.1 remains untested until
all of that live evidence and the attempt-binding receipt are recorded. Browser hot reload is a separate inbound
listener test, not evidence that Claude's provider traffic supports SOCKS.
[Network documentation, checked 2026-11-01](https://code.claude.com/docs/en/network-config)

### 13.4 Workflow acceptance criteria

NC identifiers are additional requirements local to this section. **All are
pending.** A component test alone cannot satisfy a live row. Record both positive
and negative controls, exact versions and evidence paths. Missing evidence is
pending, never pass; a failure blocks the complete native Claude workflow claim.

| ID | Acceptance condition | Existing gates retained |
| --- | --- | --- |
| NC01 | The design spike completes without a false `tree_empty`; defense probes have working outside-sandbox positive controls. Known contract/test mismatches have explicit resolutions and the required documentation/schema/acceptance-map checks pass. | K90, K92, K93; all live rows still require release qualification |
| NC02 | On the named protected Mac, a clean account installs and starts the documented workflow without sudo, SIP changes or development environment variables. Missing entitlement, tools, credential and unsafe install-root controls refuse before release with a specific remedy; upgrade preserves state and credentials. | K94, K98, K102, K104; §4.12 |
| NC03 | The setup-token flow completes a real interactive request and a headless task using the authenticated bridge. The record names `binding: attempt`; canary secret checks find no token in child-visible files/environment, workspace, retained state, logs, receipts or transcripts. Missing/invalid sources refuse, upstream expiry is actionable, and revocation stops new credential substitution under the existing vault contract. No silent API-key selection, host Keychain access or refresh-token import. | K99, K100; J12 vault requirements |
| NC04 | After verified normal exit, settings and conversation resume in the same checkout for ten consecutive exit/resume cycles. A second workspace cannot read that history. Parallel sessions cannot acquire the same writable state lease; the existing visible throwaway fallback remains explicit. | J14 state/lease requirements; §4.9 |
| NC05 | Interrupted preparation, agent failure and uncertain cleanup do not release a held state lease without proof or explicit abandonment. A discarded credential file and a contaminated-state fixture exercise discard/quarantine without printing a secret or changing the host's Claude login. | K88, K89, K95; J14 recovery |
| NC06 | From a fresh fixture, Claude inspects Git, runs locked dependency installation, makes the specified edit and passes the unit tests. Only the checkout/cache and declared state are writable. Unrelated-project, protected-path and denied-destination canaries remain inaccessible; a repository request to broaden grants fails. Refusals identify the path/destination and operator remedy without an uncontained retry. | K90, K99, K100, K102 |
| NC07 | The explicitly granted server is reachable from the host browser; an edit visibly hot-reloads. An ungranted port, wildcard/LAN bind, outbound connection to an unrelated host service and Unix-socket deputy attempt fail. Port conflict is actionable. Normal stop and single-custodian fault trials leave no recorded server/worker survivors before harness cleanup. | K87–K92, K99; new listener defense controls |
| NC08 | Real Claude and deterministic pty controls pass resize, Unicode/bracketed paste, Ctrl-C, Ctrl-Z/fg and hangup. Ctrl-C retains Claude's normal semantics; explicit attempt cancellation ends descendants. Terminal mode is restored when restoration is possible, including agent death, and any hangup exception is recorded. No member has the operator's terminal descriptor and no control sequence signals the guardian. | K91, K101; J14 terminal record |
| NC09 | Normal exit, explicit stop and wall expiry leave the recorded fixture empty within the existing stop budget. Single-custodian kill/stall cases meet K88/K89. Both-lost cases retain `tree_unknown`, list known survivors before emergency cleanup and show §4.9's exact applicable recovery command, including reboot when identity cannot be established. No automatic `gc --abandon`, guessed PID kill or false success. | K87–K89, K92, K95–K97 |
| NC10 | Every normal journey receipt names `native_tree`, the effective grants, attempt credential binding and `macos-closed-v1`. Summary recomputation agrees; observed mutation counts are not described as file contents or a complete diff. Forced observation loss degrades observation without inventing custody loss; forced custody gaps cannot produce an unsupported clean-drain claim. Requested attach failure refuses before exec. | K93, K105–K107, K113 |
| NC11 | The paired startup and terminal measurements meet §13.5's initial budgets; the named ordinary heavy build has no custody gaps. Event storms and memory-pressure faults are also run and reported separately rather than excluded from the record. | K92, K93, K96, K103 |
| NC12 | Complete ten fresh-workspace journeys, the ten resume cycles, a headless counterpart and a four-hour working-session soak covering two workspaces and sleep/wake. No unexplained state loss, unreported evidence loss or unverified end reported as clean. All existing native release/compatibility gates, including K104 and J17, pass on the installed candidate; all NC rows have reviewable evidence. | K23–K26, K87–K107, K113; §9.4 and release procedure |

The paid model's output is not a deterministic test oracle. Record the requested
edit, resulting diff and test result; isolate model/provider failures from Ukai
failures without discarding either. A failed journey is retained and diagnosed;
ten completed journeys are required, not a claim that ten selectively reported
attempts all succeeded. Deterministic fixtures establish control behavior even
when an agent declines a request. Real secret entry is excluded from recordings;
secret scans use a harness that returns presence/absence without printing values.

### 13.5 Performance budgets and evidence

These are **initial acceptance targets**, not current measurements:

- **Warm native startup:** additional p95 latency below 200 ms across 20 paired
  direct/native launches on the named Mac. Use the same deterministic local
  marker program, workspace and tool grants, with custody, J17, proxy/vault and
  state preparation enabled in the jailed case. Measure invocation to the
  readiness marker emitted immediately on entry, subtract each paired direct baseline,
  and publish raw samples plus p50/p95. No provider request is involved. Report
  real Claude time-to-first-prompt and cold starts separately; do not attribute
  network/model latency to the jail or use a custody-only microbenchmark as the
  full-launch result. A synthetic vault fixture contains no real credential.
- **Terminal responsiveness:** p95 additional local pty round-trip latency at
  most 20 ms over 200 paired direct/relayed samples, with no lost or duplicated
  bytes in the deterministic input test. Record the real Claude interaction
  checks separately; perceived model-response delay is not a pty measurement.
- **Cleanup:** retain §4.5's initial five-second stop budget and the separately
  recorded guardian follow-up. A later recovery does not turn a missed initial
  budget into a timely pass. The intentionally both-lost residual is judged by
  honest recovery reporting, not an invented cleanup guarantee.
- **Load:** K93's ordinary-heavy-build no-gap requirement and K96's ten memory
  pressure trials remain mandatory. Record idle CPU/memory and their change
  during the soak; do not claim hard native resource ceilings.

A missed budget blocks workflow acceptance until optimized or explicitly
revised in the spec with the measurements and tradeoff recorded. It cannot be
waived by removing observation, weakening policy or omitting slow samples.

For each candidate, save a reproducible evidence directory under
`docs/benchmarks/jail/results/` containing the source revision/dirty-state
record, package and executable digests, host/OS/SIP/provisioning facts, pinned
Claude/tool/fixture versions, profile digest and grants, exact commands and
prompts, redacted terminal captures, test logs, before/after fixture diffs,
receipts, summary checks, fault identities and raw timing samples. An index maps
every NC item and existing K/A gate to its evidence and result. This plan creates
no evidence directory or pass record in advance.

The release checklist must continue to require entitlement approval, packaging
and notarization, normal-SIP K104 acceptance, all native observation and
compatibility rows, and the full stress/fault matrix. Update the guide,
compatibility record and installer claims only from that evidence. J18's gates
remain required for the optional VM and are not credited by native acceptance.
