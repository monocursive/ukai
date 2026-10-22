# Jail proposal: macOS in two tiers, native custody and a warm VM (J16–J18)

Status: work in progress on the integration branch, 2026-10-22;
J16–J18 are not supported or released. `dev` at `ae14865f8` remains the
refusal-only historical baseline, not the integrated implementation.
Current implementation: native execution is **off by default**. Setting
`UKAI_JAIL_MACOS_NATIVE=dev` enables development only; a native receipt records
`native_execution=dev`. Native credential, vault and vendor staging answer
`unsupported` and refuse. `J17_OBSERVE=false`: `ObserveRun` exists but is
unwired; `fs.write` would still be `degraded`/partial even if wired. Every
`run --vm` refuses before connecting: no qualified VM backend exists yet.
The new custody implementation has not run with live Endpoint Security.
J16 lacks the bundle, Info.plist, entitlements and `~/Applications` installer;
J18 lacks network, the `agent` profile, a workspace share and in-guest
credentials. Decision 5's K92/K93/K90-class-2 measurement spike has not run.
The development VM was deleted on 2026-10-22 and must be re-cloned (§4.12).
Apple's entitlement and the protected-Mac acceptance run (K104) remain
release gates, alongside completing and validating the implementation.
Sections below specify release requirements where they describe behavior
beyond those gates; they are not live acceptance evidence. Historical
prototype evidence is identified separately.
Decisions were settled on 2026-10-22 (§12). The proposal was written against
`dev` at `68512e1f1`, after
Apple Developer Technical Support answered code-level support case `22799543`
(the [question and answer](../benchmarks/jail/apple-lifetime-question.md)).

- **The direction.** The operator chose two tiers.
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
- **inferred**: argued from those, not observed.

Normative words follow jail-v2. **must** is a release gate. **initial** is a
tunable default that must be recorded. **candidate** is unproved until the
named measurement passes.

Apple's answer to "does macOS provide a supported, kernel-owned boundary that
stops every descendant once every userspace custodian is gone?" was:
*"No, nothing like this currently exists."* Apple's suggestion was to make the
custodians impossible for the workload to kill. Each custodian holds an
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
| If every Ukai process of the attempt is lost | **the tree may survive**. The workload cannot cause the loss (§4.7). | the guest's own death chain ends it, as on any Linux host (§6) |
| Receipt's `lifetime.boundary` | `native_tree` | `pid_namespace` (a Linux receipt) |

The native tier is the intended default after qualification. Today the
default refuses; the development opt-in does not make it supported. A run
that needs a kernel-bound lifetime must use a supported Linux deployment or
the separate released VM preview within its documented limits. `run --vm`
in this tree refuses.

## 1. Scope

Release targets (not all implemented):

- **J16, the native tier.** Seatbelt containment and two Endpoint Security
  custodians. Covers `tool`, `build` and `agent`, headless and in terminal
  mode, with J12 launch and J14 persistent vendor state, and observation off.
  Includes receipts, `gc`, `doctor`, packaging with the entitlement, and the
  rows of §9.1.
- **J17, native observation.** Exec and filesystem-mutation evidence from a
  separate ES client (§5).
- **J18, the VM tier.** The released VM preview becomes a warm, shared-workspace
  backend selected with `--vm`. It also adds the policy key that requires a
  kernel-bound lifetime (§6).

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
conditions. The workload must be unable to take both custodians away. An
external loss of both leaves the disclosed possibility of survivors.

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
what it is. The proposed VM backend is not yet available; the current
`run --vm` path refuses before connecting.

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
     controls, so crafted input cannot crash both custodians through code they
     share. Apple names client bugs as the main risk.
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
   kernel clamping below the allowance). The receipt records 1024 only after
   this check. Every member inherits the limit, and none can raise it without
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
   - the record and the guardian's ends of A and B;
   - the launcher's ends of R and E, which the guardian passes on and closes;
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

   The guardian then lowers `RLIMIT_NPROC` (rule 6) and reports `ready` on B.
   If any of this fails, it exits naming the failure, and the supervisor
   refuses.
4. **Launch.** The guardian calls `posix_spawn` once for `sandbox-exec`. It
   interprets nothing in the launch block: it turns the block into
   `posix_spawn` arguments and nothing else. It then closes its copies of R,
   E, the standard descriptors and any pty slave, so that end-of-file means
   what it does on Linux (jail-v1 §8.3). `sandbox-exec` applies the profile
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
| Supervisor dies: crash or `SIGKILL` | No, by §4.7 | The guardian sees end-of-file on A, stops the tree and writes its record. The receipt stays at its last phase, as on Linux after a supervisor crash. `gc` verifies the end from the record (§4.9). |
| Guardian dies | No | The supervisor sees end-of-file on B and the guardian's exit, and stops the tree from client S, as Linux stops on the watcher's death. `tree_empty=true` stays possible from S's stream alone. Liveness is weaker without the guard step (§4.5). |
| Supervisor stalls (`SIGSTOP`, a debugger, a stopped terminal job) | No | The guardian ends the tree at the wall deadline plus the grace, with cause `wall`. A stall alone is never taken as a loss. There is no heartbeat, so an operator's `Ctrl-Z` of the whole job does not kill the run. |
| Guardian stalls | No | At stop, the supervisor drains alone and then ends the guardian. The error is `custodian_stalled`. |
| A custody stream gaps | Yes, with an event storm | Detected. The stop proceeds, and the result is `tree_unknown` unless the other custodian drained. |
| A member changes user (a setuid program the profile missed) | Only through a gap in the profile | Integrity loss, so `tree_unknown`. K90 hunts for the gap. |
| A crafted program name or argument | No | Custody handlers never read variable-length fields (§4.1, rule 3). |
| ES ends the guardian for its stop-time authorization subscription | No (by reading): fail-closed mode denies a missed deadline and never kills the client (`ESTypes.h`) | Were it to happen, as "guardian dies". The supervisor holds no authorization subscription. |
| `killall ukai-jail` (`SIGTERM`) | No | An orderly stop. The supervisor stops the run, and the guardian ignores the signal. |
| **Both custodians die**, for example `killall -9 ukai-jail` | **No, and only from outside the workload** | **The named residual.** The tree may keep running. Nothing acts until the next `run`, `doctor` or `gc` (§4.9). |
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

**must:**

- The shipped profile closes every class below.
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
6. **Event load.** A storm can only overflow a notification queue, which shows
   as a sequence gap (by reading). That a notification-only client is never
   terminated for load is not documented by Apple. It is K93's measurement and
   §11's question 1.

Same-UID processes outside any jail (the operator's other tools, an agent
that is not run under Ukai) can end both custodians. That is the "external
events" Apple names, and it is why the boundary is `native_tree`.

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
  - the process headroom (rule 6) and pending handshake-event count;
  - per custodian (`supervisor`, `guardian`), one `result`: `drained`,
    `not_drained`, `lost` or `stalled`, plus `stream` (`contiguous`,
    `gapped` or `unknown`). `events` is an integer, not a per-event object;
    without a guardian record it is null and the guardian stream is
    `unknown`. An absent record never asserts continuity;
  - the stop's member count, budget and elapsed time.
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
- Observation is off: no attached audit observer and no audit counts.
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
| `closed_set_observation` | `unsupported`; J17 is off and `ObserveRun` is unwired. |
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
- **macOS profile baselines** (`profiles.rs` is already per-OS) set two values
  until J17, which the policy snapshot records as baseline values, not
  implicit choices (jail-v1 I02):
  - `observe = off`. An explicit `--observe on` refuses with
    `unsupported_platform`, and the summary says `evidence: not observed on
    macOS native`.
  - `build`'s memory ceiling becomes preferred, recorded as not applied,
    instead of required.
- **The bridge on a shared loopback.** The bridge keeps jail-v2's two ports,
  HTTP and SOCKS5, on ephemeral loopback ports. Each requires a per-attempt
  secret, carried in the child's proxy URLs (HTTP proxy authentication, and
  SOCKS5 username and password). The profile allows outbound loopback to
  those two ports only. This is a candidate, and K99 measures Claude Code and
  OpenCode through both. A connection is attributed to the attempt as soon
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
- **Keychain.** The Security server and the keychain files are denied. A
  sandboxed `security find-generic-password` fails (K100).
- **The Mach allowlist** is the smallest set under which Node, Git, a shell
  and the bundled agents work. Each entry is justified in the backend
  evaluation.

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
- **Development VM:** deleted on 2026-10-22. It must be re-cloned under the
  existing [runbook](../benchmarks/jail/macos-development.md) before further
  SIP-disabled live-ES measurements; none were run on the new implementation.
- **Release must** repeat every J16 row on a normally protected Mac, with the
  approved profile. **J16 cannot ship before Apple grants the entitlement.**

## 5. Native observation (J17)

Current status: `J17_OBSERVE=false`; the `ObserveRun` worker API exists but
is unwired into an attempt. The native baseline stays `observe = off` and
an explicit observation requirement refuses. Toggling the constant alone
does not qualify observation. No live observed attempt is recorded.

A fourth ES client is proposed, in addition to S, G and G′ and held by the
supervisor. The unwired worker maps:

- `NOTIFY_EXEC` for the `exec` class;
- `NOTIFY_CREATE`, `NOTIFY_RENAME`, `NOTIFY_UNLINK`, `NOTIFY_LINK`,
  `NOTIFY_TRUNCATE`, `NOTIFY_SETATTRLIST`, `NOTIFY_SETMODE` and `NOTIFY_CLOSE`
  with `modified` set, for `fs.write`.

Unlike the custody clients, it reads paths. A crash there takes the
supervisor, which the guardian covers (§4.6).

The worker resolves the existing workspace directory through `F_GETPATH`
before creating ES: symlink aliases, `/var` versus `/private/var`, and stored
capitalization on case-insensitive APFS use the kernel path. Missing or
non-directory roots refuse. Delivered event paths are not looked up later.

Both global and per-type sequences may start at 0 or 1. A first value above
1 is a gap with unknown exact loss. Audit frames and coverage notes carry
`sequence_start: "unverified"`, including the initial partial-coverage note
for an empty audit stream: loss before the first delivered message can remain
undetectable. Global and per-type loss counters are not added together. The
shim's cumulative ring-drop count remains exact; a potentially overlapping
sequence gap has a null count. Repeated snapshots do not count a drop again,
and no exact combined total is invented.

The worker treats a sequence or sink loss as an observation gap with
`degraded` status. Its bookkeeping is separate from custody; live integration
still needs K106. Even without a detected gap, `fs.write` is always
`degraded`/partial (`macos-es-notify-partial-v1`): uncovered mutation paths
and mmap writes are disclosed gaps with null observed counts. `exec` may
be active in the worker, but is unsupported in an actual unobserved run.
Other classes:

- **`fs.deny`** stays `unsupported`. Seatbelt denials are not ES events, and a
  sandbox denial log is not evidence (jail-v1 §3.3).
- **`proxy.net`** comes from the bridge, as on Linux.
- **The macOS baselines** stay `observe = off`. A later baseline change
  requires wiring and acceptance; `strict` evidence cannot claim complete
  coverage while required classes are unsupported or degraded.
- **`learn`** stays refused while `fs.deny` is unsupported.

For native journal frames, the summary separates paths whose content was
`modified` (including truncation), entries `created`, and paths `with metadata
changes`. Workspace-root changes are stated as `workspace root content
modified`, `workspace root created` or `workspace root metadata changed`,
and are excluded from entry counts. Partial coverage still makes those
counts lower bounds. These worker/summary behaviors do not enable J17.

## 6. VM tier: a warm guest (J18)

The [VM preview](../../crates/ukai-jail/vm/README.md) cold-boots a disposable
Ubuntu guest for every command. It copies inputs in and outputs out, and it is
offline. Current J18 CLI execution is unavailable: **every `run --vm`
refuses before connecting**, without contacting the control or attempt
socket or staging credentials. There is no qualified backend. The helper
and protocol tests do not prove a guest preflight, full policy translation,
workspace sharing, network, agent or credential support. A missing or invalid
VM installation is a host prerequisite refusal: exit 125, `backend_unavailable`
at `probing`, remediation `host_setup`, including `--profile none`. Once
installation discovery succeeds, VM-policy requirements refuse with
`unsupported`: enforcement is unavailable in this build. With native
development enabled, `--lifetime kernel-bound` also refuses with
`unsupported`, explaining that
native macOS cannot provide it and VM policy enforcement is unavailable in
this build; adding `--vm` is not offered as a working remedy.

The lifetime key is implemented in top-level profile files and operator and
project `[jail]` tables as `lifetime_boundary = "kernel-bound"`. It has the
same narrowing, canonical bytes and digest as the CLI; omission in a later
layer does not remove it, and an unknown value is `invalid_config` (exit 2).

The helper's orderly SIGTERM path now exits 0 during startup, idle,
preparation or running and removes its service socket; a previously recorded
custody/transport failure still exits 125. Synthetic helper tests establish
that distinction without booting a VM or qualifying `run --vm`.

The following are future backend requirements, not current behavior:

- **Selection.** `--vm` on macOS.
- **The requirement.** J18 also adds a policy key that requires a
  kernel-bound lifetime (`lifetime.boundary` `pid_namespace`). It comes with
  a jail-v1 §6.3 narrowing row, a canonical-bytes update and a derived
  requirement name, `owner_loss_termination`. Native macOS reports it
  `unsupported` and refuses; this build's VM tier is unavailable too.
  Linux `none` refuses. A future qualified VM backend must supply the
  kernel-bound lifetime before it can accept the requirement.
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
    wall deadline still ends the attempt.
  - **`ukai-vm` dies.** The VM service ends, and every guest process with it.
    The preview measured each of its kill cases once, and K110 repeats them.
- **The receipt** is the guest's Linux receipt. It is verified on the host and
  stored in the host's attempt directory beside a transport record naming the
  VM and the host-side facts. The summary prints the guest summary plus one
  transport line from that record, as the J15 action adds its host-setup line.
- **Workspace.** A per-attempt virtio file-system share of exactly the
  workspace. The guest jail then applies the policy's grants. Changing a
  running VM's share is by reading and a candidate. K109 measures it. Mac-built
  native dependencies, such as `node_modules` add-ons, do not run in the
  guest, and the guide says so.
- **Network and credentials.** The guest has a NAT adapter, and the guest
  jail's proxy enforces the policy, as on any Linux host. Credentials go from
  the host's vault files to the guest supervisor over vsock, once per attempt,
  and are never written to the guest disk.
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
| `profiles.rs` macOS baselines | `observe = off` and a preferred `build` memory ceiling until J17 (§4.10). | Baseline |
| [jail-launch-and-summary](jail-launch-and-summary.md) §3.3 (J12) | The macOS group-writable rule (§4.11). | Amendment |
| jail-launch-and-summary §4 (J13), `ukai.jail.summary/1` | The survivors line names native custody (§4.8). | Addition |
| [jail-interactive-sessions](jail-interactive-sessions.md) §3 (J14) | macOS terminal mode is the pty relay (decision 3). X05 does not hold for macOS terminal runs. | Amendment |
| jail-v1 §6.1, §6.3 (J18) | `--vm`, `vm stop`, and the kernel-bound lifetime key with its narrowing row and requirement name (§6). | Addition |
| `crates/ukai-jail` | Default native refusal; development-gated preparation, guardian and launcher modes, and the ES shim. Credential/vendor staging and closed-set observation refuse. | Implementation |
| `crates/ukai-jail/vm` | Helper and transport components exist; every `run --vm` refuses pending a qualified backend. | Implementation |
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
| K98 | Refusals before any workload process: no entitlement, the client limit reached, a custody event that stays muted after unmuting (injected in a development build), `--profile none`, an explicit `pids`, `mem` or `cpu` ceiling, and `--observe on`. |
| K99 | Proxy: Claude Code and OpenCode reach an allowed host through the authenticated HTTP and SOCKS5 ports. A connection without the secret, and any other loopback port, fails. The credential entry records `binding: attempt`. |
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
| K105 | Once wired, the A01 fixture's expected exec and supported file-mutation events are present; exec may be `active`, `fs.write` remains `degraded` with its partial-coverage gaps and null count, and `fs.deny` is `unsupported`. Until then native observation refuses. |
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

### 9.4 Compatibility records (A-rows)

Each tier is supported for an agent only after its own record:

- **J16:** Claude Code interactive and headless, with the vaulted token, and
  OpenCode headless (K26).
- **J18:** Claude Code headless in the guest.

The pass conditions are those of the Linux rows, plus:

| Row | Claim |
| --- | --- |
| K113 | Each compatibility record's summary names its custody (native) or its transport (VM). |

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
  The pre-first-message sequence ambiguity (§4.4) is a separate residual.
  The proposed VM backend is unavailable; only the released preview has its
  own recorded, narrower contract.

## 11. Open questions

1. **Apple follow-up (to send now, decision 5).** Can a notification-only
   descendants client be terminated by the system because of load generated
   by its descendants? Or does it only drop messages, with gaps in `seq_num`
   as `ESMessage.h` describes? The design is built for "only drops" (§4.7
   class 6). K93 measures it, and Apple's word would make it contract. The
   guard client needs no question: `ESTypes.h` says fail-closed mode never
   kills the client.
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

## 12. Decisions (settled 2026-10-22)

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
5. **Order.**
   - **First, a measurement spike in the development VM**, because these rows
     can still change the design: K92 (drain proof and freeze), K93 (event
     load and the heavy-build gap check), and K90's class 2 (deputies).
   - **Then J16**, developed against the SIP-disabled VM while the
     entitlement is pending.
   - **Then J18**, which has no Apple dependency, so a Mac gets the strong
     tier even if the entitlement is still pending when J16 is code-complete.
   - **J17 last.**
   - **Apple:** §11's question 1 goes to the forum thread now. It is the only
     remaining question.
6. **Install-directory rule, amended 2026-10-22.** The root+operator group
   exception was withdrawn because directory-service membership cannot be
   proved complete. Homebrew's admin-writable prefix refuses. Remediation:
   install the agent in an operator- or root-owned directory that is neither
   group-writable nor other-writable. The operator chose to keep this refusal;
   Linux is unchanged.
