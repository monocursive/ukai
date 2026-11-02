# Apple technical question: inherited workload lifetime

**Submitted through Apple code-level support on 2026-10-11.** This is the original
draft; the [submission record](apple-lifetime-support-2026-10-11.md) preserves the
exact form text and confirmation. Apple's acknowledgement confirms
**Case-ID: 22799543**. Apple DTS asked for the question to be posted on the
Developer Forums and answered it there; the answer, relayed by the operator on
2026-10-22, is recorded [below](#apples-answer-2026-10-22): no such facility exists.
The operator relayed a [follow-up exchange](#notification-load-follow-up-relayed-2026-11-01)
on 2026-11-01: notification overload drops messages rather than terminating a
notification-only client. This is DTS guidance, not a live acceptance result.
Related entitlement request: **S9YJTLLH28**, submitted
2026-09-29 for `com.apple.developer.endpoint-security.client`, Monocursive team
`64SGQ348QJ`, proposed identifier `com.monocursive.ouroboros.jail`.
See the [saved request](endpoint-security-request.md).

We are building a contained developer workload runner. Before advertising native
macOS support, we need a supported lifetime boundary covering normal arbitrary
fork/spawn/exec descendants, including detached sessions and double-fork daemons.
Execution must remain contained when every userspace custodian dies, rather
than relying on a surviving process to enumerate and kill descendants.

Does macOS provide a supported facility that can:

1. Establish an immutable workload scope before its first instruction and
   atomically inherit membership through fork/spawn/exec, without modifying the
   workload or preventing ordinary Node, shell and Git subprocess behavior?
2. Stop or terminate every member after loss of the final control owner, with
   enforcement retained in the kernel and no userspace callback required?
3. Handle concurrent creation during teardown and expose a verifiable final
   drain, using stable process identities rather than PID-only scans?

Our development evidence on macOS 27.0 build 26A428, XNU 13432.1.9, includes:

- Descendant-scoped ES clients observe the tested subtree. Reciprocal custodians
  handle either client's loss, but killing both leaves all known members
  running. Uncached fail-closed AUTH_EXEC permits a survivor to execute a new
  command after both clients disappear. See
  [200 reciprocal-custody trials](macos-reciprocal-custody.md).
- `PT_ATTACHEXC` gives kernel-enforced debugger-death cleanup for attached
  targets, but later fork/spawn children survive. See
  [80 debugger-lifetime trials](macos-kernel-lifetime-2026-10-10.md).
- A locally installed, identity-protected Mach exception handler is inherited
  through the tested fork/spawn/exec paths. Owner death changes it to a dead
  handler without stopping normal execution; a child can clear it. Breakpoint
  controls confirm real kernel exception delivery. See
  [24 Mach-lifetime trials](macos-mach-lifetime-2026-10-10.md).
- Published XNU contains per-task fatal-port no-senders cleanup, but
  `machdep.task_get_fatal_port` is absent on this tested release kernel. We have
  not treated it as a supported application API.
- LaunchServices creates a real application coalition, and XPC service lifetime
  follows app death. However, all seven workload descendants survive, retain
  coalition membership and can execute a new command. Shared and private audit
  sessions both fail; eight-second follow-ups also retain all seven survivors.
  A temporary root launchd service restarts and reaps seven recorded processes
  after a crash, but does not restart a stopped custodian. See
  [native-service trials](macos-native-services-2026-10-10.md).

These are isolated SIP-disabled tests, not normal-SIP qualification. We
understand the ES entitlement is separate from a lifetime guarantee. Please
clarify whether an approved descendant-scoped ES deployment can provide that
owner-loss guarantee through a documented API, whether another supported
facility is appropriate, or whether meeting this contract requires a VM boundary.

## Apple's answer (2026-10-22)

Kevin Elliott (DTS Engineer, CoreOS/Hardware) answered on the Developer Forums
thread opened for this case. The operator relayed it on 2026-10-22. Verbatim:

> No, nothing like this currently exists. What is possible is:
>
> An es_new_descendants_client can defend itself from all child activity.
> External events may still terminate it, but its children cannot.
>
> A "full" client (using es_new_client) can defend itself from ALL activity
> system-wide.
>
> The main risk/downside here is bugs in the client causing the client to
> terminate, but the best solution to that is to minimize the code involved so
> that it's as simple as possible to test and validate. To that end, I would
> probably start with a basic two-level architecture like this:
>
> The first process's ONLY job is to monitor child process activity and defend
> itself and the secondary client from manipulation from children. It sets all
> of that up using es_new_descendants_client, then spawns the second process.
>
> The second process is responsible for all other monitoring that occurs and is
> where the bulk of the work actually occurs. It sets up its own
> es_new_descendants_client, then spawns the "work" that you'll actually be
> monitoring.
>
> (optional) If you're concerned about system-wide attacks, then I think I
> would introduce a 3rd process which uses the full es_client to defend itself
> and the other two processes.
>
> That 3rd component can also be embedded in either/both of 1 & 2.

The answer closes the question this document asked. macOS has no supported
facility that ends an inherited workload once every userspace custodian is
gone. The reciprocal prototype already has the shape Apple suggests, a
guardian and a ward each holding a descendants client. Its simultaneous-loss
counterexample therefore remains a limit of this design without a root
component. Apple's optional full `es_new_client` could defend the custodians
against external kills, but needs root and Full Disk Access; the two-tier
design declines that component (§7). It would still not supply a kernel-owned
death chain after every custodian is gone. The [two-tier proposal](../../specs/jail-macos.md) designs the
native tier around that, with a disclosed weaker lifetime, and keeps a
kernel-bound VM tier. Apple did not comment on the Mach exception-port,
debugger or fatal-port evidence.

## Notification-load follow-up (relayed 2026-11-01)

The operator supplied the follow-up question and Kevin Elliott's reply from
the same Developer Forums thread on 2026-11-01. The pasted thread labels both
posts "1w"; the date here is when the exchange was relayed, not an asserted
publication date. The supplied copy contains no forum URL.

### Our follow-up question

Verbatim from the supplied copy. Its "external-only" wording is qualified in
the interpretation below and in the macOS spec.

> Thank you, that answers the core question. We will design around simultaneous custodian loss as an external-only residual, with custodians the workload cannot signal or control.
>
> One follow-up: our custody clients subscribe only to NOTIFY_FORK, NOTIFY_EXEC and NOTIFY_EXIT on an es_new_descendants_client. If descendants generate events faster than the client drains them, can the system terminate a notification-only client? Or does it only drop messages, observable as gaps in seq_num / global_seq_num? We treat any gap as a failed verification, so drops are acceptable to us, but termination for load would let the monitored workload remove a custodian.

### Apple's reply

Kevin Elliott, DTS Engineer, CoreOS/Hardware. Verbatim; nested quotes are the
parts of our question quoted in the reply.

> > If descendants generate events faster than the client drains them,
>
> I've said this in a few different contexts, but this is an avoidable issue. The reality is that the delivery overhead of an individual ES event is SO much smaller than a syscall that your client should be able to process events FAR faster than your descendants can generate them. That's particularly true for notifications, since delayed delivery means we can batch them and deliver them in chunks. On top of that, the combination of auth events and unlimited deadlines means that you can easily throttle anything you want— just pause the approval of auth events until the volume decreases, then start approving your backlog.
>
> Case in point, here:
>
> > One follow-up: our custody clients subscribe only to NOTIFY_FORK, NOTIFY_EXEC and NOTIFY_EXIT on an es_new_descendants_client.
>
> If you switch to ES_EVENT_TYPE_AUTH_EXEC, then you can pause or slow new process creation anytime you want by simply delaying when you approve the auth request. This has other advantages as well— you're focused on dropped messages, but if you actually test this, I think you'll find that the machine starts to become unusably slow WELL before the message volume becomes a problem.
>
> Finally, this isn't difficult to test and then design around— all you need to do is pick the event you’re concerned about, write a test tool that uses lots of threads to ONLY generate that action, then run as many instances of that tool as you want.
>
> > Can the system terminate a notification-only client?
>
> No. Only auth events can trigger termination. However, when using es_new_descendants_client, even that can be avoided by using es_set_deadline_min_milliseconds to increase the deadline to an arbitrarily long value[1] and using es_set_deadline_miss_mode to change to something other than ES_DEADLINE_MISS_MODE_KILL.
>
> > Or does it only drop messages, observable as gaps in seq_num / global_seq_num?
>
> Yes, that's what it would do.
>
> [1] Max uint32_t milliseconds is ~49 days. If you need to stall an approval for that long, then we may need to have a conversation about your larger product design/goal

### Interpretation and remaining gates

- **Resolved by DTS guidance:** notification-queue overload does not itself
  terminate a notification-only descendants client. Notifications can be
  dropped, with gaps in `seq_num` / `global_seq_num`. This closes the macOS
  spec's pending Apple question; it does not measure our implementation or
  resolve its separate pre-first-message sequence ambiguity.
- **Authorization is a separate path:** DTS suggests delaying `AUTH_EXEC`
  approvals for backpressure and configuring deadlines and a non-kill miss
  mode. The roughly 49-day maximum is finite. The existing design retains
  notification-only custody while the workload runs and a separate
  `FAIL_CLOSED` guard during teardown; this reply does not require a redesign.
  Apple's [deadline-miss API documentation](https://developer.apple.com/documentation/endpointsecurity/es_set_deadline_miss_mode%28_%3A_%3A%29?language=objc)
  also specifies that `FAIL_CLOSED` denies AUTH messages dropped when the
  queue is full.
- **The residual is not proved external-only:** direct workload signals,
  suspension, debugging and control through other services must be denied.
  The queue-overload answer does not establish immunity to client bugs or
  workload-induced system memory pressure. Loss of both custodians, whatever
  its cause, can leave descendants running. External kills are one example,
  not an exhaustive description. The original answer still rules out a
  supported kernel-owned death chain after all custodians disappear.
- **Tests and release gates remain:** K92's adversarial drain proof, K93's
  event storms, gap handling and ordinary heavy-build check, K95's both-lost
  behavior and K96's workload-induced memory-pressure trials remain required.
  No trial is marked passed by this reply. Entitlement approval, packaging,
  K104's SIP-enabled protected-Mac acceptance on the release build, and the
  other J16–J18 gates in the [macOS spec](../../specs/jail-macos.md) remain in
  place. The native tier remains development-only pending qualification.

### Implementation evidence after the reply — 2026-11-01

The [isolated development-VM spike](results/macos-custody-spike-2026-11-01/README.md)
found a concrete reason to retain that qualification: a sandboxed
`launchctl kickstart` request starts a preloaded unsandboxed job, which can
signal either custodian. The candidate `mach-bootstrap` denial does not
close it. Both outside positive controls worked; `load` was denied in the
corresponding trials. This is our implementation evidence, not an additional
Apple statement. K90 and NC01 remain open, and the event-load guidance does
not turn this workload-reachable deputy into an external-only residual.
