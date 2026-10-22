# Apple technical question: inherited workload lifetime

**Submitted through Apple code-level support on 2026-10-11.** This is the original
draft; the [submission record](apple-lifetime-support-2026-10-11.md) preserves the
exact form text and confirmation. Apple's acknowledgement confirms
**Case-ID: 22799543**. Apple DTS asked for the question to be posted on the
Developer Forums and answered it there; the answer, relayed by the operator on
2026-10-22, is recorded [below](#apples-answer-2026-10-22): no such facility exists.
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
