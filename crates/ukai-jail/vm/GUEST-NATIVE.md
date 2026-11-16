# Guest-native launch contract

This contract describes the opt-in implementation for a catalog-installed
native Linux program on the macOS VM backend. The
[retained component proof](../../../docs/benchmarks/jail/results/macos-vm-admission-2026-11-15/native-v7/README.md)
admits one exact guest image and catalog shape. It does not complete K113 or
change any published release coordinate. The existing literal-command VM path
remains a separate mode. New images need new component measurements, and
rebuilt hosts need fresh installed-client qualification.

## Supported execution

The first qualification target is the unchanged bundled `claude` launch
profile, a native AArch64 ELF, explicit `--state attempt`, detached terminal,
and closed stdin. The implementation selects programs through catalog data;
the execution core does not special-case a vendor name. Persistent state,
interactive attachment, arbitrary installation roots, scripts, npm wrappers,
and operator launch-profile overrides are outside this contract and refuse.
Native launches use the `agent` profile and retain the existing VM prerequisites:
an explicit wall limit of 1–300 seconds, a case-sensitive live workspace, and
a NAT-enabled service. The profile's default two-hour wall limit is outside
the measured VM shape and refuses.

The host chooses a typed local or guest program before consulting PATH. A
guest alias never falls back to host PATH, and a guest path never becomes a
host executable descriptor, canonicalization target, or mount-alias walk.
The guest-derived read-only root enters policy resolution before the project
layer. Exact carry validation preserves the original bundled network layer
before applying the final host allow set. Unsupported project narrowing or
extra host roots refuse before a secret or Run frame; they are not discarded.
The supported host exposure projection is the live workspace.

## Image catalog

The image directory contains `guest-program-catalog.json` beside `image.json`.
The manifest's optional `guest_program_catalog_sha256` binds its exact bytes.
Either both file and binding are absent (legacy image), or both are valid.
The package retains those exact bytes in its signed file manifest. The guest
copy is `/usr/local/share/ukai-vm/guest-program-catalog.json`. Neither catalog
contains its disk or seed digest: `image.json` supplies those external
bindings without a digest cycle.

The catalog is strict JSON, at most 65,536 bytes, with no duplicate or unknown
fields and one to sixteen entries. Its object has
`schema: "ukai.vm.guest-program-catalog/1"` and `entries`.
Each entry contains:

| Field | Meaning |
| --- | --- |
| `id`, `alias`, `version` | Unique installation identity, launch name, version |
| `format` | `elf64-aarch64` |
| `executable`, `install_root` | Absolute normalized guest paths |
| `program_root` | `1`, the executable's immediate parent |
| `argv_prefix` | Exactly the catalog executable as the sole argument |
| `executable_sha256`, `executable_size` | Exact ELF bytes and length |
| `profile_sha256` | Exact unchanged bundled launch profile bytes |
| `guest_jail_sha256` | Exact Linux jail binary containing that profile |
| `supported_states` | Exactly `["attempt"]` |
| `interpreter` | `/lib/ld-linux-aarch64.so.1` |
| `tree` | Exact inventory of the immutable installation root |

Entry IDs contain 1–128 ASCII characters, versions 1–64; both start with an
alphanumeric character and then allow alphanumerics, `.`, `_`, or `-`.
Aliases contain 1–64 characters, start with a lowercase ASCII letter, and then
allow lowercase letters, digits, `_`, or `-`. Executables are 64 bytes to
512 MiB. The installation root is exactly `/opt/ukai/programs/<alias>/<version>`
and the executable basename is the alias.

The inventory has a directory entry with `path: "."`, `kind: "directory"`,
`mode: 365` (0555), `uid: 0`, `gid: 0`, and one executable-basename entry with
`kind: "file"`, the same mode/owner/group, and `nlink: 1`. No extra files,
links, devices, scripts, writable directories, or alternate interpreter are
accepted. Root and ancestor traversal uses no-follow descriptors. The guest
checks the complete inventory, stable file identity, whole executable hash,
ELF header/interpreter, and actual jail binary hash before advertising the
contract, and rechecks before execution.

Root-owned profile declaration metadata lives outside writable workload grants at
`/usr/local/share/ukai-vm/guest-program-profiles/<alias>.toml`. Its bounded
no-follow bytes must match `profile_sha256`. It supplies declared credential
IDs for validation; it is never installed as a launch override. The host
independently compares the catalog profile hash with its own bundled bytes.

The initial private qualification input is unmodified Claude Code 2.1.311,
293,658,808 bytes, SHA-256
`2e2496c9a8065df93acb0fca2d341f59a6b8777649b2e025ab8c9bcd5eef61f3`,
at `/opt/ukai/programs/claude/2.1.311/claude`. Its bundled profile SHA-256 is
`e3d804e5557c5829205b5156d636a9fbcdc1e1dcff7d3bebd5b88891bbe17a24`.
Preparation is explicit and uses a separate seed payload, not a huge
cloud-init base64 value or a per-attempt workspace upload. This records a
private input, not permission or a decision to redistribute a vendor binary.

## Preparation and secret ordering

The running guest Session advertises
`guest_contracts.native_program: "ukai.vm.guest-native-launch/1"` and
`guest_program_catalog_sha256` only after installation validation. Service
Ready forwards the actual Session facts for the current boot. Legacy guests
may omit these fields for literal commands; native requests require exact
versions and the image-bound digest. Existing credential-revocation and
full-journal contracts remain required as well.
Native attempts also require the Session's
`guest_contracts.sampled_exposure: "ukai.vm.sampled-exposure/3"` declaration
before Prepare stages the selected source. Known historical native `/1` with
sampling `/1` or `/2` Sessions remain usable for literal commands; they cannot
accept a current native request. Unknown or mixed contracts refuse. Historical
`/2` reports keep their original offline parsing and completeness semantics.

Prepare's optional `native_program` object has exactly these fields:

| Field | Value or binding |
| --- | --- |
| `schema` | `ukai.vm.guest-native-launch/1` |
| `catalog_sha256`, `entry_id` | Current verified catalog and entry |
| `launch_name`, `profile_sha256` | Unchanged bundled launch profile |
| `state` | `attempt` |
| `selected_credential_id` | Exactly the selected declared source |
| `argv_suffix` | Canonical padded-base64 byte arguments; no NUL |
| `request_argv_digest` | Existing canonical argv hash of launch name plus suffix |
| `resolved_argv_digest` | Same hash of catalog prefix plus suffix |
| `expected_policy_digest` | Independently resolved exact guest policy |

Prepare's ordinary `argv` remains the full resolved vector. Every reader
checks it against the catalog prefix and decoded suffix. A native request
limits both vectors to 4,096 arguments and 1 MiB of decoded bytes, so the
executable prefix consumes part of the full-vector budget. A native request
cannot also carry LaunchToml. The service validates intent before Reset or
secret transfer, then sends a value-free `native_prepare` operation containing
`native_program` and `argv`. The guest returns `native_prepared`, echoing the
exact verified intent. Only this matching acknowledgement allows forwarding
the selected Secret. It establishes a verified installation, request, and
private configuration root; it does not claim the jail has executed policy.

Native configuration is `/run/ukai-vm/native-config` on the guest tmpfs, with
the source at `credentials/<selected_credential_id>`. The controller owns the
configuration directory as root:workload-group, mode 0750. The Linux jail must
enumerate uncontained-run markers there before launch resolution; the workload
group may read and traverse this directory, but cannot change it. The credentials
directory remains root:workload-group, mode 0710, allowing only traversal to the
selected source rather than directory listing.
The selected single-link file is workload-UID:GID, mode 0600. Only native runs
receive this `UKAI_CONFIG_DIR`. No launch override is written. Revocation
removes the exact staged source before the existing exact-ID acknowledgement.

Host source staging uses a distinct bounded, zeroizing source lease. It keeps
anchored owner/mode/link checks, source preference, both absent-source hints,
and captured generation revalidation. It cannot enter a local Vault or proxy,
and never constructs a Secret with an emptied executable restriction. An
unsafe preferred source does not fall back. No host vendor-state directory,
persistent lease, or proxy socket is registered for guest-only state.

## Execution and evidence

Run2 repeats the exact prepared intent and full argv. The guest revalidates
the installation, refuses altered intent, and invokes the actual Linux jail
with `--from-path --launch <alias> --state attempt -- <suffix>`. Only the
supervisor PATH resolves the catalog executable. The workload environment
comes from the existing baseline and unchanged bundled profile. Real Linux
program resolution, descriptor pinning/revalidation, `@program` initiator
checks, source generation checks, and policy enforcement remain authoritative.

The existing receipt binding retains host attempt/boot and guest attempt/boot
identities. Its optional `native_program` object is mandatory for native mode
and contains `catalog_sha256`, `entry_id`, `profile_sha256`,
`executable_sha256`, `selected_credential_id`, `state`,
`request_argv_digest`, `resolved_argv_digest`, and `policy_digest`.
The resolved digest must equal the actual receipt argv digest and expected
full argv digest. The policy digest must equal both the actual guest receipt
and the independent host expectation. The original suffix and resolved argv
are retained separately in transport evidence.

The controller's executable hash is an explicit transport identity, not a
new field invented in the frozen Linux receipt. Verification also requires
actual program-resolution provenance/derived roots and the canonical bound
full guest journal. Host lifecycle and cleanup remain host facts. Guest
credential counts, state cleanup, execution, and population claims come only
from verified guest evidence. EOF, missing data, mismatched binding, and
unverified wall termination remain unknown; they never synthesize cleanup.

## Sampled process exposure evidence

The controller samples native attempts every 100 ms, independently of output
relay. Version 3 arms the monitor while the actual workload is blocked at the
Linux managed gate. The outer jail supervisor still starts and sends Released
at the original point; wall and source-watch deadlines are not reset. The
controller authenticates the private Prepared control frame and captures the
exact, bounded Linux Prepared receipt as `evidence/managed-prepared.json`.
It checks the expected policy, resolved argv, selected credential, program-root
grant and enforced boundary/ceilings, then rechecks immutable inputs and awaits
a healthy first tick observing both supervisor and prepared workload identities.
Only the controller can then write the single release frame. Cancellation,
revocation, invalid control or failed arming closes that gate without release.

The `/3` report has the scope
`managed-native-periodic-readable-environment-and-argv-only` and an exact
`managed_gate` object. It binds both the raw and canonical Prepared digests and
its workload PID/birth to the final receipt, plus controller-monotonic observed,
validated, armed, release-start and release-completed timestamps. These bracket
controller operations; they are not kernel exec timestamps. The host retains
the checked Session contract in the transport, so a `/2` report cannot satisfy
a `/3` native Session. No valid Prepared or no constructed monitor means
sampling is unavailable. After valid Prepared, initialization/arming failure
can produce an explicit incomplete `/3` report with null arm/release times.
A fast exit observed before the post-write release-completed timestamp also
remains incomplete rather than being treated as malformed chronology.

This moves trusted setup before the monitored release. It does not excuse later
inventory churn, missed reads, identity changes, caps, monitor failures or hits.
Complete `/3` observations additionally require ordered release through observed
supervisor exit and a settled, executed final receipt with verified empty tree
and clean cleanup. Nonzero target exit alone does not invalidate observation
completeness. No existing image or historical qualification acquires this scope;
a new image and its separate component/admission evidence are still required.

The sampler follows supervisor descendants and all four workload UID fields, excluding only
the previously pinned infrastructure identities; the jail can move processes
between cgroups. Each process read is anchored to its proc directory and birth
identity. A sample counts as the catalog program only when its executable
device/inode matches the verified installation. Environment and argv reads are
bounded; unreadable, oversized, vanished, unstable, skipped, and late samples
remain explicit. Versions 2 and 3 distinguish the controller's actual jail
`supervisor` (PID and captured birth tick) from `receipt_process`, the workload
PID and birth tick in the Linux receipt. The host retains the Released
`supervisor_pid` and compares it with the report; it never equates the jail
supervisor with its workload child. An initialization failure before the
supervisor's birth is readable may report a null birth only with zero ticks,
zero observations, and the explicit initialization failure.

Parent and UID metadata select processes for each tick; reported roles retain
that selection history. A selected process can be reparented or change UID
without changing its PID and birth identity. The sampler keeps observing that
same birth for the current tick, while still validating every stat/status read,
the anchored proc directory and the executable. Birth changes, directory or
executable replacement, and read failures retain their existing error behavior.
The next tick selects processes again from its own inventory.

`verified_program_reads` counts all catalog-executable observations.
`receipt_program_reads` counts only observations of the exact receipt workload
identity, and `receipt_program_observed` requires both its environment and argv
to have been read. Another catalog process or an earlier birth of the same PID
cannot provide this credit. Complete observations require both the actual
supervisor and these positive receipt-workload reads; absent coverage remains
incomplete. Supervisor lifetime timestamps stay anchored to the actual jail
process, including when its workload has exited.

After bounded sampler shutdown and attempt stop, the controller creates the
reserved `evidence/sampled-exposure.json` exclusively. A workload-created file
cannot stand in for it. The report binds host and guest attempt/boot identities,
the raw guest receipt SHA-256, catalog/executable identities, and sampler source
hash. The separate optional outer receipt-binding field
`sampled_exposure_sha256` names the exact report bytes; it is not part of the
deterministic `native_program` binding and creates no receipt digest cycle.

The report retains counters, timing, numeric process identities, and hit/error
categories. It retains no environment or argv text, process names, paths,
credential values, secret-derived hashes, or arbitrary exception messages.
Missing, invalid, or incomplete sampling evidence prevents its qualification;
it does not change an independently verified Linux execution Outcome. Sampling
does not observe process memory, past states, or values between samples. A
separate live guest control must detect a public canary in both environment and
argv using the same sampler source. Post-stop file/output scanning remains a
separate requirement.

The report distinguishes observation counts from monitor lifecycle. Pure
sampler tests may emit a historical `/2` manual report with null lifecycle times; that report
cannot qualify a native attempt. Qualification requires an independently
scheduled monitor, positive reads, no hits or scan errors, and ordered start,
sample, supervisor-exit, and stop times. Scheduling gaps and missed ticks stay
visible rather than being converted into a claim of continuous coverage.

Native image preparation runs the detector control in the actual guest before
freezing the disk. Its only target is an owned child containing a public canary;
it must detect both raw channels, verify the child's birth and executable
identities, and reap that child. The image records the exact control bytes and
both module hashes. This demonstrates detector operation on that guest kernel;
it does not manufacture a jail receipt or qualify workload observation.

## Qualification still required

The native admission guard additionally pins the catalog, entry identity,
profile, and executable to the measured disk/seed pair. Its proof combines
same-image vault staging with an actual Linux `@program` control: the allowed
program made one successful request, while a byte-identical copy at another
file identity received `credential_process_denied`. That control used the
literal service path and synthetic credentials. It did not execute the catalog
vendor or establish the native alias path's behavior.

Unit and protocol tests cover malformed catalogs, changed trees, missing
contracts, poisoned host PATH, mixed launch modes, unsupported narrowing,
incorrect source selection, mismatched intent/digests, and honest cleanup.
Native alias and derived-root execution, installed signed-client runs, both real supported
auth modes, neither-source refusal, midstream revocation, ten fresh vendor
tasks, guest-side environment/argv sampling with a positive leak control,
and independent full-summary verification are separate evidence requirements.
No passing fixture or synthetic credential run substitutes for those rows.
Public distribution additionally requires a notarized and stapled final DMG
and the [release procedure](../../../docs/RELEASING.md)'s K108–K113 checks on
the exact shipped bytes. A private Developer ID signature is not notarization.
