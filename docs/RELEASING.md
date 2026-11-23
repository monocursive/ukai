# Publish Ukai Jail

[Stable Ukai Jail 0.1.0 for Linux x86_64](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0)
is published. The [public installation record](benchmarks/jail/release-0.1.0-linux-x86_64.md)
identifies the signed files, qualified host and two public installer checks.

[Linux preview 0.1.0-rc.8](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.8)
was published on 18 November 2026 from `bf365665197a0861752d704eef05ca9d0dde9952`.
The [publication record](benchmarks/jail/release-preview-2026-11-18.md) identifies the signed archives and native install checks.
The [production-readiness review](benchmarks/jail/production-readiness-rc8.md) records the full-scope verdict and remaining gates.

[Linux preview 0.1.0-rc.5](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.5), which carries
the fixes of the 22–23 October review, was published on 23 October 2026 from
`0fe655440db7fd0012257cbbbc7d7a790cd7eca1`; its
[publication record](benchmarks/jail/release-preview-2026-10-23.md) lists the
exact-commit checks, the clean-VM evidence and the verified installations.

[Linux preview 0.1.0-rc.3](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.3), the first
release under the Ukai name, was published on 18 October 2026 from
`f95f2d3963bc8829ab08f8b320d43abbb9f220f8`; its
[publication record](benchmarks/jail/release-preview-2026-10-18.md) lists the
exact-commit checks, the refreshed clean-VM evidence (now with a vaulted
provider key, since OpenCode's free tier refuses its CLI) and the verified
installations.

[Linux preview 0.1.0-rc.2](https://github.com/monocursive/ukai/releases/tag/ouro-jail-v0.1.0-rc.2), published before
the Ukai rename on 15 October 2026, was released on 14 October 2026 from
`531d252a6c56e0403ae7b1937988f2037e294853`, following the procedure below; its
[publication record](benchmarks/jail/release-preview-2026-10-14.md) lists the
exact-commit checks, the clean-VM evidence and the verified installations.

[Linux preview 0.1.0-rc.1](https://github.com/monocursive/ukai/releases/tag/ouro-jail-v0.1.0-rc.1)
was published on 10 October 2026 from
`06a48d5a2de89d5d0ebffa84a9561d034cdd8b5d`. All eight signed assets were
downloaded anonymously and matched the reviewed candidate. The
[acceptance and public-install record](benchmarks/jail/release-preview-2026-10-10.md)
retains CI, native host checks and a fresh VM installation without Rust.

The first distribution is `ukai-jail` for Linux x86_64 and ARM64 in
`monocursive/ukai`. Tags use `ukai-jail-vVERSION`; the previews published
before the rename used `ouro-jail-vVERSION`, starting with
`ouro-jail-v0.1.0-rc.1`. This keeps the archived runtime's `v0.1.x` releases
separate. The fleet, ledger, Homebrew and macOS execution are outside this package.

The separate [macOS Linux VM preview](../crates/ukai-jail/vm/README.md) has its
own offline DMG and Bash installer. It does not add Darwin artifacts to the
Linux release or satisfy the native macOS clauses. Its [package qualification](benchmarks/jail/macos-vm-preview-package-2026-10-11.md)
records signing, notarization, installation and VM fault checks separately.
The dedicated prerelease is `ouro-vm-v0.1.0-preview.1`. The public installer
selects it on Apple Silicon and pins the final stapled DMG's SHA-256 in its
managed pin block, rendered with `render_vm_pin` in
[bootstrap.py](../crates/ukai-jail/dist/bootstrap.py).
Use the [Mac quickstart](guide.md#macos-vm-preview) for installation and limits.
The DMG's build-time notes and original qualification metadata retain their
unpublished state; publication does not modify the tested artifact.
The [publication record](benchmarks/jail/macos-vm-publication-2026-10-11.md)
adds verified public installation, live website delivery and quickstart proof.

[release.json](../crates/ukai-jail/dist/release.json) keeps two VM versions:
`vm.version` is the public preview the installer pins (`0.1.0-preview.1`),
and `vm.candidate_version` is what `package.py` builds and what the DMG's
`PREVIEW.txt` and `cli.VERSION` name (`0.1.0-preview.2`, the warm-service
candidate). A candidate is published only after it is notarized and stapled,
the full K108–K113 rows rerun and pass on that stapled DMG with a shipped
client (an install check alone is not enough), and the clauses leave both
unsupported lists. Publication then tags `ukai-vm-v<candidate_version>`
(`tag_prefix` plus the version), renders the installer pin with
`render_vm_pin`, sets `vm.version` and `published_tag`, and updates the
guide's quickstart.

The Bash entry point adapts `legacy:install.sh`: explicit versions, HTTPS,
architecture detection, no sudo or compiler, and installation to `~/.local/bin`.
It embeds the SHA-256 hash for each Linux archive, verifies the selected archive
before extracting or executing it, and installs it directly. Users need Bash,
curl, tar, and sha256sum or shasum; Minisign is not an installation dependency.
A downgrade requires `--allow-downgrade`.

Never direct Jail users to `releases/latest/download/install.sh`: that installs
the archived runtime. The current public preview command is:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://ukai.sh/install.sh | bash
```

The HTTPS-served script is the trust anchor for the embedded hashes. A mirror
or a downloaded checksum manifest cannot replace those pins. `--from-dir DIR`
also checks the same pinned archive offline. `--version` and `--bin-dir` are
accepted through `bash -s -- ...`; versions without embedded pins refuse before
any download.

To publish a new installer, assemble the reviewed native archives below. Assembly
sets the default release and embeds both archive hashes in `bootstrap.sh`, while
retaining previously pinned releases, the macOS preview's included. After
publication, copy that reviewed bootstrap to the root `install.sh`, set the new
version in [release.json](../crates/ukai-jail/dist/release.json) (the website,
the VM tooling and the tests read the coordinates there), set that platform's
`published_tag` to the actual published tag, update the
docs, and deploy the website, which serves the root `install.sh` and
`release.pub` directly. Verify the website script's bytes and an actual public
installation. Never discover a trusted hash from a mutable remote manifest at
install time.

The original immutable RC1 GitHub `bootstrap.sh` and low-level `install.sh`
remain signed historical assets and still require Minisign. The live website
and current repository installer provide the dependency-free SHA-256 path.
The release binaries and their tag are unchanged.

Maintainer candidate signing and publication checks still use the
[dedicated release public key](../crates/ukai-jail/dist/release.pub), created on
10 October 2026. Users of the current installer do not need this key.
Its private half retains its pre-rename location outside the repository at
`~/.config/ouroboros/release-keys/ouro-jail-2026-10-10.key`, in a mode-0700 directory
with file mode 0600. It is unencrypted for local noninteractive signing; maintain
a private backup for future releases. Private key material is never sent to CI.

## Stable Linux publication

A version without a SemVer prerelease suffix ships one native
`x86_64-unknown-linux-gnu` archive. ARM64 users can explicitly select a pinned
preview with `--version 0.1.0-rc.8`. The signed plan records the qualified
configuration of each target it ships: for x86_64 the tested Ubuntu 26.04.1 LTS
host, kernel 7.0.0-31-generic, bubblewrap 0.11.1, ptrace observation and
reference cgroup delegation. The
[Linux runtime audit](security-audit-2026-11-18-linux.md) describes the
evaluated x86_64 workloads and remaining platform limits.
The [22 November x86_64 reference run](benchmarks/jail/results/linux-x86-reference-2026-11-22/reference-conformance.json) passed 3,079 tests after refreshing the clean-VM OpenCode onboarding and learning records.

A stable release is qualified per target. `cargo xtask freeze --doctor
<run>/doctor.json` records each conformance run under the target it ran on:
the reference run in the freeze file's `[tested]` table, the ARM64 run in
`[tested_aarch64]`. `cargo xtask freeze --check --target <target>` then
requires that target's run; the release-candidate workflow requires it for
every native archive it builds, and the publisher for every target a stable
release ships. The conformance driver reaches a guest through a forwarded SSH
port with `--port`.

A stable release ships ARM64 only once `arm64_stable_version` and
`arm64_stable_host` in [release.json](../crates/ukai-jail/dist/release.json)
name the first such release and its qualified configuration, and
`publication_scope` takes its two-target name, `linux-x86_64-arm64-stable`.
Nothing in the publisher re-measures K17 or reviews the evidence, so set these
together, in one reviewed change, only after the ARM64 gates are confirmed on
a quiet host; the release tests hold them to that. Until then a stable release
ships x86_64 alone and the ARM64 archive stays in previews.

Use the native stages from the release-candidate workflow for the exact commit.
Run the assembly and publication steps below with one stage per target and the
stable version. Check the draft installer in an empty prefix on each qualified
host. Publication marks the signed release stable and latest. Download and
verify every public asset, install from the public bootstrap on each host and
check the installed build, doctor and a contained workload. Then roll out the
signed bootstrap at `ukai.sh/install.sh` and repeat the public install there.
The [ARM64 qualification record](benchmarks/jail/arm64-qualification-2026-11-19.md) covers the Raspberry Pi and Ubuntu runs against the stable runtime inputs.
The [ARM64 remediation run](benchmarks/jail/arm64-remediation-2026-11-19.md) covers the subsequent journal and foreign-ABI changes. The [SSD-backed ARM64 qualification](benchmarks/jail/arm64-ssd-qualification-2026-11-19.md) records the K17 pass and the native ARM32 limitation on the M5 Pro.
The [64-bit-only ARM64 qualification](benchmarks/jail/arm64-only-qualification-2026-11-19.md) records what the M5 guest kernel rejects before execution and the release gates tested on that configuration.
The [R01.8 review and M5 rerun](benchmarks/jail/arm64-r018-qualification-2026-11-19.md) defines the native-refusal receipt and tracks the previously missing checks.
The [20 November M5 gate review](benchmarks/jail/arm64-gate-review-2026-11-20.md) identified 15 missing checks. The [22 November supervision and observation run](benchmarks/jail/arm64-supervision-2026-11-22.md) closed four more gates. The [23 November complete ARM64 run](benchmarks/jail/arm64-stable-qualification-2026-11-23.md) passed all seven and is the recorded ARM64 tested run. Its K17 measurement is not confirmed, so ARM64 stays in previews until a quiet host measures it.
The public Mac VM keeps its own version and pins.

## Linux-only Jail release scope

On 10 October 2026, the Linux evidence gaps were closed by live CLI tests,
native signed-install tests and a recorded fresh-VM OpenCode workflow. The
[acceptance record](benchmarks/jail/release-preview-2026-10-10.md) gives each
clause's disposition and raw evidence. Future releases require the exact-commit
validation and publication steps below.

Use `cargo xtask gates --linux-release` and
`cargo xtask conformance --linux-release` for this developer preview. This fixed
scope reports the explicit `jail.unsupported_clauses` in
[`release.json`](../crates/ukai-jail/dist/release.json) as **unsupported**:
K23.1, K24.1, K26.1, K29.1, L02.12, M01.4 and each `.1` clause
from K87.1 through K113.1, individually listed in that file. These are the
untested native and Mac VM acceptance claims; no prefix exemption
is used. K108.1–K113.1 are also the VM scope's `vm.unsupported_clauses`:
their 2026-11-02/03 development measurements do not meet the clauses (the
acceptance map's notes say why). The xtask scope test requires every named
clause to fail the full verdict as untested, so a clause promoted while
still named here is caught. Tested component clauses remain required. The full verdict without
the flag continues to fail those untested clauses. Every Linux clause, shared test and macOS
execution-refusal test remains required; no failing Linux test is waived.
The signed release plan binds the exclusions and the target set for its release channel.

## macOS Jail bundle (pending entitlement — NOT yet releasable)

The Linux-only scope above has a macOS counterpart defined by
[jail-macos.md](specs/jail-macos.md) §4.12 and §8. J16–J18 are work in
progress on `dev`, not supported or releasable.
The [2026-11-01 measurement spike](benchmarks/jail/results/macos-custody-spike-2026-11-01/README.md)
ran live Endpoint Security in an isolated SIP-disabled development VM. Its
preloaded-job `launchctl kickstart` route was closed on 2026-11-02 and
re-measured in the same VM
([kickstart-fix record](benchmarks/jail/results/macos-k90-kickstart-fix-2026-11-02/README.md)),
and after a direct-client probe showed `launchctl`'s own XPC client is built
from the inherited bootstrap port, the launcher now strips that port before
the exec ([bootstrap-strip
record](benchmarks/jail/results/macos-k90-bootstrap-strip-2026-11-02/README.md)).
K90 and NC01 remain blocked pending full release qualification, and the
protected-Mac release run (K104) stays explicitly blocked without a usable
approved ES profile and protected-host acceptance. The November 15 local
provisioning inventory found no matching profile; Apple's account-side decision
was not verified. No release gate is promoted by these measurements.
J16 now has [native candidate tooling](../crates/ukai-jail/dist/macos/README.md)
for the exact `Ukai.app` layout, macOS 27 Info.plist, clean-source provenance,
profile-gated signing and per-user install/upgrade/removal with recovery.
Unsigned staging is not runnable-workflow qualification; no approved Ukai ES
profile was available locally, and no signed/notarized native candidate or
protected-host acceptance was obtained. Signing and notarization are separate
explicit maintainer actions.
Native execution remains disabled by default and NC02/K104 remain blocked.
J18's K108–K113 are
`untested`, a policy element the guest jail does not carry refuses with
`vm:not-carried:<field>`, and no macOS `ukai-jail` client ships in the existing
public preview or earlier candidate: those packages carry only `ukai-vm`
and `ukai-vm-install`, so their client is built from source. The current
packager builds, signs and installs `ukai-jail` with its sibling service
from the same clean revision. The local Developer-ID-signed DMG at
`53e5605fd` includes both commands and passed its bounded installer and guest
component checks; [the retained proof](benchmarks/jail/results/macos-vm-admission-2026-11-15/README.md)
names its exact bytes. It is neither notarized nor published. A rebuilt host
runtime needs clean-source build, signing, installed-byte verification and
fresh installed-client qualification; the guest admission record does not
supply that proof. Notarization and the full installed K108–K113 release
clauses remain requirements.
Apple's Endpoint Security grant (request `S9YJTLLH28`, submitted 2026-09-29)
is necessary, but does not by itself make the release run ready. The procedure
below remains a release requirement; the candidate tooling implements packaging
mechanics, not the entitlement grant or live acceptance.

Current implementation: native execution is **off by default**. Setting
`UKAI_JAIL_MACOS_NATIVE=dev` enables development only; a native receipt records
`native_execution=dev`. Native credential, vault and vendor staging answer
`unsupported` and refuse. J17 is wired before release (`J17_OBSERVE=true`):
`macos-closed-v1` declares the exact ES notification set; loss-free attached
`exec` and `fs.write` coverage is active only over that set. Synthetic producer
checks do not establish live acceptance.

The current VM probe admits twelve requirements only for the exact disk and
seed in the [15 November signed-image record](benchmarks/jail/results/macos-vm-admission-2026-11-15/README.md):
ten direct guest capabilities plus derived `execution_boundary` and vault-only
`credential_staging`. Required `pids=64` and `mem=512MiB` can pass admission;
required swap remains unmeasured, and the owner-loss bound remains unsupported.
An unmeasured requirement or another guest image refuses at probing with
`vm:not-measured:<requirement>` before any connection or boot. A `tool` or
`agent` plan still needs an explicit `--limit wall=<n>s` of 1–300 s; the
profiles' own 30 m and 2 h walls refuse with `vm:not-carried:limits.wall`.
The proof uses the installed, Developer-ID-signed package built from source
`53e5605fd`. It does not qualify a rebuilt host client, normal host source
monitoring, vendor compatibility or full K113. K108–K113 remain `untested`.

The separate [signed `9ceada861` host candidate](benchmarks/jail/production-qualification-2026-11-15.md#corrected-signed-host-candidate)
records fresh installed synthetic source-watch, warm-workflow, bounded wall
termination and source-rebuild checks. It remains private and unnotarized;
those results do not establish vendor compatibility or full release acceptance.
The released cold-boot VM preview remains the only public Mac deliverable.

After implementation, packaging and the measurement spike are complete and
the entitlement is granted, prepare a Mac release bundle as follows:

1. **One entitled executable.** The supervisor and the guardian are both
   `ukai-jail` inside `Ukai.app/Contents/MacOS/ukai-jail`, carrying
   `com.apple.developer.endpoint-security.client`, authorised by the bundle's
   **embedded provisioning profile**.
2. **Bundle identifier** `com.monocursive.ouroboros.jail` — the identifier
   request `S9YJTLLH28` names. It predates the rename; it stays rather than
   reopening the request.
3. **Signing requirements.** Developer ID, hardened runtime and
   notarization; macOS 27 or later (`es_new_descendants_client`, by
   reading). No root, no TCC approval and no Full Disk Access.
4. **Install shape.** The installer places the bundle in `~/Applications`
   without sudo and links `ukai-jail` onto the `PATH`.
5. **Protected-Mac release run.** Before publishing, repeat every J16 row
   ([jail-macos.md](specs/jail-macos.md) §9.1, including K23–K26) on a
   normally protected Mac with SIP enabled and the approved provisioning
   profile, on the release build (K104). A SIP-disabled development VM run
   does not satisfy this.

Historical prototype evidence and the current implementation's 2026-11-01
spike are separate records. The earlier VM was deleted on 2026-10-22; the
spike used a fresh pinned clone under
[macos-development.md](benchmarks/jail/macos-development.md). Its ad-hoc
bundle, adjusted guest process ceiling and disabled guest SIP do not prove
release installation or default-host compatibility. K95/K96 faults and
pressure tests, Apple's entitlement, packaging and K104 remain required.

## Prepare and validate

Commit and review the release tree. Require `rust`, `contracts` and the actual
`conformance` reference-host job to pass on that exact commit. Conformance runs
the suite with `UKAI_RELEASE_EVIDENCE=1`, so the recorded clean-VM and
real-vendor evidence (K11, K27) must match this build's inputs; a source change
since the recorded VM run needs a new one first (`onboarding_vm.py`). A plain
`cargo test` skips those two checks. The reference host
needs at least 4 GiB free for a release build. Record successful conformance with
`cargo xtask freeze --doctor`, then require
`cargo +1.98.1 run -q -p xtask -- freeze --check` to pass. A release with an
ARM64 archive needs the ARM64 conformance run recorded the same way. A tree-only freeze,
skipped reference host or an older passing run is insufficient. The next
release needs a fresh reference conformance rerun on the VPS, followed by
`cargo xtask freeze --doctor <successful-run>/doctor.json`. The current
`milestone-1-freeze.toml` must describe the candidate's inputs. A historical
`[tested]` record does not cover later source changes. Regenerating a tree-only
freeze intentionally removes that record and cannot establish release readiness;
only a successful matching reference run can restore it.

Set the reviewed candidate version and the production key. Each new release
requires a new version.

```sh
release_version=${RELEASE_VERSION:?set the new candidate version}
release_revision=$(git rev-parse HEAD)
release_public_key=$(sed -n '2p' crates/ukai-jail/dist/release.pub)
release_private_key="$HOME/.config/ouroboros/release-keys/ouro-jail-2026-10-10.key"
```

Build the same clean checkout or Git archive on both native Linux hosts with
Rust 1.98.1. A Git archive avoids macOS `._` metadata entering release inputs:

```sh
UKAI_BUILD_REVISION="$release_revision" UKAI_BUILD_DIRTY=false \
  cargo +1.98.1 build --locked --release -p ukai-jail
target/release/ukai-jail version --json
python3 crates/ukai-jail/dist/test_install.py target/release/ukai-jail
```

Set `release_inputs` from `build.inputs` in the version output. Stage each binary
on its native host; staging executes `version --json` and checks architecture,
revision, optimization, toolchain and source inputs:

```sh
python3 crates/ukai-jail/dist/prepare_release.py stage \
  --binary target/release/ukai-jail --target x86_64-unknown-linux-gnu \
  --revision "$release_revision" --inputs "$release_inputs" \
  --version "$release_version" --out /private/stage-x86
```

Use `aarch64-unknown-linux-gnu` and `/private/stage-arm` on ARM64. Both records
must name the same inputs and revision. Retain native doctor, contained-command,
receipt and installation evidence. Host limits remain in the release notes;
installation alone does not establish enforcement support.

Alternatively, run the `release-candidate` Actions workflow on the chosen commit,
or push its tag. Native Ubuntu x86_64 and ARM64 jobs exercise installation using
temporary keys, stage both packages, and upload an **unsigned** candidate.
Download the native stages for local signing:

```sh
gh run download RUN_ID --repo monocursive/ukai \
  --name native-x86_64-unknown-linux-gnu --dir /private/stage-x86
gh run download RUN_ID --repo monocursive/ukai \
  --name native-aarch64-unknown-linux-gnu --dir /private/stage-arm
```

## Sign and inspect

Assembly uses a fresh directory and signs both archives, the low-level
installer, the pinned Bash bootstrap, release notes and provenance plan:

```sh
python3 crates/ukai-jail/dist/prepare_release.py assemble \
  --stage /private/stage-x86 --stage /private/stage-arm \
  --revision "$release_revision" --inputs "$release_inputs" \
  --version "$release_version" --out /private/release-candidate \
  --signing-key "$release_private_key" --public-key "$release_public_key"
python3 crates/ukai-jail/dist/publish_release.py check \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

Review the plan, support notes and validation evidence. Native records are
builder attestations; signatures do not replace conformance. Test the SHA-256-pinned
bootstrap on both native hosts without Minisign available to the user:

```sh
bash /private/release-candidate/bootstrap.sh \
  --from-dir /private/release-candidate --bin-dir "$HOME/.local/bin"
ukai-jail version --json
ukai-jail doctor --profile tool --json
```

Run the [user guide's first command](guide.md#run-your-first-command), inspect its
settled receipt and preserve unavailable capabilities.

## Draft and publish

Once source, candidate and validation agree, push the exact tag and create a draft:

```sh
git tag -a "ukai-jail-v$release_version" "$release_revision" \
  -m "Ukai Jail $release_version developer preview"
git push origin "ukai-jail-v$release_version"
python3 crates/ukai-jail/dist/publish_release.py draft \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

The helper requires a clean tree at the candidate commit, tested freeze,
successful exact-commit CI, live reference conformance and the correct remote
tag. It creates a prerelease draft with exactly eight assets, downloads every
draft asset and verifies its bytes. It never overwrites an existing release.
Smoke-test installation from those downloaded draft assets on both native hosts.

After reviewing that concrete draft and its evidence:

```sh
python3 crates/ukai-jail/dist/publish_release.py publish \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

This rechecks the gates and draft bytes, publishes with `--latest=false`, then
downloads all public assets without authentication and verifies their digests.
If public verification fails after GitHub accepts publication, the release may
already be public. Inspect it and rerun `verify`; do not assume rollback:

```sh
python3 crates/ukai-jail/dist/publish_release.py verify \
  --candidate /private/release-candidate --public-key "$release_public_key"
```

Verify the public installer and first command on a clean supported Linux host.
Then update the README, guide and website with the real release link, trusted
archive hashes and host requirements. GitHub's [release procedure](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
documents draft and prerelease behavior.

## Release the GitHub Action

The action's source is [`action/`](../action/README.md) on `dev`
([jail-ci-action.md](specs/jail-ci-action.md) §9 decision 3). Users fetch it
from a slim ref, never from a full-tree tag (§7: about a minute and 1.9 GB
per job from the full tree, under a second from a slim ref). When the root
installer is rolled out for a new release, the same rollout commit sets
`version`'s default in `action/action.yml` to that release (the self-test's
static check compares them). After the release is published and the root
installer rolled out, add one commit holding only `action/` and that
`install.sh`, taken from the rollout commit, to the orphan branch `action`,
tag it, and push both:

```sh
rollout=$(git rev-parse <the rollout commit>)
export GIT_INDEX_FILE=$(mktemp -u)
git read-tree --empty
git read-tree --prefix=action/ "$rollout:action"
git ls-tree "$rollout" install.sh | git update-index --index-info
tree=$(git write-tree)
unset GIT_INDEX_FILE
parent=$(git rev-parse -q --verify origin/action || true)   # none before the first
commit=$(git commit-tree "$tree" ${parent:+-p "$parent"} \
  -m "Ukai Jail action for ukai-jail-v$release_version (rollout $rollout)")
git tag -a "ukai-jail-action-v$release_version" "$commit" \
  -m "Ukai Jail action for ukai-jail-v$release_version: action/ and install.sh of rollout $rollout"
git push origin "$commit:refs/heads/action" "ukai-jail-action-v$release_version"
```

The branch is never merged anywhere and holds nothing else. Then run the
action self-test against that tag (row K86: the tag installs exactly release
X, its commit holds only `action/` and an `install.sh` equal to the root
installer of the rollout byte for byte, and its "Set up job" fetch stays
slim). The tag-mode self-test is added with the first action release; until
then `.github/workflows/action-selftest.yml` tests `action/` in place.

## Local checks

```sh
shellcheck install.sh crates/ukai-jail/dist/install.sh
python3 -m unittest discover -s crates/ukai-jail/dist -p test_bootstrap.py
python3 -m unittest discover -s crates/ukai-jail/dist -p test_publish.py
python3 -m unittest discover -s crates/ukai-jail/dist -p test_release.py
python3 -m unittest discover -s crates/ukai-jail/dist -p test_versions.py
python3 crates/ukai-jail/dist/test_install.py target/release/ukai-jail
```

Bootstrap tests use pinned fixture archives and local download adapters, with
Minisign calls forced to fail. Maintainer tests use temporary signing keys.
They cover installation,
upgrade/downgrade, truncated pipes, tampering, signed provenance and publication
gates; they do not establish public availability.
