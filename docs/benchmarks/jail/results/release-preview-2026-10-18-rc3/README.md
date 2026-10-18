# rc.3 preview evidence refresh, with a vaulted provider key

The J12/J13 and F8 work changed the Jail build inputs, so the previous K11/K27
records no longer matched the current binary. This fresh disposable x86_64
QEMU VM run records the current build; the previous evidence remains unchanged.

- Source revision: `d4988945e53322b0c0182aabf3efea502cf4512d`.
- Build inputs: `sha256:32e294a36c9d1dffd23ed2e9afc3ec8a87148e2b8cda26538d22737feffbaf89`.
- Binary SHA-256: `40bfe5416daf918f87a8dc06f22959476fa6a2507d8b93364c8404df8d491491`.
- Binary source: the clean optimized build from reference-host conformance run
  [39110441263](https://github.com/monocursive/ukai/actions/runs/39110441263)
  (attempt 2). That run failed only its two stale preview-evidence tests (K11,
  K27); this record supplies fresh evidence for the next run rather than
  changing that result.
- Ubuntu image, guest configuration, teardown and the key scan: [vm.json](vm.json).
- Onboarding, learning and distribution results: [guest/result.json](guest/result.json).

**What changed in the harness.** On 18 October 2026 OpenCode's free tier
refused its own CLI, the pinned 1.18.32 included, with no jail involved:
"OpenCode's free tier can only be used from within OpenCode." The earlier
records used that free model (`opencode/big-pickle`). This run gives OpenCode
an Anthropic API key instead, the transport the credential benchmarks
measured with this OpenCode version:

- The runner copied the operator's private key file (mode 0600) into the
  disposable guest only. The guest stored it with `ukai-jail credential set
  anthropic` and deleted the copy (`runner_copy_removed: true`).
- Both OpenCode runs used an operator `opencode-vault` profile written into the
  guest's config directory: the bundled `opencode` profile's hosts plus
  `api.anthropic.com`, the key vaulted for that host as `x-api-key`, and the
  agent given only the placeholder. Both receipts list the credential as
  `vault`, `never_staged: true`. The model was `anthropic/claude-sonnet-4-5`.
- After the guest exited and the VM was destroyed, the runner searched every
  recorded file for the key's bytes: 81 files, none containing it
  (`credential_exposure` in vm.json). An independent fixed-string search of
  this directory agreed. The scan covers recorded files only, not guest memory.

Signed installation, contained `true` and the real OpenCode 1.18.32 task
completed in 66.624 seconds. The timer includes agent download and excludes
VM and dependency setup. The learning workflow and the archive and signature
corruption checks passed. No Rust toolchain was installed in the guest and no
host policy was changed. The disposable VM was destroyed.

The guest's `doctor` sweep over the fourteen embedded profiles now runs from
the project directory, as the guide runs it. The first attempt ran it from
home, where `doctor --launch claude` refused because the stored key lay
inside that would-be workspace; that run is kept unchanged as
[release-preview-2026-10-18-rc3-doctor-home-failed](../release-preview-2026-10-18-rc3-doctor-home-failed/README.md).

The package uses a temporary test signing key and the `0.1.0-rc.3` version
label for this local qualification. It is not a published release or a
production-signed artifact. Both `onboarding` and `learning` checks in
`verify_preview_evidence.py` pass against the input digest above.
