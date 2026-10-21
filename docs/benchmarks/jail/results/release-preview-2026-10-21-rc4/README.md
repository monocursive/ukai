# rc.4 preview evidence refresh, with a vaulted provider key

J14 (interactive sessions), its review fixes and the rustls-webpki and
webpki-roots advisory bumps changed the Jail build inputs, so the rc.3 K11/K27
records no longer matched the current binary. This fresh disposable x86_64
QEMU VM run records the rc.4 candidate; earlier evidence remains unchanged,
including [the run for the candidate before the advisory fix](../release-preview-2026-10-21-rc4-before-advisories/README.md).

- Source revision: `cccf5db30196a9f0a1de5570a7af3f99e252e3ea`.
- Build inputs: `sha256:893f85686e76cffeeb87f57c33ba27fe16685524d73676ec7b72c937e7c20d03`.
- Binary SHA-256: `40621f6df47571c501ddf3558407b3e144905c826f001c6a1900d2bcd9756928`.
- Binary source: a clean optimized build on the reference host from a Git
  archive of that revision (`UKAI_BUILD_REVISION` set, `UKAI_BUILD_DIRTY=false`,
  Rust 1.98.1, `cargo build --locked --release -p ukai-jail`, 0 warnings);
  `version --json` reports revision `cccf5db30…`, `dirty: false` and the
  inputs above. The interactive Claude Code record's confirmation pass ran
  the same binary.
- Ubuntu image, guest configuration, teardown and the key scan: [vm.json](vm.json).
- Onboarding, learning and distribution results: [guest/result.json](guest/result.json).

The harness is unchanged since
[the rc.3 refresh](../release-preview-2026-10-18-rc3/README.md): the runner
copied the operator's private Anthropic key file (mode 0600) into the
disposable guest only, the guest stored it with `ukai-jail credential set
anthropic` and deleted the copy (`runner_copy_removed: true`), and both
OpenCode runs used the operator `opencode-vault` profile with the key vaulted
for `api.anthropic.com` as `x-api-key` and the model
`anthropic/claude-sonnet-4-5`. After the guest exited and the VM was
destroyed, the runner searched every recorded file for the key's bytes: 81
files, none containing it (`credential_exposure` in vm.json). An independent
fixed-string search of this directory on the runner host agreed. The scan
covers recorded files only, not guest memory.

Signed installation, contained `true` and the real OpenCode 1.18.32 task
completed in 67.4 seconds (rc.3: 66.6 s; the run before the advisory fix:
161.9 s, not repeated here). The timer includes the agent's download and
excludes VM and dependency setup. The learning workflow and the archive and
signature corruption checks passed. No Rust toolchain was installed in the
guest and no host policy was changed. The disposable VM was destroyed.

The package uses a temporary test signing key and the `0.1.0-rc.4` version
label for this local qualification. It is not a published release or a
production-signed artifact. Both `onboarding` and `learning` checks in
`verify_preview_evidence.py` pass against the input digest above.
