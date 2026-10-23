# rc.5 preview evidence refresh, with a vaulted provider key

The review fix wave of 2026-10-22/23 (the J16–J18 macOS work, merged on `dev`
with every native and VM path refused or development-gated) changed the Jail
build inputs, so the rc.4 K11/K27 records no longer matched the current binary.
This fresh disposable x86_64 QEMU VM run records the rc.5 candidate; earlier
evidence remains unchanged, including [the rc.4 record](../release-preview-2026-10-21-rc4/README.md).

- Source revision: `94198dcea6c1793cd303c941aca6ccc7007ca09a`.
- Build inputs: `sha256:188328556e73ff58f3e8e47e54604f4bfa2a3fdb7cd9a3bc18bf53b9a379e140`.
- Binary SHA-256: `a7bdf41d9f8b14dd327f1c7b57958d68aac4f186c5d363e838640191b2948138`.
- Binary source: the optimized release binary of the reference host's hosted
  conformance run `20261023T090904Z-94198dcea6c1` for that revision
  (`binaries.sha256` in the kept run directory names the same digest; Rust
  1.98.1, 0 build warnings); `version --json` reports revision `94198dcea…`,
  `dirty: false` and the inputs above. That conformance run passed every gate
  except K11 and K27, the two gates this record refreshes.
- Ubuntu image, guest configuration, teardown and the key scan: [vm.json](vm.json).
- Onboarding, learning and distribution results: [guest/result.json](guest/result.json).

The harness is unchanged since [the rc.4 refresh](../release-preview-2026-10-21-rc4/README.md):
the runner copied the operator's private Anthropic key file (mode 0600) into the
disposable guest only, the guest stored it with `ukai-jail credential set
anthropic` and deleted the copy (`runner_copy_removed: true`), and both OpenCode
runs used the operator `opencode-vault` profile with the key vaulted for
`api.anthropic.com` as `x-api-key` and the model `anthropic/claude-sonnet-4-5`.
After the guest exited and the VM was destroyed, the runner searched every
recorded file for the key's bytes: 81 files, none containing it
(`credential_exposure` in vm.json). An independent fixed-string search of this
directory on the runner host agreed. The scan covers recorded files only, not
guest memory.

Signed installation, contained `true` and the real OpenCode 1.18.32 task
completed in 62.9 seconds (rc.4: 67.4 s). The timer includes the agent's
download and excludes VM and dependency setup. The learning workflow and the
archive and signature corruption checks passed. No Rust toolchain was installed
in the guest and no host policy was changed. The disposable VM was destroyed.

The package uses a temporary test signing key and the `0.1.0-rc.5` version
label for this local qualification. It is not a published release or a
production-signed artifact. Both `onboarding` and `learning` checks in
`verify_preview_evidence.py` pass against the input digest above.
