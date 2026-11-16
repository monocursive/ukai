# rc.6 candidate onboarding and learning evidence

A fresh disposable Ubuntu x86_64 VM installed the unpublished candidate and
ran OpenCode 1.18.32 with a vaulted Anthropic credential. The official image,
its verified SHA-256, guest configuration and teardown are in [vm.json](vm.json).
The command rows, build provenance and results are in [guest/result.json](guest/result.json).

- Binary source revision: `5cfcf0c64e9832ba81b46b5f698374a863564790`.
- Jail inputs: `sha256:efdc169e8e09f514c908e02bb6f972bc8761d2efc9af94d9b53d914a436f14e6`.
- Binary SHA-256: `1bea7a205246c7717216b43c79f8ffcc65230736efc30e9e950abc232233cf2a`.
- Clean native x86_64 release build, Rust 1.98.1, optimization level 3.
- Harness change: `e8ed786af`; exact source hashes are in [harness-at-start.json](harness-at-start.json).
- Model: `anthropic/claude-sonnet-5-5`.
- Signed installation through the first contained agent result: 74.174 seconds,
  including the agent download and excluding VM/package bootstrap.

Installation, contained `true`, the real agent task, learning, upgrade, archive
corruption rejection and signature corruption rejection passed. Both agent
receipts record enforced containment, observed execution, a verified empty
process tree, complete state cleanup, exit 0 and all six coverage classes
active without gaps. The learning proposal is bound to the actual receipt and
cites the denied-read evidence; its parent directory is not granted.

No Rust toolchain was installed in the guest, no host security policy changed,
and the disposable VM was destroyed. The credential source was removed after
vaulting. The runner scanned all 91 recorded files for the actual key bytes and
found none; an independent scan agreed before adding this record. This covers
recorded files, not guest memory. No provider retry was needed.

Two earlier fresh-VM attempts are preserved locally under
`evidence/production-2026-11-15/onboarding*`. The second attempt's diagnostic log
proved that the old `claude-sonnet-4-5` alias was absent from OpenCode's fetched
catalog; it suggested Sonnet 5.5. The first generic failure lacked that diagnostic
record and is not retrospectively assigned a definitive cause. The current
model is documented in [Anthropic's model reference](https://platform.claude.com/docs/en/models/sonnet-5-5/overview).
The credential, network grants and acceptance assertions were unchanged. The
harness now preserves failed attempts before deciding whether to retry.

The package uses an ephemeral test signing key and an rc.6 candidate label.
This is current-input K11/K27 evidence, not a production signature, publication,
performance benchmark or general agent-reliability qualification. Both
`verify_preview_evidence.py --check onboarding` and `--check learning` must pass
against the input digest above before the current evidence index is promoted.
