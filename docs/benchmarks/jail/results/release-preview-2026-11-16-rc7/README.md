# rc.7 candidate onboarding and learning evidence

One fresh disposable Ubuntu x86_64 VM under TCG installed the unpublished rc.7
candidate and ran OpenCode 1.18.32 with a vaulted Anthropic API key. The raw
[VM record](vm.json) and [guest command/result record](guest/result.json) retain
this single run. All 92 evidence files were copied byte-for-byte and checked
against the finalized [retained inventory](proof/evidence-inventory.json).

- Binary source F: `f745bfbfc5bfe4945cf5fc7c5d88e497db9e6768`.
- Harness source G: `dce53219bb8cb0ecf89047dd9820404da9a51c26`.
- Jail inputs: `sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`.
- Binary SHA-256: `348e4c2b9ade7d0d5109a9c78c275be322da76524ba70763f9a7945c153c295a`.
- Clean native x86_64 release build, Rust 1.98.1, optimization level 3.
- Model: `anthropic/claude-sonnet-5-5`; OpenCode: `1.18.32`.

F and G have the same compiled inputs; the binary remains attributed to F.
The exact 19-file G harness export and full ignored run/review hashes are bound
in [source binding](proof/source-binding.json), [source inventory](proof/source-inventory.json)
and [input equality](proof/F-G-runtime-input-equality.json).

K27's signed-install-through-first-contained-agent timer was **152.032 seconds**,
including agent download and excluding **460.846 seconds** of VM/dependency
bootstrap. The complete outer run took 773.324 seconds. There were exactly two
vendor CLI rows, normal execution and learning, each launched once with
`vendor_attempts=1`; neither was retried. This launch limit is not a hard
provider-request, token or dollar cap.

Installation, contained `true`, the real agent task, learning, upgrade, archive
corruption rejection and signature corruption rejection passed. Both vendor
receipts show enforced containment, observed execution, exit 0, a verified empty
process tree and all six coverage classes active without gaps. The exact owning
K27 and K11 checks passed again on this copied directory; their commands and
results are in [copied-record verification](proof/copied-verification.json).

The [learning proposal](guest/opencode-learned.toml) proposed only
`/etc/nsswitch.conf`, with exact receipt/journal evidence. It did **not** propose
the intended `/home/ubuntu/learning-needed.txt` fixture, its parent, or any network
grant. Fifteen unresolved reads remain ungranted. This proves the supported
subset and provenance checks, not discovery of every program need or coverage
of every denied path. The [independent review](proof/independent-review.json)
records that limitation and passed 274 checks.

The [coordinator result](proof/coordinator-result.json), [local custody result](proof/local-result.json)
and [final summary](proof/final-summary.json) retain clean teardown: VM destroyed,
temporary VM data and private credential stage removed, scope absent, child/client
reaped, and original credential source generation unchanged. The owning scans
used held original raw key bytes and found no hits in their bounded retained-file
scopes. These are recorded scan-time results; later summary files were written
after those scans. This is not an independent secret rescan, encoded-spelling,
swap, guest-memory or universal absence claim.

The package used an ephemeral test signing key. There was no production signing,
publication or host security-policy change. This is current-input Linux K11/K27
evidence only. It does not qualify prior macOS VM/native API failures, general
reliability, other agents or OAuth; those earlier failures and OAuth's pending
status remain unchanged.
