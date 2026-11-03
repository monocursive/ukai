# Ukai VM 0.1.0-preview.2 — the warm redesign's publication candidate — 2026-11-03

The warm-service redesign cannot ship as `0.1.0-preview.1`:
[ouro-vm-v0.1.0-preview.1](https://github.com/monocursive/ukai/releases/tag/ouro-vm-v0.1.0-preview.1)
is already public (2026-10-11) with the cold-boot preview's DMG
(`sha256:f3a85e14…`, 536,341,282 bytes), and release tags are immutable.
`release.json`'s `vm.version` is now `0.1.0-preview.2` — the one place the
coordinates flow from, mirrored under test by `cli.VERSION` and
`PREVIEW.txt` — while `published_tag` keeps naming the release that is
actually public today.

This build ([provenance.json](provenance.json)):
`ukai-vm-0.1.0-preview.2-macos-arm64.dmg`,
`sha256:3e066cea…` **before notarization**, Developer-ID-signed
(`64SGQ348QJ`, timestamped), the snapshot-pinned image
(`apt_snapshot 20261020T000000Z`, disk `310cee86…`), the Rust `ukai-vm`
warm service as the operator surface.

Verified on the built artifact:

| Check | Result |
| --- | --- |
| Fresh install (`install.sh --prefix`) | installs clean; `doctor` ready, `version` reports the warm schemas |
| Installer contract (`check_install.py`, 5 cases) | **5/5** — [installer-check/](installer-check/summary.json) |
| Warm smoke (3 attempts, one boot, live share) | **PASS** — [warm-smoke.json](warm-smoke.json): granted writes on the host, `.git` untouched, network denied, 11.8/12.5 ms release latency |

The K108–K113 rows were measured on the preview.1-labeled build of the
same sources ([installed rows](../macos-vm-installed-2026-11-03/README.md),
[the Claude Code guest record](../macos-vm-claude-2026-11-03/README.md));
this artifact differs in version labeling. **What still gates
publication, in order:** notarytool credentials (none exist on this Mac —
re-verified today), then `vm/notarize.py --package …` (submit → staple →
validate → `spctl`, every step retained in `notarization.json`), then the
full row rerun on the stapled DMG, then the tag `ouro-vm-v0.1.0-preview.2`,
the guide quickstart and `render_vm_pin` update, and the `published` flip.
The public installer's `ouro-vm` command/directory naming
(`~/.local/share/ouro-vm/…`, per the guide) must be reconciled with this
package's `ukai-vm` layout at the same moment, the way the October
publication record handled the naming for preview.1.
