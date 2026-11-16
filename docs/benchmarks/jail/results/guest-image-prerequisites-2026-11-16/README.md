# Next guest-image prerequisites — 16 November 2026

The next experimental Mac guest builder has authenticated Ubuntu 26.10 inputs and an exact private signed Linux payload. These checks establish source and input prerequisites. No new guest image has been prepared or booted, and no installed managed-native version-3 Mac host is qualified.

The frozen Linux preview remains J `0be9d1e820b0d47493883053253491bbd2196ba3`, version `0.1.0-rc.7`; its signed candidate bytes and tested-I freeze remain unchanged. This builder-only source change does not alter the owning 230 compiled inputs (`sha256:2448a8057ab3e5821e1d519879be036ab7af03915a8e43d97df2c3ff0016f3ae`) or create another Linux candidate.

## Authenticated input and actual layout

The dated [Ubuntu ARM64 minimal image](https://cloud-images.ubuntu.com/minimal/releases/stonking/release-20261105/ubuntu-26.10-minimal-cloudimg-arm64.img) is exactly 413,204,480 bytes with SHA-256 `bac15af78c37fec8e9474a9a784041c13ddb2603b9095435b7e4269e3faf3064`. The earlier checksum/signature and snapshot metadata authentication remains retained without changes; the later read-only inspection additionally verified the actual downloaded image bytes.

The standalone, unencrypted qcow2 has a 4,831,838,208-byte virtual disk. Both GPT copies and their entry CRCs verified. Partition 1 is ARM64 root, partition 13 is an ext4 XBOOTLDR volume labelled `BOOT`, and partition 15 is EFI/FAT32. The two ext4 primary superblocks report state 1, no recovery flag, no orphan and zero recorded errors. This bounded header inspection is not a filesystem check or boot test. The builder converts the whole disk and extends it to 6 GiB; it has no fixed root-partition index or single-ext4 assumption. The additional XBOOTLDR partition is an explicit compatibility input for the future image run.

All six ARM64 main/universe package indexes from the matching [20261106T000000Z snapshot](https://snapshot.ubuntu.com/ubuntu/20261106T000000Z) were checked against SHA-512 and length entries in the authenticated Stonking, Updates and Security InRelease files. Candidate paragraphs include `bubblewrap 0.12.0-1` and `dbus-user-session 1.16.2-5ubuntu2`. This establishes available package records, not a dependency solution or successful installation. Large image and index bytes remain in the retained reference-host task directory.

## Builder source checks

The native opt-in payload is the exact production-signed J ARM executable, SHA-256 `c0c1f0e7cecb1fabe9c4ff42f9ae4534e24b16cb9dc0cf5ab21f4d827db6e38f`. The existing trusted-key verification, copied-candidate recheck, profile hash, executable/type/identity checks and immutable catalog construction remain in force. J remains unpublished: the public default release coordinates are unchanged, and this native payload requires the verified local signed-candidate input.

The builder writes the matching snapshot stanza and checks the standard APT source files before the first update. Its bounded no-follow guard permits only the exact own stanza and otherwise absent, blank or comment-only `.list`/`.sources` files; unexpected active or disabled non-comment entries are refused. This guard does not inspect arbitrary APT configuration or hooks and does not claim an inventory of source files in the unopened image.

The authenticated image manifest includes `dbus-broker 37-5ubuntu5`. Read-only inspection of four authenticated package payloads (366,464 bytes total) shows that its maintainer script enables a global user `dbus.service` alias, while `dbus-user-session` provides the packaged single-process `dbus-daemon --nofork` unit. Installing the daemon alone would leave provider selection ambiguous. The existing guest retains the session-bus MainPID; the broker launcher/child model is therefore a compatibility concern, not an observed boot failure. The reviewed builder now disables the broker’s global user selection before creating the new user manager, then checks the effective packaged daemon unit and stable MainPID, birth, executable, argv and all four UIDs before enabling the controller. The system bus and guest infrastructure allowlist remain unchanged.

The two-file source slice passed all 34 focused tests normally and with optimization enabled, with zero skips. The tests execute the exact embedded guards against small fixtures; they do not start systemd or a VM. Independent review rehashed the source, both logs and all 230 compiled inputs. The systemctl guard has a 30-second command deadline and a 16 KiB accepted-output check after capture, not a hard pipe-allocation cap.

An independent provider review also passed nine focused controls. A separately authorized read-only `systemctl --user show` on the already-active reference-host daemon produced unmodified properties accepted by the exact frozen parser. It performed no start, reload, selection or process reads. This checks observed formatting on that existing host; it does not qualify the proposed image.

## Remaining gates

The future image still needs actual package resolution, EFI/cloud-init boot, user-manager and session-bus checks, loader/native execution, version-3 sampling, fresh component proof/admission and installed Mac qualification. The retained primary-superblock flags and source tests cannot substitute for those measurements. Ubuntu's previously reviewed CVE status does not establish a broader security audit or explain any historical kernel failure.

Measured prior allocations require roughly 16.64 GB free for image preparation and 21.59 GB for the fresh image plus package/installer phases while preserving 12 GiB. The latest retained primary-Mac observations remain below that combined requirement; a reviewed external-storage route remains pending. No new image build was performed; the full workflow still lacks sufficient Mac storage.

The earlier fourteen API-key lanes remain eight strict passes and six failures. OAuth remains deferred; native macOS Endpoint Security and notarization remain pending. No historical failure, release signature, freeze, admission pin or published status changes.

## Retained proof

This selected record contains small results and source checks. It does not duplicate the public image, package indexes, package payloads or existing signed Linux candidate. The [machine-readable record](report.json) binds each copied file.

- [Original metadata authentication](proof/authentication-review.json) and [GnuPG verification](proof/authentication-verification.json); the original metadata-only limits remain historical.
- [Authenticated package manifest](proof/image-manifest.txt), [actual image/layout result](proof/image-layout-review.json) and [six-index result](proof/image-index-review.json).
- [D-Bus package metadata](proof/dbus-package-review.json) and [independent prerequisite review](proof/public-prerequisite-independent-review.json).
- [Provider operational review](proof/provider-operational-review.json) and [existing-reference formatting observation](proof/provider-format-observation.json).
- [Source/test validation](proof/source-validation.json), [independent source review](proof/source-independent-review.json), [normal log](proof/source-normal.log) and [optimized log](proof/source-optimized.log).

The [signed private rc.7 record](../release-candidate-2026-11-16-rc7/README.md) remains authoritative for J. This source/prerequisite documentation does not alter that artifact, its signature or the tested-I freeze.
