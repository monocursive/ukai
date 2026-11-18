# Ukai Jail 0.1.0-rc.8 Linux preview, 18 November 2026

The annotated tag `ukai-jail-v0.1.0-rc.8` points to the signed candidate's source commit
`bf365665197a0861752d704eef05ca9d0dde9952`. PR #54 merged that commit into `dev`
at `14db5feecb376420ad08e0319dae9733be191f5c`. GitHub published all eight
candidate assets as a prerelease. The build-input digest is
`sha256:e995064da2bb966eb5019e98992044571f04933507fc8111d5d5e5d5d1bee805`.
[GitHub release](https://github.com/monocursive/ukai/releases/tag/ukai-jail-v0.1.0-rc.8)
and [merged PR](https://github.com/monocursive/ukai/pull/54).

The reference host passed strict Linux preview conformance. Both native packaging
jobs passed on the exact release commit. OpenCode onboarding and learning ran
on an earlier commit with the same build inputs. Real-agent reliability remains
experimental. [Reference conformance](https://github.com/monocursive/ukai/actions/runs/44286726626),
[native builds](https://github.com/monocursive/ukai/actions/runs/44286726534)
and [OpenCode run](results/release-preview-2026-11-18-dev/README.md).

## Published bytes

The production Minisign key verified the checksum manifest. Both native hosts
installed the downloaded GitHub draft. After publication, anonymous HTTPS
downloads of all eight files matched the candidate byte for byte. The public
website served the signed bootstrap at `https://ukai.sh/install.sh` with SHA-256
`1b7b3d047511c223fa24feaf7d9ce198b3c2f5941333326601f032fcb09037c7`.

| Linux target | Archive SHA-256 | Installed executable SHA-256 |
| --- | --- | --- |
| x86_64 GNU | `176514f7ec07ef955429683067e2d83778a22998ae460930e507584ec0c71592` | `af4c3413ef453b1f94ad8773c33918fb092f8f353aecdd50d74033048b98ab3d` |
| AArch64 GNU | `85b479d4b57ea3909d20b56a8bfb24e3496af56e23af0beb77296c2ae2ae77df` | `c4c5970bff11988364cf6e926568afc1dcc4c6b3b99fa39f51bde1a12654cb7b` |

## Native public installs

On the Ubuntu x86_64 reference host and an Ubuntu ARM64 guest on Apple Silicon,
we tested each public entry point in its own empty home. We downloaded the
bootstrap anonymously, checked its hash, and ran it twice using its default
version, source, and install path. Each install produced the expected release
record and executable. Each host reported the signed build's revision and
passed `doctor --profile tool --json`. Each contained `/usr/bin/true` exited
zero. Its receipt recorded enforced containment, a verified empty process tree
and completed cleanup.

| Installer | x86_64 receipt SHA-256 | ARM64 receipt SHA-256 |
| --- | --- | --- |
| GitHub release bootstrap | `ed36134ff6c2eda45d76050109ff3fa2afb64bb414e4010dda6914c695d782a9` | `6daab22f9cc052d6ecefb3da8718ea4391eb7faba360cfdf9b1ab6f96a29d8fa` |
| ukai.sh installer | `38483fea778f7cfbee1a2bec0c31d9d6e9ceb0d1bd2c2d6f24b51849e3611a13` | `122139cc269d90a80164c02c1f2493c1ec8ee8471e399e2bbdae6a57c27c7bcd` |

The website rollout updated eight existing assets on the production deployment.
Its public key matched the repository key. The Linux binaries require glibc
2.39 or newer and the tested tool profile requires host support. Stock Ubuntu
24 containment remains refused. The macOS VM has a separate release.
