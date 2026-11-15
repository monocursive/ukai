# Native macOS candidate tooling

This is maintainer packaging and installation tooling, requiring Python 3.11+
and Apple Silicon macOS 27+. It is **not a supported native release**. An unsigned
stage proves layout and build provenance only. Native execution stays disabled
by default; native credential, vault and vendor staging remain unsupported.
NC02, K104 and protected-host workflow acceptance are not satisfied by packaging.
The separate warm-VM product and its K108–K113 gates are unchanged.

## Stage without signing

Build `ukai-jail` in a clean source checkout with its pinned Rust toolchain,
`--release --locked -p ukai-jail --bin ukai-jail`, and the exact full
`UKAI_BUILD_REVISION` and `UKAI_BUILD_DIRTY=false`. Use an external target directory
to keep the source clean. Then, from this tooling directory:

```sh
python3 native.py stage --source /path/to/clean/source \
  --binary /path/to/target/release/ukai-jail --out /path/to/new/unsigned \
  --version 0.1.0-native.1 --build-number 1
python3 native.py validate --package /path/to/new/unsigned
```

Staging requires a clean full revision, independently recomputes the binary's
source-input digest from Git objects, and checks native Mach-O arm64, optimization,
debug mode and pinned compiler provenance. The linker may add an ad-hoc signature
to an arm64 binary; "unsigned" here means no Developer ID/ES distribution signing.
The package contains one executable:

```text
Ukai.app/Contents/Info.plist
Ukai.app/Contents/MacOS/ukai-jail
Ukai.app/Contents/Resources/LICENSES.txt
Ukai.app/Contents/Resources/provenance.json
```

The identifier is `com.monocursive.ouroboros.jail`; minimum OS is 27.0. The
supervisor and guardian use this same executable. There is no privileged helper,
launchd installation, system extension or native-gate override. `package.json`
binds every bundle file's bytes/mode and always says `qualified=false` and
`published=false`. It is a local integrity record, not authenticated distribution
metadata. Do not install an untrusted package or trust its bundled Python tools.

## Sign only after Apple approves the matching profile

No signing identity or profile is inferred from local accounts. Supply a
Developer ID Application identity and a Developer ID provisioning profile for
the exact bundle/team with Endpoint Security approved:

```sh
python3 native.py sign --package /path/to/unsigned --out /path/to/new/signed \
  --profile /path/to/approved.provisionprofile \
  --identity 'Developer ID Application: Organization (TEAMID1234)'
python3 native.py validate --package /path/to/new/signed
```

The signing command embeds `Contents/embedded.provisionprofile`, signs the app
with hardened runtime and a secure timestamp, then checks the Apple-anchored
Developer ID certificate requirements and exact entitlements. Decoding a profile
is **only metadata preflight**: the signed binary must also execute `version
--json` under macOS's normal restricted-entitlement/profile validation, with no
development gate in its environment. Failure leaves diagnostic bytes but no valid
package manifest. A fabricated decoded plist cannot satisfy these Apple checks.
Signing and signature validation first require standard enabled SIP, refusing
disabled, custom or unrecognized status. This is a bounded prerequisite for the
OS launch check, not exhaustive host attestation or native workload acceptance.

Validation is read-only: it never signs, submits or staples. Distribution
validation additionally requires both `stapler validate` and `syspolicy_check
distribution`; failure is fatal. Apple's tools and normal host protection must
be present. Successful signing still does not qualify native jail behavior.

## Notarization is a separate explicit action

Only after reviewing the signed candidate, these commands submit to Apple and
then create a separate stapled output. They are not performed by staging,
validation or installation. Configure a notarytool keychain profile separately;
this tooling neither reads passwords nor creates credentials.

```sh
python3 notarize.py submit --package /path/to/signed --out /path/to/new/submission \
  --keychain-profile ukai-notary
python3 notarize.py staple --package /path/to/signed \
  --receipt /path/to/submission/receipt.json --out /path/to/new/stapled
python3 native.py validate --package /path/to/new/stapled --distribution
```

Apple's accepted receipt is bound to the submitted package. Stapling and final
Apple distribution checks operate on the actual copied bundle; the JSON receipt
does not confer trust. No notarization or signing has been exercised with an
approved Ukai ES profile yet. A consumer download/archive and its quarantine
behavior still need release qualification on a normally protected clean Mac.

## Per-user installation and recovery

```sh
python3 install.py install --package /path/to/stapled
# Explicit local layout/provenance review only; never a release qualification:
python3 install.py --home /path/to/private/test-home install \
  --package /path/to/unsigned --allow-unsigned
python3 install.py remove
python3 install.py recover
```

The installer places the real app in `~/Applications/Ukai.app` and links
`~/.local/bin/ukai-jail` to its executable. Add `~/.local/bin` to PATH yourself;
shell startup files are not edited. Normal installation requires actual Developer
ID and stapled Apple distribution validation on the staged copy. The explicit
unsigned option accepts only an unsigned candidate, and implies no runtime
authorization. The installer never enables `UKAI_JAIL_MACOS_NATIVE=dev`.

A persistent per-user advisory lock serializes install, remove and recovery.
Directories, bundle contents and managed records are checked before changes;
unmanaged apps, symlinked installation directories and unrelated command paths
are not replaced. Upgrades retain the previous app until activation succeeds.
Ordinary failures roll back; a killed/interrupted operation leaves a journal and
refuses further changes until `recover` validates and restores its owned bytes
(or finalizes an already committed operation). Modified recovery paths fail
closed for manual inspection. This is process-interruption recovery, not a
claim of power-loss atomicity or protection from a malicious same-user process.

Removal deletes only the recorded app and its matching command symlink. An
unrelated replacement command is preserved. It does not touch credentials,
receipts, projects, operator configuration, `UKAI_DATA_DIR`, or parent directories.
The small lock remains to avoid lock-inode races. No sudo is required or accepted.

## Verification and remaining acceptance

```sh
python3 -m unittest discover -s crates/ukai-jail/dist/macos -p 'test_*.py' -v
```

Synthetic tests cover staging failures, signature/profile authority refusal,
concurrent installer contention, symlink conflicts, upgrades, rollback, interrupted
recovery and removal. They cannot replace an approved ES profile, Developer ID
signing/notarization, protected-host K104, J16 install/upgrade/removal acceptance,
or native credential/workflow implementation.

Apple references:
[provisioning-profile authority](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles),
[Endpoint Security entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client),
[notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).
