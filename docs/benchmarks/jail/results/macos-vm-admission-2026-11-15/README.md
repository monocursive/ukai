# Measured Mac VM guest admission — 15 November 2026

The signed installed package at source `53e5605fd9d0728ea46da2449c635f364ba2b4f4`
passed ten direct guest capability probes and separate execution-boundary and
vault credential component checks. The VM client admits these twelve
requirements only for the exact measured guest disk and seed. Other images
receive `vm:not-measured:<requirement>` before connection or staging.

| Identity | SHA-256 |
| --- | --- |
| Signed DMG | `b399e8f7116180f3fe9dbb2c4c8540387f101e44a762bd567f23389644431c44` |
| Guest disk | `81bc57865f7b9d1ea9b1fd579a3d5c1dfa69495e0d2024ff9e46a7a9c11367bf` |
| Guest seed | `7a9197f33bd205636279dee4d2435915270e12d55d6e97911a8e0837fca71653` |
| Raw credential inputs | `5d0b1ab4256b418f967fc78597e24f070e2998bd2658f830ed649af312cb3178` |

The guest contains the signed Linux `6ffff05dc` candidate. Its actual Session
advertises `ukai.vm.secret-revocation/1` and `ukai.vm.guest-journal/1`; both
exact contracts are required again before any credential transfer. The source
lease watcher, service and guest remove the staged generation without adopting
a replacement. Unsupported copied or program-bound credentials, refresh,
persistent vendor state and other policy carry continue to refuse. The
owner-loss bound remains unsupported. Required `pids=64` and `mem=512MiB` now
have an execution-boundary record; required swap still has no capability row.

The [direct probes](handshake-capabilities/capabilities.json) retain sixteen
attempts and their receipts. The [boundary record](handshake-execution-boundary/execution-boundary.json)
derives 121 checks from four distinct resource/tree attempts on the same boot.
The [credential admission v2](handshake-credential-admission-v2/credential-staging.json)
derives 24 checks from the exact raw transport experiment and the verified
signed installation. The synthetic credential's upstream stream closed about
204 ms after revocation; the next request was denied without a second upstream
credential use. Guest cleanup and retained leak scans passed.

These are component admission measurements. They do not establish normal
installed-client source monitoring, blocked-output behavior in a live VM,
vendor/TLS compatibility, program binding, full K113 or release qualification.
The unchanged original [live report](handshake-raw-credential/raw-credential-revocation.json)
says FAIL because its old judge rejected the valid five-field Outcome object.
The [corrected replay review](k113-tooling/outcome-replay-1cb8f1af7/review.json)
records the successful judgment of unchanged bytes. No failed report was
overwritten. The [original v1 derivation](handshake-credential-admission/credential-staging.json)
is also preserved; v2 explicitly separates the measured four-part installation
identity from the disk/seed pair needed for guest admission.

A rebuilt host runtime does not inherit host qualification. It must be built
from clean source, signed, verified against its package and tested through the
installed command. Re-signing helpers changes their bytes without changing the
measured guest pair. All four selected artifact digests still have to match the
service's status and Ready messages. The package remains unnotarized and
unpublished.

## Reproduce the record judgments

From the repository root, this uses bounded retained source bytes, not stored
PASS labels, to re-derive the two admissions:

```sh
python3 - <<'PY'
import json, sys
from pathlib import Path
sys.path.insert(0, 'crates/ukai-jail/vm')
import credential_revocation_measurement as revocation
import credential_staging_measurement as admission
import execution_boundary_measurement as boundary
root = Path('docs/benchmarks/jail/results/macos-vm-admission-2026-11-15')
replayed = revocation.replay_raw(root / 'handshake-raw-credential')
assert replayed['outcome'] == 'PASS', replayed['errors']
stored = json.loads((root / 'handshake-credential-admission-v2/credential-staging.json').read_bytes())
assert admission.derive(replayed, stored['installation']) == stored
capabilities = json.loads((root / 'handshake-capabilities/capabilities.json').read_bytes())
facts, passed = boundary.judge(capabilities)
stored_boundary = json.loads((root / 'handshake-execution-boundary/execution-boundary.json').read_bytes())
assert passed and facts == stored_boundary['facts']
print('PASS: credential and boundary record judgments reproduce')
PY
```

The [independent review](handshake-admission-independent-review/review.json)
inventories original hashes and scope. Repeating Apple signature verification
requires the exact DMG identified above; text-only replay does not attest the
signer or re-scan a VM disk. Stream timing, header digests and leak scans are
retained host observations, not independent hardware attestation.

Only bounded text proof is stored here. It contains no binaries, VM disks,
private keys or credential values. Exact raw files retain a private LAN address
and a workspace path because changing those bytes would invalidate the binding.
