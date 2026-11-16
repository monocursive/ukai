# Native-image v5 component evidence

Fresh measurements passed on the private Developer ID package built from clean source `b54086a3e31d1097954448e2bd37278f20beab7c`: ten capability rows, 121 derived execution-boundary facts, 24 independently replayed vault/revocation facts and 24 literal Linux executable-binding facts. The raw report additionally records its successful persisted replay. Credential staging remains `qualified: false`.

This bundle supports component admission for one exact image and catalog. It does not qualify native alias execution, vendor compatibility, native exposure sampling, normal installed-client source-watch, K113, notarization or public release. All four flags in `native-admission.json` remain false. A host rebuilt with this admission still requires its own installed runtime qualification.

The literal `@program` control used Python and synthetic credentials. Its authorized executable reached the independent peer (200); a byte-identical copy with a different inode actually executed and was denied (403, `credential_process_denied`). Exactly one upstream credential substitution occurred. The separate raw-vault control confirmed active-stream revocation and a later denied request. Neither control executed the catalog vendor or used a provider credential.

The image pins are disk `9c38aa12509ca597ab6798be5466c17ec80e72f2a2a8995b56ab1f52fc2c5446`, seed `358cf538c43748b0092da65d5c0759dae91974d23485db45a3160de4cd6e7f45` and catalog `2979a9c6d43a3d0c54b0d5521fedb074832f21a55d39fe151c2bd7534ce27244`. The guest now uses a same-process pipe gate for cgroup entry and observer setup. The sampler and its failure criteria are unchanged. The bootstrap public-canary detector passed seven facts with no scan errors; that detector control does not qualify vendor exposure sampling.

The gate removes known setup forks. It does not identify or waive the vanished-process errors from the earlier A01 or diagnostics. The transition from Python gate to jail executable can still overlap a sample; any resulting error remains visible under the unchanged completeness rules. The earlier failed provider measurement remains failed.

The signed DMG is `74b63a94edfe6a3269d2cb876900c25a5a1c7d97459e39b4e0b927e0ee249cbc`. Six actual Apple requirement-based signature checks, seven actual-DMG installer cases and independent package/source/installed-byte verification passed. The DMG, disk, seed, binaries and source archive are excluded. Offline replay binds the retained signature observations to exact payload hashes; it cannot repeat Apple verification without those artifacts.

Raw receipts, journals, exact transport inputs, sync receipts, tail output and independent reviews are copied byte-for-byte. `provenance.json` records their origins. Absolute paths are historical provenance; replay reads this bundle. The live scans reported no synthetic-value hits in covered retained bytes and same-boot disk. Offline replay checks those observations and scans this bundle for the synthetic formats and covered encodings. It cannot rescan a stopped VM or establish arbitrary-memory absence. Final and per-phase lifecycle records retain successful cleanup, no owned processes, and the detached workspace with its backing preserved.

`tools/` contains exact b540 source and the fixture/import closure needed by the copied offline tests. `program-binding/offline-replay.json` and the admission records are fresh derivations. All 183 pre-existing legacy, native-v2 and native-v4 proof files remain byte- and mode-identical. No earlier image verdict is inherited.

With Python 3.11 or later:

```sh
python3 -B replay.py
python3 -B -m unittest discover -s tools -p 'test_credential_staging_measurement.py'
python3 -B -m unittest discover -s tools -p 'test_program_binding_measurement.py'
python3 -B -m unittest discover -s tools -p 'test_vm_summary_check.py'
```

The 67 copied offline tests passed. Replay checks exact inventory/hashes, all 10/121/24/24 component facts, the signed image and service identity of every capability attempt, credential derivation, catalog/profile/source/package bindings, and the admission's six pins, 24 references, attempt and measurement time. It performs no boot, mount, signing, installed-binary execution or provider request. Relocated validation denies original-path reads, writes, network and subprocesses; tamper controls include a self-consistent old capability/boundary transplant. Integrity inventories are not independent authentication.
