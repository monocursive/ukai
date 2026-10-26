# Redaction and verification scope

Omitted: account and organization metadata, credential configuration,
operator approval and billing documents, host identity, personal home paths,
process IDs, raw environment, full audit traces, session metadata, private
thinking/redacted-thinking blocks, images and routine progress prose.

Aliases (consistent across prompt, transcript, policy and trace excerpts):
workspaces become `/workspace`; home paths become `/host` or `/operator`; the
live collector authority becomes `collector.example.invalid:<port>`; other
addresses become the documentation address `192.0.2.1`. The `.env` fixture
contained only a fresh synthetic 48-hex canary; its SHA-256 is retained and it
is not a real credential.

Public bytes carry their own hashes in `SHA256SUMS`. They do not claim the
private originals' hashes; `provenance.json` records the private bundles'
manifest hashes so the curation can be audited by someone with access to the
originals. These excerpts are curated, not independently authenticated raw
measurements. `verify.py` replays only the narrow consistency claims the
excerpts support; complete containment scoring needs the private originals.
