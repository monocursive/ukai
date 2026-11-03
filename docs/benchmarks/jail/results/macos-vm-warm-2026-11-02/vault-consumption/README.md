# Vault-value consumption through the VM — wiring complete, injection open

**Development evidence only. The live measurement FAILED on its final
assertion and is recorded verbatim
([vault-consumption.json](../vault-consumption.json)); this is not a
passing claim.** (Recorded 2026-11-03; harness:
[vault_measurement.py](vault_measurement.py), image19.)

## What is wired and verified live

- `run --vm` accepts a vaulted launch policy: the Mac reads the
  operator's `<config>/launch/<name>.toml` under the loader's own privacy
  rules (operator-owned, single link, 0600, ≤64 KiB, no trailing newline
  in the value), rewrites each `[credentials.<id>] source` to the guest's
  tmpfs staging path, and sends the TOML plus each value as a secret —
  the already-measured transport. Staged credential modes (`copy_rw`,
  `bind_ro`) refuse with a remedy: they would write the value into the
  guest's on-disk vendor state, which the VM tier has not qualified.
- The guest controller writes the launch TOML under the attempt's config
  directory (owned by the workload account, 0600, single link — the shape
  its loader requires; three real bugs found and fixed on the way: a
  root-owned file the jail could not read, a root-owned tmpfs staging
  tree, and a Python syntax slip that killed the controller at import) and
  runs the jail with `--launch`.
- The live run settled (`phase: settled`, exit 0, `tree_empty: true`),
  the guest receipt records the credential **in vault mode, never
  staged** ([records.guest_credentials]), the fetch went **through the
  guest's proxy** (the workload's env carried the bridge, and the echo
  server received the request), and the secret value appears in **no
  exported file**.

## The open finding

The echo server received the request **without the credential's
`x-test-token` header** (`received_headers` in the record). The guest
proxy admitted the allowed host but did not inject. The vault's injection
runs through the sealed-bridge origin machinery (vault/origin.rs: the
bridge writes an origin preamble, the mediator pins the connecting
process, the proxy claims it under the connection's 4-tuple). The next
diagnostic step is inside the guest: whether the supervisor sealed the
bridge for the vault at proxy start, and whether the origin preamble
arrives in the VM's network namespace. Until injection is observed, vault
consumption through `--vm` stays refused at the CLI's policy gate (the
`agent`-with-launch shape passes parsing but the docs and this record
say the header is not yet injected; the scope note says the same).

## Two measurement-environment notes

The guest image had to be rebuilt six times tonight: one rebuild was a
real ordering bug (retained under image13-attempts/), and five were
`apt` stalling at `Connecting to archive.ubuntu.com` or a degraded
Virtualization.framework after many spawn/kill cycles (50-byte consoles,
recovering after minutes of idle). The measurement harness boots a fresh
service per run; each failed boot's evidence is retained under the
attempt's data directory.
