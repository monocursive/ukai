# Claude Code headless in the warm guest — the J18 compatibility record — 2026-11-03

**MEASURED PASS** ([k113-claude.json](k113-claude.json), harness
`vm/claude_vm_row.py`, attempt [k113-attempt/](k113-attempt/)): Claude Code
**2.1.311** (linux-arm64 native build, `sha256:2e2496c9…`, the
downloads.claude.ai manifest digest) ran headless inside the guest of the
**installed package** (the same signed, notarization-pending ukai-vm
0.1.0-preview.1 that carried the K108–K112 rows), driven by
`ukai-jail run --vm --profile agent --launch claude-vm`.

## What the one attempt proved

- **The agent worked.** `-p` with `--dangerously-skip-permissions
  --output-format json`, two turns on `claude-sonnet-5-5`, `is_error:
  false`, result `"done"`, $0.0042 — and its one real task landed: it
  created `k113-marker.txt` whose content is `contained`, **on this host
  through the live virtio-fs share**.
- **The credential stayed in the vault.** The operator's OAuth access
  token (Claude Code's keychain session, 108 bytes, read at run time into
  a 0600 single-use source outside the repository — the value is never
  printed and appears in **no exported byte**; the leak scan covers every
  attempt file). The child held only the placeholder, bound to
  `CLAUDE_CODE_OAUTH_TOKEN` by the vault's `env` placement, and the
  guest's proxy substituted the value in flight into
  `Authorization: Bearer …` for `api.anthropic.com` over TLS (the boundary
  points the child's trust variables at the per-attempt CA). The guest
  receipt records the credential `vault, never staged`.
- **The jail held.** Profile `agent` with the proxy network
  (`api.anthropic.com:443` the only allowed host), settled, exit 0,
  `tree_empty: true`, the stored receipt the guest's Linux receipt
  (kernel `7.0.0-38-generic`), the transport record
  ([k113-attempt/vm-transport.json](k113-attempt/vm-transport.json))
  binding attempt `att_ff3c80a0…`, boot `vm-9e2e72b1…`.
- **The summary names its transport** (K113's claim): the run's terminal
  summary carries `vm: guest-reported facts in evidence/jail.json · boot
  vm-9e2e72b1… · image 310cee86ccca5b5d… · vsock 1024 · receipt
  sha256:10c3c58f…`, every value lifted from the transport record, and
  `ukai-jail tail --summary --attempt …` reproduces the summary (exit 0).

## The two earlier runs, retained verbatim

1. **The first run failed with the API's own `401 OAuth access token has
   expired`.** The harness had sourced the token from
   `~/.claude/.credentials.json`, which had sat stale since 2026-09-27;
   Claude Code on this Mac keeps its live session in the keychain. The
   failure is evidence in the record's favor: the API's answer names an
   *expired OAuth token*, not an invalid key — the stale value (not the
   placeholder) reached Anthropic through the guest proxy, which proves
   the substitution and the TLS path end to end. The harness now takes
   the freshest unexpired source (keychain first, file as fallback).
2. **The second run succeeded at everything the row measures** but the
   harness's own verdict: the pty prefixes the agent's result line with a
   render byte, so the JSON parse missed it. The parser reads from the
   line's first `{` now. Both defects were in the harness, not the
   product; the guest path behaved identically in all three runs.

## What this record does not cover

One attempt, one prompt, one model, headless only. Not covered: every
other Claude Code version, npm installs, interactive sessions, `--resume`
and `--continue`, the API-key fallback, other terminal shapes, other
hosts, and traffic beyond `api.anthropic.com` (nonessential traffic was
disabled for the run: `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`). The
observer was not attached (`0/6 classes active`), so this record claims
the agent's own output and the jail's receipts, not observation coverage.
The package itself is still signed-but-not-notarized and unpublished; the
token is the operator's live session and expires with it.
