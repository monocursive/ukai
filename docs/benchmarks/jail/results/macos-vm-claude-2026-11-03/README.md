# Claude Code headless in the warm guest — the J18 compatibility record — 2026-11-03

**MEASURED PASS** ([k113-claude.json](k113-claude.json), harness
`vm/claude_vm_row.py`, attempt [k113-attempt/](k113-attempt/)): Claude Code
**2.1.311** (linux-arm64 native build, `sha256:2e2496c9…`, the
downloads.claude.ai manifest digest) ran headless inside the guest of the
**installed package** (the same signed, notarization-pending ukai-vm
0.1.0-preview.1 that carried the K108–K112 rows), driven by
`ukai-jail run --vm --profile agent --launch claude-vm`.

## Errata (2026-11-03, fix wave 1103)

Added after review; the raw files are unchanged, and the text below is kept
as written except for the digest erratum 1 corrects inline. **This is not a
J18 compatibility record, and K113 is `untested`:** one attempt meets none
of J18 §9.4's Linux-row conditions (the A01 fixture, ten repetitions, the
no-source refusal, revocation mid-stream, observation on with strict
evidence, the summary's credential use count).

1. **The receipt digest.** The transport line was first cited here as
   `receipt sha256:10c3c58f…`, which matches no file. The terminal summary
   ([k113-claude.json](k113-claude.json) `stdout_tail`) printed
   `receipt sha256:53837b58636d54bd`; the guest receipt
   `k113-attempt/evidence/jail.json` is `sha256:53837b58…`, the digest
   [vm-transport.json](k113-attempt/vm-transport.json) carries.
2. **The stored receipt is the host's.** `k113-attempt/jail.json`
   (`sha256:b0e534f0…`) is the host's own receipt, not "the guest's Linux
   receipt", and it contradicts the guest receipt: network `pending`,
   observer not attached and kernel unknown, against the guest's `proxy`
   network, attached ptrace observer and kernel `7.0.0-38-generic`.
3. **Observation.** "The observer was not attached (`0/6 classes active`)"
   below repeats the host summary. The guest receipt shows the observer
   attached with six classes active; the summary's "network: not applied"
   is wrong the same way.
4. **The harness's summary check** was satisfied by the run's own output:
   `claude_vm_row.py`'s `summary_names_transport` searches the
   `tail --summary` output concatenated with the run's own terminal output,
   so it passes from the run's output alone and does not show that
   `tail --summary` reproduced the line. Nothing compared the summary's
   other lines with the guest receipt.
5. **The client** was built from the repository at `f25ffca8d`; no macOS
   `ukai-jail` client ships. The package was the development build labeled
   `0.1.0-preview.1` (DMG `sha256:de86fb71…` before notarization), not the
   public preview.
6. **The first run's `401`** is recorded only in this prose; its attempt
   directory was overwritten by the later runs.

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
  sha256:53837b58…` (erratum 1), every value lifted from the transport record, and
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
