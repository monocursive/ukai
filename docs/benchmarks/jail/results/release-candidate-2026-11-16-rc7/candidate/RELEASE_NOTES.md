# Ukai Jail 0.1.0-rc.7 — developer preview

Linux x86_64 and ARM64. This preview installs `ukai-jail`; the fleet and ledger are not part of this package.

After this release is published, install with:

```sh
curl --proto "=https" --tlsv1.2 -fsSL https://github.com/monocursive/ukai/releases/download/ukai-jail-v0.1.0-rc.7/bootstrap.sh | bash
```

Requires Bash, curl, tar, and sha256sum or shasum. The installer checks embedded SHA-256 hashes before extracting or executing the archive. The GNU/Linux binaries require glibc 2.39 or newer; Alpine/musl is unsupported. Installs to `~/.local/bin`; no sudo or Rust compiler. Install bubblewrap separately before running contained commands.

Linux x86_64 and ARM64 binary and installer targets; native installation alone does not establish runtime host qualification. Host enforcement depends on `ukai-jail doctor`; attach validation matching this candidate's revision and build-input digest and complete operator review before claiming support for a host.
Ubuntu 24 stock execution remains refused. Previously documented host limitations remain in force unless superseded by matching validation; architecture or installation does not waive them.
Real-agent reliability remains experimental: attach the completed compatibility record before changing that claim.
Maintainers can also verify the signed SHA256SUMS with an independently trusted public key.
