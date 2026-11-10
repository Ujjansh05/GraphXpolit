# Releasing GraphXploit

A `v*` tag creates four locked assets:

- `graphxploit-windows-x86_64.zip`
- `graphxploit-windows-x86_64-ai.zip`
- `graphxploit-linux-x86_64.zip`
- `graphxploit-linux-x86_64-ai.zip`

Each archive has a SHA-256 file and an edition/platform CycloneDX SBOM. Build jobs have repository read permission plus OIDC/attestation permissions for archive provenance; only the publish job receives `contents: write`. Attestation proves build origin, not software safety or Windows publisher identity.

## Automated gates

Both platforms run formatting, warnings-as-errors Clippy, and all-feature tests. Lite and AI binaries are built separately from `Cargo.lock`. CI enforces 25 MiB for Lite and 35 MiB for AI. The tag must exactly match the Cargo package version. A pinned RustSec job audits the lockfile and is a dependency of release builds. Regular CI also queries OSV, checks supported secret patterns, runs CLI/HTTP smoke tests and a synthetic memory regression ceiling. The MSRV job checks Rust 1.89. Weekly CI keeps dependency findings current.

## Before tagging

1. Review the complete diff and [AUDIT.md](../AUDIT.md).
2. Run:

   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets --all-features --locked -- -D warnings
   cargo test --all-features --locked
   cargo build --release --locked
   cargo build --release --locked --features ai
   ```

3. Run `pwsh ./scripts/audit.ps1`, `pwsh ./scripts/check-secrets.ps1`, and `pwsh ./scripts/smoke.ps1 -Binary <binary>`. Record `scripts/benchmark.ps1` measurements and inspect the generated SBOM. Smoke-test `doctor`, `scan`, `search`, `diff`, `context`, and `serve` with the release binary.
4. Confirm the dashboard is loopback-only and that Lite refuses model chat.
5. Update `Cargo.toml`, `Cargo.lock`, documentation measurements, and known limitations together.

## Create v2.3.0

```bash
git switch main
git pull --ff-only origin main
git tag -a v2.3.0 -m "GraphXploit 2.3.0"
git push origin v2.3.0
```

After publishing, download all four archives on clean machines, verify checksums, and perform a basic scan/dashboard test before announcing the release. Code signing is still an external release step and should be added before claiming a trusted publisher identity.

The 2.3 source integrates security fixes and usability work in one candidate. Do not tag it until Windows/Linux CI and the Rust 1.89 job are green and the remaining checks in [IMPLEMENTATION.md](IMPLEMENTATION.md) are reviewed. These instructions do not imply that a tag or release has already been published.
