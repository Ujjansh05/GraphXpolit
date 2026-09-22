# Releasing GraphXploit

A `v*` tag creates four locked assets:

- `graphxploit-windows-x86_64.zip`
- `graphxploit-windows-x86_64-ai.zip`
- `graphxploit-linux-x86_64.zip`
- `graphxploit-linux-x86_64-ai.zip`

Each archive has a matching SHA-256 file. Build jobs have read-only repository permission; only the final publish job receives `contents: write`.

## Automated gates

Both platforms run formatting, warnings-as-errors Clippy, and all-feature tests. Lite and AI binaries are built separately from `Cargo.lock`. CI enforces 25 MiB for Lite and 35 MiB for AI. The tag must exactly match the Cargo package version. A separate pinned RustSec job audits the lockfile.

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

3. Smoke-test `doctor`, `scan`, `search`, `diff`, `context`, and `serve` with the release binary.
4. Confirm the dashboard is loopback-only and that Lite refuses model chat.
5. Update `Cargo.toml`, `Cargo.lock`, documentation measurements, and known limitations together.

## Create v2.1.0

```bash
git switch main
git pull --ff-only origin main
git tag -a v2.1.0 -m "GraphXploit 2.1.0"
git push origin v2.1.0
```

After publishing, download all four archives on clean machines, verify checksums, and perform a basic scan/dashboard test before announcing the release. Code signing is still an external release step and should be added before claiming a trusted publisher identity.
