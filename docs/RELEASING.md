# Releasing GraphXploit

A tag beginning with `v` triggers locked Windows and Linux builds of the default lightweight executable. The workflow tests the default build, checks that the tag equals the `Cargo.toml` version, enforces the 25 MiB executable ceiling, and publishes each ZIP with a SHA-256 file.

## Before tagging

1. Merge only after main-branch formatting, all-feature Clippy/tests, RustSec audit, release build, and size checks are green.
2. Review [AUDIT.md](../AUDIT.md) and document any new known limitation.
3. Update the version in `Cargo.toml`, run `cargo update --workspace` if needed, and commit the resulting `Cargo.lock`.
4. Smoke-test `doctor`, `scan`, `impact`, and `serve` using the release binary.

## Create a release

```bash
git switch main
git pull --ff-only origin main
git tag -a v2.0.0 -m "GraphXploit 2.0.0"
git push origin v2.0.0
```

The workflow creates:

- `graphxploit-windows-x86_64.zip` and `.zip.sha256`
- `graphxploit-linux-x86_64.zip` and `.zip.sha256`

Download both platform assets after publishing, verify their checksums, and run a clean-machine smoke test before announcing the release. The publish job alone receives `contents: write`; build jobs remain read-only.
