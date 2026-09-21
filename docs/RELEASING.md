# Releasing GraphXploit

GitHub Actions builds the default lightweight executable for Windows and Linux when a tag beginning with `v` is pushed. It publishes ZIP files to a GitHub Release.

## Before tagging

1. Ensure the main-branch CI workflow is green.
2. Review [AUDIT.md](../AUDIT.md). Do not publish a public release while its release-blocking findings remain unresolved.
3. Update the version in `Cargo.toml` and any release notes as needed.

## Create a release

```bash
git switch main
git pull --ff-only origin main
git tag -a v2.0.0 -m "GraphXploit 2.0.0"
git push origin v2.0.0
```

The `Publish release` workflow creates:

- `graphxploit-windows-x86_64.zip`
- `graphxploit-linux-x86_64.zip`

Check the workflow logs and download both assets from the created release for a manual smoke test before announcing it.

If the release job cannot create a release, ensure GitHub Actions has write permission to repository contents. The workflow requests `contents: write`.
