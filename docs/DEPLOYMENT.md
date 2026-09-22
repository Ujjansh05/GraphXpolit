# Deployment

GraphXploit is distributed as a desktop-style CLI with a loopback web interface. There is no central server to deploy and no user source code needs to be uploaded.

## Recommended: GitHub Releases

1. Merge a verified version to `main`.
2. Create the matching annotated tag described in [RELEASING.md](RELEASING.md).
3. GitHub Actions builds Windows/Linux Lite and AI archives, checks size limits, creates checksums, and publishes the release.
4. Users download one archive, verify its checksum, extract the executable, and run `serve <project>`.

This is the lowest-storage deployment: one executable plus a generated per-project SQLite index.

## Edition selection

Publish both editions and make Lite the default recommendation:

- Lite is appropriate for offline analysis, graph visualization, Git impact, and context export.
- AI is appropriate only when a user already has a trusted Ollama or OpenAI-compatible endpoint and wants in-product chat.

Do not bundle a model. A bundled coder model usually dominates download size, RAM, and CPU and defeats GraphXploit's lightweight goal.

## Do not deploy the dashboard publicly

`serve` intentionally binds to `127.0.0.1` and assumes a single local OS user. Do not:

- change it to `0.0.0.0`;
- expose it through a reverse proxy, tunnel, port-forward, or cloud load balancer;
- run it as a shared multi-user service;
- package the process token into another website.

For team use, distribute the executable to each developer or build a separate, explicitly multi-user service with authentication, authorization, tenant isolation, encrypted storage, audit logs, rate limiting, and a new threat model.

## Build your own artifacts

```bash
git clone https://github.com/Ujjansh05/GraphXpolit.git
cd GraphXpolit
cargo test --all-features --locked
cargo build --release --locked
cargo build --release --locked --features ai
```

The second command overwrites the same target binary with the AI edition, so copy/package Lite before building AI. Preserve `Cargo.lock` and publish a SHA-256 checksum for every archive.

## Updates and rollback

Releases do not mutate project source. Replacing the executable updates the application. Existing indexes carry a schema version and migrate forward when supported. For rollback testing, keep the previous executable and remove/rebuild generated indexes if an older binary cannot read a newer schema.

Before broad distribution, add platform code signing. Windows users otherwise may see SmartScreen warnings even when the SHA-256 checksum is correct.
