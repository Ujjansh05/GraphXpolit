# Runtime and security verification

Engineering checks for the GraphXploit 2.3 candidate, performed on Windows on 2026-11-10/11. This is not an independent security certification. The source update has not been published by this implementation session.

## Completed locally

- Formatting and strict Clippy for all targets/features pass.
- Lite: **39 tests pass** (29 unit and 10 integration). AI: **42 tests pass** (32 unit and 10 integration).
- Regression coverage includes cancellation, generation reuse, concurrent readers, cache cleanup locking, incremental/fresh edge equivalence, lexical/import aliases, unresolved receivers, deleted/renamed Git symbols, process deadlines, workspace boundaries and conflicting undo.
- AI tests use a loopback mock provider to check request contents, usage, response limits, redirects, serialized request bounds and model-configuration fingerprints.
- Lite and AI locked Windows release builds complete.
- CLI/HTTP smoke tests pass for both editions: JSON search, source hashes, indexed-file overview, file graph/call evidence, missing-token refusal, cross-origin refusal and secret-file exclusion.
- Embedded JavaScript passes `node --check`. Browser automation could not initialize in this environment; visual/interaction testing is not claimed.
- OSV queried **208 public package/version entries** from Cargo.lock and returned **zero known advisory matches**. The supported-pattern working-tree secret check found no matches. Neither check proves absence of vulnerabilities or secrets.
- Edition-specific CycloneDX SBOM generation succeeds. Hosted Windows/Linux, Rust 1.90 and dependency checks are recorded per commit in GitHub Actions; release provenance still requires a tagged build.

## Resource observations

The benchmark creates fresh temporary Python projects with two functions per file. It measures process elapsed time, samples peak working set every 10 ms, performs an unchanged scan, then adds a function to one file. Index bytes include generated data/WAL sidecars. Short-lived peaks can be missed. Browser and model memory are excluded.

| Files | Initial scan | Unchanged | One-file change | Index size |
|---:|---:|---:|---:|---:|
| 100 | 1.20 s | 48 ms | 68 ms | 163,840 bytes |
| 1,000 | 11.94 s | 46 ms | 62 ms | 958,464 bytes |
| 10,000 | 337.59 s | 102 ms | 193 ms | 9,154,560 bytes |

That run used the 9,199,616-byte candidate. Its largest sampled working set was 20,226,048 bytes (19.29 MiB) during the 10,000-file initial scan. A subsequent 1,000-file run with the final indexing/schema guards (9,201,152-byte build) measured **18.42 s / 72 ms / 93 ms**, with a 9,125,888-byte sampled initial-scan peak (8.70 MiB). The later terminal-display sanitation does not alter the indexer.

These are observations from one Windows machine, with other development work running during parts of the measurement, not isolated medians or a cross-platform performance guarantee. The spread in initial scan times needs profiling. In particular, **large-project cold scans are a remaining performance concern**; inexpensive rescans do not establish fast first-run indexing.

Following API smoke traffic, idle working sets were 7,540,736 bytes (7.19 MiB) for Lite and 8,347,648 bytes (7.96 MiB) for AI. Each used 0 measurable CPU milliseconds during a two-second idle sample. This short check does not establish long-term idle behavior.

Final local Windows candidate artifacts:

| Edition | Executable | ZIP download |
|---|---:|---:|
| Lite | 9,202,176 bytes (8.78 MiB) | 2,424,957 bytes (2.31 MiB) |
| AI | 10,727,936 bytes (10.23 MiB) | 3,219,765 bytes (3.07 MiB) |

Archives contain the executable and `gx.cmd`; matching checksums and SBOMs are separate. These local builds are unsigned, unpublished candidates; hosted builds may differ. Rust build caches/toolchains are development storage and are not shipped to users. No model, browser engine, Node runtime, Docker image or graph server is bundled.

## Reproduce

Build each edition separately; the second build overwrites `target/release/graphxploit` (or `.exe`).

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --locked
cargo test --all-features --locked
cargo build --release --locked
./scripts/smoke.ps1 -Binary target/release/graphxploit.exe
./scripts/benchmark.ps1 -Binary target/release/graphxploit.exe -Files @(100,1000,10000)
./scripts/audit.ps1
./scripts/check-secrets.ps1
./scripts/sbom.ps1 -OutputFile target/graphxploit-lite.cdx.json
cargo build --release --locked --features ai
./scripts/smoke.ps1 -Binary target/release/graphxploit.exe
./scripts/sbom.ps1 -OutputFile target/graphxploit-ai.cdx.json -Ai
```

Scripts require PowerShell 7; use the extensionless binary path on Linux. They are developer verification tools, not runtime requirements.

## Remaining validation

See [implementation status](docs/IMPLEMENTATION.md) for the feature-by-feature record and release checks. Remaining work includes the hosted Windows/Linux/MSRV/release run, browser interaction testing, realistic large-project profiling, sustained fuzzing/soak/concurrency tests, low-memory hardware, clean-machine install tests, independent review, and publisher signing.

Static analysis is partial. Git reports conservatively include all declarations from changed files and cap work/results. Source exclusions do not detect secrets embedded in otherwise ordinary files. Approved commands run with the user's OS privileges; path checks and process groups are not an OS sandbox.
