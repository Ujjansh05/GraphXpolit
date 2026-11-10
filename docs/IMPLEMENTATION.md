# 2.3 implementation and release status

This candidate combines the security fixes and code-understanding improvements in one source update. It has not been published by this implementation session. A version number in Cargo.toml is not evidence of a completed GitHub release.

| Area | Implemented behavior | Validation / limit |
|---|---|---|
| Dependencies | Updated SQLite, Tokio and TLS dependencies; locked builds | OSV reports zero known matches for 208 public package versions at verification time; RustSec reruns in CI |
| Workspace reads | Shared path, secret-name, link/reparse, ignore and byte-limit rules | Nested ignore, traversal, secret-path and link regression cases; not an OS sandbox against concurrent filesystem manipulation |
| Mutations | Plan mode by default, post-approval hash/path checks, atomic replacement, conflict-aware undo | Undo conflict tests; every write/create/command still requires local confirmation |
| Processes | Absolute external PATH lookup, shell-name normalization, bounded output, process-group deadlines | Deadline regression on Windows; Linux process-group case runs in CI |
| Remote AI | Prompt preview on every remote agent send; full configuration bound to dashboard previews | Mock adapter tests, redirect/response/request bounds, configuration fingerprint test |
| Context budget | Whole-prompt compaction and byte caps; local Markdown/JSON export with hashes | Small-budget regression; token counts are estimates, not guaranteed provider counts |
| Storage | Read-only SQLite queries, smaller caches, schema guards, cooperating cache-cleanup locks | Reader/writer and exclusive cleanup-lock regressions |
| Indexing | Streaming discovery, parser reuse, mtime+size fast path, unchanged-generation reuse, affected call-edge rebuilding | Incremental/fresh comparison; imports still rebuild on changed scans |
| Resolution | Lexical name selection, explicit Python and JS/TS named/namespace imports, ambiguous-module refusal | Scope, alias, unrelated-receiver and cross-file regression cases; no full type system or runtime resolution |
| Git impact | Disposable before/after indexes retain deleted and renamed symbols | Deletion/rename tests; reports include all declarations in changed files conservatively |
| Dashboard | Version from binary, indexed-file overview, diagnostics, file graph, edge evidence/filter, one-step exploration | API smoke tests and JavaScript syntax passed; visual browser test could not run in this environment |
| CLI | `map`, `ctx`, `cache`; JSON on `f`, `i`, `d`; invalid flags fail | CLI/API smoke tests and argument regression |
| Distribution | Lite/AI builds, binary ceilings, dependency release gate, SBOMs, provenance step, scheduled checks | Local Windows builds and SBOM generation checked; hosted release workflow remains pending |

## Required before a broad release

- Run the updated Windows/Linux CI and Rust 1.90 job against the exact commit to be tagged. Review dependency audit output and attestation generation.
- Exercise the dashboard visually, including keyboard interaction, graph selection, source display and preview approval.
- Profile the 10,000-file cold scan. The measured candidate took several minutes despite inexpensive rescans; do not advertise large-project cold-scan speed yet.
- Test actual large repositories, source with many symbols, parallel dashboard traffic, sustained sessions and low-memory physical devices. Synthetic measurements are not these tests.
- Run sustained fuzzing and an independent security assessment. The current regression suite is not a fuzz campaign or penetration test.
- Validate packaged downloads on clean Windows/Linux systems and verify SBOMs/checksums/provenance from the hosted workflow.
- Arrange publisher/code signing separately if a trusted publisher identity is required. GitHub provenance does not replace signing.

## Deliberate product limits

The app remains local and single-user. No bundled browser, embedding server, graph service, local model, telemetry or automatic updater was added. Runtime storage is the executable, generated indexes and any explicitly saved sessions.

Static resolution is partial, including incomplete handling of variable shadowing, dynamic dispatch, framework wiring, re-exports, default/wildcard imports and some language constructs. Findings are review evidence, not proof that a refactor is safe. Git comparison is capped at 10,000 supported files and 64 MiB per revision; analysis outside those limits fails or reports incompleteness.

Graph overview displays the first 300 indexed files; symbol search remains available for other files. Semantic search/embeddings, a full language server, whole-repository graph rendering, and exact per-provider tokenization are not implemented.
