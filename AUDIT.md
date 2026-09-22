# Runtime and security audit

This document records the GraphXploit 2.1.0 engineering verification performed on 2026-09-22. It is not a security certification or a performance guarantee.

## Verified in this change

- Rust formatting passes.
- Strict Clippy passes for every target and feature with warnings denied.
- All 19 unit/regression tests pass with every feature, including parsing, ambiguity, exact query caps, path boundaries, transactional cancellation, graph/search/context, Git parsing, endpoint validation, token generation, browser request checks, and evidence citation extraction.
- JavaScript syntax validation passes for the embedded dependency-free dashboard.
- Locked Lite and AI Windows release builds complete.
- Lite measures 7,925,248 bytes (7.56 MiB), below its 25 MiB CI ceiling.
- AI measures 9,413,120 bytes (8.98 MiB), below its 35 MiB CI ceiling.
- Lite smoke tests complete for `doctor`, sample scan, search, and source-backed context generation.
- CI builds Windows/Linux Lite and AI archives, verifies tag/version agreement, generates SHA-256 files, and runs a pinned RustSec audit.

The GitHub-hosted Linux builds and RustSec job are verified by CI after push; they cannot be represented as completed by this local Windows run.

## Resource benchmark

A release-mode Lite benchmark generated 1,000 small Python files in a fresh temporary project and a fresh data directory:

| Operation | Time | Peak/size |
|---|---:|---:|
| Initial scan | 15.80 s | 15,507,456-byte peak working set (14.79 MiB) |
| Unchanged rescan | 0.17 s | 8,486,912-byte peak working set (8.09 MiB) |
| SQLite index | — | 1,019,904 bytes |
| Idle dashboard | — | 6,225,920-byte working set (5.94 MiB) |

The temporary benchmark project and index were removed afterward. Values are single runs on one Windows machine and depend on hardware, filesystem, antivirus, code density, and language mix.

## Important hardening changes

1. Scans are generation-based and atomic. Cancellation or edge-rebuild failure rolls back all file/symbol changes.
2. Edge rebuilding streams 512 references at a time; search, traversal, file expansion, graph output, and context evidence are bounded.
3. Blocking SQLite/source/Git work runs outside async request tasks behind a two-slot semaphore; scans and model calls have separate one-slot bounds.
4. Git is invoked without a shell, external diffs, or text conversion and has time/output limits.
5. Context previews are server-stored for 10 minutes and cryptographically bound to the question, target, revision, evidence, and endpoint. Chat accepts only selected IDs from that exact preview.
6. The dashboard remains loopback-only, token-protected, same-origin, non-cacheable, and governed by a restrictive CSP.
7. Lite excludes the HTTP model client. AI requires explicit evidence selection and approval and reports provider token usage when supplied.

## Remaining external validation

The following remain release/process limitations, not hidden implementation work:

- code signing and publisher reputation;
- independent reproducible-build verification;
- fuzzing of parsers, Git output, HTTP APIs, and SQLite migrations;
- long-duration soak and concurrent workload testing;
- large real monorepositories and low-memory physical devices;
- live behavior across specific third-party model providers;
- compatibility testing across older Linux distributions;
- independent penetration testing.

Static analysis also cannot guarantee coverage of dynamic dispatch, reflection, generated code, runtime wiring, or all macro behavior.
