# Runtime and security audit

This document records the production-hardening state of GraphXploit 2.0 as verified on 2026-09-22. It is an engineering verification record, not a security certification. Raw benchmark harnesses are excluded because they contained local-machine details.

## Verified release baseline

- The locked default Windows release built successfully and measured 7,660,032 bytes (7.31 MiB), below the enforced 25 MiB ceiling.
- Formatting passed; Clippy passed with warnings denied for every target and feature; all 15 unit/regression tests passed with every feature enabled.
- A release-binary smoke test completed `doctor`, incremental sample scanning, and an impact query.
- A live dashboard probe returned HTTP 200 for the local page, 403 for a hostile `Host`, 403 for a cross-site request, and 401 for an API request without its token. CSP and `nosniff` headers were present.
- CI now runs a pinned RustSec audit against `Cargo.lock`. A previous OSV check found no advisory match for the public registry packages then present in the lockfile.

## Resolved release blockers

1. The dashboard validates exact loopback hosts, same-origin requests, and browser fetch metadata before returning bootstrap data.
2. Dashboard tokens use 256 bits of operating-system randomness; dynamic bootstrap values are JSON encoded; restrictive response headers are applied.
3. JSON bodies, source previews, query depth/results/visits, source discovery, concurrent scans, retained jobs, and optional-model responses are bounded.
4. Edge rebuilding is transactional and cancellable. Ambiguous overloads are no longer guessed, duplicate qualified names remain distinct, and partial queries are marked incomplete.
5. Optional model URLs are structurally parsed. Remote HTTP, embedded credentials, queries, redirects, unsafe secret-variable names, source sharing, and oversized prompts/responses are rejected.
6. Release automation tests locked sources, enforces the binary budget, verifies tag/version agreement, publishes SHA-256 files, pins third-party actions, and receives Dependabot updates.

## Earlier performance observations

On synthetic Python projects, initial scans measured 2.15 seconds and 8.53 MiB peak working set for 100 files, 19.34 seconds and 22.02 MiB for 1,000 files, and 95.07 seconds and 63.07 MiB for 5,000 files. An unchanged 5,000-file rescan took 3.60 seconds. The dashboard measured 5.96 MiB at idle.

These were single runs on one Windows 11 laptop with 16 GB RAM and predate the latest hardening changes. They do not guarantee memory, CPU, latency, browser use, or index size on another device.

## Remaining external validation

Before claiming support for a new platform or scale, test it there. Real low-memory hardware, large real repositories, long-running/concurrent use, fuzzing, live third-party model providers, Linux distribution compatibility, code signing, and independently reproduced release artifacts have not yet been fully validated. Static call analysis also cannot guarantee coverage of dynamic dispatch, reflection, generated code, or runtime behavior.
