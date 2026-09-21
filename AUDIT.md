# Runtime and security audit

This document summarizes a local audit of the GraphXploit 2.0 Rust application.
It is not a security certification. Raw benchmark data and developer harnesses
are intentionally excluded from this public repository because they included
local machine details.

## Measured prototype results

The default Windows release executable measured 6.2 MB. On synthetic Python
projects, initial scans measured 2.15 seconds and 8.53 MiB peak working set for
100 files, 19.34 seconds and 22.02 MiB for 1,000 files, and 95.07 seconds and
63.07 MiB for 5,000 files. An unchanged 5,000-file rescan took 3.60 seconds.
The dashboard server measured 5.96 MiB at idle in a short Windows observation.

These were single-run synthetic results on a Windows 11 laptop with 16 GB RAM;
they do not guarantee memory, CPU, latency, browser use, or index size on any
other device. The audit found no advisory matches in OSV for the 193 public
registry package/version pairs in Cargo.lock at the time of checking.

## Checks that passed

- The default release build and existing Rust tests passed.
- The server binds to `127.0.0.1`.
- Missing or incorrect dashboard tokens returned HTTP 401.
- Ordinary relative and absolute source-path escape attempts returned HTTP 400.
- Oversized JSON requests returned HTTP 413.
- The default analyzer does not execute indexed source or download models.

## Release-blocking fixes

Do not make a public production release until these are fixed and retested:

1. Validate dashboard Host and Origin headers so a hostile hostname cannot
   retrieve the page bootstrap token.
2. Parse AI endpoint URLs and validate the actual hostname/IP. String-prefix
   checks accepted lookalike non-loopback hosts over HTTP.
3. Enforce result limits during traversal, bound source-excerpt reads, limit
   concurrent scan jobs, expire completed jobs, and cap model response sizes.
4. Generate the dashboard token from the operating system's cryptographic
   random source; safely escape bootstrap data and add response security headers.
5. Make the release workflow run tests, enforce the binary-size budget, use a
   locked dependency build, and publish checksums or signed artifacts.

## Not yet verified

Real Linux installation, 4 GB hardware, browser memory, large real projects,
long-running/concurrent use, fuzzing, live optional-model providers, and
published-release integrity still need testing.

Read [docs/SECURITY.md](docs/SECURITY.md) before distributing GraphXploit.