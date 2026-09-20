# Runtime and security audit

Scope: current local GraphXploit 2.0 Rust implementation. This is an audit,
not a security certification. Application code was not changed to fix findings.
Reproduction scripts are in `tools/audit_*.py`; raw measurements are in
`audit-results.json`, `audit-extra.json`, `audit-cpu.json`, and
`audit-dependencies.json`. Scripts use isolated temporary generated projects
and configuration. The runtime probes require Windows and Python 3; the
dependency probe uses Python 3.11+ and sends public crate names/versions to OSV.

## Measurements

Machine: Windows 11 Home, Intel i7-13700H, 20 logical processors,
approximately 15.65 GiB visible RAM. Default optimized release build, AI
feature disabled. Each synthetic Python file contains 20 small functions with
19 direct calls. These are simple workloads, not representative of every real
repository. No browser was included in memory/CPU measurements. Measurements
are single runs per condition, not statistical percentiles. OS cache and
antivirus effects are uncontrolled; no actual 4 GB machine was tested.

| Files | Initial scan seconds | Unchanged scan seconds | One-file update seconds | Initial peak working set MiB | Impact query seconds |
|---:|---:|---:|---:|---:|---:|
| 100 | 2.145 | 0.111 | 0.176 | 8.53 | 0.035 |
| 1,000 | 19.344 | 0.726 | 0.954 | 22.02 | 0.070 |
| 5,000 | 95.073 | 3.597 | 4.353 | 63.07 | 0.254 |

The 5,000-file one-file update peaked at 63.38 MiB. Queries used the default
depth of five and returned five callers, not a large result set. Peak working
set measures resident process memory, not total committed memory or whole
system use. Every benchmark exited successfully without diagnostics.

- Windows executable: 6,202,368 bytes (6.20 MB / 5.92 MiB).
- Test ZIP, Python deflate defaults: 1,615,170 bytes (1.62 MB). GitHub's packaging
  may produce a different size.
- A separately verified 1,000-file SQLite index: 6,541,312 bytes (6.54 MB).
- Combined indexes for the three main fixture projects: 42,262,528 bytes.
- Idle server: 5.96 MiB working set; 0.0 CPU-seconds measured over five seconds.
  This short observation is not a guarantee of zero background CPU.
- Separate 1,000-file CPU probe: initial scan 10.310 wall-seconds,
  1.750 CPU-seconds; unchanged scan 0.646 wall-seconds, 0.469 CPU-seconds.
  CPU time includes kernel and user time across the process. The initial scan
  averaged 0.17 core equivalents; this is not peak CPU utilization.

Initial scan wall time varied substantially (10.3 versus 19.3 seconds for the
same generated structure). More repetitions and real repositories are needed
before stating latency targets. Every scan rebuilds all graph edges, including
an unchanged scan; queries also load the entire symbol list into memory.

## Checks that passed

- `cargo build --release --locked --offline` and all three existing Rust tests.
- Missing or incorrect API tokens return HTTP 401; a correct token works.
- Relative `../` and absolute path escape attempts outside the request's root
  return HTTP 400. This tested ordinary paths, not symlink races.
- Cross-origin preflight returned HTTP 405 without an allow-origin header.
- A 3 MiB JSON request returned HTTP 413.
- Four early cancellation requests reached cancelled status in 0.199 seconds.
  They were cancelled before parsing; long scans and edge-rebuild cancellation
  were not validated by this observation.
- [OSV](https://osv.dev/) batch queries returned no advisory matches for 193
  registry package/version pairs in Cargo.lock, including optional/development
  packages. This is a point-in-time database result, not proof that dependencies
  contain no vulnerabilities. Native bundled libraries were not independently
  scanned, and exploit reachability was not assessed.
- Static review confirms the server binds to 127.0.0.1, queries use SQL
  parameters for user values, result/source UI uses textContent, and the default
  application does not execute analyzed source or download models.

## Release-blocking findings

### 1. Bootstrap accepts hostile Host headers (high priority)

An HTTP request with `Host: attacker.invalid` receives the dashboard HTML and
its valid API token. Token-protected API requests do not validate Host or
Origin either. This is a DNS-rebinding exposure: a successful browser attack
also depends on DNS/browser/network conditions, which were not reproduced
end-to-end. Ordinary cross-origin requests remain constrained by CORS.
Fix by validating loopback Host/port, validating browser origins, and using
appropriate response security headers. See `src/web.rs:116` and `:142`.

Authenticated requests can select a different root and read its files; the
probe retrieved only a generated synthetic secret. This is the app's current
multi-project authority, not an independent authentication bypass. It makes
protecting the bootstrap and API token particularly important.

### 2. AI HTTP endpoint validation can be bypassed (high priority)

`http://localhost.attacker.invalid` and
`http://127.0.0.1.attacker.invalid` were accepted by model configuration.
They are not loopback hosts. No requests were made to these domains.
The ordinary `http://example.invalid` control was rejected. Parse the URL and
validate its actual hostname/IP, disallow userinfo, and define a redirect policy.
With the optional AI feature, a misleading endpoint could receive evidence and
credentials over insecure HTTP. See `src/ai.rs:66`.

### 3. Resource limits are incomplete (high priority)

- A target with 600 direct callers returned 600 results despite the configured
  500 limit. It was marked partial, but the limit was exceeded. Check limits
  during neighbor expansion, not just before it (`src/analysis.rs:168`).
- The source endpoint returned 4,194,325 response bytes for a 4 MiB synthetic
  file. The scan's 2 MiB limit does not apply to source reads; the file is fully
  read before excerpting (`src/analysis.rs:236`). Enforce byte and line limits.
- All four concurrent scan requests were accepted. Static review shows each
  starts a thread, with no admission limit, and completed jobs are retained
  indefinitely (`src/web.rs:192`). Add a bounded queue, per-project exclusion,
  and completed-job expiry. No unbounded stress test was attempted.
- Model responses are read in full without a response-byte ceiling. A timeout
  exists, but is not a memory limit (`src/ai.rs:134`); static finding only.

### 4. Token and HTML bootstrap hardening (medium priority)

The token is generated from time and a counter, not a cryptographic random
source (`src/web.rs:82`). No brute-force attempt was made. Use OS randomness.

A supplied launch argument containing a script-closing tag was inserted into
the bootstrap HTML unescaped. This needs control of the launch argument and
was confirmed at the HTTP response level, not executed in a browser. JSON
escaping alone does not make a value safe inside an HTML script element.
Escape HTML-sensitive characters or use a safe bootstrap data endpoint.
No CSP, frame restriction, or MIME-sniffing protection headers were present.

### 5. Release gate and integrity checks (medium priority)

The tag release workflow builds and publishes without running the test suite
or enforcing the binary budget. It does not require the separate CI job's
success. Builds omit `--locked`; release actions are referenced by moving
version tags. No checksums or binary signing are supplied. Run validation on
the exact release revision, enforce size limits, lock dependencies, and add
integrity verification. Linux ZIP executable permissions and supported Linux
runtime compatibility still need installation tests.

## Not verified

- Real Linux execution/installation, real 4 GB hardware, and browser-tab memory.
- Large real repositories across all supported languages; worst-case parser
  depth, malformed input, file-count exhaustion, filesystem races, and fuzzing.
- Long-running soak tests, sustained concurrent queries, private/committed
  memory, battery impact, and peak CPU utilization.
- Live AI-provider behavior, redirect/TLS cases, response-size attacks, and
  remote credential handling; endpoint configuration was tested without calls.
- Published release integrity, signing, distribution and installation flow.

Conclusion: the default binary is small and measured memory on the synthetic
workloads is modest. Security failures remain; do not describe this audit as
a deployment pass. The report and harnesses are retained for fixing and
retesting the issues.
