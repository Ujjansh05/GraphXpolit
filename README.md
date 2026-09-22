# GraphXploit

GraphXploit is a lightweight, local code-intelligence workbench. It indexes a repository without executing it, visualizes static relationships, maps Git changes to affected symbols, and prepares compact evidence for codebase questions.

No TigerGraph, Docker, Python, Node.js, bundled browser, GPU, or model download is required.

## Choose an edition

| Edition | Release asset | Includes |
|---|---|---|
| Lite | `graphxploit-<platform>-x86_64.zip` | Scanner, CLI, interactive graph, source inspector, Git impact, and local context export |
| AI | `graphxploit-<platform>-x86_64-ai.zip` | Everything in Lite plus opt-in requests to an Ollama or OpenAI-compatible endpoint you configure |

Lite never contains model-networking code. AI shows the exact source evidence and estimated token count before a request; nothing is sent until the user selects evidence and approves it.

## Quick start

Download a ZIP and matching `.sha256` file from [Releases](https://github.com/Ujjansh05/GraphXpolit/releases), verify it, and extract the single executable.

```powershell
# Windows
.\graphxploit.exe scan "C:\path\to\project"
.\graphxploit.exe serve "C:\path\to\project"
```

```bash
# Linux
./graphxploit scan /path/to/project
./graphxploit serve /path/to/project
```

Open the printed `http://127.0.0.1:<port>` address in your existing browser. The application itself does not embed Chrome or another browser engine.

Useful CLI workflows:

```powershell
.\graphxploit.exe search C:\project authenticate
.\graphxploit.exe impact C:\project "src/auth.py::authenticate"
.\graphxploit.exe diff C:\project --working
.\graphxploit.exe context C:\project "What uses authentication?" --target authenticate --include-source
```

## What developers can showcase

- Interactive SVG dependency/impact graph with pan, zoom, source inspection, search, and ambiguity handling.
- Working-tree and branch comparison that maps changed lines to symbols and potential dependants.
- Low-token code chat: local retrieval, adaptive 1,000–8,000 token budget, evidence IDs, explicit source approval, and citation checking.
- Incremental SQLite index with atomic scan generations; cancelled or failed scans leave the previous usable index intact.
- Seven parser modes covering Python, JavaScript, TypeScript/TSX, Go, Rust, and Java.
- Local-first security: loopback-only server, per-process 256-bit token, origin/host/fetch-metadata checks, restrictive CSP, bounded workers, requests, previews, queries, Git output, and model responses.

Static analysis intentionally does not guess ambiguous calls, dynamic dispatch, reflection, generated code, or runtime behavior. Results are review evidence, not a guarantee that every effect is found.

## Measured footprint

A local Windows 11 verification of v2.1.0 measured:

| Item | Measurement |
|---|---:|
| Lite executable | 7,925,248 bytes (7.56 MiB) |
| AI executable | 9,413,120 bytes (8.98 MiB) |
| 1,000-file initial scan | 15.80 s, 14.79 MiB peak working set |
| 1,000-file unchanged rescan | 0.17 s, 8.09 MiB peak working set |
| 1,000-file SQLite index | 1,019,904 bytes (1.0 MiB) |
| Idle local server | 5.94 MiB working set |

These are single-machine engineering measurements, not universal guarantees. Repository language, symbol density, filesystem, antivirus, and operating system affect results. CI rejects Lite binaries above 25 MiB and AI binaries above 35 MiB.

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [CLI reference](docs/CLI.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Privacy and security](docs/SECURITY.md)
- [Releasing](docs/RELEASING.md)
- [Runtime and security audit](AUDIT.md)

## Build from source

Rust stable 1.85 or newer is needed only to build.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --release --locked                 # Lite
cargo build --release --locked --features ai   # AI
```
