# GraphXploit

GraphXploit is a lightweight, local code-intelligence workbench. It indexes a repository without executing it, visualizes static relationships, maps Git changes to affected symbols, and prepares compact evidence for codebase questions.

No TigerGraph, Docker, Python, Node.js, bundled browser, GPU, or model download is required.

## Choose an edition

| Edition | Release asset | Includes |
|---|---|---|
| Lite | `graphxploit-<platform>-x86_64.zip` | Scanner, CLI, interactive graph, source inspector, Git impact, and local context export |
| AI | `graphxploit-<platform>-x86_64-ai.zip` | Everything in Lite plus opt-in requests to an Ollama or OpenAI-compatible endpoint you configure |

Lite never contains model-networking code. The AI edition connects only to an endpoint the user configures. The preview-based ask command requires explicit evidence approval; the interactive agent sends bounded read context while requiring a separate local confirmation for every write or process launch.

## Quick start

Download a ZIP and matching `.sha256` file from [Releases](https://github.com/Ujjansh05/GraphXpolit/releases), verify it, and extract the executable with its small gx launcher.

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

A local Windows 11 verification measured v2.2.0 binary sizes; the runtime/index figures are retained from the unchanged v2.1 indexing benchmark:

| Item | Measurement |
|---|---:|
| Lite executable (v2.2) | 7,981,568 bytes (7.61 MiB) |
| AI executable (v2.2) | 9,505,792 bytes (9.06 MiB) |
| 1,000-file initial scan | 15.80 s, 14.79 MiB peak working set |
| 1,000-file unchanged rescan | 0.17 s, 8.09 MiB peak working set |
| 1,000-file SQLite index | 1,019,904 bytes (1.0 MiB) |
| Idle local server | 5.94 MiB working set |

These are single-machine engineering measurements, not universal guarantees. Repository language, symbol density, filesystem, antivirus, and operating system affect results. CI rejects Lite binaries above 25 MiB and AI binaries above 35 MiB.

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [CLI reference](docs/CLI.md)
- [Interactive code agent](docs/AGENT.md)
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


## Interactive terminal agent (v2.2)

The AI edition can now be used like a compact coding CLI:

```powershell
gx -C C:\path\to\project
gx -C C:\path\to\project "explain the startup flow"
gx -C C:\path\to\project ui
```

It reuses the incremental local index, limits context to 1,000-8,000 tokens, supports read-only planning, and requires a separate confirmation for every edit, create, or process launch. Existing long `graphxploit` commands remain compatible. See [Interactive code agent](docs/AGENT.md) and [CLI reference](docs/CLI.md).
