# GraphXploit

[![Release](https://img.shields.io/github/v/release/Ujjansh05/GraphXpolit)](https://github.com/Ujjansh05/GraphXpolit/releases/latest) [![CI](https://github.com/Ujjansh05/GraphXpolit/actions/workflows/ci.yml/badge.svg)](https://github.com/Ujjansh05/GraphXpolit/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

GraphXploit is a lightweight, local code-intelligence workbench. It indexes a repository without executing it, visualizes static relationships, maps Git changes to affected symbols, and prepares compact evidence for codebase questions.

No TigerGraph, Docker, Python, Node.js, bundled browser, GPU, or model download is required.

## Choose an edition

| Edition | Release asset | Includes |
|---|---|---|
| Lite | `graphxploit-<platform>-x86_64.zip` | Scanner, CLI, interactive graph, source inspector, Git impact, and local context export |
| AI | `graphxploit-<platform>-x86_64-ai.zip` | Everything in Lite plus opt-in requests to an Ollama or OpenAI-compatible endpoint you configure |

Lite never contains model-networking code. The AI edition connects only to an endpoint the user configures. The preview-based ask command requires explicit evidence approval; the interactive agent sends bounded read context while requiring a separate local confirmation for every write or process launch.

## Download and quick start

Download the current release and its matching `.sha256` file:

| Platform | Lite — fully local analysis | AI — adds your existing model endpoint |
|---|---|---|
| Windows x86-64 | [ZIP](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-windows-x86_64.zip) · [SHA-256](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-windows-x86_64.zip.sha256) | [ZIP](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-windows-x86_64-ai.zip) · [SHA-256](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-windows-x86_64-ai.zip.sha256) |
| Linux x86-64 | [ZIP](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-linux-x86_64.zip) · [SHA-256](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-linux-x86_64.zip.sha256) | [ZIP](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-linux-x86_64-ai.zip) · [SHA-256](https://github.com/Ujjansh05/GraphXpolit/releases/latest/download/graphxploit-linux-x86_64-ai.zip.sha256) |

Extract the archive, open a terminal in that folder, and select a project.

```powershell
# Windows
.\gx.cmd -C "C:\path\to\project" ix
.\gx.cmd -C "C:\path\to\project" ui
.\gx.cmd -C "C:\path\to\project"
```

```bash
# Linux
chmod +x graphxploit gx
./gx -C /path/to/project ix
./gx -C /path/to/project ui
./gx -C /path/to/project
```

The `ui` command prints a private `http://127.0.0.1:<port>` dashboard address for your existing browser. The application does not bundle a browser engine.

The Lite edition supports scanning, search, graphs, Git impact, local context and dashboard commands. Natural-language questions require the AI edition and an Ollama or OpenAI-compatible endpoint that you configure.

```powershell
.\gx.cmd model configure ollama http://127.0.0.1:11434 qwen2.5-coder:7b
.\gx.cmd -C "C:\path\to\project" "explain the authentication flow"
```

Existing long-form `graphxploit` commands remain supported. See the [CLI reference](docs/CLI.md) and [agent guide](docs/AGENT.md).

## Why developers use GraphXploit

- **Lightweight and local:** a 7.61 MiB Lite binary or 9.06 MiB AI binary, with no Docker, graph server, GPU, bundled browser, or background service.
- **Understand unfamiliar code:** search symbols, inspect source, trace dependencies, and see the possible impact of a change before editing.
- **Visualize relationships:** explore an interactive dependency and impact graph with search, pan, zoom, and source inspection.
- **Review Git changes:** map working-tree or branch changes to affected symbols and potential dependants.
- **Use fewer LLM tokens:** retrieve relevant local evidence first, then send only a bounded 1,000-8,000-token context to an existing Ollama or OpenAI-compatible endpoint.
- **Keep control of changes:** every AI-proposed edit, file creation, or command requires local approval; plan mode is read-only and recent edits can be undone.
- **Fast repeated analysis:** the SQLite index is incremental, so unchanged files are not parsed again.
- **Useful across common stacks:** supports Python, JavaScript, TypeScript/TSX, Go, Rust, and Java.

Typical uses include onboarding to a repository, planning refactors, reviewing pull requests, investigating regressions, exploring legacy systems, and checking change impact before modifying an API.

```powershell
gx -C C:\path\to\project
gx -C C:\path\to\project "explain the authentication flow"
gx -C C:\path\to\project i authenticate
gx -C C:\path\to\project ch
gx -C C:\path\to\project ui
```

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

If GraphXploit is useful to you, please consider giving the repository a ⭐ — it helps other developers discover the project.
