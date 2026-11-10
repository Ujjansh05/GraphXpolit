# GraphXploit

[![Release](https://img.shields.io/github/v/release/Ujjansh05/GraphXpolit)](https://github.com/Ujjansh05/GraphXpolit/releases/latest) [![CI](https://github.com/Ujjansh05/GraphXpolit/actions/workflows/ci.yml/badge.svg)](https://github.com/Ujjansh05/GraphXpolit/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

GraphXploit is a lightweight, local code-intelligence workbench. It indexes a repository without executing it, visualizes static relationships, maps Git changes to affected symbols, and prepares compact evidence for codebase questions.

No TigerGraph, Docker, Python, Node.js, bundled browser, GPU, or model download is required.

## Choose an edition

| Edition | Release asset | Includes |
|---|---|---|
| Lite | `graphxploit-<platform>-x86_64.zip` | Scanner, CLI, interactive graph, source inspector, Git impact, and local context export |
| AI | `graphxploit-<platform>-x86_64-ai.zip` | Everything in Lite plus opt-in requests to an Ollama or OpenAI-compatible endpoint you configure |

Lite never contains model-networking code. The AI edition connects only to an endpoint the user configures. The agent starts in read-only plan mode. Every remote agent request displays its prompt for approval, including follow-up requests containing tool output. Local model requests use your configured loopback endpoint. Edits and commands require separate local approval.

## Download and quick start

Download the current published release and its matching `.sha256` file. The source changes described below target **2.3.0**; the latest-download links remain on the previous version until its release workflow completes:

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

- **Lightweight and local:** a small native executable, with no Docker, graph server, GPU, bundled browser, or background service.
- **Understand unfamiliar code:** search symbols, inspect source, trace dependencies, and see the possible impact of a change before editing.
- **Visualize relationships:** explore an interactive dependency and impact graph with search, pan, zoom, and source inspection.
- **Review Git changes:** compare temporary before/after indexes, retaining evidence for deleted and renamed symbols.
- **Use fewer LLM tokens:** retrieve relevant local evidence first, then send a byte-bounded context with an estimated 1,000–8,000-token budget to an existing Ollama or OpenAI-compatible endpoint.
- **Keep control of changes:** every AI-proposed edit, file creation, or command requires local approval; plan mode is the default and undo refuses to overwrite external changes.
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

## Explore and export

```powershell
gx -C C:\code\project ix
gx -C C:\code\project map
gx -C C:\code\project f authenticate --json
gx -C C:\code\project ctx "explain authentication" --target authenticate --format markdown
gx -C C:\code\project ui
```

The dashboard shows indexed files, languages and diagnostics. Pick a file to see its declarations; select a node to inspect source or explore one more step. Relationship filters separate calls, imports and containment, and edge tooltips show source evidence.

Both indexing and agent search honor nested `.gitignore` and `.graphxploitignore` patterns. Secret-like paths, links, dependency directories and generated bundles are excluded. Source files larger than 2 MiB are skipped with a diagnostic. Run `gx ix --verify` when content may have changed without a timestamp/size change.

## Measured footprint

Windows measurements and their test conditions are recorded in [AUDIT.md](AUDIT.md). The 2.3 workbench remains a native executable with a per-project SQLite index; it does not install a model or browser.

The local Windows 2.3 candidate ZIP is **2.31 MiB for Lite** or **3.07 MiB for AI**. Extracted executables are 8.78 MiB and 10.23 MiB respectively, plus project indexes. These are candidate measurements, not the previous published release's sizes.

Use `gx cache stats` to inspect actual index sizes. Preview cleanup with `gx cache prune --project ID --dry-run`, then add `--yes` to remove that generated index. Source files and saved sessions are preserved.

RAM depends on code density, active operations, and the operating system. Browser and model RAM are additional. Git comparison temporarily allows up to 64 MiB of source per revision plus its index and removes those files after the report. CI enforces executable ceilings of 25 MiB (Lite) and 35 MiB (AI).

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [CLI reference](docs/CLI.md)
- [Interactive code agent](docs/AGENT.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Privacy and security](docs/SECURITY.md)
- [Releasing](docs/RELEASING.md)
- [Runtime and security audit](AUDIT.md)
- [Implementation status and release checks](docs/IMPLEMENTATION.md)

## Build from source

Rust 1.90 or newer is needed only to build.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo build --release --locked                 # Lite
cargo build --release --locked --features ai   # AI
```

If GraphXploit is useful to you, consider starring the repository.
