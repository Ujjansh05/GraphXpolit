# GraphXploit 2.0

GraphXploit is a local, lightweight code-impact analyzer. It indexes a source tree on the user's machine, then shows callers, dependencies, and a read-only source excerpt. It never executes the analyzed project.

The active implementation is a single Rust executable with embedded SQLite. It replaces the previous TigerGraph/Docker prototype as the supported deployment path.

## What users need

Download the executable for their operating system from a GitHub Release, put it on `PATH`, and run it. There is no installer, account, Docker daemon, database service, browser extension, GPU, model download, Node.js, Python, or network connection required.

```powershell
# Windows
graphxploit.exe scan C:\path\to\project
graphxploit.exe impact C:\path\to\project "src/auth.py::login"
graphxploit.exe serve
```

```bash
# Linux
./graphxploit scan /path/to/project
./graphxploit dependencies /path/to/project 'src/auth.py::login'
./graphxploit serve
```

`serve` binds only to `127.0.0.1` and prints the address for a small read-only dashboard to open in a normal browser. It does not expose a network service to other devices.

## Resource profile

- One portable executable: the verified default Windows release build is about **6.2 MB**, with a CI limit of 25 MiB per binary.
- One embedded SQLite database per indexed project, stored in the user's local application-data directory. No server or container is installed.
- Incremental rescans skip unchanged files. Files over 2 MiB and common build, dependency, virtual-environment, and VCS folders are skipped by default.
- The analyzer reads source text and stores metadata only. It does not run the project, install dependencies, invoke compilers, or download models.

This design is intended for ordinary 4 GB laptops and is materially lighter than a browser-plus-server-plus-graph-database stack.

## Supported languages and analysis

Python, JavaScript, TypeScript, Go, Rust, and Java are parsed locally with Tree-sitter. GraphXploit indexes files, declarations, direct calls, and imports, then follows the stored graph for impact or dependency queries.

Static local targets are resolved when unambiguous. Dynamic dispatch, reflection, generated code, macros, and ambiguous calls are retained as unresolved rather than guessed. Treat results as review evidence, not a claim of complete semantic analysis.

## Optional existing AI model

AI is deliberately excluded from the default download. If a user already runs an Ollama or OpenAI-compatible endpoint, a maintainer can build the separate optional feature:

```powershell
cargo build --release --features ai
graphxploit.exe model configure ollama http://127.0.0.1:11434 qwen2.5-coder:7b
graphxploit.exe explain C:\path\to\project "src/auth.py::login"
```

Model configuration stores only the endpoint, model identifier, and an optional environment-variable name for an API key. It never saves key values. The AI request contains a compact impact summary only; source contents are not sent. `send_source` is disabled by design.

## Build from source

Rust stable (1.85+) is required only for contributors building from source.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

The executable is created at `target/release/graphxploit` (`.exe` on Windows). GitHub Actions validates Windows and Linux builds, tests, formatting, linting, and the binary-size budget, then attaches platform executables to the workflow run.

## Data and privacy

Set `GRAPHXPLOIT_DATA_DIR` to choose where project indexes are stored. Without it, GraphXploit uses the operating system's normal local application-data location. Delete that `GraphXploit/projects` directory to remove all indexes; it contains generated metadata and will be rebuilt on the next scan.

## Legacy prototype

The Python/FastAPI/TigerGraph/Docker code remains in this repository only as historical reference. It is not the deployment target for GraphXploit 2.0 and its old installation commands should not be used.