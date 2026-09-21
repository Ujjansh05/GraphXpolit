# GraphXploit

GraphXploit is a lightweight, local code-impact analyzer. It indexes source on the user's computer and shows callers, dependencies, and read-only source excerpts. It never executes the project being analyzed.

The default application is one Rust executable with embedded SQLite. It does not require Docker, TigerGraph, Python, Node.js, a GPU, a model download, or a network connection.

## Start here

Download the Windows or Linux ZIP from the repository's [Releases](https://github.com/Ujjansh05/GraphXpolit/releases) page, extract it, and run the executable.

```powershell
# Windows
.\graphxploit.exe scan C:\path\to\project
.\graphxploit.exe impact C:\path\to\project "src/auth.py::login"
.\graphxploit.exe serve C:\path\to\project
```

```bash
# Linux
./graphxploit scan /path/to/project
./graphxploit dependencies /path/to/project 'src/auth.py::login'
./graphxploit serve /path/to/project
```

`serve` prints a `127.0.0.1` address for the local dashboard. It never opens a public network service.

## Documentation

- [Getting started](docs/GETTING_STARTED.md)
- [CLI reference](docs/CLI.md)
- [Releasing GraphXploit](docs/RELEASING.md)
- [Privacy and security](docs/SECURITY.md)
- [Runtime and security audit](AUDIT.md)

## Features

- Parses Python, JavaScript, TypeScript, Go, Rust, and Java locally.
- Uses a per-project incremental SQLite index; unchanged files skip parsing.
- Provides CLI and loopback-only dashboard workflows.
- Limits the default executable to 25 MiB in CI; the verified Windows binary is about 6.2 MB.
- Offers an optional build feature for an Ollama or OpenAI-compatible model that the user already operates. Source text is not sent to that model.

GraphXploit resolves direct static calls and imports where they are unambiguous. Dynamic dispatch, reflection, generated code, macros, and ambiguous targets are not guessed, so results are review evidence rather than a guarantee of complete impact coverage.

## Build from source

Rust stable 1.85 or newer is required only when building from source.

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --locked
```

The executable is written to `target/release/graphxploit` (`.exe` on Windows).