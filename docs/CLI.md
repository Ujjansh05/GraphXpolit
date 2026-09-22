# CLI reference

Use `graphxploit --help` or `graphxploit <command> --help` for flags supported by the installed version.

## Index and inspect

### `doctor`

Prints version, storage directory, edition, parser support, and Git availability.

### `scan <path> [--verify]`

Atomically builds or updates the per-project index. Unchanged files skip parsing; `--verify` hashes them again. Cancellation or failure rolls back the generation instead of exposing a partial index.

Individual files are limited to 2 MiB and discovery to 100,000 supported files. Common dependency/build directories and hidden directories are skipped.

### `search <path> <query> [--limit 25] [--json]`

Runs a ranked, bounded symbol/file search without loading the full graph into memory.

### `impact <path> <target>`

Shows callers and importers that may be affected by a target.

### `dependencies <path> <target>`

Shows direct and transitive indexed relationships used by a target.

Both graph queries accept `--depth` and `--json`. Depth is capped at 25, traversal at 10,000 visited nodes, and results at 500. Ambiguous names return candidates instead of guessed edges.

Qualified targets look like:

```text
auth.py::authenticate
src/api/users.ts::createUser
main.go::HandleRequest
```

## Git change impact

### `diff <path> --working [--json]`

Maps tracked staged and unstaged changes against `HEAD` to indexed symbols and potential dependants.

### `diff <path> --base <revision> [--json]`

Compares `HEAD` with its merge base against a validated branch or commit. If neither flag is provided, working mode is used. Untracked files are not included until Git tracks them.

Git subprocesses do not use a shell or external diff program and are bounded to 15 seconds and 8 MiB of output.

## Compact context and AI

### `context <path> <question>`

Builds deterministic local evidence and never calls a model.

Options:

- `--target <symbol>`
- `--include-source`
- `--budget <tokens>` (clamped to 1,000–8,000)
- `--json`

### `ask <path> <question>`

Displays the exact context preview, then requires approval before calling the configured model. `--approve` is intended for already-reviewed automation and approves every displayed item. This command requires the AI edition.

### `model configure <provider> <endpoint> <model>`

Configures an existing `ollama` or `openai` compatible endpoint. Use `--api-key-env NAME` to store only a secret environment-variable name. Remote endpoints require HTTPS; HTTP is accepted only for exact loopback addresses.

### `model status`

Prints non-secret configuration.

### `explain <path> <target>`

Legacy bounded graph-evidence explanation command. Prefer `ask` when source-backed, explicitly approved context is needed.

## Dashboard

### `serve [path] [--port 0]`

Starts the embedded dashboard on `127.0.0.1`. Port `0` asks the OS for an available port. Press Ctrl+C to stop it. Do not expose, proxy, or port-forward this local single-user service.
