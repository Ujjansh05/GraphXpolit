# CLI reference

Run `graphxploit --help` or `graphxploit <command> --help` for the exact flags provided by the installed version.

## `doctor`

Shows the version, data directory, supported parsers, and optional-model status.

```text
graphxploit doctor
```

## `scan <path>`

Builds or updates the local project index. It parses only supported source files, skips common dependency/build folders, and skips unchanged files unless verification is requested.

```text
graphxploit scan <path>
graphxploit scan <path> --verify
```

Files larger than 2 MiB are recorded as skipped. Discovery stops at the 100,000 supported-file safety ceiling; use `.graphxploitignore` for generated or vendored trees. Source is never executed.

## `impact <path> <target>`

Shows indexed callers and importers that may be affected by a target change.

```text
graphxploit impact <path> <target>
graphxploit impact <path> <target> --depth 3
graphxploit impact <path> <target> --json
```

## `dependencies <path> <target>`

Shows indexed static calls/imports used by a target.

```text
graphxploit dependencies <path> <target>
```

Query depth is capped at 25, traversal at 10,000 visited nodes, and output at 500 nodes. Partial output is marked incomplete.

Use a fully qualified target when names are ambiguous. Paths are relative to the scanned project and use forward slashes:

```text
auth.py::authenticate
src/api/users.ts::createUser
main.go::HandleRequest
```

## `serve [path]`

Starts the local read-only dashboard. It binds to `127.0.0.1`, allows one scan worker, and protects APIs with a fresh process token. Press `Ctrl+C` in the terminal to stop it. Do not expose this port through a reverse proxy or port-forward.

```text
graphxploit serve
graphxploit serve <path>
graphxploit serve <path> --port 49152
```

## Optional model commands

These commands configure an existing Ollama or OpenAI-compatible model. They require an executable built with `--features ai`; the ordinary release does not include AI networking.

```text
graphxploit model configure ollama http://127.0.0.1:11434 qwen2.5-coder:7b
graphxploit model status
graphxploit explain <path> <target>
```

Use `--api-key-env NAME` to refer to an environment variable containing a key. GraphXploit stores only the variable name, never its value. Remote endpoints require HTTPS; unencrypted HTTP is accepted only for exact loopback addresses.
