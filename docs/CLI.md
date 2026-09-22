# CLI reference

The release contains `graphxploit` and a small `gx` launcher. Both invoke the same binary. Existing long commands remain compatible.

## Fast workflow

```text
gx                         interactive session in the current directory
gx "explain this project"  one request, then exit
gx -C PATH "question"      choose a workspace
gx run --json "question"   newline-delimited agent events
gx ui                      local dashboard
gx ix                      incremental scan
gx f QUERY                 symbol search
gx i TARGET                reverse impact
gx d TARGET                dependencies
gx ch [BASE]               Git change impact
gx q "question"            one agent request
gx check                   lightweight diagnostics
```

Global options:

- `-C, --cwd PATH`: workspace for interactive and short commands.
- `--no-scan`: do not run the incremental startup scan.
- `--budget N`: requested context budget, clamped to 1,000-8,000 tokens and the project policy.

`run --json` emits one JSON object per line for status, tool requests/results, approvals, answers, and errors. Mutation approval is denied automatically when stdin is not an interactive terminal.

## Compatible analysis commands

```text
graphxploit scan PATH [--verify]
graphxploit search PATH QUERY [--limit N] [--json]
graphxploit impact PATH TARGET [--depth N] [--json]
graphxploit dependencies PATH TARGET [--depth N] [--json]
graphxploit diff PATH [--working | --base REV] [--json]
graphxploit context PATH QUESTION [--target TARGET] [--include-source] [--budget N] [--json]
graphxploit ask PATH QUESTION [--target TARGET] [--budget N] [--approve]
graphxploit explain PATH TARGET [--depth N] [--question TEXT]
graphxploit serve [PATH] [--port N]
graphxploit doctor
```

Use the qualified name printed by search when a short symbol is ambiguous.

## Model configuration

```text
graphxploit model configure ollama ENDPOINT MODEL
graphxploit model configure openai ENDPOINT MODEL --api-key-env ENV_NAME
graphxploit model status
```

Only the environment-variable name is stored. Plain HTTP is accepted only for a parsed loopback host; remote endpoints require HTTPS. Redirects are disabled.

See [Interactive code agent](AGENT.md) for approvals, undo, sessions, policy, and resource limits.
