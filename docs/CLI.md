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
gx f QUERY [--json]        symbol search
gx i TARGET [--json]       reverse impact
gx d TARGET [--json]       dependencies
gx ch [BASE]               Git change impact
gx q "question"            one agent request
gx map                     indexed files/languages/diagnostics (JSON)
gx ctx QUESTION            local evidence export (Markdown)
gx ctx QUESTION --format json --target SYMBOL
gx cache stats             generated index sizes (JSON)
gx cache prune --project ID --dry-run
gx cache prune --project ID --yes
gx check                   lightweight diagnostics
```

Global options:

- `-C, --cwd PATH`: workspace for interactive and short commands.
- `--no-scan`: do not run the incremental startup scan.
- `--budget N`: requested context budget, clamped to 1,000–8,000 estimated tokens and the project policy; whole-prompt byte limits also apply.

`run --json` emits one JSON object per line for status, tool requests/results, approvals, answers, and errors. Mutation and remote-model approval are denied when stdin is not an interactive terminal. Approval prompts go to stderr; operational failures return a nonzero exit code.

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

## Freshness and Git comparisons

Run `gx ix` before local query/export commands. Unchanged scans retain the existing generation. `--verify` checks content when timestamps and sizes cannot be trusted.

`gx ch` compares tracked worktree content against HEAD. `gx ch BASE` compares the merge base with HEAD, independently of uncommitted edits. Run these from the Git repository root. Results label each symbol `basis: before` or `basis: after`; all symbols in changed files are included conservatively. Temporary snapshots are bounded to 10,000 supported files and 64 MiB per revision. Untracked files, submodules, links, ignored files and unsupported constructs are excluded.

Cache cleanup defaults to a preview. Close other GraphXploit processes before confirming. A cooperating process holding the index prevents removal. Empty lock files may remain so future readers and cleanup share a stable lock identity.
