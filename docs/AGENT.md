# Interactive code agent

GraphXploit 2.2 adds a terminal workflow designed for low-resource machines. It uses the existing local SQLite index for retrieval and connects only to a model endpoint you configure.

## Start

From a project directory:

```powershell
gx
```

Or point it at another project:

```powershell
gx -C C:\code\my-project
gx -C C:\code\my-project "explain the authentication flow"
gx -C C:\code\my-project run --json "find risky changes"
```

The startup scan is incremental. Use `--no-scan` only when you intentionally want the existing index.

## Interactive commands

| Command | Purpose |
|---|---|
| `/find QUERY` | Search indexed symbols |
| `/impact TARGET` | Find possible dependants |
| `/deps TARGET` | Find dependencies |
| `/changes [BASE]` | Analyze working or branch changes |
| `/scan` | Refresh the index |
| `/mode agent|plan` | Allow approval-gated actions or force read-only planning |
| `/undo` | Undo the most recent edit/create in this process |
| `/save [NAME]` | Explicitly save the compact conversation |
| `/resume ID` | Resume a saved conversation for the same project |
| `/clear` | Clear ephemeral conversation history |
| `/model` | Show the configured model |
| `/status` | Show workspace, index, mode, and budget |
| `/ui` | Show the dashboard command |
| `/quit` | Exit |

Sessions are ephemeral unless you use `/save`. Saved sessions contain user/assistant text, not raw source excerpts or tool output, and are limited to 2 MiB.

## Safety model

Read-only inspection can run automatically. Every file edit, file creation, or process launch shows the exact diff or command and defaults to **No**. Plan mode refuses mutations completely.

Edits are confined to canonical workspace paths, reject symlinks, binary/non-UTF-8 files, files above 2 MiB, replacements above 256 KiB, and stale SHA-256 hashes. The first version intentionally has no delete or move tool.

Commands have no stdin, no background mode, a policy-bounded timeout (60 seconds by default, 300 maximum), and 1 MiB output limits. Direct shells and inline interpreter evaluation are rejected. The configured model API-key environment variable is removed from child processes.

Repository text and command output are treated as untrusted data, not model instructions.

## Shared team policy

Commit a non-secret `.graphxploit.json` in the repository:

```json
{
  "default_budget": 4000,
  "auto_scan": true,
  "command_timeout_seconds": 60,
  "allowed_programs": ["cargo", "npm", "git"]
}
```

An empty `allowed_programs` list does not add a team allow-list; interactive approval still applies. Policy values can only reduce built-in limits. Never place tokens or API keys in this file.

## Model setup

Use an existing Ollama or OpenAI-compatible endpoint:

```powershell
gx model configure ollama http://127.0.0.1:11434 qwen2.5-coder:7b
gx model configure openai https://provider.example/v1 MODEL --api-key-env MODEL_API_KEY
```

The Lite edition keeps all local slash commands but rejects natural-language agent requests with a clear message. No model is downloaded by GraphXploit.


## Install the `gx` launcher

On Windows, keep `gx.cmd` beside `graphxploit.exe`. Run `.\gx.cmd` from that folder, or add the extracted folder to your user `PATH` and reopen PowerShell to use `gx` anywhere. GraphXploit does not modify `PATH` automatically.

On Linux, keep `gx` beside `graphxploit`, run `chmod +x gx graphxploit`, and optionally place both files in a directory already on `PATH`.

## Model data boundary

Configuring and using the AI edition is opt-in. A natural-language agent turn sends its bounded context and subsequent bounded read-tool results to the configured endpoint. An approved command's bounded output may also be returned to that endpoint. File writes and process launches still require separate local confirmation. Use Lite or local slash commands when no repository data may leave the computer; use the legacy `ask` command when you want a full evidence preview before the first model request.
