# Interactive code agent

GraphXploit 2.3 provides a terminal workflow designed for low-resource machines. It uses the existing local SQLite index for retrieval and connects only to a model endpoint you configure.

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

Sessions start in **plan** mode. Switch explicitly with `/mode agent` when you want approval-gated mutations. Local inspection can run automatically; remote model calls require approval each time. Every file edit, file creation, or process launch shows the exact diff or command and defaults to **No**. Plan mode refuses mutations completely.

Edits are confined to canonical workspace paths, reject symlinks, binary/non-UTF-8 files, files above 2 MiB, replacements above 256 KiB, and stale SHA-256 hashes. The path/hash is checked again after approval; replacements use a temporary file in the same directory. Undo verifies the post-edit hash and preserves conflicting external edits. The first version intentionally has no delete or move tool.

Commands have no stdin, no background mode, a process-group deadline (60 seconds by default, 300 maximum), and 1 MiB output limits per stream. Unix process groups and Windows Job Objects cover ordinary descendants and output drains. Direct shells and inline interpreter evaluation are rejected. Executables resolve from absolute PATH directories outside the workspace. The configured model API-key variable is removed from child processes. Approved commands run with your OS permissions: builds and test runners can execute repository code, access the network, or read other files. This is not an OS sandbox.

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

Configuring AI is opt-in. For a remote endpoint, every planner or answer request displays the exact outgoing prompt and asks for approval. Tool results can contain source or command output and are previewed on subsequent requests. Non-interactive remote agent requests fail closed; use local context export for automation.

A configured loopback model can receive bounded context automatically. The dashboard and `ask` still require evidence approval. The `ask --approve` flag is explicit authorization for its displayed evidence.

Whole prompts include instructions, question, retrieved evidence, history and tool results. Older history/results and lower-ranked excerpts are compacted first. Budgets use estimates, not a provider tokenizer; byte limits are enforced and provider usage is reported when available. A serialized model request cannot exceed 32 KiB.

Saved sessions may contain sensitive text in user questions or model answers. They are not encrypted. Data directories use mode 0700 on Unix; Windows uses the user profile's inherited permissions.
