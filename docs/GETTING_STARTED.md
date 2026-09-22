# Getting started

GraphXploit is a single executable. It reads supported source files, writes a generated SQLite index to the normal application-data directory, and never executes the analyzed project.

## Install on Windows

1. Download `graphxploit-windows-x86_64.zip` (Lite) or `graphxploit-windows-x86_64-ai.zip` (AI) and its matching `.sha256` from Releases.
2. Verify the archive:

   ```powershell
   (Get-FileHash .\graphxploit-windows-x86_64.zip -Algorithm SHA256).Hash.ToLower()
   Get-Content .\graphxploit-windows-x86_64.zip.sha256
   ```

3. Extract the ZIP and open PowerShell in that folder.
4. Run `.\graphxploit.exe doctor`.

Windows SmartScreen may show an unrecognized-publisher warning until releases are code-signed. Confirm that the checksum matches this repository's release asset before allowing an unsigned build.

## Install on Linux

```bash
sha256sum -c graphxploit-linux-x86_64.zip.sha256
unzip graphxploit-linux-x86_64.zip
chmod +x graphxploit
./graphxploit doctor
```

## Use the dashboard

```powershell
.\graphxploit.exe serve "C:\Users\you\source\my-project"
```

Open the printed local address. Then:

1. Select **Scan project**.
2. In **Explore**, search for a symbol, select the qualified match, choose Dependencies or Impact, and select **Visualize**.
3. Select a node to view a bounded, read-only source excerpt.
4. In **Changes**, analyze working changes or compare `HEAD` with a base branch.
5. In **Code chat**, enter a question, optionally provide a target, and build a compact local preview.

Lite can copy the preview for use anywhere. In AI edition, configure a model first, review the excerpts, check only approved evidence, tick the approval box, and send it. A preview expires after 10 minutes and cannot be substituted after approval.

## Configure the AI edition

For an existing Ollama server:

```powershell
.\graphxploit.exe model configure ollama http://127.0.0.1:11434 qwen2.5-coder:7b
.\graphxploit.exe model status
.\graphxploit.exe ask C:\project "What may break if authenticate changes?" --target authenticate
```

For a remote OpenAI-compatible HTTPS endpoint:

```powershell
$env:MY_MODEL_KEY = "set-it-for-this-shell"
.\graphxploit.exe model configure openai https://models.example.com/v1 my-model --api-key-env MY_MODEL_KEY
```

Only the environment-variable name is saved. The key value stays in the process environment.

## CLI-only use

```powershell
.\graphxploit.exe scan C:\project
.\graphxploit.exe search C:\project login
.\graphxploit.exe dependencies C:\project "src/auth.py::login"
.\graphxploit.exe impact C:\project "src/auth.py::authenticate"
.\graphxploit.exe diff C:\project --working
.\graphxploit.exe diff C:\project --base main
.\graphxploit.exe context C:\project "How does login work?" --target login --include-source --budget 2000
```

Add `--json` to search, query, context, and diff commands when integrating with developer tools.

## Storage

Indexes live outside repositories under the operating system's application-data directory. Set `GRAPHXPLOIT_DATA_DIR` to choose a different parent directory:

```powershell
$env:GRAPHXPLOIT_DATA_DIR = "D:\GraphXploitData"
.\graphxploit.exe scan "D:\source\my-project"
```

The index contains generated paths, symbols, static relationships, and diagnostics—not a second source-code copy. Removing an index is safe; the next scan rebuilds it. Add dependency, generated, or vendor paths to `.graphxploitignore` to reduce scan time and storage.
