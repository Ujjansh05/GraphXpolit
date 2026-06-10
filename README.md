# GraphXploit


<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/927ab6da-0a3a-4f7e-9ce5-48c6ddb99d89"
    alt="GraphXploit Logo"
    width="400"
  />
</p>



GraphXploit is an impact analysis platform for large Python codebases. It parses code into Abstract Syntax Trees (AST), structures the dependencies within a TigerGraph database, and leverages Large Language Models to evaluate the downstream impact of structural changes.

## Architecture

```text
CLIENT                     BACKEND                     GRAPH & LLM
                         
┌─────────────┐          ┌─────────────┐             ┌─────────────┐
│ CLI / React │ ───────▶ │ FastAPI     │ ──────────▶ │ TigerGraph  │
└─────────────┘          └─────────────┘             └─────────────┘
                               │
                               │                     ┌─────────────┐
                               └───────────────────▶ │ LLM Backend │
                                                     └─────────────┘
```

The system operates in three phases:
1. **Parsing:** Source files are parsed into functions, classes, calls, and imports.
2. **Graph Traversal:** TigerGraph determines complex downstream call-graphs.
3. **Synthesis:** An LLM generates a human-readable impact report based on the isolated subgraph.

## Installation

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/Ujjansh05/GraphXpolit/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/Ujjansh05/GraphXpolit/main/install.ps1 | iex
```

**Or install directly via pip:**
```bash
pip install graphxploit-analyzer
```

## Quick Start

Initialize the datastores (requires Docker):
```bash
graphxploit start
```

Analyze a local project:
```bash
graphxploit analyze ./path/to/project
```

Query the impact graph:
```bash
graphxploit query "What breaks if I change the login function?"
```

## UI Dashboard

To launch the web interface and API server:
```bash
graphxploit visualize
```
*In development scenarios, run `npm run dev` in the `frontend/` directory to access the interface at `localhost:5173`.*

## Model configuration

GraphXploit utilizes a "Bring Your Own Model" (BYOM) architecture. By default, it runs a local Ollama instance. You can mount external providers such as OpenAI or HuggingFace endpoints.

All configurations are securely encrypted locally at `~/.graphxploit/models.json`.

```bash
# Enter the interactive model setup
graphxploit model mount

# View available models
graphxploit model list

# Switch active model context
graphxploit model switch <model_id>
```

## Available commands

| Command | Description |
|---------|-------------|
| `graphxploit analyze <path>` | Full pipeline: parse, graph, load, query |
| `graphxploit model <cmd>` | Manage LLM integrations |
| `graphxploit query <query>` | Natural language impact query |
| `graphxploit start` | Start infrastructure containers |
| `graphxploit status` | Health-check services |
| `graphxploit stop` | Stop and tear down containers |
| `graphxploit visualize`| Spin up the UI server |

## Development

```bash
# Clone the repository
git clone https://github.com/Ujjansh05/GraphXpolit.git
cd GraphXpolit

# Install in editable mode
pip install -e ".[dev]"

# Run backend API
uvicorn backend.main:app --reload --port 8000

# Run frontend UI
cd frontend && npm install && npm run dev
```

## License
MIT
