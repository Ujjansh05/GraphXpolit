# Privacy and security

## Local operation

The default GraphXploit executable reads supported source files and stores metadata in a local SQLite index. It does not execute the analyzed project or contact a network service. The dashboard binds only to `127.0.0.1`.

## Optional model feature

Model networking is excluded from the default build. An AI-enabled build can connect to an existing Ollama or OpenAI-compatible endpoint. Its configuration stores endpoint and model details plus an optional environment-variable name; it does not store the API-key value. Source text is not included in model requests.

## Current release status

The latest audit identified security and resource-limit fixes required before a public production release. Read [AUDIT.md](../AUDIT.md) before deploying or distributing GraphXploit outside a controlled test environment.

## Reporting a vulnerability

Do not post credentials or exploit details in a public issue. Use GitHub's private security advisory feature when it is enabled for this repository, or contact the repository owner through a private channel.
