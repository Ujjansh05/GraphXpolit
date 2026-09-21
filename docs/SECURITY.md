# Privacy and security

## Local operation

The default GraphXploit executable reads supported source files and stores generated metadata in a per-project SQLite index under the user's application-data directory. It does not execute analyzed source, download a model, or contact an external service. The dashboard listens only on `127.0.0.1`.

Treat anyone who can run programs as the same operating-system user as trusted: such a process can already read the source and local index directly. GraphXploit is not a multi-user server and must not be placed behind a public reverse proxy.

## Dashboard protections

The local dashboard uses a fresh 256-bit token from the operating system for each process. API requests require that token. Before any page or bootstrap data is returned, the server validates the `Host` header, rejects foreign `Origin` values and cross-site browser fetches, and permits only exact loopback hosts. Responses use a restrictive Content Security Policy, deny framing, disable MIME sniffing, omit referrers, and are not cached.

The server accepts at most 64 KiB per JSON request, permits one scan worker, stores at most 32 jobs, and expires finished jobs after 10 minutes. Source previews are canonicalized inside the chosen project and limited by file size, line count, and response bytes.

## Analyzer resource boundaries

GraphXploit skips individual source files larger than 2 MiB, reads them through a bounded stream, caps a project at 100,000 supported source files, and caps ignore files at 1 MiB. Queries are limited to depth 25, 10,000 visited nodes, and 500 returned nodes. A truncated result is explicitly marked incomplete.

These are safety ceilings, not performance promises. Use `.graphxploitignore` to exclude large generated or vendored trees.

## Optional model feature

Model networking is excluded from the default release. An AI-enabled custom build can connect to an existing Ollama or OpenAI-compatible endpoint. Plain HTTP is accepted only for an exact loopback hostname or address; remote endpoints require HTTPS. Redirects are disabled, connection and request timeouts are enforced, and responses are capped at 1 MiB.

Configuration stores only endpoint/model details and an optional environment-variable name. API-key values remain in the environment. Raw source sharing is rejected; only bounded graph evidence and the user's bounded question are sent.

## Verification scope

The production hardening checks and remaining validation limits are recorded in [AUDIT.md](../AUDIT.md). Security controls reduce known risks but do not constitute a formal certification or guarantee that every defect has been found.

## Reporting a vulnerability

Do not post credentials or exploit details in a public issue. Use GitHub's private security advisory feature when it is enabled for this repository, or contact the repository owner through a private channel.
