# Privacy and security

## Trust and deployment model

GraphXploit is a local, single-user developer tool. The dashboard binds only to `127.0.0.1`; it is not an authenticated multi-user service and must not be exposed through a reverse proxy, tunnel, container port, or public bind address.

Anyone able to run software as the same operating-system user can already read that user's source and generated index. Use normal workstation access controls to protect them.

## Local indexing

Lite has no model-networking dependency. Both editions parse supported files without executing project code and store generated metadata in a per-project SQLite database outside the repository. Scans use an immediate outer transaction and a monotonically increasing generation. Unchanged scans do not advance the generation. Queries open SQLite read-only with a 2 MiB cache, and writers use a 4 MiB cache. A cancelled or failed scan rolls back, so queries never observe a half-updated index.

Source discovery streams files, reuses language parsers, and bounds AST traversal. Changed scans refresh affected call edges; import edges are rebuilt. The graph still uses heuristic static resolution: lexical names and a subset of explicit Python/JavaScript imports are supported, while unknown receivers and ambiguous module names remain unresolved.

## Dashboard controls

Before serving content, the local server validates exact loopback `Host` values, matching HTTP `Origin`, and browser fetch metadata. Every API requires a fresh 256-bit per-process token embedded in the same-origin bootstrap script. Token comparison is constant-time for equal-length values.

Responses use a restrictive Content Security Policy, deny framing and MIME sniffing, disable referrers and unnecessary browser permissions, and use `no-store`. UI content is created with DOM text nodes rather than injected HTML.

Resource bounds include:

- 64 KiB JSON bodies;
- one scan, two read/query workers, and one model request;
- 32 scan jobs and 16 context previews;
- 10-minute expiration for completed jobs and context previews;
- graph visualization capped at 300 nodes;
- queries capped at depth 25, 10,000 visits, and 500 results;
- source excerpts capped at 200 lines and 256 KiB;
- source files capped at 2 MiB by default;
- Git subprocesses capped at 15 seconds and 8 MiB output;
- model responses capped at 1 MiB and serialized requests at 32 KiB;
- AST traversal capped at 200,000 nodes and depth 512;
- Git snapshots capped at 10,000 supported files and 64 MiB per revision.

Busy read/model workers return HTTP 429 rather than accumulating an unbounded worker queue. Limits bound individual operations; they do not make the local server suitable for a public hostile network.

Indexing, previews and agent reads reject workspace escapes, symlinks, Windows reparse points, alternate data streams, secret-like names and excluded paths. Ignore patterns apply at their directory roots. File contents are bounded on read; a source hash and excerpt are derived from the same bytes. There is no claim of atomic confinement against a hostile process changing ancestor directories concurrently.

## Git safety

Git commands are executed directly without a shell. Revisions are length/character validated and resolved with `--end-of-options`. External diff programs, text conversion, and relevant environment overrides are disabled. Working analysis includes tracked staged and unstaged changes; untracked files are intentionally excluded.

## AI edition

AI support is compiled out of Lite. In AI edition:

- only an already configured Ollama or OpenAI-compatible endpoint is contacted;
- plain HTTP is accepted only for exact loopback addresses; remote endpoints require HTTPS;
- embedded credentials, query strings, redirects, and unsafe secret-variable names are rejected;
- API-key values remain in environment variables;
- connect/request timeouts and response byte limits are enforced;
- repository content is labelled untrusted in the prompt;
- a context preview is bound to the question, target, index revision, evidence, and full model configuration (provider, endpoint, model and protocol);
- the user must select evidence and explicitly approve it before sending;
- expired or substituted preview IDs are rejected;
- answers are checked for `[E#]` citations and unknown/missing citations are surfaced.

Approved evidence can contain source. Review the destination and every checked excerpt before approval. Provider retention and training policies are outside GraphXploit's control.

## Agent and command boundary

Plan mode is the default. Every remote agent prompt requires interactive approval, including follow-ups. Local model requests are automatic after configuration. Edits are checked again after approval; undo verifies that the current file still matches the edit being reverted. Terminal control characters are escaped in model responses and mutation previews.

Command approvals are not a sandbox. An approved build tool or script can run arbitrary repository code with the user's OS permissions. Program-name restrictions, PATH checks, deadlines, output caps, process groups and API-key environment removal reduce accidents; they do not isolate an approved malicious process. A child that deliberately escapes ordinary process-group containment is outside this guarantee.

Generated indexes and saved sessions are local, unencrypted data. Filename exclusions cannot identify every secret embedded in ordinary source. Review outgoing evidence.

## Known limits

Static call analysis cannot prove coverage of dynamic dispatch, reflection, generated code, macros, runtime dependency injection, or every language construct. GraphXploit deliberately reports uncertainty instead of guessing.

Security checks are engineering controls, not formal certification. See [AUDIT.md](../AUDIT.md).

## Reporting a vulnerability

Do not place credentials or exploit details in a public issue. Use GitHub private security advisories when enabled or contact the repository owner privately.
