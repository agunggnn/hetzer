# System logic and implementation status

This document tracks implemented behavior and known boundaries. Test counts change over time; run `npm run check` for the current result.

## Credential lifecycle

```mermaid
sequenceDiagram
    participant Config as .env configuration
    participant CLI as Hetzer CLI
    participant Vault as Grimoire vault
    participant Child as Child process
    Config->>CLI: secretRef:id
    CLI->>Vault: resolve id with target/action
    Vault-->>CLI: decrypted value in memory
    CLI->>Child: approved environment binding
    Child-->>CLI: stdout/stderr chunks
    CLI-->>CLI: rolling sanitize
    CLI-->>Config: output only; no plaintext writeback
```

`--allow` selects reference bindings. `--strict` also removes inherited environment variables except a small cross-platform runtime allowlist. The child still receives plaintext values in its environment and memory.

## Implemented components

| Component | Source | Current behavior |
|---|---|---|
| Grimoire vault | `cli/vault/hetzer-vault.mjs` | AES-256-GCM credential values in SQLite with target/action/expiry checks |
| Secret scanner | `cli/vault/sniffer.mjs` | Provider regexes, database URLs, bounded PEM keys, and Shannon-entropy candidates |
| Process runner | `cli/vault/exec.mjs` | Scope resolution, strict base environment, reflection guard, shared stdout/stderr sanitizer |
| Compose runner | `cli/vault/compose-runner.mjs` | Scoped Compose environment and sanitized Docker/containers output pipes |
| Credential CLI | `cli/vault/creds.mjs` | Set/list/reveal, TTY and agent heuristics, required native UI confirmation |
| Canary | `cli/vault/canary.mjs` | Aborts guarded canary reveal/resolution and maps to CLI exit code 43 |
| Git hook | `cli/core/git-hook.mjs` | Scans staged `.env` names and added text grouped by file |
| MCP | `cli/mcp/` | Metadata-only credential tools, scanner tools, module tools, response sanitation |
| Agent installer | `cli/skills/` | Workspace guidance and selected user-level client configuration |
| Module system | `cli/modules/` | Disabled-by-default optional module recipes and Compose profile resolution |

## Correctness properties covered by tests

- AES-GCM round trips and access restrictions;
- strict execution excludes unapproved inherited values and the master key;
- known short values and values divided across output chunks are redacted;
- multiline PKCS#8 keys and credentialed database URLs are detected;
- generic high-entropy candidates are detected without duplicating overlapping provider matches;
- auto-vaulting a second provider token does not overwrite an existing provider credential;
- canary errors carry exit code 43;
- installer tests redirect user-level paths to a temporary home.

## Known boundaries

- Pattern and entropy scanning is heuristic and bounded. It cannot prove that text contains no secrets.
- `hetzer exec` is not a sandbox. Authorized child code can transform a value, send it over the network, or access other same-user resources.
- TTY, environment-marker, process-name, and UI checks do not authenticate a human and can be imitated by same-user code.
- The isolated key file is separate from the project but remains a user-readable file.
- Canaries observe only guarded application paths.
- MCP sanitation covers Hetzer MCP results, not every tool a client can invoke.
- Local Git hooks can be skipped.
- Performance depends on input and environment. End-to-end Git-hook time includes Git subprocesses.
- Tests are implementation evidence, not a security audit or compliance certification.

## Release gate

Before release:

1. Run `npm run check` on Windows, Linux, and macOS.
2. Confirm no credential, `.env`, vault database, key, log, backup, or user data is tracked.
3. Verify each container digest against its upstream source and required platforms.
4. Review documentation for absolute security, performance, comparison, cost, and compliance claims.
5. Perform independent security testing when the release will handle production or regulated credentials.

## Future work

- OS-backed key storage or external KMS integration;
- server-side Git scanning integration;
- stronger child-process isolation profiles;
- fuzzing for stream boundaries, encodings, scanners, and environment construction;
- signed release provenance and reproducible build evidence;
- third-party security review.
