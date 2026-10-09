# Hetzer architecture

Hetzer's core runtime consists of the Node CLI, Grimoire vault, secret scanner, MCP credential proxy, and ephemeral container sandbox. Multi-container operations and stack management are delegated to [Jagdpanzer](https://github.com/agunggnn/jagdpanzer).

## Main components

```mermaid
flowchart LR
    User[CLI or AI Agent] --> CLI[Hetzer Node CLI]
    CLI --> Vault[(SQLite Grimoire Vault)]
    CLI --> Scanner[Regex and entropy scanner]
    CLI --> Exec[Guarded child process]
    CLI --> Sandbox[Ephemeral container sandbox]
    CLI --> Broker[Loopback HTTP credential broker]
    CLI --> MCP[MCP virtual credential proxy]
    Exec --> Redactor[Bounded stream sanitizer]
    Sandbox --> Broker
```

The package declares no third-party runtime npm dependencies. It depends on Node.js and its standard modules, including `node:sqlite`, `node:crypto`, `node:fs`, and `node:child_process`. Optional services have their own container dependency trees.

## Security invariants (what Hetzer guarantees)

Hetzer guarantees exactly three things. Everything else in this document is defense-in-depth, not a boundary:

1. **Plaintext credentials live in exactly two places**: the sealed Grimoire vault and the memory of the broker process. They never appear in environment variables, CLI arguments, files, or agent-readable stdout/stderr.
2. **The broker is the only mediated path into a child process.** Without a reviewed broker policy, `hetzer exec` fails closed. (The `--allow-raw-unmediated` escape hatch is deprecated, always audited when used, and will be removed in a future major release.)
3. **Every credential use is scoped and audited.** Use is bound to an HTTPS origin plus method/path allowlists, and recorded in the hash-chained audit ledger (`hetzer audit verify`).

If a component appears to violate one of these invariants, the component is wrong — not the invariant.

## What Hetzer does NOT guarantee

- **Same-user isolation without a container.** Any process running as the same OS user can read the vault database, the master-key file, and broker policy files, and can debug the broker process. `0600` file permissions only stop *other* accounts. Same-user guards (TTY checks, process-ancestry inspection, stream sanitizers, canaries) are misuse safeguards: they stop accidents and casual abuse, not a determined same-user process. The only real isolation boundary Hetzer offers is the ephemeral container sandbox (`hetzer exec --sandbox`).
- **Perfect output redaction.** The stream sanitizer is best-effort hygiene: it does not cover direct terminal-device writes, files, IPC, debuggers, or unrelated processes, and it can miss transformed or unsupported formats.
- **Perfect secret detection.** The scanner is heuristic (regex + entropy). It misses encoded, split-across-files, or transformed values and can flag benign data. A clean scan is a warning cleared, not proof of cleanliness.

## Grimoire vault

Vault metadata is stored in SQLite. Credential values are encrypted separately using AES-256-GCM. Each encryption uses a random 12-byte IV, an authentication tag, and additional authenticated data bound to the credential identifier and creation time. The master key is normalized and expanded with HKDF-SHA-256.

The master key is resolved with deterministic precedence: explicit runtime environment (`HETZER_GRIMOIRE_KEY`), followed by local workspace `.env` configuration, falling back to the user-level isolated file (`~/.hetzer/grimoire.key`). `hetzer creds isolate-key` moves a workspace key into the user-level file and requests POSIX mode `0600` (along with Windows DACL hardening). This separates the key from the workspace to prevent automated agent file-reads; it does not protect against the same OS user executing arbitrary commands outside a container sandbox.

Credential records can restrict target and action. `secretRef:<id>` resolution checks the target, allowed action, validity, and expiry before decryption. Internal decryption is decoupled into private `#decryptRaw`, capability-scoped `resolve()`, non-revealing equality `matchesSecret()`, and human-guarded `reveal()`.

## Scanner

`scanText` scans explicit input for:

- selected npm, OpenAI, Anthropic, Gemini, GitHub, Slack, AWS, and JWT formats;
- credentialed PostgreSQL, MySQL, MongoDB, and Redis URLs;
- PKCS#8 and algorithm-prefixed PEM private-key blocks up to 16 KiB;
- high-entropy candidates from 24 to 512 characters with Shannon entropy of at least 4.3 bits per character.

Specific matches take priority over overlapping generic entropy matches. These heuristics can miss unsupported, encoded, split-across-files, unusually long, or transformed values and can flag benign data.

The scanner is a UX warning system, not a security boundary. A clean scan result must never be read as proof that no secret is present.

`redactAndVault` always removes detected values from returned text. It reports `vaultedCount`, per-item `vaulted` status, and `vaultErrors`. If the provider's default credential ID already contains a different value, a hash-suffixed ID is allocated instead of overwriting the existing credential.

## Guarded process execution

`hetzer exec` selects reference bindings only through `--allow`. If `.hetzer/brokers/<credential-id>.json` exists, Hetzer starts that reviewed HTTP broker policy and gives the child its loopback base URL and short-lived capability instead of the credential. A compatible policy can also be supplied with `--broker-policy`. Credentials without a broker policy fail closed unless the same ID is explicitly listed in `--allow-raw-unmediated`; that opt-out is audited and, when an execution policy is active, must be permitted by `allowRawUnmediated`. With `--strict`, the child starts from a small cross-platform environment allowlist; the vault master key is not inherited.

Execution policy manifests (`--policy`) enforce exact structured `argv` matching rather than loose prefix string matching, preventing command chaining or trailing argument bypasses. Any shell metacharacters (`&`, `|`, `;`, `<`, `>`, `$`, `` ` ``, `\n`, `\r`, `%`, `^`) in commands or arguments are rejected upfront. Child processes execute with `shell: false` across all platforms (with Windows npm/npx safely resolved directly to their underlying node entrypoints), eliminating shell interpretation and argument injection vulnerabilities. Policy files are treated as trust roots and undergo regular-file verification, POSIX permission checks, and SHA-256 integrity auditing.

Common environment-reflection command strings are rejected before spawn. This is a misuse safeguard, not a sandbox: equivalent code, native binaries, debuggers, encodings, and external side effects remain possible inside an authorized child.

Guarded child and Docker Compose stdout/stderr pass through independent UTF-8 rolling sanitizers. Each retains `max(128, longest injected secret × 2)` characters and scans a bounded 512-character lexical window. Before emission, a streaming filter removes terminal control/format characters and suppresses supported private-key blocks, credentialed database URLs, and provider-token candidates without waiting for a fixed 16 KiB window. Known injected values are detected even when writes split them across chunks. Deliberately transformed values, unsupported formats, non-UTF-8 output, and output written directly to a terminal device, file, or network remain outside this filter.

The sanitizer is hygiene, not a security boundary: it reduces accidental leaks in the paths it covers and stops nothing outside them.

## HTTP credential broker

`hetzer broker` and mediated `hetzer exec` start short-lived listeners on `127.0.0.1` and launch compatible HTTP clients with random capabilities instead of selected vault credentials. A versioned policy fixes the HTTPS upstream origin, client and upstream authentication headers, allowed methods and path prefixes, environment variable names, request limits, and lifetime. The broker replaces a capability with its resolved credential only on an allowed upstream request.

Broker v1 blocks redirects, binary responses, over-limit bodies, non-loopback clients, matrix parameters (`;`), and unsupported methods or paths. Fixed-point path canonicalization eliminates nested percent-encoding and directory traversal attacks. It sanitizes the exact credential from supported upstream responses and child output. It is not transparent process or network containment: the child may open unrelated connections, and same-user access to the policy, key, vault, or broker process remains outside this boundary. See [HTTP credential broker](http-credential-broker.md).

## Credential reveal, same-user agentic guard, and canaries
 
Credential revelation (`hetzer creds reveal` and programmatic `Grimoire.reveal()`) enforces `assertInteractiveHumanSession()`: requiring a direct interactive TTY, rejecting known agent environment markers, and inspecting process ancestry trees (with in-process sub-millisecond caching) on Windows, macOS, and Linux. This is a **misuse safeguard, not a security boundary**: it raises the cost of casual autonomous-agent dumps while preserving non-interactive runner and broker execution via decoupled `Grimoire.resolve()`. A native modal confirmation is also enforced on CLI execution. It does not stop a same-user process that unsets the marker environment variables, renames its binary, or simply reads the vault database and master-key file directly — ancestry inspection fails open when process inspection is unavailable. Do not rely on it against a determined same-user actor; use the container sandbox for that.
 
Canary IDs are checked by guarded vault reveal and reference-resolution paths. A hit logs an incident, attempts an SQLite audit record, throws `ERR_CANARY_TRIPWIRE_TRIGGERED`, and maps to CLI exit code 43. Arbitrary reads of vault, key, environment, process memory, or incident files are not monitored by the canary.

## MCP boundary

The MCP server exposes credential existence and metadata listing but no plaintext reveal tool. Tool results and errors are serialized and scanned before return. This protects the Hetzer MCP response path only; an MCP client may have other tools with broader access.

## Git guard

The pre-commit hook invokes Git to list staged files and obtain the added diff. It blocks staged `.env` variants and scans added text grouped by file, which allows multiline private-key detection and line reporting. Hook time includes Git process startup and varies with repository size. Local hooks can be bypassed, so enforced environments should add server-side scanning.

## Ephemeral container sandbox vs. multi-container stack orchestration
 
Hetzer focuses on single-command, ephemeral process containment via `hetzer exec --sandbox [image]`. Untrusted agent executions are isolated inside transient containers with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, and strict process limits, while bridging the host loopback HTTP broker via `host.docker.internal`.
 
Multi-container full-stack operations (such as 9Router AI gateways, PostgreSQL/pgvector memory clusters, and cognitive extractors) are deprecated in the Hetzer core CLI and delegated to [Jagdpanzer](https://github.com/agunggnn/jagdpanzer), allowing Hetzer to maintain a clean, zero-dependency footprint strictly focused on credential safety and agent armor.

## What we deliberately do not build

Scope discipline is a security feature: every component we refuse to build is a component we cannot misconfigure. Hetzer will not:

1. Build a transparent network sandbox or `CONNECT`-style proxy — out of scope; delegate to OS/container egress controls.
2. Build a per-request approval hook or OPA sidecar — adds latency and complexity; per-broker policy scoping is sufficient for now.
3. Build a broker daemon with a control-socket API — interesting, but no consumer needs it yet (revisit if Brumm or another control plane asks for one).
4. Expand the sniffer with ML or ever-more patterns — heuristics stay heuristics; more patterns mean more false positives, not a boundary.
5. Pursue hardware root of trust (TPM attestation) now — it stays on the roadmap (`hardware-root-of-trust-roadmap.md`), not in this phase.

## Closed architecture proposals

- [RFC: Native OS Pinentry & GUI Masked Prompt Bridge](rfc-native-os-pinentry-bridge.md) — **Closed: Will Not Do.** The proposed agent-triggered GUI and loopback handoff does not provide a trustworthy same-user credential boundary.
