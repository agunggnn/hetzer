# Hetzer architecture

Hetzer's core runtime consists of the Node CLI, Grimoire vault, secret scanner, MCP credential proxy, and ephemeral container sandbox. Multi-container operations and stack management were removed in 0.6.0 and are out of scope.

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

## Grimoire vault

Vault metadata is stored in SQLite. Credential values are encrypted separately using AES-256-GCM. Each encryption uses a random 12-byte IV, an authentication tag, and additional authenticated data bound to the credential identifier and creation time. The master key is normalized and expanded with HKDF-SHA-256.

The master key is resolved with deterministic precedence: explicit runtime environment (`HETZER_GRIMOIRE_KEY`), followed by local workspace `.env` configuration (written by builds before 0.7.0), the per-instance key file named by `HETZER_INSTANCE_ID` (`~/.hetzer/keys/<instance-id>.key`, written by `hetzer init` from 0.7.0), and finally the shared user-level file (`~/.hetzer/grimoire.key`, read for workspaces isolated before 0.7.0). `hetzer creds isolate-key` moves a workspace key into the per-instance file and requests POSIX mode `0600` (along with Windows DACL hardening). This separates the key from the workspace to prevent automated agent file-reads; it does not protect against the same OS user executing arbitrary commands outside a container sandbox.

Credential records can restrict target and action. `secretRef:<id>` resolution checks the target, allowed action, validity, and expiry before decryption. Internal decryption is decoupled into private `#decryptRaw`, capability-scoped `resolve()`, non-revealing equality `matchesSecret()`, and human-guarded `reveal()`.

## Scanner

`scanText` scans explicit input for:

- selected npm, OpenAI, Anthropic, Gemini, GitHub, Slack, AWS, and JWT formats;
- credentialed PostgreSQL, MySQL, MongoDB, and Redis URLs;
- PKCS#8 and algorithm-prefixed PEM private-key blocks up to 16 KiB;
- high-entropy candidates from 24 to 512 characters with Shannon entropy of at least 4.3 bits per character.

Specific matches take priority over overlapping generic entropy matches. These heuristics can miss unsupported, encoded, split-across-files, unusually long, or transformed values and can flag benign data.

`redactAndVault` always removes detected values from returned text. It reports `vaultedCount`, per-item `vaulted` status, and `vaultErrors`. If the provider's default credential ID already contains a different value, a hash-suffixed ID is allocated instead of overwriting the existing credential.

## Guarded process execution

`hetzer exec` selects reference bindings only through `--allow`. If `.hetzer/brokers/<credential-id>.json` exists, Hetzer starts that reviewed HTTP broker policy and gives the child its loopback base URL and short-lived capability instead of the credential. A compatible policy can also be supplied with `--broker-policy`. Credentials without a broker policy fail closed unless the same ID is explicitly listed in `--allow-raw-unmediated`; that opt-out is audited and, when an execution policy is active, must be permitted by `allowRawUnmediated`. With `--strict`, the child starts from a small cross-platform environment allowlist; the vault master key is not inherited.

Execution policy manifests (`--policy`) enforce exact structured `argv` matching rather than loose prefix string matching, preventing command chaining or trailing argument bypasses. Any shell metacharacters (`&`, `|`, `;`, `<`, `>`, `$`, `` ` ``, `\n`, `\r`, `%`, `^`) in commands or arguments are rejected upfront. Child processes execute with `shell: false` across all platforms (with Windows npm/npx safely resolved directly to their underlying node entrypoints), eliminating shell interpretation and argument injection vulnerabilities. Policy files are treated as trust roots and undergo regular-file verification, POSIX permission checks, and SHA-256 integrity auditing.

Common environment-reflection command strings are rejected before spawn. This is a misuse safeguard, not a sandbox: equivalent code, native binaries, debuggers, encodings, and external side effects remain possible inside an authorized child.

Guarded child stdout/stderr passes through an independent UTF-8 rolling sanitizer. Each retains `max(128, longest injected secret × 2)` characters and scans a bounded 512-character lexical window. Before emission, a streaming filter removes terminal control/format characters and suppresses supported private-key blocks, credentialed database URLs, and provider-token candidates without waiting for a fixed 16 KiB window. Known injected values are detected even when writes split them across chunks. Deliberately transformed values, unsupported formats, non-UTF-8 output, and output written directly to a terminal device, file, or network remain outside this filter.

## HTTP credential broker

`hetzer broker` and mediated `hetzer exec` start short-lived listeners on `127.0.0.1` and launch compatible HTTP clients with random capabilities instead of selected vault credentials. A versioned policy fixes the HTTPS upstream origin, client and upstream authentication headers, allowed methods and path prefixes, environment variable names, request limits, and lifetime. The broker replaces a capability with its resolved credential only on an allowed upstream request.

Broker v1 blocks redirects, binary responses, over-limit bodies, non-loopback clients, matrix parameters (`;`), and unsupported methods or paths. Fixed-point path canonicalization eliminates nested percent-encoding and directory traversal attacks. It sanitizes the exact credential from supported upstream responses and child output. It is not transparent process or network containment: the child may open unrelated connections, and same-user access to the policy, key, vault, or broker process remains outside this boundary. See [HTTP credential broker](http-credential-broker.md).

## Credential reveal, same-user agentic guard, and canaries
 
Credential revelation (`hetzer creds reveal` and programmatic `Grimoire.reveal()`) enforces `assertInteractiveHumanSession()`: requiring a direct interactive TTY, rejecting known agent environment markers, and inspecting process ancestry trees (with in-process sub-millisecond caching) on Windows, macOS, and Linux. This blocks same-user autonomous agents from dumping plaintext credentials while preserving non-interactive runner and broker execution via decoupled `Grimoire.resolve()`. A native modal confirmation is also enforced on CLI execution. These provide defense-in-depth safeguards rather than an impenetrable OS privilege barrier.
 
Canary IDs are checked by guarded vault reveal and reference-resolution paths. A hit logs an incident, attempts an SQLite audit record, throws `ERR_CANARY_TRIPWIRE_TRIGGERED`, and maps to CLI exit code 43. Arbitrary reads of vault, key, environment, process memory, or incident files are not monitored by the canary.

## MCP boundary

The MCP server exposes credential existence and metadata listing but no plaintext reveal tool. Tool results and errors are serialized and scanned before return. This protects the Hetzer MCP response path only; an MCP client may have other tools with broader access.

## Git guard

The pre-commit hook invokes Git to list staged files and obtain the added diff. It blocks staged `.env` variants and scans added text grouped by file, which allows multiline private-key detection and line reporting. Hook time includes Git process startup and varies with repository size. Local hooks can be bypassed, so enforced environments should add server-side scanning.

## Ephemeral container sandbox vs. multi-container stack orchestration
 
Hetzer focuses on single-command, ephemeral process containment via `hetzer exec --sandbox [image]`. Agent commands run inside transient containers with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, and a process limit, while the host loopback HTTP broker is bridged via `host.docker.internal`.

- **Mount**: only the project directory is mounted (`--sandbox-mount <dir>`, default the current directory). The filesystem root, the home directory, the Hetzer home and their ancestors are refused. Hetzer-owned paths inside the mount (env file, vault database and journals, key file, audit and incident logs, `.hetzer/`, credential requests) are hidden with an empty read-only file or a read-only tmpfs; only paths that exist are hidden, and a path that cannot be hidden stops the run.
- **Environment**: only variables Hetzer injected (raw bindings, broker URL and capability, canary token) and a terminal/locale allowlist are forwarded, by name. Values travel through the engine CLI's own environment, so they are not in its command line. `docker inspect` still shows a running container's environment values.
- **Image**: the default is pinned by digest. A pin does not receive base-image updates on its own; refresh it with the commands next to `DEFAULT_SANDBOX_IMAGE` in `cli/vault/sandbox.mjs`, or set `HETZER_SANDBOX_IMAGE`.
- **Network**: outbound access is open by default and the sandbox prints the mode before starting. `--sandbox-network none` removes it but cannot be combined with a brokered credential.
- **Not covered**: files that appear after the container starts are not hidden; the broker still binds `0.0.0.0` in sandbox mode and accepts RFC 1918 clients (capability-gated); a sandbox does not protect a credential that was raw-injected into it.
 
### Container-free engine: `srt`

`--sandbox-engine srt` (and `hetzer agent`, which uses it by default) runs the command under Anthropic's sandbox-runtime, invoked as an external program like `docker`: `sandbox-exec` on macOS, bubblewrap with seccomp on Linux, and a host proxy that only lets `--sandbox-allow-host` entries through. Hetzer writes the settings for each run to a private temporary directory and removes them afterwards: reads of the home directory, the Hetzer home and named credential stores are denied, the project is re-allowed with the same Hetzer-owned paths hidden, writes are limited to the project and a per-run `TMPDIR`, and `.git/hooks`, `.git/config` and other files that tools execute later are write-protected. srt is started from the project with `shell: false`; it shell-quotes the command's arguments for its own wrapper. Brokered credentials are refused under srt because its network namespace does not reach the host loopback broker. Rationale and limits: [ADR-0004](adr/0004-container-free-sandbox-and-agent-containment.md), [agent-sandbox.md](agent-sandbox.md).

Multi-container full-stack operations (such as 9Router AI gateways, PostgreSQL/pgvector memory clusters, and cognitive extractors) were removed from the Hetzer core CLI in 0.6.0, which lets Hetzer keep a clean, zero-dependency footprint strictly focused on credential safety and agent armor.

## Proposed architecture decisions

- [ADR-0001: Authority model first, then a local-first engine with thin adapters](adr/0001-authority-model-and-engine-boundary.md) — **Proposed.** Based on the [October 2026 architecture and security review](architecture-review-2026-10.md).
- [ADR-0004: Container-free sandbox engine and agent containment](adr/0004-container-free-sandbox-and-agent-containment.md) — **Accepted**, implemented in 0.7.0.

## Closed architecture proposals

- [RFC: Native OS Pinentry & GUI Masked Prompt Bridge](rfc-native-os-pinentry-bridge.md) — **Closed: Will Not Do.** The proposed agent-triggered GUI and loopback handoff does not provide a trustworthy same-user credential boundary.
