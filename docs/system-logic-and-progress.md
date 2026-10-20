# System logic and implementation status

This document tracks implemented behavior and known boundaries. Test counts change over time; run `npm test` for the current result.

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

`--allow` selects reference bindings. Matching `.hetzer/brokers/<credential-id>.json` policies are started automatically and place only a loopback URL and capability in the child. Direct plaintext injection fails closed unless explicitly requested through the audited `--allow-raw-unmediated <id>` opt-out. `--strict` also removes inherited environment variables except a small cross-platform runtime allowlist. Only raw-opted-out values enter child environment and memory.

## Implemented components

| Component | Source | Current behavior |
|---|---|---|
| Grimoire vault | `cli/vault/hetzer-vault.mjs` | AES-256-GCM credential values in SQLite with origin grants (`allowedOrigins`), mandatory action grants (`allowedActions`), raw injection policy (`rawInjection`), policy approvals (`vault_approved_policies`), private `#decryptRaw` isolation, and `matchesSecret()` |
| Master key custody | `cli/vault/hetzer-vault.mjs` (`locateMasterKey`, `writeInstanceKey`, `isolateMasterKey`), `cli/core/cli.mjs` (`initializeProject`) | Lookup order: environment, workspace `.env` (builds before 0.7.0), `~/.hetzer/keys/<HETZER_INSTANCE_ID>.key`, shared `~/.hetzer/grimoire.key`. `init` writes a per-instance key file (0600 in a 0700 directory) and only the instance id to `.env`; refuses to replace a missing key over an existing vault; `doctor` warns while the key is in `.env` |
| Human guard | `cli/vault/human-guard.mjs` | Same-user agentic reveal block enforcing interactive TTY, agent env denial, and process ancestry inspection with sub-ms caching |
| Secret scanner | `cli/vault/sniffer.mjs` | Provider regexes, database URLs, bounded PEM keys, and Shannon-entropy candidates |
| Process runner | `cli/vault/exec.mjs` | Broker-by-default selection, vault-gated raw injection opt-out, strict base environment, reflection guard, stream sanitizer, subprocess canary stream tripwire, execution timeout guard |
| Agent runner | `cli/core/cli.mjs` (`hetzer agent`) | Starts a whole agent in the sandbox (srt unless an engine or image is named) with an inherited terminal, no credential unless `--allow` names one, `--host`/`--no-sandbox`/`--broker-policy` refused, a pre-start check for commands installed under the home directory, `SANDBOX_EXEC` (`agent: true`) and `AGENT_EXIT` audit events |
| Execution policy | `cli/vault/exec-policy.mjs` | Declarative capability policies: command whitelisting, credential boundaries, raw-opt-out boundaries, strict isolation, and timeout limits |
| Sandbox | `cli/vault/sandbox.mjs`, `cli/vault/srt-sandbox.mjs` | Engines `docker`/`podman` (ephemeral OCI container, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, loopback broker translation, project-only mount with Hetzer-owned paths hidden, variables forwarded by name) and `srt` (Anthropic sandbox-runtime as an external program, 0.0.78 tested: home directory, Hetzer home and credential stores read-denied, project re-allowed with Hetzer files hidden, writes only in the project and a per-run `TMPDIR`, Git hooks and other host-executed project files write-protected, network only to `--sandbox-allow-host` entries, brokered credentials refused). `--sandbox-engine` selects; `auto` tries Docker, Podman, then srt |
| Audit ledger | `cli/vault/audit.mjs` | Single append-only event ledger with SHA-256 hash chaining (`prevHash`), version 2 entries covering the actor, optional HMAC with the `hetzer:audit-integrity:v1` subkey, vault events mirrored in |
| Compose runner | `cli/vault/compose-runner.mjs` | Scoped Compose environment and sanitized Docker/containers output pipes |
| Credential CLI | `cli/vault/creds.mjs` and `cli/vault/credential-request.mjs` | Set/list/reveal plus metadata-only request/approve/status handoff; direct secret entry requires a human TTY and reveal retains native confirmation |
| Canary | `cli/vault/canary.mjs` | Decoy token injection, aborts guarded reveal/resolution/stream leak with exit code 43, terminates child process tree. External decoys (`hetzer canary plant`): values from an outside alerting service written to an untracked bait file, kept out of Git with `.git/info/exclude`, only SHA-256 fingerprints stored in `~/.hetzer/canaries/` |
| Git hooks | `cli/core/git-hook.mjs` | Dual Git hooks (`pre-commit` & `commit-msg`), scans staged `.env` names, diff additions, and commit message text |
| HTTP broker | `cli/vault/http-broker.mjs` | Loopback proxy injecting upstream credentials via ephemeral capabilities; enforces vault-approved target origins, mandatory `broker.proxy` action grants, and short-lived TTLs |
| MCP | `cli/mcp/` | FastMCP server, metadata-only tools, virtual credential proxy (`secretRef:<id>` payload resolution bound to verified tool destination origins), canary guard, response sanitation |
| Agent installer | `cli/skills/` | Workspace guidance and selected user-level client configuration |
| Module system | `cli/modules/` | Disabled-by-default optional module recipes and Compose profile resolution |

## Correctness properties covered by tests

- AES-GCM round trips and access restrictions;
- strict execution excludes unapproved inherited values and the master key;
- execution policy enforcement restricts commands and credentials to declared JSON manifests;
- reveal through a direct Node import is refused without an interactive TTY, with a known agent marker (including Claude Code's `CLAUDECODE` and `CLAUDE_CODE_ENTRYPOINT`), or with an agent process among five ancestors; these are heuristics that same-user code can imitate (see Known boundaries);
- editor terminals (VS Code, Cursor) are refused for reveal, grant, approval and audit rotation; `creds set` may add a new credential there but not replace a stored one (which keeps its grants), and `canary plant` may run there;
- process ancestry inspection caches results in-process to maintain sub-millisecond execution latency;
- a key in the workspace `.env` (written by builds before 0.7.0) takes precedence over key files; `init` writes new keys to a per-instance file so workspaces never share or overwrite one another's key, and no workspace file holds the key (`VERIFY-SEC-016`);
- non-interactive runners, HTTP brokers, and MCP proxies resolve capability-scoped secrets without TTY blockage;
- known short values and values divided across output chunks are redacted;
- multiline PKCS#8 keys and credentialed database URLs are detected;
- subprocess execution timeout guard terminates runaway/hanging processes within configured budgets and redacts emitted output;
- generic high-entropy candidates are detected without duplicating overlapping provider matches;
- `NAME=<hex>` identifiers and checksums are skipped like bare hex unless the name marks a secret (`KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `AUTH`, `CREDENTIAL`, `PRIVATE`, `SIGNATURE`), which keeps the whole token scored;
- `init` adds a marked `.gitignore` block for `.env`, `.env.*` (not `.env.example`), the vault file and `.hetzer/`, and keeps the user's own lines;
- `protect` writes agent guidance only inside the project, names (never values) of plaintext credentials it could not move, and leaves agent apps in the home directory to `hetzer skill install`, which updates only apps that are installed;
- auto-vaulting a second provider token does not overwrite an existing provider credential;
- canary errors carry exit code 43;
- commit-msg hook blocks raw credentials in commit message text and exempts comment lines;
- MCP virtual credential proxy resolves `secretRef:<id>` in tool payloads and sanitizes outputs;
- subprocess canary stream tripwire terminates child processes on stream leak;
- exact structured argv allowlist matching prevents command chaining and shell metacharacter injection;
- subprocess execution uses shell: false across all platforms, eliminating shell expansion vulnerabilities;
- policy trust roots enforce regular file checks, POSIX permissions, and SHA-256 integrity auditing;
- HTTP broker path canonicalization prevents multi-layer percent-encoding, matrix parameter (`;`), and directory traversal bypasses;
- HTTP broker capabilities authenticate scoped requests and reject unpermitted paths;
- workspace broker policies cannot widen access without explicit vault origin and SHA-256 policy hash approval (`VERIFY-SEC-007`);
- caller `--allow-raw-unmediated` is rejected with `ERR_RAW_UNMEDIATED_DENIED_BY_GRANT` unless vault grant explicitly permits raw injection, and with `ERR_HOST_BINDING_MISMATCH` when the grant lists `bindHosts` that do not include this host (`VERIFY-SEC-008`);
- in-process `Grimoire.resolve()` strictly enforces mandatory action grants and the grant's `bindHosts`, returning null for ungranted or omitted actions and on a host the grant does not list, so the binding holds for `hetzer exec`, the HTTP broker, MCP and the SDK; `hetzer exec` and the broker report the mismatch as `ERR_HOST_BINDING_MISMATCH` before resolving (`VERIFY-SEC-009`). The public SDK does not expose plaintext; R-05 remains open for in-process callers holding the master key until out-of-process engine isolation;
- MCP virtual credential proxy binds `secretRef:<id>` to verified tool destination origins, failing closed on ungranted endpoints (`VERIFY-SEC-010`);
- the sandbox mounts an explicit project directory, hides Hetzer-owned paths inside it, forwards only injected variables by name (never on the engine command line), and refuses unsafe mount targets (`VERIFY-SEC-013`, builder-level; container behaviour of the masks was checked separately on Docker Desktop for Windows);
- the SDK contract (`apiVersion` 1, `docs/sdk-contract.md`) lists its members and fails a test when they change, has no resolve/reveal/decrypt/lease member, and uses the same credential id grammar as the vault and `secretRef`; the vault carries a format version (`docs/vault-format.md`) and a newer vault is refused before any change; the format 2 migration runs in one transaction, keeps its ledger record owed until the ledger takes it, reports a legacy JSON vault it no longer imports, and key lookup refuses the retired key alias with a rename instruction (`cli/vault/vault-migration.test.mjs`; the migration is one-way and rows in the dropped tables are counted, not copied); the audit entry schema and event catalog (`docs/audit-event-schema.md`) are checked against the code (`VERIFY-SEC-015`; in-process callers can still import the vault module (R-05), older builds do not check the marker, and lease interfaces are not part of version 1);
- audit entries are versioned, cover the actor and are keyed with the master key when it is available; verification rejects edits, truncation, wrong keys, unkeyed entries after keyed ones and key-less extension, old ledgers still verify, concurrent writers lose no events, `--strict` does not start without its start event, and `hetzer audit rotate --yes` (human session only, by heuristic) recovers a refused ledger by archiving it and recording the old head in the new one (`VERIFY-SEC-014`; a consistent unkeyed rewrite needs `--require-mac`, key holders can forge, and deleting the archive together with the rotation entry is not detected);
- vault grant columns are HMAC-signed with a subkey derived from the master key, failing closed upon direct SQLite database tampering (`VERIFY-SEC-011`);
- unsigned or altered grants and broker policy approvals are never honored and never signed automatically; a legacy credential becomes usable only after an operator reviews it with `hetzer creds grant --sign-existing` (`VERIFY-SEC-012`). Signatures carry no version, so a previously valid signed grant can be replayed by a writer who kept an old copy of the database, and a writer who can read the master key can still forge grants;
- operator `hetzer creds grant <id>` CLI command safely configures grants behind interactive human TTY confirmation;
- the srt settings deny reads of the home directory, the Hetzer home and credential stores, re-allow the project with Hetzer files hidden, confine writes, allow no network without a listed host, refuse re-opening credential stores and writing the home directory, and are enforced by a real srt where one is installed (`VERIFY-SEC-017`, `cli/vault/srt-sandbox.test.mjs`, CI job `srt-sandbox` on Linux and macOS);
- `hetzer agent` starts the agent through the sandbox without the workspace credentials or the master key, records its start and exit, and refuses host mode (`VERIFY-SEC-018`);
- external decoys are written to an untracked bait file, the workspace `.env` is refused, and the registry outside the workspace holds fingerprints, not values (`VERIFY-SEC-019`);
- installer tests redirect user-level paths to a temporary home.
- credential approval requests contain no secret material, expire, and expose status only to the requesting workflow;

## Known boundaries

- Pattern and entropy scanning is heuristic and bounded. It cannot prove that text contains no secrets.
- `hetzer exec` is not a sandbox. Raw-opted-out child code can transform a value, send it over the network, or access other same-user resources. Brokered clients can still make any operation permitted by their broker policy and upstream account.
- TTY, environment-marker, process-name, and UI checks do not authenticate a human and can be imitated by same-user code. A process that detaches from its parent (for example with `setsid`) leaves the inspected ancestry, and an editor's agent that allocates a terminal can add a new credential with `creds set`. Run untrusted agents with `hetzer agent` so the sandbox, not these checks, keeps them from the key and the vault.
- The generic high-entropy rule scores whole tokens against one threshold, so a short hex value under a secret name (for example `SESSION_TOKEN=<32 hex>`) can fall below it; provider rules cover known formats.
- Key files under `~/.hetzer/keys` are outside the workspace but readable by any process running as the same user outside a sandbox.
- Local canaries observe only guarded application paths. External decoys alert, through the issuing service, only when used.
- The sandbox engines are process sandboxes, not virtual machines; kernel and engine vulnerabilities, and every path or host re-opened with `--sandbox-allow-*`, are outside them. Container engines leave outbound network open unless `--sandbox-network none`. srt 0.0.78 cannot deny a project path that does not exist yet on Linux, and does not reach the host broker. Interactive `hetzer agent` sessions are not redacted.
- Host binding compares `bindHosts` with the OS hostname of the running process. It identifies the machine, but it is not an attestation: same-user code that controls the hostname, or a copied vault on a machine given the same name, passes the check.
- MCP sanitation covers Hetzer MCP results, not every tool a client can invoke.
- Local Git hooks can be skipped.
- Performance depends on input and environment. End-to-end Git-hook time includes Git subprocesses.
- Tests are implementation evidence, not a security audit or compliance certification.

## Release gate

Before release:

1. Run `npm run check` on Windows, Linux, and macOS, `npm run lint` (errors fail CI), and the test suite on the oldest Node release in the `engines` range (22.13.0).
2. Confirm no credential, `.env`, vault database, key, log, backup, or user data is tracked.
3. Verify each container digest against its upstream source and required platforms.
4. Review documentation for absolute security, performance, comparison, cost, and compliance claims.
5. Perform independent security testing when the release will handle production or regulated credentials.
6. After the merge to `main`, approve the version that `publish-npm` staged on npmjs (npmjs.com, Staged Packages, or `npm stage approve <stage-id>`), then confirm `npm view hetzer version` shows it.

## Future work

- OS-backed key storage or external KMS integration;
- server-side Git scanning integration;
- stronger child-process isolation profiles (srt reaching the broker; a broker-only network profile for container engines);
- fuzzing for stream boundaries, encodings, scanners, and environment construction;
- signed release provenance and reproducible build evidence;
- third-party security review.
- Exfil-hardening backlog (proposed, pending review): capability broker expansion (DB proxy, cloud signing sidecar), short-lived audience-bound leases, canonical matcher for known secrets, auto-sandbox for agent ancestry, default-deny exec policy profiles — see `docs/rfc-exfil-hardening-backlog.md`.
