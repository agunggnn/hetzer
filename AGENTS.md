# Hetzer Contributor & Agent Guidance

> **Version**: v0.5.7 | **Verify**: `npm run check && npm test && npm run verify`

---

<!-- hetzer:start -->
## 🛡️ Hetzer credential safety
- NEVER print secret tokens, passwords, or API keys in plaintext in conversation, code, or logs.
- Always use references: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).
- Execute with mediated scoping: `hetzer exec --allow <id> --strict -- <cmd>` (never run `creds reveal` or `printenv`).
- Raw injection requires the audited `--allow-raw-unmediated <id>` opt-out for local/non-brokerable credentials.
- `hetzer exec` mediates configured HTTP credentials and sanitizes guarded child output; it does not intercept unrelated tools or prompts.
- User management command: `hetzer creds set <id>`.
<!-- hetzer:end -->

---

## 📌 Architecture & Safety Boundaries
1. **Stream Redactor (`cli/vault/exec.mjs`)**: Sliding buffer `Math.max(128, longestSecret * 2)` with 512B window scan. Suppresses private keys, database URLs, and provider tokens. Do NOT inflate to 16KB.
2. **Strict Scoping (`cli/vault/secret-env.mjs`)**: `--strict` strips unapproved parent env vars and master key. Only `--allow` credentials resolve.
3. **Git Hooks (`cli/core/git-hook.mjs`)**: Pre-commit exempts fixtures (`*.test.mjs`, `test/`) and agent IDs (`call_*`, `tool_*`). Commit-msg blocks tokens in commit text.
4. **MCP Proxy (`cli/mcp/`)**: Agents pass `secretRef:<id>`; runtime resolves vault credentials just-in-time and sanitizes outputs.
5. **Canary Tripwire (`cli/vault/canary.mjs`, `cli/vault/exec.mjs`)**: Honeytokens (`canary-token`, `canary-*`, `decoy-*`, `canary_trap_*`) abort with `exitCode 43` (`ERR_CANARY_TRIPWIRE_TRIGGERED`). `hetzer exec --canary` injects `HETZER_CANARY_TOKEN`; stream leaks immediately terminate child processes.
6. **Timeout Guard (`cli/vault/exec.mjs`)**: `--timeout <duration>` (e.g. `30s`, `5m`, `10000ms`) terminates hanging subprocesses with SIGTERM followed by tree-kill (`taskkill /T /F` on Windows, `SIGKILL` on Unix) and exits with code 124 (`ERR_SUBPROCESS_TIMEOUT`).
7. **Execution Policy (`cli/vault/exec-policy.mjs`)**: `--policy <path>` restricts child execution via exact structured `argv` rules, rejects shell metacharacters (`&`, `|`, `;`, `<`, `>`, `$`, `%`), executes with `shell: false`, and validates policy trust roots via SHA-256 integrity hashes.
8. **HTTP Credential Broker (`cli/vault/http-broker.mjs`)**: Short-lived loopback proxy injecting upstream secrets. Enforces bounded fixed-point path canonicalization (blocking matrix parameters `;` and directory traversal), dynamic RFC 7230 hop-by-hop connection stripping, atomic quota reservation, and multi-representation secret redaction.
9. **Sensitive Host Path & Downloader Guard (`cli/vault/exec-policy.mjs`)**: Blocks access to host browser cookies (`%LOCALAPPDATA%`, Chrome, Edge, Brave, Opera), crypto wallets (`solana/id.json`, Exodus), SSH/cloud credentials, and Living-Off-The-Land downloaders (`certutil -urlcache`, `bitsadmin`, `mshta`, `irm | iex`).
10. **Ephemeral Container Sandbox (`cli/vault/sandbox.mjs`)**: `hetzer exec --sandbox [image]` isolates untrusted agent executions inside transient containers (`--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit=100`, unmounting host AppData and home directories) while bridging loopback HTTP credential broker upstream (`host.docker.internal`).
11. **Pure Armor & Ops Separation**: Hetzer focuses on single-command runtime armor, stream redaction, and container isolation. Multi-container stack orchestration is deprecated in Hetzer core and delegated to [Jagdpanzer](https://github.com/agunggnn/jagdpanzer).
12. **No False Claims**: Defense-in-depth security layer. Do not claim PCI-DSS 6.4.3 or "100% unbreakable". All claims verified via `npm run verify`.
13. **Cryptographic Audit Ledger (`cli/vault/audit.mjs`)**: Append-only JSONL event log with SHA-256 hash chaining (`prevHash`) recording execution, canary trips, sensitive path denials, SSRF blocks, and credential approvals. Tamper verification via `hetzer audit verify`.
14. **Anti-SSRF & Reserved IP Containment (`cli/vault/http-broker.mjs`)**: Enforces DNS and IP boundaries rejecting loopback (`127.0.0.0/8`), private RFC 1918 subnets, and cloud instance metadata services (`169.254.169.254`).
15. **Universal OCI Container Engine (`cli/vault/sandbox.mjs`)**: Auto-probes Docker and Podman with Linux SELinux `:Z` mounts and loopback bridge mapping (`host.docker.internal` / `host.containers.internal`).
16. **Same-User Agentic Reveal Guard & Ancestry Inspection (`cli/vault/human-guard.mjs`, `cli/vault/hetzer-vault.mjs`)**: Blocks automated agents under the same OS user account from dumping plaintext secrets via direct `Grimoire.reveal()` or programmatic imports, while decoupling `#decryptRaw` and `resolve()` so that `hetzer exec`, HTTP brokers, and MCP proxies operate without human TTY interruption. Caches process ancestry tree scans for sub-ms execution.
17. **Master Key Isolation Precedence & Separation (`cli/vault/hetzer-vault.mjs`)**: `isolateMasterKey` moves encryption keys from workspace `.env` to `~/.hetzer/grimoire.key` with restrictive ACLs (0600) to protect against agent workspace read operations. `resolveMasterKey` enforces deterministic precedence (runtime env -> local `.env` -> isolated user store fallback).

---

## 📝 Pending Agent Review & PR Stack
Review and merge open PRs in order:
1. **[PR #31](https://github.com/agunggnn/hetzer/pull/31)** (`fix/agent-reveal-block-same-user` -> `main`): Block same-user agentic reveal without breaking internal broker and execution. (282 tests, SEC-23 & SEC-24 resolved)
2. **[PR #29](https://github.com/agunggnn/hetzer/pull/29)** (`perf/in-process-exec-and-benchmark-calibrations` -> `main`): Execute `hetzer exec` in-process directly and calibrate benchmark claims. (0 merge conflicts with PR #31)
3. **[PR #30](https://github.com/agunggnn/hetzer/pull/30)** (`feat/tui-flicker-free-refresh-and-alt-screen` -> `main`): Tactical HUD ASCII banner, issue analyzer, and remediation guide. (Requires rebase onto updated `main` to resolve `hetzer-vault.mjs` conflicts)
