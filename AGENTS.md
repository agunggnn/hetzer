# Hetzer Contributor & Agent Guidance

> **Version**: v0.4.16 | **Verify**: `npm run check && npm test && npm run verify`

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
9. **No False Claims**: Defense-in-depth security layer. Do not claim PCI-DSS 6.4.3 or "100% unbreakable". All claims verified via `npm run verify`.

---

## 📝 Pending Agent Review (For Codex)
Review branches sequentially in stack order:
1. **[PR #10](https://github.com/agunggnn/hetzer/pull/10)** (`feat/mcp-proxy-security-hardening` -> `main`): Security Hardening for MCP Virtual Credential Proxy. (173 tests)
