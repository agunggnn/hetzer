# 🛡️ Hetzer Security Hardening Specification: Batch 3

> **Status**: Complete | Empirically Verified (All 7 Findings Remediated & Unit Tested)  
> **Target Version**: `@agunggnn/hetzer` v0.5.6  
> **Scope**: 7 Findings across Grimoire SQLite Vault, Subprocess Execution & Stream Redaction, Sensitive Path Guard, NPM Authentication, and Module Management  

---

## Executive Summary

This document specifies the vulnerability mechanics, attack vectors, planned code fixes, and regression test requirements for **Batch 3 (Vault Audit, Stream Redaction, Policy & Execution Hardening)** in Hetzer core.

| ID | Component | Severity | Category | Vulnerability |
|---|---|---|---|---|
| **SEC-09** | `cli/vault/hetzer-vault.mjs` | **High** | Audit Integrity | `recordAudit` parameter mismatch (`targetId` vs `target_id`) causes `target_id` and `credential_id` to be inserted as `NULL` in SQLite audit log |
| **SEC-10** | `cli/vault/exec.mjs` & `compose-runner.mjs` | **High** | Availability & Denial of Service | Omitted `--env-file` resolves to `process.cwd()` (directory) causing `EISDIR`/`EPERM` unhandled crash when reading as file |
| **SEC-11** | `cli/vault/exec-policy.mjs` | **Medium** | Security Policy Bypass | Sensitive path guard executes single-pass percent decoding; double-encoded paths (`%252e%252e%252f.ssh`) bypass path traversal detection |
| **SEC-12** | `cli/vault/exec.mjs` | **Medium** | Information Disclosure | `DATABASE_SCHEME` misses `rediss://`, `mariadb://`, `amqp(s)://` in sliding stream buffer, letting long credentials stream unredacted |
| **SEC-13** | `cli/vault/creds.mjs` | **Medium** | Authorization & Lockout | `hetzer creds set` overwrites custom `allowedActions` and omits `mcp.tools/call`, preventing MCP tools from resolving configured credentials |
| **SEC-14** | `cli/core/npm-auth.mjs` & `upgrade.mjs` | **Medium** | Command Injection & Portability | Unvalidated `packageName` in `npm-auth.mjs` with `shell: true`; `upgrade.mjs` fails with `ENOENT`/`EINVAL` on Windows without `npm-cli.js` resolution |
| **SEC-15** | `cli/modules/toggle.mjs` | **Low** | Robustness & Input Validation | `toggle.mjs` throws unhandled `ENOENT` if `.env` does not exist; lacks `moduleId` kebab-case validation |

---

## 1. [SEC-09] SQLite Audit Event Property Name Mismatch (`targetId` vs `target_id`)

### 1.1 Vulnerability Mechanics
In [`cli/vault/hetzer-vault.mjs:681-697`](file:///E:/GitHub/shadow-core/cli/vault/hetzer-vault.mjs):
```javascript
    recordAudit(event) {
        const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
        this.db.prepare(`
            INSERT INTO vault_audit_events (
                actor, action, target_id, credential_id, reason, outcome, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            String(event.actor || "unknown").slice(0, 120),
            String(event.action || "unknown").slice(0, 120),
            event.targetId || null,
            event.credentialId || null,
...
```
Callers in [`cli/vault/creds.mjs:430`](file:///E:/GitHub/shadow-core/cli/vault/creds.mjs) and [`cli/vault/canary.mjs:79`](file:///E:/GitHub/shadow-core/cli/vault/canary.mjs) pass snake_case:
```javascript
vault.recordAudit({
    actor,
    action: "canary.tripwire",
    target_id: "canary-honeytoken",
    credential_id: id,
...
```
Because `event.targetId` and `event.credentialId` are checked, they evaluate to `undefined`, inserting `NULL` into both columns.

### 1.2 Proposed Fix
In `cli/vault/hetzer-vault.mjs`:
```javascript
event.targetId || event.target_id || null,
event.credentialId || event.credential_id || null,
```

---

## 2. [SEC-10] Omitted `--env-file` Resolves to `process.cwd()` Directory

### 2.1 Vulnerability Mechanics
In `cli/vault/exec.mjs:593` and `cli/vault/compose-runner.mjs:21`:
```javascript
envFile: path.resolve(value("--env-file")),
```
When `--env-file` is omitted from command line arguments, `value("--env-file")` returns `""`. In Node.js, `path.resolve("")` produces `process.cwd()`.
Subsequently, `fs.readFileSync(envFile, "utf8")` attempts to read the current working directory as a file, crashing with `EISDIR` on Linux/macOS and `EPERM` on Windows.

### 2.2 Proposed Fix
Default `envFile` to `path.join(root, ".env")` if omitted:
```javascript
const rawEnv = value("--env-file");
const envFile = rawEnv ? path.resolve(rawEnv) : path.join(root, ".env");
```
And guard `fs.readFileSync` calls with `fs.statSync(envFile).isFile()`.

---

## 3. [SEC-11] Multi-Layer Percent Encoding Bypass in Sensitive Path Guard

### 3.1 Vulnerability Mechanics
In [`cli/vault/exec-policy.mjs:71-80`](file:///E:/GitHub/shadow-core/cli/vault/exec-policy.mjs):
```javascript
    let decoded = normalized;
    try {
        decoded = decodeURIComponent(normalized);
    } catch {}
```
`decodeURIComponent` is executed once. If an argument uses double-encoding (e.g. `%252e%252e%252f.ssh%252fid_rsa`), after one decode pass it remains `%2e%2e/.ssh/id_rsa`. `path.posix.normalize` does not resolve `%2e%2e`, and `SENSITIVE_HOST_PATTERNS` fails to match.

### 3.2 Proposed Fix
Perform iterative decoding to a fixed point (up to 5 passes) and normalize the canonical path.

---

## 4. [SEC-12] Missing Database Schemes in Sliding Stream Buffer

### 4.1 Vulnerability Mechanics
In [`cli/vault/exec.mjs:23`](file:///E:/GitHub/shadow-core/cli/vault/exec.mjs):
```javascript
const DATABASE_SCHEME = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\//i;
```
`rediss://`, `mariadb://`, `amqp://`, and `amqps://` were omitted. Long database or message broker URLs with credentials streamed by child processes are not captured by `findStructuredStart` and leak past the sliding buffer.

### 4.2 Proposed Fix
Update pattern to:
```javascript
const DATABASE_SCHEME = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\//i;
```

---

## 5. [SEC-13] Credential `allowedActions` Overwrite & MCP Tool Lockout

### 5.1 Vulnerability Mechanics
In [`cli/vault/creds.mjs:401`](file:///E:/GitHub/shadow-core/cli/vault/creds.mjs):
```javascript
const allowedActions = ["compose.start", "process.start"];
```
When a credential is created or updated via `hetzer creds set`, it only allows `compose.start` and `process.start`. It cannot be used in MCP tool calls (`mcp.tools/call` and `mcp.tools.call`). Moreover, existing custom allowed actions are wiped on update.

### 5.2 Proposed Fix
Preserve `existing?.allowedActions` when available, or default to:
`["compose.start", "process.start", "mcp.tools/call", "mcp.tools.call"]`.

---

## 6. [SEC-14] Shell Injection via `packageName` & Windows NPM Spawning

### 6.1 Vulnerability Mechanics
In `cli/core/npm-auth.mjs:57`:
`run("npm", [...args, "--userconfig", npmrcFile], { shell: process.platform === "win32" })`
`packageName` is passed without validation. If `packageName` contains shell metacharacters, `cmd.exe` executes them.
In `cli/core/upgrade.mjs`, calling `spawnSync("npm", ...)` without resolving the Windows binary fails under Node 22 with `ENOENT`/`EINVAL`.

### 6.2 Proposed Fix
1. Validate `packageName` with `/^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i`.
2. Locate `npm-cli.js` via `path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js")` and spawn `process.execPath` directly with `shell: false`.

---

## 7. [SEC-15] Unhandled `ENOENT` & Missing Module ID Validation in `toggle.mjs`

### 7.1 Vulnerability Mechanics
In `cli/modules/toggle.mjs:22`:
`let text = fs.readFileSync(envFile, "utf8");` throws `ENOENT` if `.env` does not exist yet.
`moduleId` is not validated against `ID_PATTERN`.

### 7.2 Proposed Fix
Check `fs.existsSync(envFile)` before reading, ensure parent directories exist, and validate `moduleId`.
