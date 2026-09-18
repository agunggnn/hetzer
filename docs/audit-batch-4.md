# 🛡️ Hetzer Security Hardening Specification: Batch 4

> **Status**: Verified & Implemented | All 7 Findings Resolved & Tests Passing<br>
> **Target Version**: `@agunggnn/hetzer` v0.5.6<br>
> **Scope**: 7 Findings across Git Commit Hook, Container Sandbox Broker Bridging, CLI Upgrader, Brokered Process Timeouts, MCP Canary Tripwire, and Sniffer Identifiers

---

## Executive Summary

This document specifies the vulnerability mechanics, attack vectors, planned code fixes, and regression test requirements for **Batch 4 (Audit Completion & Final Hardening)** in Hetzer core.

| ID | Component | Severity | Category | Vulnerability |
|---|---|---|---|---|
| **SEC-16** | `cli/core/git-hook.mjs` | **High** | Secret Detection Bypass | `checkCommitMessage` strips all lines starting with `#`, allowing credentials in issue references (e.g. `#104: key`) or Markdown headers (`# Title key`) to commit unredacted |
| **SEC-17** | `cli/vault/http-broker.mjs` & `exec.mjs` | **High** | Container Sandbox Isolation | Broker strictly binds `127.0.0.1` and rejects non-loopback IPs; container sandbox bridged via `host.docker.internal` is rejected with 403, preventing sandboxed agent broker execution |
| **SEC-18** | `cli/core/upgrade.mjs` | **Medium** | Portability & Reliability | Validates `activeBranch === "main" \|\| activeBranch === "master"`, but hardcodes `git pull origin main`, breaking repositories with `master` default branch |
| **SEC-19** | `cli/vault/http-broker.mjs` | **Medium** | Availability & Runaway Execution | `executeBrokeredProcess` fails to forward `timeoutMs` to `pipeSanitizedChild`, failing to enforce execution timeout budgets on brokered child processes |
| **SEC-20** | `cli/mcp/protocol.mjs` | **Medium** | Canary Tripwire Containment | FastMCP tool execution handler intercepts `ERR_CANARY_TRIPWIRE_TRIGGERED` and returns a JSON-RPC error response instead of triggering process termination with exit code 43 |
| **SEC-21** | `cli/mcp/call.mjs` | **Low** | Robustness & Error Handling | `JSON.parse(args)` throws unhandled `SyntaxError` without standard `ERR_INVALID_TOOL_ARGUMENTS` error code on malformed tool input |
| **SEC-22** | `cli/vault/sniffer.mjs` | **Low** | False Alarm Reduction | Anthropic Claude tool use identifiers (`toolu_...`) omitted from `NON_SECRET_PREFIXES`, causing false alarms in pre-commit hooks |

---

## 1. [SEC-16] Commit-Msg Hook `#` Comment-Line Secret Detection Bypass

### 1.1 Vulnerability Mechanics
In [`cli/core/git-hook.mjs:164`](file:///E:/GitHub/shadow-core/cli/core/git-hook.mjs):
```javascript
for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trimStart().startsWith("#")) {
        activeLines.push({ line: index + 1, text: line });
    }
}
```
Git status comments generated in `.git/COMMIT_EDITMSG` begin with `# ` (e.g. `# Please enter the commit message...`, `# On branch main`).
However, legitimate commit lines often begin with `#` (e.g. issue references `#104: fix api key sk-ant-...` or Markdown headers `# Release with token ghp_...`).
Because all lines where `line.trimStart().startsWith("#")` are skipped, raw credentials on these lines completely bypass commit message scanning.

### 1.2 Proposed Fix
Differentiate Git template status comments from user content:
Only skip lines matching standard Git status comment patterns, or scan lines for high-confidence secrets (API keys, private keys, database URLs, and provider tokens) regardless of leading `#`.

---

## 2. [SEC-17] Container Sandbox Bridging to Host HTTP Credential Broker

### 2.1 Vulnerability Mechanics
In `cli/vault/http-broker.mjs`:
- Line 681: `if (host !== "127.0.0.1") throw new Error("Credential broker must bind to 127.0.0.1.");`
- Line 699: `if (!isLoopback(request.socket.remoteAddress)) return sendJson(response, 403, "Loopback clients only.");`

In `cli/vault/sandbox.mjs:103`, environment variables translating loopback use `host.docker.internal`.
When a container in the ephemeral sandbox attempts to access the broker via `host.docker.internal`, the host Docker/Podman bridge routes the request with a container network IP (e.g. `172.17.0.2` or gateway `172.17.0.1`).
The broker rejects the connection with 403 "Loopback clients only." or fails to receive packets if not listening on the bridge network interface.

### 2.2 Proposed Fix
Add `allowSandbox` option to `startHttpCredentialBroker` and `openHttpCredentialBroker`.
When `allowSandbox` is enabled:
1. Broker binds to `0.0.0.0`.
2. Broker permits incoming connections from private container network addresses (RFC 1918 subnets `172.16.0.0/12`, `10.0.0.0/8`, `192.168.0.0/16`) in addition to loopback, strictly verified via the cryptographically secure 32-byte capability bearer token.
3. When `allowSandbox` is false (default), the broker strictly preserves `127.0.0.1` binding and loopback-only client checks.

---

## 3. [SEC-18] Upgrader Hardcodes `origin main` on `master` Branches

### 3.1 Vulnerability Mechanics
In [`cli/core/upgrade.mjs:81-103`](file:///E:/GitHub/shadow-core/cli/core/upgrade.mjs):
```javascript
if (activeBranch && activeBranch !== "main" && activeBranch !== "master") {
...
const pullRes = spawnFn("git", ["pull", "origin", "main"], {
```
If the user's repository uses `master`, the script validates the branch but attempts `git pull origin main`, causing git pull to fail or create unintended divergent history.

### 3.2 Proposed Fix
Use `activeBranch || "main"` dynamically:
```javascript
const pullRes = spawnFn("git", ["pull", "origin", activeBranch || "main"], {
```

---

## 4. [SEC-19] Timeout Budget Forwarding in Brokered Execution

### 4.1 Vulnerability Mechanics
In [`cli/vault/http-broker.mjs:928-931`](file:///E:/GitHub/shadow-core/cli/vault/http-broker.mjs):
```javascript
return await pipeSanitizedChild(child, [
    { id: policy.credentialId, secret },
    { id: "broker-capability", secret: broker.capability },
], { outStream, errStream });
```
`options.timeoutMs` and `options.root` are not forwarded to `pipeSanitizedChild`.
If a brokered child process hangs or exceeds its configured timeout budget, it is never terminated.

### 4.2 Proposed Fix
Forward `timeoutMs` and `root` in options to `pipeSanitizedChild`.

---

## 5. [SEC-20] FastMCP Canary Tripwire Containment

### 5.1 Vulnerability Mechanics
In [`cli/mcp/protocol.mjs:187-196`](file:///E:/GitHub/shadow-core/cli/mcp/protocol.mjs):
When `catalog.call` triggers an `ERR_CANARY_TRIPWIRE_TRIGGERED` error, the catch block intercepts it, formats it into an `{ isError: true, content: [...] }` JSON-RPC response, and allows the MCP session to continue normally.
Per Hetzer's canary tripwire specification, honeytoken access must abort execution immediately with exit code 43.

### 5.2 Proposed Fix
In `cli/mcp/protocol.mjs`, rethrow when `cause?.code === "ERR_CANARY_TRIPWIRE_TRIGGERED"`.

---

## 6. [SEC-21] MCP Tool Argument Parsing Error Normalization

### 6.1 Vulnerability Mechanics
In [`cli/mcp/call.mjs:250-252`](file:///E:/GitHub/shadow-core/cli/mcp/call.mjs):
When `JSON.parse(args)` fails, the error lacks a distinct `code` property, preventing callers from distinguishing argument formatting errors from service/vault errors.

### 6.2 Proposed Fix
Attach `err.code = "ERR_INVALID_TOOL_ARGUMENTS"` to the error.

---

## 7. [SEC-22] Anthropic Claude Tool ID Exemption in Sniffer

### 7.1 Vulnerability Mechanics
In [`cli/vault/sniffer.mjs:137-140`](file:///E:/GitHub/shadow-core/cli/vault/sniffer.mjs):
`NON_SECRET_PREFIXES` includes `call_`, `tool_`, `chunk_`, `resp_`, `turn_`, `session_`, but omits Anthropic's standard tool use ID format `toolu_[A-Za-z0-9_]{20,}`.
High-entropy Shannon checks trigger false alarms on Anthropic agent logs in git diffs.

### 7.2 Proposed Fix
Add `"toolu_"` to `NON_SECRET_PREFIXES`.
