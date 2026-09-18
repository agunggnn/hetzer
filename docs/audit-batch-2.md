# 🛡️ Hetzer Security Hardening: Batch 2 Implementation & Audit Verification

> **Status**: Completed & Empirically Verified | All Audit Review Findings Addressed  
> **Target Version**: `@agunggnn/hetzer` v0.5.6  
> **Working Branch**: `feat/security-hardening-v0.5.6`  
> **Test Suite**: 100% Pass (0 failures) | `npm test` & `npm run check`  
> **Empirical Protocols**: 7/7 NIST SP 800-115 / OWASP ASVS Protocols Pass (`npm run verify`)  
> **Diff Hygiene**: `git diff --check` Clean (Exit Code 0)  

---

## Executive Summary

Batch 2 expands Hetzer's core runtime armor, HTTP loopback broker containment, and MCP virtual credential proxy. In addition to scheduled items (**SEC-05** through **SEC-08**), this implementation directly resolves all **5 critical audit findings** (including the residual multi-encoding traversal edge case) identified during independent security review.

---

## 🔍 Resolution of Audit Findings

### Finding 1 (High): Route Traversal Bypass & Residual Multi-Encoding Traversal
- **Vulnerability**: Path traversal was possible via backslashes (`..\..\rest`), standard percent-encoded dot segments (`%2e%2e/%2e%2e/rest`), and deep multi-encoding layers (`%2525252e%2525252e/rest`). A fixed-loop decode stopping early left `%2e%2e` in the path, which `new URL()` subsequently normalized to navigate outside the allowed route prefix.
- **Fix Implemented (`cli/mcp/catalog.mjs`)**:
  - Unified path separators by converting all backslashes (`\`) to forward slashes (`/`).
  - Blocked encoded path delimiters upfront (`%2f`, `%5c`, `%00`).
  - Implemented iterative percent-decoding up to a fixed point with `MAX_DECODE_PASSES = 5`.
  - Rejects inputs exceeding the pass limit (`Excessive percent-encoding layers`).
  - Enforced strict residual percent-encoding check after the loop: `if (/%[0-9a-fA-F]{2}|%/i.test(currentPath)) throw new Error('Residual percent-encoding detected.')`.
  - Re-checked for nested encoded delimiters after each decoding step.
  - Strictly rejected null bytes (`\0`), query parameters (`?`), and fragments (`#`).
  - Validated canonical path (`path.posix.normalize`) against `allowedPrefixes` (tool path and webhook prefixes).
- **Regression Tests (`cli/mcp/protocol.test.mjs`)**:
  - Confirmed rejection of `../../rest/admin`, `..\..\rest\admin`, `%2e%2e/%2e%2e/rest/admin`, `%2e%2e%2f%2e%2e%2frest%2fadmin`, `%252e%252e/%252e%252e/rest/admin`, `%2525252e%2525252e/rest`, excessive layers (`%2525252525252e...`), nested delimiters (`subpath%25252ftest`), null bytes, and query parameters.

### Finding 2 (High): Authentication Header Overwrite Ambiguity & Proxy Header Injection
- **Vulnerability**: Case-sensitive header checking allowed injected lowercase `authorization` to conflict with portal headers, producing duplicate headers or parser ambiguity; arbitrary `proxy-*` headers were passed unconstrained.
- **Fix Implemented (`cli/mcp/catalog.mjs`)**:
  - All portal authentication header names are converted to lowercase and recorded in `protectedHeaders`.
  - Added `authorization` and `x-api-key` to default protected headers.
  - In caller-supplied `args.headers`, all header names are trimmed and lowercased.
  - Any header present in `protectedHeaders`, starting with `proxy-`, or listed in forbidden hop-by-hop headers (`host`, `connection`, `te`, `cookie`, etc.) is strictly filtered out.
- **Regression Tests (`cli/mcp/protocol.test.mjs`)**:
  - Verified that mixed-case `Authorization`, `authorization`, `X-Api-Key`, and `x-api-key` cannot overwrite vault portal credentials.
  - Verified that `Proxy-Authorization` and `proxy-custom-header` are completely stripped.
  - Verified that legitimate custom headers (`X-Safe-Header`) are preserved and delivered.

### Finding 3 (High): MCP Tool Credential Scoping Enforcement
- **Vulnerability**: Tool execution in `catalog.call` passed `targetId: entry.projectId` to `vault.resolve()`, bypassing cross-service scoping because credentials were only checked against their own project ID.
- **Fix Implemented (`cli/mcp/catalog.mjs`)**:
  - Synthesized service tools now declare `permittedTargets` (containing `service.id`, `service.moduleId`, `service.mcpServer?.name`, `service.composeService`, `"global"`, `"shared"`).
  - In `catalog.call`, `entry.projectId` is verified against `tool.permittedTargets` prior to resolution:
    ```javascript
    const permittedTargets = tool.permittedTargets || new Set(["global", "shared"]);
    if (!permittedTargets.has(entry.projectId)) {
        throw new Error(`Credential 'secretRef:${id}' (target '${entry.projectId}') is not permitted for service '${tool.serviceId || name}'.`);
    }
    ```
- **Regression Tests (`cli/mcp/protocol.test.mjs`)**:
  - Verified that a tool for `test-sec` rejects credentials scoped to `other-unauthorized-target` with an explicit authorization error.
  - Verified that credentials matching the tool's permitted targets resolve properly.

### Finding 4 (Medium): Git Worktree Hook Installation
- **Vulnerability**: In Git worktrees where `.git` is a pointer file, hooks were incorrectly written to `.git/worktrees/<wt>/hooks` instead of the repository's common hooks directory.
- **Fix Implemented (`cli/core/git-hook.mjs`)**:
  - Added `resolveGitCommonDir(gitDir)`: parses `commondir` inside worktree git directories to resolve the shared root `.git/`.
  - `installGitHook` and `uninstallGitHook` use `resolveGitCommonDir` to install and uninstall `pre-commit` and `commit-msg` hooks in the common `.git/hooks` directory.
- **Regression Tests (`cli/core/git-hook.test.mjs`)**:
  - Tested installation and uninstallation inside a simulated worktree checkout.
  - Verified hooks are placed into the main repository's `.git/hooks` and not in `worktrees/<branch>/hooks`.

### Finding 5 (Medium): Shared Catalog Object Secret Exposure
- **Vulnerability**: `catalog.lastResolvedSecrets` retained plaintext credentials on the catalog instance after tool invocation.
- **Fix Implemented (`cli/mcp/catalog.mjs`)**:
  - Removed `this.lastResolvedSecrets = collectedSecrets;`.
  - Plaintext credentials are provided only through `requestContext.secretsToRedact` for single-request output sanitization and never stored in catalog state.
- **Regression Tests (`cli/mcp/protocol.test.mjs`)**:
  - Verified `catalog.lastResolvedSecrets` is `undefined`.

---

## 📦 Scheduled Batch 2 Deliverables (SEC-05 - SEC-08)

1. **[SEC-06] Broker CLI `--env-file` Omission & Quota Refund**:
   - `cli/vault/http-broker.mjs`: Added guard `envFile: value("--env-file") ? path.resolve(value("--env-file")) : undefined` preventing `EISDIR`/`EPERM` crash when `--env-file` is omitted.
   - Added quota slot refund on early SSRF, DNS, or authorization rejection, preventing malicious quota exhaustion.
2. **[SEC-07] Sniffer Scheme Expansion & Base64 Variant Redaction**:
   - `cli/vault/sniffer.mjs`: Added detection rules and fast prefixes for `rediss://`, `mariadb://`, `amqp://`, and `amqps://`. Case-insensitive prefix scanning.
   - `cli/mcp/protocol.mjs` & `cli/vault/http-broker.mjs`: Added Base64 variant generation to secret expansion pipelines (`expandSecretVariants`, `getSecretRepresentations`).
3. **[SEC-08] Sensitive Path Guard & Downloader Containment**:
   - `cli/vault/exec-policy.mjs`: Added blocking rules for Kubernetes (`.kube/config`), Docker (`.docker/config.json`), browser DPAPI master key (`Local State`), and SSH configs.

---

## 📊 Verification Metrics

| Check | Target | Result | Notes |
|---|---|---|---|
| **Unit Tests** | `node --test` | **PASS** | 200+ tests passing, 0 failures |
| **Static Linter** | `npm run check` | **PASS** | 97 source files checked, 0 errors |
| **NIST / OWASP Verification** | `npm run verify` | **PASS (7/7)** | All 7 protocols passed |
| **Diff Whitespace** | `git diff --check` | **PASS** | 0 whitespace or formatting errors |
