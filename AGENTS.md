# Hetzer Contributor & Agent Guidance

> **Current Package Version**: v0.4.2
> **Verification**: Run `npm run check`, `npm test`, and `npm run verify` against the current tree; do not rely on a cached test count.

---

## 📌 Latest System State & Critical Architecture Context

Any AI model or developer working on this codebase MUST respect the following verified architectural realities:

1. **Stream Redactor & Output Buffer (`cli/vault/exec.mjs`)**:
   - Uses a dynamic sliding buffer `Math.max(128, longestSecret * 2)` with a bounded 512-character window scan.
   - Normalizes terminal control characters and incrementally suppresses supported long private-key, credentialed database URL, and provider-token output on both stdout and stderr.
   - **DO NOT** inflate this retention buffer (e.g. to 16 KB); large buffers cause terminal freeze and withhold real-time stdout.
2. **Strict Environment Scoping (`cli/vault/secret-env.mjs`)**:
   - The `--strict` flag isolates child processes using `strictBaseEnvironment`. All unapproved parent env tokens and `HETZER_GRIMOIRE_KEY` are stripped; only explicitly allowed credentials via `--allow` are resolved.
3. **Git Pre-Commit Hook (`cli/core/git-hook.mjs`)**:
   - Scans multiline staged additions for private keys, database URLs, and raw tokens.
   - Test files (`*.test.mjs`, `verify-evidence`) and agent lifecycle IDs (`call_...`, `tool_...`, `chunk_...`, `session_...`) are strictly exempted to prevent false-positive `exit 1` commit deadlocks.
4. **Process Ancestry & Reveal Guard (`cli/vault/creds.mjs`)**:
   - Inspects 5 process generations across Windows (`Win32_Process`) and Unix-like platforms (`ps`).
   - Non-interactive bypasses are forbidden. Native OS dialog confirmation is required for human reveals.
5. **Canary Honey-Token Tripwire (`cli/vault/canary.mjs`)**:
   - Tripping decoy tokens (`canary-token`, `canary-*`, `decoy-*`) logs an incident, attempts an SQLite audit entry when a vault exists, and aborts with `exitCode 43` (`ERR_CANARY_TRIPWIRE_TRIGGERED`).
   - Canaries only protect guarded resolution/reveal paths, NOT arbitrary OS disk access.
6. **No Unverified Marketing / False Compliance Claims**:
   - **DO NOT** claim PCI-DSS 6.4.3 compliance (it governs payment page scripts, not pre-commit hooks).
   - **DO NOT** claim universal "100% unbreakable" guarantees. Hetzer is an empirical defense-in-depth security layer.
   - All claims must be backed by reproducible empirical tests via `npm run verify`.
7. **Branding & Terminal Identity**:
   - Banner is terminal-native ANSI Shadow block art (`HETZER`) in `assets/hetzer-banner.jpg` and `cli/core/banner.mjs`. Do not revert to AI-illustrated pictorial drawings.

---

<!-- hetzer:start -->
## 🛡️ Hetzer credential safety
- NEVER print secret tokens, passwords, or API keys in plaintext in conversation, code, or logs.
- Always use references: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).
- Execute with scoped injection: `hetzer exec --allow <id> --strict -- <cmd>` (never run `creds reveal` or `printenv`).
- `hetzer exec` scopes referenced credentials and sanitizes guarded child output; it does not intercept unrelated tools or prompts.
- User management command: `hetzer creds set <id>`.
<!-- hetzer:end -->

---

## 🛠️ Verification & Contributor Checklist

Before committing or concluding any turn:
1. `npm run check` — Must pass (validates source syntax and forbidden token leak checks; it does not rerun tests).
2. `npm test` — Must pass; use the current command output rather than a cached test count.
3. `npm run verify` — Must pass all 6 empirical protocols (`docs/verification-evidence.json`).
4. Pin container images by multi-platform digest and document their upstream source.
5. Keep Linux, macOS, and Windows behavior equivalent; prefer Node APIs over shell-specific code.
