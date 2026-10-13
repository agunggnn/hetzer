<!-- hetzer:start -->
## 🛡️ Hetzer credential safety
- NEVER print secret tokens, passwords, or API keys in plaintext in conversation, code, or logs.
- Always use references: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).
- Execute with mediated scoping: `hetzer exec --allow <id> --strict -- <cmd>` (never run `creds reveal` or `printenv`).
- Raw injection requires the audited `--allow-raw-unmediated <id>` opt-out for local/non-brokerable credentials.
- `hetzer exec` mediates configured HTTP credentials and sanitizes guarded child output; it does not intercept unrelated tools or prompts.
- User management command: `hetzer creds set <id>`.
<!-- hetzer:end -->

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Package is `@agunggnn/hetzer` in this repo (the `shadow-core` directory name is legacy); releases ship to npmjs as unscoped `hetzer` (renamed when `scripts/package-stage.mjs` stages it) and to GitHub Packages as `@agunggnn/hetzer`, so user-facing install commands say `npm install -g hetzer`. Pure native-ESM JavaScript (`.mjs`), no build step, **zero runtime deps** (Node stdlib only, `node:sqlite` needs Node `^22.13.0 || >=23.4.0`, the first releases that load it without a flag). Architecture and security invariants live in @AGENTS.md; read it before touching `cli/vault/`.

## Commands
- Pre-PR gate: `npm run check && npm test && npm run verify -- --no-write`
- Single test file: `node --test cli/vault/exec.test.mjs` (tests are colocated `*.test.mjs`, `node:test`)
- `npm run verify` (without `--no-write`) **overwrites** the tracked `docs/verification-evidence.json`. Only run it bare when you intend to commit regenerated evidence.
- `npm run lint` runs ESLint (recommended rules, devDependency only; runtime stays zero-dep). Existing findings are warnings; don't add new ones. No formatter. Match existing style: 4-space indent, double quotes, semicolons, top-level named exports (no default exports).

## Gotchas
- Never write literal tokens in tracked files, including test fixtures. `npm run check` fails on credential-like patterns, so build them from pieces: `["gh","p_", ...].join("")`.
- `scripts/check.mjs` also bans legacy marker strings in public files (list in that script). Do not quote them, even in docs about them.
- Stream redactor in `cli/vault/exec.mjs` uses a small sliding buffer (`Math.max(128, longestSecret*2)`). Do not inflate it to 16KB.
- `shell: false` in the exec, broker and sandbox paths. Do not add shell-string execution there (`upgrade.mjs` and the release scripts do use a shell on Windows).
- Open design decisions live in `docs/adr/`. ADR-0001 (proposed) freezes new feature surface until the authority-model gates pass; check it before adding agent targets, modules or adapters.
- No absolute claims in code or docs (no "100% unbreakable", PCI-DSS, universal interception). Perf claims need measured cold-CLI vs steady-state p50/p95.
- After a security-control change, update `docs/verification-evidence.json` and `docs/system-logic-and-progress.md`. `scripts/verify-evidence.mjs` imports directly from vault modules, so API changes there can break it.
- New docs or scripts that must ship need an entry in `package.json` `"files"`.
- Version string is mirrored in `package.json`, `package-lock.json`, the `AGENTS.md` header, and `cli/mcp/{call,ping,protocol}.mjs`. Bump all together.
- Every merge to `main` releases: `release-main.yml` tags, creates the GitHub Release, publishes to GitHub Packages, and its `publish-npm` job stages `hetzer` on npmjs through trusted publishing (OIDC, no token). npmjs.com trusts that workflow by filename, so do not rename `release-main.yml` or move `publish-npm` into a reusable workflow. A maintainer approves each staged version with 2FA.

## Git
- Never commit to `main`. Branch as `<type>/<short-desc>`.
- Conventional commits with scope and PR number, e.g. `fix(exec): ... (#34)`.
- User-facing errors and logs are in English.
