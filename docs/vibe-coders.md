# Practical credential-safety guide

Hetzer helps reduce accidental credential exposure while working with coding agents. It does not automatically inspect every prompt, file, command, or tool available to an agent.

## Set up a workspace

```bash
npx hetzer protect
```

This installs supported agent guidance, adds a pre-commit hook when the directory is a Git repository, and attempts to migrate supported plaintext `.env` values into the local vault. Review the command output: migration and auto-vault operations can report values that were redacted but not stored.

For individual actions:

```bash
npx hetzer skill install
npx hetzer hook install
npx hetzer creds set openai-api-key
```

Enter credentials only through the masked `creds set` prompt. Store `secretRef:<id>` values in configuration.

## Run a command with one credential

```bash
hetzer exec --allow openai-api-key --strict -- node app.js
```

`--strict` supplies a minimal inherited environment and adds only allowed vault references from the configured `.env`. Some tools need extra non-secret environment settings; configure those explicitly rather than disabling scoping without review.

Hetzer sanitizes known injected values and supported scanner candidates in child stdout/stderr, including values divided across stream chunks. It uses a bounded buffer, so output can be delayed. Encoded, transformed, unsupported, or externally emitted values may still leak; keep normal application logging and network controls.

## Before committing

```bash
hetzer hook check
git diff --cached
```

The hook blocks staged `.env` variants and supported candidates in added text. It can produce false positives and false negatives, and Git hooks can be bypassed. Repositories that require enforcement should also scan on the server or in CI.

## Agent boundary

Installed skill files tell supported agents to use references and avoid plaintext. Hetzer's MCP server exposes vault metadata and existence checks but no plaintext reveal tool. An agent with general shell, file, debugger, or process access still operates with the permissions of its OS account.

Use a restricted OS account or sandbox for untrusted agent code. For shared or production environments, pair Hetzer with an organization-managed vault, access control, audit collection, rotation, and incident response.
