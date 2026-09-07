---
name: hetzer
description: Local credential references, scanning, and Grimoire Vault integration for autonomous agents.
---

# Hetzer credential handling

Hetzer provides a local encrypted vault, explicit secret references, a staged-diff scanner, and guarded process execution. Treat these controls as defense in depth; installing this skill does not intercept arbitrary prompts, file reads, or tools.

## 1. Strict Zero-Plaintext Policy
- **NEVER** ask the user to type or paste plaintext API keys, passwords, private keys, or tokens in conversation.
- **NEVER** output or write raw credentials (e.g. strings matching `sk-...`, `npm_...`, `ghp_...`, `AIza...`, `Bearer ...`) into files, scripts, logs, or commit messages.
- If you encounter or need a secret, **ALWAYS** refer to it using the format: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).

## 2. Environment Configuration
- In `.env` or configuration files, store secrets strictly as references:
  ```dotenv
  NODE_AUTH_TOKEN=secretRef:npm-token
  OPENAI_API_KEY=secretRef:openai-api-key
  ```
- Run `hetzer protect` or the migration command to replace supported plaintext values in `.env`; do not assume arbitrary files are intercepted.
- `hetzer creds isolate-key` can move the master key outside the workspace to `~/.hetzer/grimoire.key`. The file remains accessible to processes running as the same OS user.

## 3. Execution with Secrets (Least Privilege)
- To run commands, test suites, builds, or scripts requiring credentials, use out-of-band scoped injection:
  ```bash
  hetzer exec --allow <credential-id> -- <command> [args]
  ```
- To start the child with a minimal inherited environment, pass `--strict`:
  ```bash
  hetzer exec --allow npm-token --strict -- npm run publish-pkg
  ```
- **DO NOT** run `hetzer creds reveal` from an agent. The CLI checks for a TTY, agent environment markers, and up to five ancestor processes; these checks are safeguards rather than an OS security boundary.
- Environment reflection commands (`printenv`, `env`, `export`, `set`, `/proc/*/environ`, `docker inspect`) are forbidden under Zero-Plaintext policy.
- `hetzer exec` sanitizes its child stdout/stderr with a bounded rolling buffer. MCP responses are scanned before return. Commands and tools outside these paths are not intercepted.

## 4. Writing & Running Scripts (Python, Bash, Node)
- When writing scripts that need secrets, write code that reads environment variables normally:
  ```python
  token = os.environ.get("NODE_AUTH_TOKEN") # Available in memory during hetzer exec
  ```
- Run the script through Hetzer: `hetzer exec --allow <id> -- python my_script.py`.
- Known injected values and supported scanner candidates are redacted from `hetzer exec` output. Keep application logging controls in place because pattern scanners cannot identify every secret format.

## 5. Autonomous MCP Defense Tools
If connected via MCP, you have access to Hetzer's native defense tools:
- `hetzer_sniffer_scan(text)`: Inspect text for supported token formats, credentialed database URLs, bounded private keys, and high-entropy candidates.
- `hetzer_sniffer_redact(text)`: Sanitize text by automatically replacing raw credentials with `secretRef:<id>`.
- `hetzer_vault_has(id)`: Verify if a required secret exists in Vault without exposing its plaintext value.
- `hetzer_vault_list()`: Inspect configured credential references safely.

## 6. User Credential Management
- If a required credential is not configured, instruct the user to run:
  ```bash
  hetzer creds set <credential-id>
  ```
  *(The user will be prompted with a hidden, masked prompt and the value will be encrypted with AES-256-GCM).*

