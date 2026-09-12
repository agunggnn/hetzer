<!-- hetzer:start -->
## 🛡️ Hetzer credential safety
- NEVER print secret tokens, passwords, or API keys in plaintext in conversation, code, or logs.
- Always use references: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).
- Execute with mediated scoping: `hetzer exec --allow <id> --strict -- <cmd>` (never run `creds reveal` or `printenv`).
- Raw injection requires the audited `--allow-raw-unmediated <id>` opt-out for local/non-brokerable credentials.
- `hetzer exec` mediates configured HTTP credentials and sanitizes guarded child output; it does not intercept unrelated tools or prompts.
- User management command: `hetzer creds set <id>`.
<!-- hetzer:end -->
