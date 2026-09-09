<!-- hetzer:start -->
## 🛡️ Hetzer credential safety
- NEVER print secret tokens, passwords, or API keys in plaintext in conversation, code, or logs.
- Always use references: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).
- Execute with scoped injection: `hetzer exec --allow <id> --strict -- <cmd>` (never run `creds reveal` or `printenv`).
- `hetzer exec` scopes referenced credentials and sanitizes guarded child output; it does not intercept unrelated tools or prompts.
- User management command: `hetzer creds set <id>`.
<!-- hetzer:end -->
