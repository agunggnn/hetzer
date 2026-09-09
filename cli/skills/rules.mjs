export const HETZER_VAULT_RULE_NAME = "hetzer";
export const HETZER_SKILL_NAME = "hetzer";

export const POINTER_START = "<!-- hetzer:start -->";
export const POINTER_END = "<!-- hetzer:end -->";

export const AGENT_SYSTEM_RULE = `# Hetzer credential safety

Hetzer is defense in depth. It does not intercept arbitrary prompts, files, processes, networks, or tools.

## Required handling
- Never request, display, log, or write plaintext tokens, passwords, private keys, or API keys. Use \`secretRef:<credential-id>\`.
- Configuration must contain references, for example \`NODE_AUTH_TOKEN=secretRef:npm-token\`.
- If a credential is missing, tell the user to run \`hetzer creds set <id>\`; input is collected by a masked prompt outside the model conversation.
- Agents must not invoke \`hetzer creds reveal\` or environment-reflection commands.

## Scoped execution
- Run trusted commands with minimal inheritance: \`hetzer exec --allow <id> --strict -- <command> [args]\`.
- Application code reads the injected environment variable normally. Never place a credential in arguments or generated source.
- Hetzer sanitizes guarded stdout/stderr and its own MCP responses. MCP vault tools expose only metadata through \`hetzer_vault_has\` and \`hetzer_vault_list\`; use scanner tools only on text already in scope.

## Boundaries
- An authorized child receives plaintext in memory and may transform it or send it through files, networks, IPC, debuggers, or direct device output. Output scanning cannot prevent those actions.
- The vault key and encrypted data remain accessible to processes with the same OS-user permissions. Use least-privilege credentials, short lifetimes, restricted egress, and trusted commands.
- Never claim universal interception, containment, or compliance. Describe Hetzer as an empirical credential-safety layer.
`;

export const ENTRY_POINTER_BLOCK = [
    POINTER_START,
    "## 🛡️ Hetzer credential safety",
    "- NEVER print secret tokens, passwords, or API keys in plaintext in conversation, code, or logs.",
    "- Always use references: `secretRef:<credential-id>` (e.g. `secretRef:npm-token`, `secretRef:openai-api-key`).",
    "- Execute with scoped injection: `hetzer exec --allow <id> --strict -- <cmd>` (never run `creds reveal` or `printenv`).",
    "- `hetzer exec` scopes referenced credentials and sanitizes guarded child output; it does not intercept unrelated tools or prompts.",
    "- User management command: `hetzer creds set <id>`.",
    POINTER_END,
].join("\n");

export const CURSOR_MDC_CONTENT = `---
description: Credential handling via the Hetzer Vault
globs: *
alwaysApply: true
---
${AGENT_SYSTEM_RULE}
`;

export const CLAUDE_RULE_CONTENT = AGENT_SYSTEM_RULE;

export const CLINE_RULE_CONTENT = AGENT_SYSTEM_RULE;

export const ANTIGRAVITY_SKILL_CONTENT = `---
name: hetzer
description: Use only for tasks involving credentials, secretRef values, publishing authentication, or Hetzer vault controls.
---

${AGENT_SYSTEM_RULE}
`;

export const HETZER_SKILL_CONTENT = ANTIGRAVITY_SKILL_CONTENT;
