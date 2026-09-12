---
name: hetzer
description: Use only for tasks involving credentials, secretRef values, publishing authentication, or Hetzer vault controls.
---

# Hetzer credential safety

Hetzer is defense in depth. It does not intercept arbitrary prompts, files, processes, networks, or tools.

## Required handling
- Never request, display, log, or write plaintext tokens, passwords, private keys, or API keys. Use `secretRef:<credential-id>`.
- Configuration must contain references, for example `NODE_AUTH_TOKEN=secretRef:npm-token`.
- If a credential is missing, tell the user to run `hetzer creds set <id>`; input is collected by a masked prompt outside the model conversation.
- Agents must not invoke `hetzer creds reveal` or environment-reflection commands.

## Scoped execution
- Run trusted commands with minimal inheritance: `hetzer exec --allow <id> --strict -- <command> [args]`.
- Configure HTTP credentials with reviewed `.hetzer/brokers/<id>.json` policies so the child receives only a loopback URL and short-lived capability.
- Raw injection is denied by default. Use `--allow-raw-unmediated <id>` only for genuinely local/non-brokerable credentials; the opt-out is audited.
- Never place a credential in arguments or generated source.
- Hetzer sanitizes guarded stdout/stderr and its own MCP responses. MCP vault tools expose only metadata through `hetzer_vault_has` and `hetzer_vault_list`; use scanner tools only on text already in scope.

## Boundaries
- A raw-opted-out child receives plaintext in memory and may transform it or send it through files, networks, IPC, debuggers, or direct device output. Output scanning cannot prevent those actions.
- The vault key and encrypted data remain accessible to processes with the same OS-user permissions. Use least-privilege credentials, short lifetimes, restricted egress, and trusted commands.
- Never claim universal interception, containment, or compliance. Describe Hetzer as an empirical credential-safety layer.

