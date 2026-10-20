# Upgrading to 0.7.0

0.7.0 moves the master key out of new workspaces, adds a sandbox engine that needs no container, a command that runs
a whole coding agent in the sandbox, and externally alerting decoys. Existing workspaces keep working without
changes. Background and limits: [agent-sandbox.md](agent-sandbox.md) and
[ADR-0004](adr/0004-container-free-sandbox-and-agent-containment.md).

## What changes for existing workspaces

- **Nothing breaks.** A key already in the workspace `.env` is still read first, and `hetzer init` keeps it.
- **Move the key out of the workspace** when you are ready:
  ```bash
  hetzer creds isolate-key
  ```
  It writes the key to `~/.hetzer/keys/<instance-id>.key` (mode 0600), removes `HETZER_GRIMOIRE_KEY` from `.env`
  and records `HETZER_INSTANCE_ID` there instead. In 0.6 it wrote `~/.hetzer/grimoire.key`, one file shared by every
  workspace; that file is still read for workspaces that use it. `hetzer doctor` warns while the key is in `.env`.
- **Back up `~/.hetzer/keys/`** together with the vault. A vault without its key cannot be decrypted, and the key is
  no longer inside the project folder you may already be backing up.
- **`hetzer init` refuses to replace a missing key** (`ERR_MASTER_KEY_NOT_FOUND`) when `data/hetzer-vault.db` exists
  but no key is found for it. Before 0.7.0 it generated a new key, which left the existing credentials undecryptable.
  Restore the key, or move the vault aside if it holds nothing you need.

## What changes for new workspaces

- `hetzer init` writes the key to `~/.hetzer/keys/<instance-id>.key` and only `HETZER_INSTANCE_ID` to `.env`.
- A new workspace does not adopt an existing `~/.hetzer/grimoire.key`; it gets its own key.
- CI and containers: keep supplying `HETZER_GRIMOIRE_KEY` in the environment; nothing is written to disk then.

## New

| Command or option | Purpose |
|---|---|
| `--sandbox-engine <auto\|docker\|podman\|srt>` | Picks the sandbox engine (`auto`: Docker, then Podman, then srt) |
| `--sandbox-allow-host <host>` | Network allowlist for srt; without it srt allows no network |
| `--sandbox-allow-read <dir>`, `--sandbox-allow-write <dir>` | Re-open a directory for srt (credential stores stay hidden) |
| `hetzer agent [options] -- <agent>` | Runs a whole agent in the sandbox, srt by default, with no credential unless `--allow` names one |
| `hetzer canary plant <file> --var NAME`, `canary list`, `canary remove <id>` | Plants and manages decoys issued by an outside alerting service |

srt is [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime), installed
separately (`npm install -g @anthropic-ai/sandbox-runtime@0.0.78`; on macOS also `brew install ripgrep`, on Linux
`bubblewrap socat ripgrep`). `hetzer doctor` reports it and no longer lists a missing Docker as an issue when srt is
installed.

## Behaviour notes

- The srt engine refuses brokered credentials (`ERR_SANDBOX_BROKER_UNSUPPORTED`). Use a container engine for those.
- The allowlist options are refused with a container engine or an image (`ERR_SANDBOX_OPTIONS_CONFLICT`).
- New audit events: `AGENT_EXIT`, `CANARY_PLANTED`, `CANARY_REMOVED`; `SANDBOX_EXEC` gains `engineVersion`,
  `allowHosts` and `agent`. See [audit-event-schema.md](audit-event-schema.md).

## 0.7.1

First-run fixes; no vault or key format change.

- `hetzer init` adds a marked block to `.gitignore` for `.env`, `.env.*` (not `.env.example`), `data/hetzer-vault.db*` and
  `.hetzer/`. Your own lines stay; a block already present is left alone.
- `hetzer protect` writes agent guidance only inside the project. Use `hetzer skill install` to update agent apps
  outside it; that command now writes only for apps whose directory exists, so it no longer creates a Claude Desktop
  config or `~/.hermes` on a machine without them. When `.env` still holds plaintext credentials, `protect` names them
  (never their values) and marks the line `[!]`.
- The generated `.mcp.json` no longer lists the `sample-mod` placeholder (`http://127.0.0.1:8001/mcp`); `init` and
  `mcp configure` remove that exact entry from existing files.
- The Git hook no longer flags `NAME=<hex>` identifiers such as `HETZER_INSTANCE_ID` as high-entropy secrets. A hex
  value under a secret-looking name (`API_KEY`, `*_SECRET`, `*_TOKEN`, ...) is still scored.
- The human guard now recognises Claude Code (`CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`). In a VS Code or Cursor terminal,
  `creds set` can add a new credential and `canary plant` can run; replacing a stored credential, `creds reveal`,
  `creds grant`, `creds approve` and `audit rotate --yes` still need a standalone terminal.
- `hetzer doctor` reports a missing Docker socket as "not running" instead of a permission problem, shows one
  "No sandbox engine" issue instead of one per Docker component, and checks Compose only for a project's own Compose file.
- New workspaces' `.env.example` no longer carries an unused `HETZER_VERSION` line.
