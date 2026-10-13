# Upgrading to 0.6.0

0.6.0 carries the four gates of [ADR-0001](adr/0001-authority-model-and-engine-boundary.md). It changes what a
credential may be used for, removes the stack commands, and migrates the vault file in a way that an earlier build
does not undo. Read "Before you upgrade" first.

## Before you upgrade

1. **Copy the vault.** The vault moves to format 2 the first time 0.6.0 opens it, and a build that checks the format
   marker at 1 then refuses it. Keep a copy if you may need to go back:
   ```bash
   cp data/hetzer-vault.db data/hetzer-vault.db.before-0.6
   ```
2. **Rename the retired key variable.** `SHADOW_GRIMOIRE_KEY` is no longer read. If your environment or `.env` sets it
   and not `HETZER_GRIMOIRE_KEY`, rename it and keep the value. Otherwise key lookup stops with
   `ERR_MASTER_KEY_ALIAS_RETIRED`. Do not run `hetzer init` to get past that message: it would generate a different
   key, and 0.6.0 refuses to do so for that reason.
3. **Import a legacy JSON vault first.** `data/vault.json` is no longer imported. If you still have one that was never
   imported, open the workspace once with the version you run now, or add those credentials again afterwards with
   `hetzer creds set <id>`. 0.6.0 warns (`HETZER_LEGACY_VAULT_NOT_IMPORTED`) and names the ids it found.

## What changes for existing credentials

- **Grants are signed.** A credential now records where it may be sent (`--origin`), which actions may use it and
  whether raw injection is allowed, under a signature made with the master key. Credentials created before 0.6.0 have
  no signature, and their grants are not honored until a person reviews and signs them:
  ```bash
  hetzer creds grant --sign-existing
  ```
  Until then, use fails with `ERR_GRANT_SIGNATURE_INVALID`. Set or change a grant with
  `hetzer creds grant <id> [--origin <url>] [--raw <allow|deny>] [--host <name>] [--action <name>] [--reset]`.
- **The broker needs an approved policy and a granted origin.** A policy file is refused unless its origin is in the
  credential's grant (`ERR_BROKER_ORIGIN_NOT_GRANTED`) and that exact file was approved with
  `hetzer broker approve <policy-file>` (`ERR_BROKER_POLICY_NOT_APPROVED`). The default lease lifetime is 60 seconds.
- **Raw injection is a grant, not only a flag.** `--allow-raw-unmediated <id>` is refused with
  `ERR_RAW_UNMEDIATED_DENIED_BY_GRANT` unless the credential's grant allows it.
- **MCP.** `secretRef:` values are substituted only for tools whose destination origin is in the credential's grant.
  The `hetzer_sniffer_redact` tool was removed.

## Removed commands

Each of these now prints a pointer and exits with code 1.

| Command | Use instead |
|---|---|
| `hetzer up`, `down`, `status`, `logs`, `tui`, `update`, `modules`, `install`, `remove`, `module`, `validate` | [Jagdpanzer](https://github.com/agunggnn/jagdpanzer) for multi-container stacks |
| `hetzer upgrade`, `hetzer check-update` | `npm install -g @agunggnn/hetzer` |
| `hetzer publish` | the release scripts in `scripts/` |

`hetzer init` no longer writes a `docker-compose.yml` or generates gateway passwords.

## Sandbox

`hetzer exec --sandbox` mounts the current directory, or the one given with `--sandbox-mount <dir>`, instead of the
Hetzer instance directory. It refuses the home directory, the Hetzer home and their ancestors, and hides Hetzer-owned
paths that sit inside the mount. Only injected variables are forwarded, by name. The default image is pinned by digest
(`HETZER_SANDBOX_IMAGE` overrides it). Outbound network is open unless `--sandbox-network` restricts it.

## Audit ledger

- New entries are version 2 and carry a MAC when a master key is available. `hetzer audit verify --require-mac`
  rejects a ledger with unkeyed entries.
- `hetzer exec --strict` does not start when its start event cannot be recorded (`ERR_AUDIT_WRITE_FAILED`).
- A ledger that refuses new entries (`ERR_AUDIT_KEY_REQUIRED`, `ERR_AUDIT_KEY_MISMATCH`, `ERR_AUDIT_LEDGER_CORRUPT`,
  `ERR_AUDIT_LEDGER_TRUNCATED`) is recovered by a person with `hetzer audit rotate --yes`, which archives it and starts
  a new one that records the old head.
- Format and limits: [audit-event-schema.md](audit-event-schema.md).

## Vault file

Format 2 drops three tables Hetzer no longer uses (`vault_targets`, `vault_audit_findings`, `vault_metadata`). Their
rows are counted in the audit record and not copied. Credentials, grants and approved policies are kept. Details:
[vault-format.md](vault-format.md).

## SDK

`apiVersion` is the number `1` (it was the string `experimental-1`). Credential ids must match the vault's grammar
(lower-case letters and digits separated by single hyphens). The package exports only `@agunggnn/hetzer/sdk`. Contract:
[sdk-contract.md](sdk-contract.md).

## What this release does not change

Code that runs as the same user can still import the vault module or read the vault file and the key. The human-session
checks are heuristics. Run agents you do not trust out of process, in the sandbox. The open items are listed under each
gate in ADR-0001.
