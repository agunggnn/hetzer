# Vault format (format version 2)

**Status:** Describes what `cli/vault/hetzer-vault.mjs` creates today. Gate G2 of
[ADR-0001](adr/0001-authority-model-and-engine-boundary.md) items 10 and 12. If this note and the code disagree, the
code wins; please report the difference.

## Where it lives

A SQLite database, `<root>/data/hetzer-vault.db` unless `HETZER_VAULT_PATH` (or the SDK's `vaultPath`)
points elsewhere. The file is opened in WAL mode, so `-wal` and `-shm` files can sit next to it while it is
open. Hetzer restricts the file's permissions to the current user each time it opens the vault.

The master key is not in the database. Lookup order: `HETZER_GRIMOIRE_KEY` in the process environment,
then the same name in the workspace `.env`, then `~/.hetzer/grimoire.key` (under `HETZER_INSTALL_HOME` when set).
A 64-character hex key is used as given; any other key of at least 32 characters is replaced by its SHA-256 hex digest;
anything shorter leaves the vault locked. The legacy alias `SHADOW_GRIMOIRE_KEY` was retired in format 2.

## Format version

`vault_meta` holds `format_version`, a decimal integer. This build reads and writes version **2**
(`VAULT_FORMAT_VERSION`).

- A vault with no marker (created before format markers existed) or format 1 is migrated to format 2 on first open,
  dropping legacy pentest tables (`vault_targets`, `vault_audit_findings`, `vault_metadata`) while preserving all
  credentials, grants, and approved policies.
- A vault stamped higher than this build understands is refused with `ERR_VAULT_FORMAT_UNSUPPORTED` **before**
  any table is created, column added or row written, and the file is left as it was.
- A marker that is not a positive integer is refused the same way.
- Builds from before format markers do not check it. The protection starts with the release that introduced it,
  so an older build can still open and alter a newer vault.
- A format change raises the number and ships a migration. Going back to an older build is not supported once a
  vault has been migrated.

## Tables

| Table | Holds |
|---|---|
| `vault_meta` | `key`, `value`, `updated_at`: the format marker (`format_version`) and one-off state markers. |
| `vault_credentials` | One row per credential; see below. |
| `vault_approved_policies` | Operator-approved broker policies: `credential_id`, `policy_hash`, `target_origin`, `policy_path`, `approved_at`, `approved_by`, `sig`. Unique on `(credential_id, policy_hash)`. |
| `vault_audit_events` | A frozen mirror of vault audit events. The tamper-evident record is the file ledger, see [audit-event-schema.md](audit-event-schema.md). |

Legacy pentest tables (`vault_targets`, `vault_audit_findings`, `vault_metadata`) are dropped in format 2.
`Grimoire.upsertTarget` and `Grimoire.recordAuditFinding` remain as harmless compatibility methods for existing callers.

### `vault_credentials`

Identity and routing: `id` (primary key, lowercase kebab-case), `target_id`, `key_name` (unique with
`target_id`), `label`, `realm` (arbitrary string, default `frontier`), `auth_type`, `transport_scope`,
`access_role`, `header_name`, `username`, `notes`, `source`, `is_valid`.

Grant: `allowed_actions`, `allowed_origins`, `bind_hosts` (JSON arrays), `raw_injection` (`deny` by default),
`expires_at`, and `grant_sig`.

Lifecycle: `created_at`, `updated_at`, `last_used_at`.

Secret: `encrypted_value` and `crypto_version` (`hetzer-vault-v1`).

Columns added after the first releases (`allowed_origins`, `raw_injection`, `bind_hosts`, `grant_sig`, and
`sig` on approvals) are added on open when missing; that migration is best effort and silent.

## Encryption

- Cipher: AES-256-GCM with a random 12-byte IV per write.
- Key: HKDF-SHA256 over the normalized master key text, salt `hetzer-grimoire-v1`, info `grimoire-master-key`,
  32 bytes.
- Stored form of `encrypted_value`: `base64(iv).base64(ciphertext).base64(authTag)`.
- Additional authenticated data: `hetzer-vault:v1:<credential id>:<created_at>`. A ciphertext copied to another
  row, or to the same row with a different creation time, does not decrypt. Imports from the old JSON store used
  `grimoire:v1:<id>:<createdAt>` for the source file only; rows are re-encrypted with the form above.

Only `encrypted_value` is encrypted. `notes`, `username`, labels, grants and timestamps are stored as plain
text, so do not put a secret in them.

## Signatures

Three HMAC-SHA256 signatures use subkeys derived from the master key with a distinct label each:

| Label | Covers | Stored in |
|---|---|---|
| `hetzer:grant-integrity:v1` | JSON of `{ id, actions, origins, raw, hosts }` with the arrays sorted | `vault_credentials.grant_sig` |
| `hetzer:policy-approval:v1` | JSON of `{ credential, hash, origin }` | `vault_approved_policies.sig` |
| `hetzer:audit-integrity:v1` | The entry hash of an audit ledger entry | the file ledger, not this database |

A credential whose grant has no valid signature is not honored; signing an existing one is an operator action
(`hetzer creds grant --sign-existing`), never automatic. Someone who holds the master key can write valid
signatures, and a same-user process can read the database; see the R-05 notes in the architecture review.
