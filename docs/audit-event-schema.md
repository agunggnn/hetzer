# Audit event schema (ledger entry version 2)

**Status:** Describes what `cli/vault/audit.mjs` writes today. Gate G2 of
[ADR-0001](adr/0001-authority-model-and-engine-boundary.md) item 10. `cli/vault/audit-schema.test.mjs` checks
this note against the code: it re-implements verification from the formulas below without importing the
module, and fails when an event type exists in only one of the code and the catalog.

## Files

| File | Holds |
|---|---|
| `<root>/.hetzer/audit.log` | The ledger: one JSON entry per line. `HETZER_AUDIT_LOG_PATH` overrides the location. |
| `audit.log.head` | `{ "lastIndex", "lastHash", "updatedAt" }` after the latest append. Detects removal of the newest entries. |
| `audit.log.state` | `{ "version": 1, "initializedAt" }`. Written on first use; its presence with a missing log is reported as tampering. |
| `audit.log.lock` | Present only while a writer holds the lock. |
| `audit.log.lock.wait.<pid>.<random>` | An empty marker a waiting process leaves while it waits. Removed when it gets the lock or gives up; one left by a crashed process is ignored after 15 seconds and is not swept. |
| `audit.log.<UTC stamp>[.head\|.state]` | An archive left by `hetzer audit rotate`. |

A vault whose database is `<root>/data/*.db` (or when `HETZER_AUDIT_LOG_PATH` is set) mirrors its audit events into
this ledger. The `vault_audit_events` table is a frozen mirror, not a second source of truth.

## Entry

```json
{ "v": 2, "index": 1, "timestamp": "2026-10-11T10:15:30.123Z", "eventType": "EXEC", "target": "node",
  "result": "ALLOW", "actor": { "pid": 1, "user": "u", "isTTY": false, "processName": "hetzer" },
  "details": {}, "prevHash": "<64 hex>", "hash": "<64 hex>", "mac": "<64 hex, only when keyed>" }
```

| Field | Rule |
|---|---|
| `v` | Entry version. Absent means 1. Never decreases along the chain; this build writes 2. |
| `index` | 1 for the first entry, then +1. |
| `timestamp` | ISO 8601 UTC. |
| `eventType`, `result` | Upper-cased by the writer. `result` is free text; the values in use are in the catalog. |
| `target` | A string: what the event is about (a credential id, a command name, a host). |
| `actor` | Object. The writer sets `pid`, `user`, `isTTY` and `processName`; a caller can add fields. |
| `details` | Event-specific. See "Details". |
| `prevHash` | `hash` of the previous entry; 64 zeros (`GENESIS_HASH`) for the first entry of a ledger. |
| `hash` | SHA-256 hex over the payload below. |
| `mac` | HMAC-SHA256 hex over `hash`. Present on every entry written by a process that had the master key. |

### Hash payload

Let `s(x)` be: `""` when `x` is `null` or `undefined`; `x` when it is a string; otherwise `JSON.stringify(x)`
(object keys keep the order in which they appear in the stored line).

- **Version 2:** `v{v}|{prevHash}|{index}|{timestamp}|{eventType}|{target}|{result}|{s(actor)}|{s(details)}`
- **Version 1** (no `v` field, no actor): `{prevHash}|{index}|{timestamp}|{eventType}|{target}|{result}|{s(details)}`

`hash` is the lowercase hex SHA-256 of that text as UTF-8. Version 2 covers the version and the actor; version 1
did not, so version 1 entries can have their actor edited without detection. Old ledgers still verify, and new
entries are always version 2.

### MAC

1. Normalize the master key text: a 64-character hex key lowercased; otherwise, when it has at least 32
   characters, the lowercase hex SHA-256 of the text; otherwise there is no key and entries are unkeyed.
2. `k = HKDF-SHA256(ikm = key text, salt = "hetzer-grimoire-v1", info = "grimoire-master-key", 32 bytes)`.
3. `subkey = HMAC-SHA256(k, "hetzer:audit-integrity:v1")`.
4. `mac = hex(HMAC-SHA256(subkey, hash))`.

## Verification (`hetzer audit verify [--require-mac]`)

A ledger is rejected when any of these holds:

- an entry is not valid JSON, its `index` is not the expected next number, or its `prevHash` is not the previous `hash`;
- its `v` is not an integer, is lower than an earlier entry's, or is higher than this build writes;
- its `hash` does not match the payload;
- it carries a `mac` but is not version 2; or, when a master key is available, its `mac` does not match;
- it has no `mac` after a keyed entry (MAC downgrade);
- `--require-mac` (or `HETZER_AUDIT_REQUIRE_MAC=1`) is set and an entry has no `mac`, or no key is available;
- the log has fewer entries than `head.lastIndex`, or its last `hash` is not `head.lastHash`;
- the head anchor is missing or malformed, or the log is missing while the head or sentinel remains.

Writers add two refusals so a damaged ledger is not extended: a keyed ledger without a key or with another key
(`ERR_AUDIT_KEY_REQUIRED`, `ERR_AUDIT_KEY_MISMATCH`), and a damaged last line or a log shorter than its head
(`ERR_AUDIT_LEDGER_CORRUPT`, `ERR_AUDIT_LEDGER_TRUNCATED`). `hetzer audit rotate` is the recovery.

### Writer lock

Writers, `verify` and `rotate` serialize on `audit.log.lock`. The lock file records the holder's process id. A lock
older than 15 seconds is removed only when that process no longer exists; a live holder keeps its lock for up to
10 minutes (a critical section lasts milliseconds), because taking it over sooner would put two writers in the
critical section at once. A lock older than that is treated as leaked, for example by a long-lived process whose
release failed or by a process id reused after a crash. A waiter gives up after 10 seconds with
`Timeout acquiring audit log lock`, and the message names the file to delete if no Hetzer process is running.

The lock is not a queue; it is polite. A process that has to wait leaves a marker file
(`audit.log.lock.wait.<pid>.<random>`) next to the lock and removes it when it acquires the lock or gives up. A
writer that finds a marker of another process younger than 15 seconds pauses 45 ms before it competes again, so a
waiter polling in that window finds the lock free. Mutual exclusion is unchanged (the lock file is still created
exclusively), and a marker that cannot be written or read only costs latency. Order is still not guaranteed.

Measured on Windows, four writers that looped without any gap between events while a `rotate` ran, 25 rounds per
run. With 16 CPU-bound processes running, a waiting `rotate` timed out in 5 of 25 rounds before the markers and in
1 of 25 with them. With 12 CPU-bound processes and the markers, 0 of 25 in each of two runs; no run without the
markers was taken at 12. These are small samples: the markers reduced timeouts at the same load, they did not
remove them. A waiter that times out still means a lost event for fail-soft emitters, and a `--strict` start event
refuses to run, which is the safe outcome. This was not measured on Linux or macOS.

What the ledger does not give you: anyone who can read the master key can write a valid keyed ledger; a
consistent rewrite of the whole chain without any `mac` passes unless `--require-mac` is used (and that fails
for ledgers that were not keyed from the first entry); the head file is not an external anchor.

## Details

`details` is specific to each event type and is **not validated**. By convention no emitter records a credential
value; that is held by review and the tests of each emitter, not by a schema check. Fields can carry command
names, file paths, host names and request paths as received, so treat the ledger as sensitive operational data.

## Event catalog

Events marked fail-soft are written inside a `try` whose failure is ignored. `EXEC` and `SANDBOX_EXEC` are
mandatory under `hetzer exec --strict`: the run does not start when they cannot be written
(`ERR_AUDIT_WRITE_FAILED`).

| Event type | Emitted by | `target` | `result` | `details` keys |
|---|---|---|---|---|
| `EXEC` | `exec.mjs`, start of a host run (mandatory under `--strict`) | command name | `ALLOW` | `command`, `strict`, `canary`, `sandbox` |
| `SANDBOX_EXEC` | `sandbox.mjs`, start of a sandboxed run (mandatory under `--strict`) | command name | `ALLOW` | `engine`, `command`; `image` (container engines); `engineVersion`, `allowHosts` (srt); `agent` (set by `hetzer agent`) |
| `AGENT_EXIT` | `cli.mjs`, end of a `hetzer agent` session, fail-soft | command name | `ALLOW` | `command`, `status`, `durationMs` |
| `SENSITIVE_PATH_BLOCKED` | `exec.mjs`, fail-soft | command name | `BLOCK` | `command`, `error` |
| `DOWNLOADER_BLOCKED` | `exec.mjs`, fail-soft | command name | `BLOCK` | `command`, `error` |
| `REFLECTION_BLOCKED` | `exec.mjs`, fail-soft | command name | `BLOCK` | `command` |
| `CANARY_TRIGGER` | `canary.mjs`, fail-soft | decoy credential id | `TRIGGERED` | `threatVector`, `timestamp` (the actor carries `actor` and `action`) |
| `CRED_REQUEST` | `credential-request.mjs`, fail-soft | credential id | `ALLOW` | `requestId`, `ttlMs`, `allowedOrigins`, `rawInjection` |
| `CRED_APPROVE` | `credential-request.mjs`, fail-soft | credential id | `ALLOW` | `requestId` |
| `BROKER_LEASE_ISSUED` | `http-broker.mjs`, fail-soft | credential id | `ALLOW` | `targetOrigin`, `basePath`, `ttlSeconds`, `maxRequests`, `expiresAt` |
| `BROKER_LEASE_EXPIRED` | `http-broker.mjs`, fail-soft | credential id | `DENY` | `targetOrigin`, `url`, `expiredAt` |
| `BROKER_CAPABILITY_INVALID` | `http-broker.mjs`, fail-soft | credential id | `DENY` | `targetOrigin`, `url`, `clientHeader` |
| `BROKER_LIMIT_REACHED` | `http-broker.mjs`, fail-soft | credential id | `DENY` | `targetOrigin`, `maxRequests`, `forwardedRequests` |
| `BROKER_REQUEST_ALLOWED` | `http-broker.mjs`, fail-soft | credential id | `ALLOW` | `targetOrigin`, `method`, `path`, `status` |
| `SSRF_BLOCKED` | `http-broker.mjs`, fail-soft | host name | `DENY` | `error`, `url` |
| `AUDIT_LEDGER_ROTATED` | `audit.mjs`, entry #1 of a rotated ledger | archive name | `ALLOW` | `reason`, `archive`, `archiveSha256`, `archivedFiles`, `previousEntries`, `previousLastGood`, `previousAnchor`, `previousVerified`, `previousMacChecked`, `previousVerifyError`, `previousKeyed`, `keyed` |

### Vault events

`Grimoire.recordAudit` mirrors each vault event into the ledger. The event type is `VAULT_` plus the action with
a leading `vault.` removed, non-alphanumerics turned into `_`, and upper-cased (`vaultAuditEventType`). `target` is
the credential id, else the target id; `result` is the outcome upper-cased; the actor is `{ user: <actor> }`;
`details` is `{ reason, metadata }`.

`VAULT_MIGRATE_SCHEMA_V2` is the one vault event that is not written where it happens. The migration stores it in
the vault and writes it to the ledger once the ledger accepts it and the process has the key, which can be a later
open. Its `timestamp` is therefore when it was written; `details.metadata` carries `migratedAt`, `fromFormat`,
`toFormat` and `droppedTables` (row count per dropped table). It is written at least once: processes that open the
vault at the same moment can each write it.

| Event type | Action |
|---|---|
| `VAULT_SET_CREDENTIAL` | `vault.set-credential` |
| `VAULT_GRANT_CREDENTIAL` | `vault.grant-credential` |
| `VAULT_SIGN_LEGACY_GRANTS` | `vault.sign-legacy-grants` |
| `VAULT_MIGRATE_SCHEMA_V2` | `vault.migrate-schema-v2` |
| `VAULT_IMPORT_EXPLICIT_ENV` | `vault.import-explicit-env` |
| `VAULT_REVEAL_BLOCKED` | `vault.reveal-blocked` |
| `VAULT_PROCESS_RAW_UNMEDIATED` | `process.raw-unmediated` |
| `VAULT_POLICY_LOADED` | `policy.loaded` |
| `VAULT_BROKER_POLICY_APPROVE` | `broker.policy.approve` |
| `VAULT_HTTP_PROXY_START` | `http.proxy.start` |
