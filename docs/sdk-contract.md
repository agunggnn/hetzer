# Hetzer SDK contract (apiVersion 1)

**Status:** Frozen for `apiVersion` 1 by `sdk/sdk-contract.test.mjs`. Gate G2 of
[ADR-0001](adr/0001-authority-model-and-engine-boundary.md) item 10.

The SDK is `@agunggnn/hetzer/sdk`. It is the only specifier the package `exports` map offers besides
`package.json`; deep imports such as `@agunggnn/hetzer/cli/vault/...` are not importable through the package.
That limits what a consumer can import by name. It does not stop a process that runs as the same user from
importing the files by path, so it is not a security boundary (see "What this contract does not do").

## Versioning

`SDK_API_VERSION` (exported, currently `1`) is also `client.apiVersion`. Adding a member keeps the number.
Removing a member, renaming it, or changing what it returns or throws raises it. The contract test fails on any
change to the member list, so a change cannot ship by accident.

## Members

```js
import { createHetzer, SDK_API_VERSION, SDK_ERROR_CODES, HetzerSdkError,
         parseSecretRef, formatSecretRef, isSecretRef } from "@agunggnn/hetzer/sdk";

const client = createHetzer({ root, vaultPath, actor });
```

| Member | Purpose |
|---|---|
| `createHetzer({ root, vaultPath, actor })` | Lazy client. It checks paths and opens nothing. `vaultPath` may be `":memory:"`; credential-backed execution then fails with `ERR_SDK_INVALID_CONFIG`. |
| `client.kind`, `client.apiVersion` | `"hetzer-sdk"` and `SDK_API_VERSION`. |
| `client.credentials.list()` | Frozen list of safe metadata. |
| `client.credentials.metadata(id)` | Safe metadata for one id, or `null` when it does not exist. |
| `client.credentials.validate(reference, { targetId, action })` | Checks a `secretRef:<id>` (or bare id) against existence, target, allowed actions and expiry. Returns `{ valid: true, reference, id, targetId, action, metadata }` or throws. It never decrypts. A canary id raises the canary tripwire. |
| `client.execution.run(options)` | Runs a command under `--strict` semantics (always on) with scoped credential injection. Returns `{ status }`. |
| `client.close()` | Closes the vault if it was opened. |
| `parseSecretRef`, `formatSecretRef`, `isSecretRef` | The one `secretRef` grammar, `^secretRef:([a-z0-9]+(?:-[a-z0-9]+)*)$`. |

Safe metadata fields: `id, projectId, keyName, label, realm, authType, scope, accessRole, allowedActions,
headerName, createdAt, updatedAt, lastUsedAt, expiresAt, source, hasSecret, ageDays`. Notes, usernames and
secret material are never included.

`execution.run` options: `command`, `args`, `allow`, `allowRawUnmediated`, `brokerPolicyFiles`, `policy`,
`policyFile`, `policyHash`, `envFile`, `canary`, `sandbox`, `sandboxImage`, `sandboxNetwork`,
`sandboxMountDir` (required with `sandbox`), `sandboxRo`, `timeout`, `timeoutMs`, `stdout`, `stderr`.

### One id grammar

Credential ids are lowercase kebab-case: `^[a-z0-9]+(?:-[a-z0-9]+)*$`. This is what the vault accepts on
create, what a `secretRef` can name, and what the SDK and credential requests accept. Ids with `.` or `_`
are rejected with `ERR_CREDENTIAL_ID_INVALID` (bare id) or `ERR_CREDENTIAL_REFERENCE_INVALID` (reference).
`execution.run` also accepts environment variable names in `allow`.

### Errors

`HetzerSdkError` carries a `code`. The stable codes are the values of `SDK_ERROR_CODES`:
`ERR_SDK_INVALID_CONFIG`, `ERR_CREDENTIAL_ID_INVALID`, `ERR_CREDENTIAL_REFERENCE_INVALID`,
`ERR_CREDENTIAL_NOT_FOUND`, `ERR_CREDENTIAL_TARGET_MISMATCH`, `ERR_CREDENTIAL_NOT_ALLOWED`,
`ERR_CREDENTIAL_EXPIRED`, `ERR_VAULT_FORMAT_UNSUPPORTED` (the vault was written by a newer Hetzer and was left untouched).

`execution.run` rethrows the engine's `ERR_*` code with a fixed message (`Hetzer execution failed (<code>).`),
no `cause`, and `exitCode` when the engine set one. Engine codes such as `ERR_RAW_UNMEDIATED_DENIED_BY_GRANT`,
`ERR_REFLECTION_BLOCKED` and `ERR_AUDIT_WRITE_FAILED` are covered by tests today, but the set of engine codes is
not part of the contract; anything else becomes `ERR_SDK_EXECUTION_FAILED`.

## Not in apiVersion 1

- **No `resolve`, `reveal`, `decrypt` or lease member.** A call that returns a credential value to the caller
  has the same exposure as `Grimoire.resolve()` (R-05). The contract test fails if any member name matches
  those words.
- **Lease interfaces.** ADR-0001 item 10 names them. The HTTP broker (`hetzer broker`) already issues short-lived
  capability leases to the child it starts, but the SDK exposes no way to request or hold one. Handing a lease to
  the caller is deferred until the authority model can say what a lease is allowed to expose.
- Provider adapters and deployment synchronization (see `sdk-library-roadmap.md`).

## What this contract does not do

The SDK narrows what a well-behaved caller can ask for. It does not defend against code in the same process or
under the same user: that code can import `Grimoire`, read the vault file, or read the master key from its
store (R-05 stays open for in-process callers). Untrusted agents belong out of process, in the sandbox.
