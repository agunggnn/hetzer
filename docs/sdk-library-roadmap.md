# Hetzer SDK and Deployment Adapter Roadmap

**Status:** Proposed
**Date:** 2026-09-25
**Repository:** `@agunggnn/hetzer`
**Target release family:** Post-`0.5.x`; release number to be selected after the first implementation PR
**Primary outcome:** Applications can import a supported Hetzer SDK surface, while the existing CLI continues to use the same security implementation.

## 1. Executive decision

Evolve Hetzer into a dual-interface product:

1. A supported Node.js SDK for local applications, deployment tooling, CI runners, and provider adapters.
2. A thin CLI that delegates to the SDK instead of duplicating vault, policy, and deployment behavior.

The first SDK release must remain local-first. It must not turn Hetzer into a hosted secrets manager, browser credential store, or remote control plane.

The initial public integration should be a subpath export:

```js
import { createHetzer } from "@agunggnn/hetzer/sdk"
```

Do not immediately replace every internal import or publish a second package. First establish a stable facade over the existing implementation, then migrate internals behind that facade.

## 2. Current repository constraints

The implementation plan must respect the current repository shape:

- Runtime is Node.js `>=22.5.0`.
- The package is ESM-oriented and currently uses `.mjs` modules.
- The package has no third-party runtime npm dependencies.
- The CLI entry point is `cli/bin/hetzer.js`.
- Vault, credential resolution, execution, policy, broker, and sandbox code currently live below `cli/vault/`.
- Existing behavior is already covered by `npm run check`, `npm test`, and `npm run verify`.
- The package currently exposes a CLI binary but does not yet provide a supported SDK export.
- The current architecture explicitly treats Hetzer as local credential-safety tooling, not as a centralized secrets manager.

Relevant implementation areas:

| Area | Current source | SDK planning role |
|---|---|---|
| Vault | `cli/vault/hetzer-vault.mjs` | Internal encrypted storage and reference resolution |
| Credential metadata and setup | `cli/vault/creds.mjs` | CLI adapter; no plaintext returned by default |
| Environment binding | `cli/vault/secret-env.mjs` | Scoped execution primitive |
| Process execution | `cli/vault/exec.mjs` | Local application execution primitive |
| Execution policy | `cli/vault/exec-policy.mjs` | Capability and command restrictions |
| HTTP broker | `cli/vault/http-broker.mjs` | Brokered credential transport |
| Audit | `cli/vault/audit.mjs` | Metadata-only security events |
| MCP | `cli/mcp/` | Existing reference-based agent integration |
| CLI routing | `cli/core/cli.mjs` | Thin command adapter after migration |

## 3. Product goals

### Must have

- A documented, importable SDK entry point.
- Stable metadata types and structured errors.
- Explicit credential allowlisting for every operation.
- Target/action/expiry checks preserved from the current vault behavior.
- Broker-by-default behavior preserved where a broker policy exists.
- Strict execution and output sanitation preserved.
- CLI behavior preserved through the same underlying implementation.
- Provider adapters that operate only from a trusted local or CI process.
- Dry-run support for deployment synchronization.
- Metadata-only audit events for SDK and provider operations.
- Tests proving that secrets are not returned in normal SDK results, errors, logs, or audit records.

### Should have

- Idempotent deployment synchronization.
- Provider-neutral deployment interface.
- Vercel as the first provider adapter because this repository already documents Vercel deployment and cron usage.
- A fake provider used for deterministic tests without network access.
- A package tarball test proving only intended files are published.
- Documentation for application authors and adapter authors separately.

### Explicitly out of scope for the first release

- A hosted Hetzer control plane.
- Storing application secrets in HTRN, Supabase, or another application database.
- Browser-side SDK usage.
- A web page that accepts plaintext credentials and forwards them to Hetzer.
- Automatic production deployment triggered by an arbitrary HTTP request.
- A universal adapter for every cloud provider.
- Rewriting the vault or execution engine from scratch.
- Removing the existing CLI or breaking existing command behavior.
- Claims of complete containment, zero plaintext in all possible paths, or compliance certification.

## 4. Security invariants

Every PR in this roadmap must preserve these invariants:

1. Public SDK methods accept credential identifiers or `secretRef:<id>` values, never credential values in configuration objects.
2. No normal public SDK method returns a decrypted secret string.
3. Any unavoidable in-memory secret use is confined to an internal callback or provider sink and is never serialized, logged, or placed in an error message.
4. Credential use requires an explicit allowlist and a target/action context.
5. A reference cannot select arbitrary files, environment variables, or provider destinations.
6. The SDK must not inherit unrelated parent environment variables when strict mode is requested.
7. The master key must not be passed to child processes under strict execution.
8. Existing broker-by-default, raw opt-out, stream redaction, canary, timeout, policy, and audit behavior must not be weakened.
9. Provider tokens are themselves Hetzer-managed references, for example `secretRef:vercel-deploy-token`.
10. Deployment audit records contain provider, project, environment, variable name, reference ID, operation, result, and timestamp only. They must not contain values or authorization headers.
11. Destructive operations require an explicit option and must have a dry-run equivalent.
12. A deployed web application cannot assume access to the operator's local Hetzer vault.

If a proposed API conflicts with an invariant, stop and redesign the API before implementation.

## 5. Target architecture

```text
Application / local deployment script / CI job
                    |
                    v
        @agunggnn/hetzer/sdk public facade
                    |
        +-----------+------------+
        |                        |
  Core vault capabilities   Provider adapters
        |                        |
  policy, broker, audit    Vercel, Docker, future providers
        |
  Existing CLI commands
```

### 5.1 Public SDK facade

Create a small public facade, initially under `sdk/`, that composes existing internal modules. The facade is the only supported import surface.

Suggested files:

```text
sdk/
  index.mjs
  errors.mjs
  types.mjs              # JSDoc typedefs or runtime validators; no build-time TS requirement
  client.mjs
  metadata.mjs
  execution.mjs
  deployment.mjs
  providers/
    fake.mjs
    vercel.mjs
```

The exact directory may change during implementation, but the public boundary must remain stable once documented.

### 5.2 Public API shape

The following is the design target, not permission to implement every method in one PR:

```js
const hetzer = await createHetzer({
  root,
  actor: "deployment-sync",
  strict: true,
})

const credential = await hetzer.credentials.metadata("htrn-mcp-api-key")

await hetzer.deployment.sync({
  provider: "vercel",
  project: "htrn-platform",
  environment: "production",
  bindings: [
    { name: "MCP_API_KEY", ref: "secretRef:htrn-mcp-api-key" },
    { name: "CRON_SECRET", ref: "secretRef:htrn-cron-secret" },
  ],
  dryRun: true,
})
```

Required design properties:

- `createHetzer()` validates configuration and does not decrypt anything during construction.
- `credentials.metadata()` returns safe metadata only: ID, label, target, allowed actions, expiry, and status.
- `deployment.sync()` accepts references and provider metadata, not raw secret values.
- A provider adapter resolves a reference only inside its own tightly scoped operation.
- The result is a sanitized summary such as changed, unchanged, skipped, or failed.
- The SDK must not expose an ordinary `resolveRaw()` or `reveal()` method.
- Any internal raw-value primitive must remain private to the adapter/runtime layer and be covered by focused tests.

### 5.3 CLI relationship

The CLI remains the primary human interface. Migrate commands incrementally:

1. Add the SDK facade without changing CLI behavior.
2. Move shared validation and operation orchestration behind SDK modules.
3. Change CLI handlers to call the SDK.
4. Keep CLI-specific concerns—argument parsing, terminal prompts, exit codes, and human-readable output—in `cli/`.
5. Do not make CLI output the SDK contract.

## 6. Credential and deployment model

### Local credential creation

Credential creation remains an interactive Hetzer operation:

```text
hetzer creds set htrn-mcp-api-key
hetzer creds set htrn-cron-secret
hetzer creds set vercel-deploy-token
```

The value must be entered through the existing masked prompt. It must not be passed as a command-line argument, pasted into HTRN, or written into a tracked file.

### Application configuration

Applications may contain references such as:

```dotenv
MCP_API_KEY=secretRef:htrn-mcp-api-key
CRON_SECRET=secretRef:htrn-cron-secret
```

The reference is configuration, not the secret. The application still needs a trusted runtime integration to resolve it. A serverless deployment cannot resolve a local vault unless the deployment process injects the value through the provider's secret store.

### Deployment synchronization

The deployment flow should be:

```text
Operator or CI
  -> Hetzer SDK
  -> validate reference and destination
  -> resolve provider credential in memory
  -> call provider API or approved CLI
  -> record metadata-only audit event
  -> return sanitized result
```

The HTRN Settings page, if added later, may store binding metadata and display status. It must not receive the secret or directly access the local vault. A local `hetzer deploy sync` command or trusted CI job performs the actual synchronization.

## 7. PR roadmap

Each PR must remain independently reviewable and must include focused tests. Do not combine the SDK extraction, provider integration, and HTRN UI into one large PR.

### PR-00: Contract and threat-model freeze

**Purpose:** Approve the boundary before code changes.

**Changes:**

- Add this roadmap.
- Add a short SDK contract document if reviewers want API details separated from the roadmap.
- Record the threat model for local SDK use, CI use, provider API calls, and deployed web applications.
- Confirm that the first provider is Vercel and identify the supported Vercel API/CLI version during implementation.

**Acceptance criteria:**

- Public versus internal APIs are listed.
- Plaintext handling rules are explicit.
- No hosted control plane is implied.
- Provider authentication is defined as a Hetzer reference, not an application database field.

**Do not implement:** SDK code, Vercel calls, HTRN changes.

### PR-01: Public SDK facade with no behavior change

**Purpose:** Establish a supported import path without moving security logic yet.

**Changes:**

- Add `sdk/index.mjs` and minimal client construction.
- Add package `exports` for `./sdk`.
- Add structured SDK errors and safe result types.
- Add a metadata-only health or version method.
- Add import-contract tests on Windows-compatible Node invocation.
- Keep all existing CLI paths unchanged.

**Acceptance criteria:**

- `import { createHetzer } from "@agunggnn/hetzer/sdk"` works from a package consumer fixture.
- Construction does not open or decrypt the vault.
- No new runtime dependency is added.
- Existing `npm run check`, `npm test`, and `npm run verify` pass.
- The package tarball contains the intended SDK files and no vault databases, keys, fixtures, or local data.

**Do not implement:** raw secret resolution, provider adapters, HTRN integration.

### PR-02: Vault capability and metadata API

**Purpose:** Expose safe credential metadata and reference validation through the SDK.

**Changes:**

- Add a capability wrapper around the existing `Grimoire` behavior.
- Implement `credentials.metadata(id)` and reference parsing/validation.
- Preserve target, action, validity, expiry, and canary checks.
- Normalize IDs consistently with current CLI behavior.
- Map internal errors to stable, sanitized SDK errors.
- Keep decrypted values inaccessible through the public facade.

**Required tests:**

- Unknown reference is rejected without revealing whether unrelated IDs exist beyond the documented metadata behavior.
- Expired credentials are rejected.
- Wrong target/action is rejected.
- Canary IDs preserve the existing tripwire behavior.
- Errors never contain credential values, master keys, or database paths containing sensitive data.
- Metadata output contains no encrypted payload or plaintext.

**Acceptance criteria:**

- Existing CLI credential tests remain green.
- New SDK tests use synthetic fixtures only.
- Internal raw decrypt methods are not exported through `sdk/index.mjs`.

### PR-03: Scoped execution API

**Purpose:** Let local applications reuse Hetzer's guarded process execution without duplicating security logic.

**Changes:**

- Add a facade over `secret-env.mjs`, `exec.mjs`, and policy handling.
- Require explicit `allow` references.
- Support strict environment construction.
- Preserve broker-by-default behavior and audited raw opt-out.
- Return structured exit status and sanitized stdout/stderr handling appropriate for library consumers.
- Keep CLI exit-code mapping in the CLI layer.

**Required tests:**

- Unapproved references do not resolve.
- Parent secrets and the master key do not enter strict child environments.
- Shell metacharacters and policy bypasses remain rejected.
- Stream-split synthetic secrets are redacted.
- Timeout and process-tree termination behavior remains unchanged.
- Callback or child failures do not leak values through errors.

**Acceptance criteria:**

- CLI execution behavior is unchanged for existing commands.
- SDK consumers can run a scoped local operation using references only.
- No public API returns the master key or unrestricted environment object.

### PR-04: Provider-neutral deployment adapter contract

**Purpose:** Add deployment synchronization without coupling the SDK to one provider.

**Changes:**

- Define a provider adapter interface with:
  - provider name and version;
  - destination validation;
  - supported environments;
  - dry-run operation;
  - idempotent apply operation;
  - safe result summary;
  - metadata-only audit events.
- Add a fake in-memory provider for tests.
- Validate environment variable names, reference IDs, project names, and operation mode.
- Require an explicit `dryRun` or `apply` choice.
- Add an allowlist preventing arbitrary provider names from becoming dynamic module imports.

**Required tests:**

- Dry-run never resolves or transmits a secret when validation can complete without it.
- Apply uses only approved references.
- Repeating the same apply is idempotent.
- Failed provider calls return sanitized errors and do not print authorization headers.
- Delete/unset is denied unless explicitly requested.
- Audit events contain metadata only.

**Acceptance criteria:**

- Provider-neutral contract is documented.
- Fake provider covers success, unchanged, validation failure, auth failure, timeout, and partial failure.
- No network call is made by the test suite.

### PR-05: Vercel adapter and local sync command

**Purpose:** Provide the first real deployment integration for the repository's documented Vercel workflow.

**Changes:**

- Verify the current official Vercel API or CLI contract before implementation.
- Add a Vercel adapter behind the provider interface.
- Use a Hetzer reference for the Vercel deployment credential, for example `secretRef:vercel-deploy-token`.
- Support explicit project, team/scope, environment, and variable-name inputs.
- Implement dry-run, apply, unchanged detection, and sanitized failure handling.
- Add a CLI command only after the SDK adapter works, for example:

  ```text
  hetzer deploy sync --provider vercel --project htrn-platform --environment production --dry-run
  ```

- Ensure the provider credential is never placed in command arguments or logged.

**Required tests:**

- Use a mocked Vercel transport or local HTTP fixture; do not call production Vercel from tests.
- Assert that authorization material is not present in request logs, thrown errors, or audit records.
- Verify project/environment/variable allowlists.
- Verify timeout, retry, non-2xx, and partial-result behavior.
- Verify dry-run does not mutate the provider.

**Acceptance criteria:**

- A human can configure Hetzer references locally and perform a dry-run.
- Apply is explicit and auditable.
- The CLI is only an adapter over the SDK.
- Documentation clearly states that the command must run on a trusted machine or CI runner with vault access.

### PR-06: Package release hardening

**Purpose:** Make the SDK safe to consume as a published library.

**Changes:**

- Finalize `package.json` exports and package files.
- Add a consumer fixture that installs the packed artifact and imports only public paths.
- Document supported Node versions and ESM usage.
- Add API compatibility notes and deprecation policy.
- Add package-content checks for `.env`, SQLite files, keys, logs, test fixtures, and generated evidence.
- Add release notes that distinguish implemented behavior from future adapters.

**Acceptance criteria:**

- `npm run check`, `npm test`, and `npm run verify` pass.
- Packed artifact consumer test passes on Windows and at least one Unix environment.
- No secret-bearing fixture or local vault data enters the artifact.
- Public API documentation matches the actual exports.
- No absolute security or compliance claims are added.

### PR-07: Optional HTRN integration

**Purpose:** Connect HTRN Settings to deployment metadata without turning HTRN into a secret store.

**This PR belongs in `htrn-platform`, not Hetzer.**

**Allowed behavior:**

- Store binding metadata such as environment variable name, provider, project, environment, and `secretRef` ID.
- Display configured/not-configured state returned by a trusted sync process.
- Offer a link or operator instruction for local `hetzer deploy sync`.
- Optionally trigger a pre-authorized deployment job that runs outside the web process.

**Forbidden behavior:**

- Accepting plaintext `MCP_API_KEY`, `CRON_SECRET`, or provider tokens in the browser.
- Storing secret values in Supabase or application configuration tables.
- Invoking a local vault from a Vercel serverless function.
- Putting a Vercel API token in client-side code or a normal application row.
- Treating an authenticated HTRN user as automatically authorized to deploy production credentials.

**Acceptance criteria:**

- HTRN stores references and deployment metadata only.
- Production sync requires a separate trusted operator/CI boundary.
- The UI exposes no plaintext and no secret-reveal action.
- HTRN security tests cover unauthorized sync attempts and metadata-only responses.

## 8. API contract requirements

Before marking the SDK stable, document these contracts:

### Construction

- What `root` means and how it is normalized.
- How the vault path is selected.
- Whether construction is synchronous or asynchronous.
- Which configuration values are safe to include in logs.
- How the SDK behaves when the vault or master key is unavailable.

### Errors

Use stable error codes, for example:

```text
ERR_SDK_INVALID_CONFIG
ERR_CREDENTIAL_REFERENCE_INVALID
ERR_CREDENTIAL_NOT_ALLOWED
ERR_CREDENTIAL_EXPIRED
ERR_PROVIDER_NOT_CONFIGURED
ERR_PROVIDER_AUTH_FAILED
ERR_PROVIDER_OPERATION_FAILED
ERR_DEPLOYMENT_DESTINATION_INVALID
ERR_OPERATION_REQUIRES_APPROVAL
```

Error messages must identify the failed operation without including secret values, provider authorization material, or unrestricted filesystem details.

### Results

Return structured, sanitized results:

```js
{
  provider: "vercel",
  project: "htrn-platform",
  environment: "production",
  changed: ["MCP_API_KEY"],
  unchanged: ["CRON_SECRET"],
  failed: [],
  dryRun: true,
}
```

Never return resolved values, request headers, raw provider responses, or arbitrary child output by default.

## 9. Testing and verification gate

Every implementation PR must run the smallest relevant focused tests and then the full repository gates:

```text
npm run check
npm test
npm run verify
git diff --check
```

Additional SDK gates:

```text
npm pack --dry-run
node --input-type=module -e "import('@agunggnn/hetzer/sdk')"
```

The exact Windows command may use a temporary consumer fixture if package self-import behavior differs from the packed artifact.

Required evidence categories:

- API import and package-content evidence.
- Existing CLI regression evidence.
- Metadata-only output evidence.
- Reference allowlist and target/action evidence.
- No-plaintext error/log/audit evidence using synthetic secrets.
- Provider dry-run and idempotency evidence.
- Network mock evidence showing no accidental live provider calls.
- Cross-platform check results where the changed code is platform-sensitive.

Tests are regression evidence. They are not proof of complete containment, a security audit, or compliance certification.

## 10. Release and migration strategy

### Compatibility

- Preserve all current CLI commands and exit codes unless a separate breaking-change decision is approved.
- Keep internal module paths unsupported; only documented SDK subpaths are stable.
- Add deprecation warnings only in a later migration PR, not while extracting the first facade.
- Maintain the zero-runtime-dependency goal unless a dependency is justified and reviewed.

### Suggested release stages

1. **Experimental SDK:** import path exists, API marked experimental, local consumers only.
2. **Provider-ready SDK:** vault capabilities, scoped execution, fake provider, and audit contracts are stable.
3. **First production adapter:** Vercel adapter has mocked integration coverage and documented operator workflow.
4. **Stable SDK:** package artifact, cross-platform checks, release documentation, and security review are complete.

Do not call the SDK stable merely because the import works. Stability requires the security and package-content gates above.

## 11. Estimated effort

Planning estimates for one engineer familiar with the repository:

| Workstream | Estimate |
|---|---:|
| Contract and threat-model freeze | 0.5–1 day |
| Public facade and package exports | 2–3 days |
| Vault metadata capability | 3–5 days |
| Scoped execution facade | 3–5 days |
| Provider-neutral adapter contract | 2–4 days |
| Vercel adapter and CLI command | 4–7 days |
| Package/release hardening | 2–4 days |
| Optional HTRN metadata integration | 3–5 days |

Expected total for Hetzer SDK plus the first deployment adapter: approximately 3–5 weeks, depending on review depth and cross-platform verification. The HTRN integration is additional and should remain a separate PR sequence.

## 12. Model execution instructions

The agent implementing this roadmap must follow these rules:

1. Read `AGENTS.md`, `docs/architecture.md`, and `docs/system-logic-and-progress.md` before changing code.
2. Work on one numbered PR scope at a time. Do not implement later PRs opportunistically.
3. Preserve existing CLI behavior unless the current PR explicitly authorizes a migration.
4. Do not add a hosted service, browser SDK, database secret store, or broad provider framework outside the listed scope.
5. Never request, print, log, or commit plaintext credentials. Use only `secretRef:<id>` identifiers in code, tests, and conversation.
6. Use synthetic test values only inside isolated fixtures, and ensure test output is sanitized.
7. Do not call real deployment providers from tests.
8. Do not use `creds reveal`, `printenv`, or equivalent environment-reflection commands.
9. Use `hetzer exec --allow <id> --strict -- <cmd>` for trusted commands that require scoped credentials.
10. Run focused tests after each meaningful change, then run the full verification gate before handoff.
11. Report exact files changed, tests run, results, known limitations, and whether the work was committed or pushed.
12. Stop and ask for direction if implementation requires a new provider, a new trust boundary, or plaintext handling not explicitly approved here.

## 13. Definition of done

The Hetzer SDK roadmap is complete for the first stable release only when:

- A consumer can import the documented SDK subpath from the packed package.
- The CLI and SDK share the same security implementation.
- Credential references, target/action restrictions, strict execution, brokers, redaction, canaries, timeouts, and audit behavior remain enforced.
- No normal SDK result, error, log, audit event, or package artifact contains plaintext credentials.
- A provider adapter can perform a dry-run and an explicit, idempotent synchronization from a trusted local/CI context.
- Vercel synchronization, if approved, is tested with a mocked transport and documented with its operational boundary.
- HTRN, if integrated, stores only references and deployment metadata.
- Full repository gates and package-consumer verification pass.
- Documentation states the limits clearly: Hetzer remains defense-in-depth local credential safety, not a centralized secrets manager or a guarantee of total containment.
