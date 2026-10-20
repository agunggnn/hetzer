# ADR-0001: Authority model first, then a local-first engine with thin adapters

**Status:** Proposed
**Date:** 2026-10-10
**Deciders:** Maintainer (`agunggnn`). Sign-off needed before any consumer (AegisBrain, Jagdpanzer, Brumm) is pointed at new Hetzer interfaces.
**Evidence:** [Architecture and security review, October 2026](../architecture-review-2026-10.md). Finding IDs (R-01 and so on) refer to that document.

## Context

Hetzer is about four weeks old (first commit 2026-08-30, v0.5.12) and already ships a vault, broker, runner, sandbox, MCP server, SDK facade, TUI, module system, release tooling and a Compose stack. The maintainer wants it to become the shared credential layer for AegisBrain, Jagdpanzer, Brumm and related tools, while staying local-first.

The review found that the mechanisms are real but that **no authority model connects them**:

- The caller being constrained supplies the constraints: flags, execution policy and the broker policy file that decides where a credential is sent (R-01, R-02).
- The vault does not record where a credential may be used, so the destination is decided by whoever writes the workspace config (R-01, R-04, R-07).
- The one OS-level boundary, the sandbox, has defaults that expose the key and vault to the sandboxed process (R-03).
- Plaintext is reachable in-process through `resolve()`, and sibling tools already decrypt the on-disk format directly (R-05, review section 3).
- The audit trail can be rewritten without detection by a same-user writer (R-06).
- A large share of the codebase is stack-orchestration and release tooling unrelated to credential safety (R-11), and the README directs users to a build that is eight minor versions behind (R-08).

Forces:

- The project's own stated position is defense-in-depth for a same-user threat model, with no absolute claims. That position is correct and should be kept. It also means a fix cannot rely on process isolation the product does not have.
- `docs/sdk-library-roadmap.md` rules out a hosted control plane. AegisBrain's `/api/v1/vault/sync` already stores encrypted entries centrally, so the two designs disagree.
- Zero runtime dependencies is a deliberate constraint and a selling point.
- Consumers differ: Jagdpanzer shells out to the CLI, AegisBrain reads the SQLite file, Brumm is documentation only and treats Hetzer as one secret provider among several.

## Decision

### D1. Establish an authority model before extracting or integrating anything (Gate G0)

Separate two principals and store authority where only the first can write it.

- **Operator**: a human on the interactive path (`hetzer creds set`, approval flows). Writes *grants*.
- **Subject**: an agent, tool or script that runs commands and asks for access. Writes *requests*.

Grants live **in the vault**, not in workspace files or flags:

| Grant attribute | Meaning | Default |
|---|---|---|
| `allowedOrigins` | HTTPS origins the broker may send this credential to | none (broker refuses) |
| `allowedActions` | `process.start`, `broker.proxy`, `mcp.tools/call` (existing concept, made mandatory for non-metadata use) | none |
| `rawInjection` | whether the credential may ever be placed in a child environment | `deny` |
| `bindHosts` | optional host identifiers (AegisBrain's `--host` request) | unbound |
| `notAfter` | expiry (existing) | none |

Rules:

1. **Flags and config files can only narrow.** `--allow-raw-unmediated` becomes a *request* honoured only when the grant says `rawInjection: allow`. A broker policy file becomes untrusted input: its `target` must be one of the grant's `allowedOrigins`, and a policy whose origin is not granted is refused with a message telling the operator how to approve it. Execution-policy files may add restrictions, never remove vault-level ones.
2. **Self-declared hashes stop being a trust mechanism.** An `integrity` field inside the file it protects is removed or demoted to a checksum. Pinning happens in the vault at approval time.
3. **MCP follows the same rule.** `secretRef:` substitution in a tool call is allowed only when the destination origin is in the credential's grant. Service URLs read from the environment or `.env` are untrusted input. Agent-callable write tools (`hetzer_sniffer_redact`) are removed or require an operator-approved mode.
4. **Be honest about the ceiling.** Same-user code with direct access to the key file and database can still read what the user can read. D1 stops agent-authored config and flags from widening access, which is the realistic first threat. Stronger separation (a vault process under a different OS identity, or OS keyring with user presence) is tracked separately and is not claimed by this ADR.

### D2. Make the one OS-level boundary real by default (Gate G1)

Keep `--sandbox` and fix its defaults before adding anything to it.

- Never mount the instance root wholesale. Mount the project directory and mask the vault database, `.env`, key file, `.hetzer/` and audit log.
- Initialise with the master key isolated by default, and never inside any mounted path.
- Do not pass secret values on the container engine's command line; use an `--env-file` on a private path (removed after start) or inherit by name.
- State the network behaviour explicitly in the command output and docs; offer a broker-only network profile.
- Pin the default image by digest.
- Bind the broker to the narrowest address the engine allows rather than `0.0.0.0`.

### D3. Split into an engine and thin adapters, and publish one contract (Gate G2)

```
          +---------------------------+
          |  Adapters (thin)          |
          |  CLI | MCP | git hook |   |
          |  skills installer         |
          +-------------+-------------+
                        | SDK contract (versioned)
          +-------------v-------------+
          |  Engine (local-first)     |
          |  vault + grants           |
          |  runner + sanitizer       |
          |  broker                   |
          |  exec policy              |
          |  scanner, canary          |
          |  single audit stream      |
          +---------------------------+
```

- The SDK (`createHetzer`, already metadata-first) is the only supported in-process interface. It gains a documented, versioned contract: grant-checked execution and broker leases, metadata and validation, one audit event schema, one `secretRef` grammar.
- **The SDK never exposes `resolve()` or returns decrypted secrets in-process.** Raw secret resolution remains private to the internal runner and broker. An application or agent importing the SDK can validate references (`credentials.validate`), request broker leases, or run mediated child processes (`execution.run`), but cannot extract raw plaintext into memory through SDK methods. The public SDK does not expose plaintext; R-05 remains open for in-process callers holding the master key until out-of-process engine isolation.
- **Same-process threat ceiling**: Within the same Node.js process and OS user account, memory isolation against adversarial code is impossible. Any untrusted code (such as LLM-driven agents or dynamically evaluated tools) must be executed out-of-process via `hetzer exec` or `execution.run()` (with optional container sandbox `--sandbox`). Direct imports of internal modules (`cli/vault/hetzer-vault.mjs`) by same-user code are not an OS privilege boundary.
- The on-disk vault format gets a version marker and a written format note. Consumers must not decrypt it themselves; AegisBrain's direct decryption script migrates to `hetzer exec` or the SDK once G2 holds.
- Storage is a replaceable provider behind the engine (the SQLite Grimoire is the default implementation). This keeps Brumm's "provider-agnostic" position viable without building other providers now.
- **Central planes never resolve.** AegisBrain may store encrypted exports and `secretRef` catalog metadata. Resolution always happens locally on the execution host, through the engine. This reconciles "unify the tools" with the SDK roadmap's "no hosted control plane".

### D4. Freeze new surface until the gates hold, and cut what is not credential safety (Gate G3)

No new feature areas (new agent targets, new modules, deployment adapters, new TUI views, hardware phases) until G0 to G2 pass. Remove the stack-era and release-tooling code from the published package (table below). Extend the evidence runner so each gate has a regression protocol, and bring docs claims in line with the verified boundary.

## Options considered

### Option A: Continue the current roadmap (features first)
| Dimension | Assessment |
|---|---|
| Complexity | Rising: SDK PR-04 to PR-07, a Vercel adapter, hardware phases, TUI growth |
| Cost | Highest long-run; every feature inherits R-01 to R-04 |
| Risk | Consumers integrate against an interface whose trust model changes later |
| Team familiarity | High |

**Pros:** visible progress, matches existing plans.
**Cons:** unification would spread the authority gap to three more projects; docs and reality drift further apart.

### Option B: Authority model first, then engine extraction (chosen)
| Dimension | Assessment |
|---|---|
| Complexity | Medium: schema change for grants, sandbox default changes, deletion of stack code |
| Cost | Roughly 4 to 6 weeks for G0 to G3 for one engineer, mostly in G0 and G2 (planning estimate, not a commitment) |
| Risk | Breaking changes to flags and policy files; needs a migration note |
| Team familiarity | High; builds on the existing SDK, policy and broker code |

**Pros:** closes the findings that go beyond the documented boundary; gives consumers one safe interface; shrinks the maintained surface.
**Cons:** pauses feature work; some documented workflows (workspace broker policy files, ad-hoc raw opt-outs) need an operator approval step.

### Option C: Rebuild as a central or hosted vault with all tools as clients
| Dimension | Assessment |
|---|---|
| Complexity | High |
| Cost | High; new operations burden, new trust boundary |
| Risk | Contradicts the local-first position and the SDK roadmap; creates a single high-value target |

**Pros:** one source of truth.
**Cons:** the problems in R-01 to R-06 are not about storage location and would persist; much larger blast radius.

### Option D: Retire the vault and become a thin shim over an existing secret manager
| Dimension | Assessment |
|---|---|
| Complexity | Medium |
| Cost | Lower code ownership, dependency on external services and accounts |
| Risk | Gives up local-first simplicity; most managers do not provide agent-oriented brokering, redaction or canaries |

**Pros:** no custody of crypto or keys.
**Cons:** loses the part of Hetzer that is unique (broker, mediation, redaction, canary). Partly addressed by D3's replaceable storage provider.

## Trade-off analysis

The main trade is **feature velocity against a trustworthy foundation**. The features that matter most to consumers (host binding, encrypted export, stable CLI) all need the grant model anyway: host binding is a grant attribute, and an export format is meaningless if the access rules are not part of the vault. Doing D1 first therefore delays little that the consumers actually need.

D3's "central planes never resolve" rule is the second trade: it limits what AegisBrain can do from the cloud, in exchange for keeping the compromise of a cloud account from becoming a compromise of every credential. If a remote-resolve use case appears, it should be a separate ADR with its own threat model.

## Keep / Freeze / Cut

Verdicts are relative to the authority model above. "Not reviewed" means the verdict is provisional.

### Keep (engine core)

| Component | Path | Verdict | Why and what changes | Gate |
|---|---|---|---|---|
| Vault storage and crypto | `cli/vault/hetzer-vault.mjs` | Keep and fix | Add grants; version the format; enforce or delete `accessRole`; remove domain-bleed tables (see Cut) | G0, G2 |
| Master key custody | `resolveMasterKey`, `isolateMasterKey` | Keep and fix | Isolate by default and keep out of mounts. Add a passphrase and key-derivation mode only if AegisBrain's disaster-recovery flow is confirmed | G1 |
| Process runner | `cli/vault/exec.mjs` (runner part) | Keep, split | Move sanitizer, environment preparation and CLI entry into separate modules; flags only narrow | G0 |
| Stream sanitizer | `exec.mjs` (sanitizer part) | Keep, extract | Valuable and well tested; keep the p50/p95 evidence protocol | G2 |
| HTTP broker | `cli/vault/http-broker.mjs` | Keep and fix | Origin comes from the grant; add allowed-request audit records; no new auth schemes until G0 | G0 |
| Execution policy | `cli/vault/exec-policy.mjs` | Keep | Add a default-deny agent profile (backlog item B5); label argv, path and downloader guards best-effort | G0 |
| Scanner and Git hooks | `cli/vault/sniffer.mjs`, `cli/core/git-hook.mjs` | Keep (not reviewed in depth) | Low coupling to the authority model | none |
| Canary | `cli/vault/canary.mjs` | Keep, small fixes | Match only issued tokens; stop depending on a name prefix; drop the placeholder-key vault open | G2 |
| SDK facade | `sdk/` | Keep, becomes the contract | Versioned, grant-checked; defers provider adapters | G2 |
| Credential request flow | `cli/vault/credential-request.mjs` | Keep (skimmed) | This is the operator handoff D1 relies on | G0 |
| Env migration | `cli/vault/migrate-env.mjs` | Keep (not reviewed) | Useful onboarding path | none |
| MCP server | `cli/mcp/` | Keep, minimal | Metadata tools plus destination-bound substitution; remove or gate `hetzer_sniffer_redact`; correct the read-only `instructions` string; single version source | G0 |

### Freeze (no new work until the gate shows)

| Component | Path | Why frozen | Condition to unfreeze |
|---|---|---|---|
| OCI sandbox | `cli/vault/sandbox.mjs` | Only OS boundary; unsafe defaults (R-03). **Fix, do not extend.** | G1 passes |
| Audit | `cli/vault/audit.mjs`, SQLite audit table | Two stores, rewritable chain, fail-soft (R-06) | One event schema, keyed MAC or external anchor option, fail-closed under `--strict` (G2) |
| Human guard and native confirmation | `human-guard.mjs`, parts of `creds.mjs` | Heuristic by nature; duplicated (R-11) | Duplicate removed; docs state it is a speed bump |
| Skills installer | `cli/skills/` | Nine agent targets; each is ongoing maintenance | A new target needs a stated consumer |
| TUI | `cli/modules/tui.mjs` | 1,377 lines, misplaced, shows Docker state | Moved out of `modules/` and merged with `doctor`, or dropped |
| Enterprise and banking positioning | README section, `docs/enterprise-readiness.md` | Project age and absence of independent review | Independent review exists |
| Hardware root-of-trust roadmap | `docs/hardware-root-of-trust-roadmap.md` | No runtime adapter; TPM, TEE and HSM phases are premature | Only the OS-keyring phase feeds D2; the rest waits |
| SDK deployment adapters | `docs/sdk-library-roadmap.md` PR-04 to PR-07 (provider contract, Vercel, HTRN) | Outside the engine scope in D3 | G2 passes and a consumer needs it |

### Cut (remove from the published package; archive or move)

| Component | Path | Where it goes | Gate |
|---|---|---|---|
| Module system | `cli/modules/{registry,toggle,resolve,create,validate,runtime,list,install-wizard}.mjs`, `builtin.json`, `templates/modules` | Jagdpanzer (owner of orchestration) | G3 |
| Compose and 9Router support | `compose-runner.mjs`, `docker-compose.yml`, `core/docker.mjs`, `core/verifier.mjs`, `core/reasoner.mjs` | Jagdpanzer or archive | G3 |
| Deprecated commands | `up`, `update <module>`, `down`, `status`, `logs`, `modules`, `install`, `remove`, `module` | Already marked deprecated; remove after one release with a pointer message | G3 |
| `init` stack behaviour | `NINE_ROUTER_*` generation, Compose and modules copy | `init` creates the vault, an isolated key and MCP config only | G1, G3 |
| Release tooling in the CLI | `publish`, `core/npm-auth.mjs`, `core/upgrade.mjs`, `core/version-check.mjs` | `scripts/` for releases; users upgrade through npm | G3 |
| Vault schema leftovers | `vault_targets`, `vault_audit_findings`, `REALMS`, `SHADOW_GRIMOIRE_KEY`, legacy `vault.json` migration | Schema v2 with a one-time data-preserving migration | G2 |
| Test seams in production | `.test` / `.example` lookup shortcut in `http-broker.mjs` | Inject through parameters | G0 |
| Duplicate guard code | agent-ancestry copy in `creds.mjs` | Single implementation in `human-guard.mjs` | G2 |
| Risky install guidance | README `curl \| bash` and `irm \| iex` installers; `npx hetzer` quickstart pointing at v0.4.5 | One package identity, one pinned install path, documented | G1 |

## Consumer contract (provisional)

Provisional because Brumm is not yet specified and AegisBrain's requirements are roadmap items, not shipped behaviour.

| Contract | Used by | Status | Depends on |
|---|---|---|---|
| C1 Run a command with granted credentials (`hetzer exec`, SDK `execution.run`) | Jagdpanzer, AegisBrain | Exists; trust model changes under D1 | G0 |
| C2 Broker lease to a granted origin | Any tool calling HTTP APIs | Exists; origin from grant | G0 |
| C3 Metadata and validation (`credentials.list/metadata/validate`) | AegisBrain catalog, Brumm | Exists | none |
| C4 One `secretRef` grammar, exported as `parseSecretRef` | All four repositories | Needs decision (review section 3 lists at least five grammars) | G2 |
| C5 Host binding on a grant (`bindHosts`) | AegisBrain | Requested in its roadmap | G0 |
| C6 Encrypted export and import of the vault with its grants | AegisBrain disaster recovery | Requested; a passphrase mode needs a key-derivation design | G2 plus a separate design note |
| C7 Single audit event schema | AegisBrain, Brumm | Not defined | G2 |

How the three consumers move:

- **Jagdpanzer** keeps shelling out to the CLI. It should pass `--allow` and `--strict` where credentials are involved and drop its dual-name install probing once there is one package identity.
- **AegisBrain** replaces `scripts/mikrotik-client.mjs` direct decryption with `hetzer exec` or the SDK. Its D1 sync stores ciphertext and catalog metadata only, and never resolves credentials in the cloud.
- **Brumm** can sit above Hetzer as a policy decision point that issues short-lived leases. That handshake is not designed here. If it is pursued, Hetzer would verify a lease against the grant rather than trusting it.

## Consequences

**Becomes easier**
- One interface for every consumer, with a defined trust model.
- Honest, narrower docs: claims match what the evidence runner proves.
- Smaller package and faster reviews once stack and release code leave.

**Becomes harder**
- Existing workflows that rely on workspace broker policy files or ad-hoc raw opt-outs need a one-time operator approval step.
- Grants add a schema change and a migration to support.
- Feature requests (new agent targets, new adapters) wait for the gates.

**To revisit**
- OS-level separation of the vault from the subject (different OS identity, or keyring with user presence). D1 does not provide it.
- Whether other storage providers are worth building behind the engine.
- A remote-resolve use case, which would need its own ADR and threat model.
- The passphrase and recovery design for C6.

## Action items

Effort figures are planning estimates for one engineer familiar with the code, not commitments.

**G0: Authority model (Completed in G0 / G0.1)**
1. [x] Add grants to the vault schema (`allowedOrigins`, `rawInjection`, `bindHosts`, mandatory `allowedActions`) with HMAC signature (`grant_sig`) verification derived from a master-key subkey. Direct SQLite tampering fails closed, including clearing the signature: unsigned grants are never signed automatically. Credentials that predate signing are reviewed and signed by an operator with `hetzer creds grant --sign-existing`; broker policy approvals are signed the same way. Known limits: signatures carry no version (replay of an old signed grant is possible) and a writer who can read the master key can still forge grants.
2. [x] Operator path: extend `hetzer creds set` and `hetzer creds grant <id>` to record and sign grants; add `hetzer broker approve <policy>` pinning origin and SHA-256 policy hash in the vault.
3. [x] Broker: reject any policy whose origin or policy hash is not approved in vault; strictly require `broker.proxy` action grant; record `BROKER_REQUEST_ALLOWED` audit events.
4. [x] Runner: treat `--allow-raw-unmediated` and policy flags as requests narrowed by vault grants (`ERR_RAW_UNMEDIATED_DENIED_BY_GRANT`).
5. [x] MCP: bind `secretRef:` substitution to granted origins; remove `hetzer_sniffer_redact`; fix the `instructions` string.
6. [x] Evidence runner: add empirical protocols VERIFY-SEC-007 through VERIFY-SEC-012 for workspace broker policy origin/hash pinning, raw opt-out gating, in-process action checking, MCP origin binding, grant HMAC anti-tampering, and signature clearing, forged approvals and update laundering. (Note: R-05 remains open until Gate G2 out-of-process engine extraction).

**G1: Isolation defaults (about 1 week)**
7. [x] Sandbox masks vault, `.env`, key, `.hetzer/` and audit paths and mounts the project, not the instance home. [x] `init` isolates the key by default in a per-instance file, `~/.hetzer/keys/<instance-id>.key`, and refuses to replace a missing key over an existing vault (0.7.0, `VERIFY-SEC-016`; [ADR-0004](0004-container-free-sandbox-and-agent-containment.md)).
8. [x] Secret values removed from the container engine's argument list (passed by name through the engine CLI environment); network mode stated; default image pinned by digest. [ ] **Open:** a broker-only network profile and narrowing the sandbox broker bind (not validated on the test machine). The container-free `srt` engine added in 0.7.0 (ADR-0004) denies network except listed hosts, but does not reach the broker yet.
9. [ ] **Deferred (not sandbox work):** README: one package identity and install path; remove `curl | bash` and `irm | iex` as primary options; republish or correct the unscoped package so the quickstart is not eight minors behind.

**G2: Contract (about 1.5 to 2 weeks)**
10. [x] SDK `apiVersion` 1 (`docs/sdk-contract.md`, frozen by `sdk/sdk-contract.test.mjs`) with grant-checked execution; the public SDK entry exposes no `resolve()`, `reveal()` or decrypt member and the package `exports` map offers only that entry (R-05 remains open for in-process callers and for anyone who imports files by path); one credential id and `secretRef` grammar across the vault, the SDK and credential requests; the audit entry schema and event catalog in `docs/audit-event-schema.md`, checked against the code; vault format version 1 that refuses a newer vault before changing anything, with a format note in `docs/vault-format.md` (`VERIFY-SEC-015`). [ ] **Deferred:** lease interfaces. The HTTP broker already issues leases to the child it starts, but the SDK exposes none and is not given any in apiVersion 1; handing a lease to a caller needs the authority model to say what it may expose. [ ] **Open:** builds from before the format marker do not check it; audit `details` are event-specific and not validated.
11. [x] Audit consolidated into one stream: vault events mirrored into the file ledger, versioned entries covering the actor, optional keyed MAC with downgrade detection, key-less writers refused, damaged tails refused, concurrent writers safe, `hetzer exec --strict` (host and sandbox) fails closed on its start event (`VERIFY-SEC-014`). [ ] **Open:** an external anchor for the head and for a full-chain rewrite (today only `--require-mac` catches an unkeyed rewrite, and only for ledgers keyed from entry 1); an enforced link from the new ledger to its archive (`hetzer audit rotate` records the old head and archive hash in entry #1, but nothing checks that the archive still exists); dropping the SQLite audit table (format 2 keeps it as a frozen mirror, see item 12); strict handling in the broker and credential-request writers; a guaranteed-order writer lock (waiters now leave a marker that writers pause for, which cut rotation timeouts at 16 CPU-bound processes from 5 of 25 rounds to 1 of 25 on Windows (small samples), but a waiter can still time out after 10 seconds); the cause of one `ERR_AUDIT_LEDGER_TRUNCATED` seen once in a rotation-under-load test, where two writers were apparently inside the critical section at once (the lock hardening in this gate is defensive; it was not shown to be the cause, and 0 of 20 later runs failed).
12. [x] Remove the duplicate guard logic (agent-ancestry copy in `creds.mjs` unified into `human-guard.mjs`); vault schema v2 migration (format version 2, dropped `vault_targets`, `vault_audit_findings`, `REALMS` enum restriction, `SHADOW_GRIMOIRE_KEY`, and legacy `vault.json` migration; `vault_audit_events` retained as frozen mirror per `VERIFY-SEC-014`). The migration runs in one transaction, records the row count of each dropped table, and keeps its ledger record owed until the ledger takes it; the retired key alias is refused with a rename instruction (also by `hetzer init`) and an unimported legacy `vault.json` is reported (`cli/vault/vault-migration.test.mjs`, `VERIFY-SEC-015`). [ ] **Open:** the migration is one-way (a build that checks the marker at format 1 refuses the migrated vault, although the schema change alone would not need that) and rows in the dropped tables are not copied; `upsertTarget` and `recordAuditFinding` still accept data and store nothing; `realm` is free text.
13. [x] Narrow SEC-23 and R-05 wording in `docs/audit-batch-5.md`, `AGENTS.md`, and `docs/system-logic-and-progress.md` (clarifying that `reveal()` blocks naive TTY/CLI dumps, while internal `resolve()` and direct SQLite reads operate under same-user trust; untrusted agents must run out-of-process in a sandbox).

**G3: Cut (Completed in Gate G3)**
14. [x] Move or archive the module system, Compose runner, 9Router helpers, TUI placement and release tooling per the Cut table; keep a one-release deprecation pointer for removed commands.
15. [x] Update `AGENTS.md` (stale PR list, version references) and `docs/architecture.md`.

**Independent of the gates**
16. [x] Decide disclosure timing for review findings R-01, R-03 and R-04 before publishing the review document. Decided by the maintainer on 2026-10-13: the review is published together with the gate stack, ahead of the 0.6.0 release that carries the fixes. The fix commits, tests and evidence describe the same issues, so holding the document back would have hidden little. Until 0.6.0 is released, 0.5.12 remains as the review describes it.
17. [ ] Cover the "Not reviewed" areas in the review (second reviewer or a further pass) before G2 sign-off.

## Open questions

1. **Threat model**: is the target a single developer machine with agents as semi-trusted callers (assumed here), or should multi-user and shared-host cases be in scope?
2. **Disaster recovery**: is AegisBrain's "unlock master passphrase on a fresh machine" a firm requirement? It forces a key-derivation design that does not exist today.
3. **Package identity**: should the unscoped `hetzer` on npm remain the public name, or should the scoped package be published there? This must be settled before the README is fixed.
4. **Brumm**: will it act as a policy decision point that issues leases, or stay a documentation-level peer?
5. **Review depth**: the unread areas listed in the review can be covered by a further pass (for example by the other assistant you mentioned). The remaining file-level work is bounded.

## Correction to earlier discussion

An earlier conversational answer grouped the OCI sandbox with the Compose stack as over-engineering. The code shows they are separate. `sandbox.mjs` is the only OS-level boundary and belongs to the **Freeze and fix** list. The module registry, Compose runner, 9Router helpers, the `up` and `down` family and `init`'s `NINE_ROUTER_*` generation are the **Cut** candidates.
