# Architecture and security review, October 2026

> **Status**: Review findings, input to [ADR-0001](adr/0001-authority-model-and-engine-boundary.md). Not a security audit or certification.
> **Update**: findings R-01 to R-13 describe the code at the review basis below. [Section 7](#7-resolution-status-after-gate-g0-and-g01-2026-10-10) records which ones the later authority-model work changed.
> **Date**: 2026-10-10
> **Review basis**: `main` at `c2e85cd` (v0.5.12) plus uncommitted work-in-progress in `cli/vault/exec.mjs`, `cli/vault/http-broker.mjs` and their tests, and the untracked `docs/rfc-exfil-hardening-backlog.md`. Findings may move as that work lands.
> **Method**: reading the code and docs, running the existing test suite (302 tests, 301 passed, 1 skipped, 0 failed), and a small number of probes using synthetic credentials in throwaway temp directories. The probe scripts are intentionally not committed.

## 1. Summary

Hetzer has real mechanisms: an encrypted vault, a loopback credential broker, output redaction, canary tripwires, an execution policy, an audit log, and an SDK facade. What it does not yet have is an **authority model**: nothing separates the party that grants access (the operator) from the party being constrained (the agent or consuming tool).

Today the constrained party supplies most of the constraints. It chooses the flags (`--allow`, `--allow-raw-unmediated`, `--host`, `--policy`), it can write the broker policy file that decides where a credential is sent, and the vault does not record which destinations a credential is allowed to reach. The mechanisms are therefore best understood as **leak reduction against a cooperative or naive caller**, which is what the docs say. They are not yet a boundary against a caller that is manipulated (for example by prompt injection) into acting adversarially, which is the scenario `docs/agent-sandbox-threat-model.md` is written around.

This matters for the planned unification of AegisBrain, Jagdpanzer and Brumm: pointing more tools at the current engine copies the gap into each of them. See ADR-0001.

### Calibration

Two items below (R-02, R-05) sit inside boundaries the docs already state (same-user, heuristic guards). They are reported because the test names, the audit-batch wording and the CLI messages read more strongly than the boundary supports, not because they are undisclosed. The items that go beyond the stated boundary are R-01, R-03, R-04 and R-08.

### Evidence tags

- **probe**: reproduced against the repo code with synthetic values.
- **code**: established by reading the code; not executed.
- **doc**: a claim or mismatch in documentation.

## 2. Findings

| ID | Finding | Rating | Evidence |
|---|---|---|---|
| R-01 | Broker policy is workspace-authored; credentials are not bound to destinations in the vault | High | probe, code |
| R-02 | Constraining flags are supplied by the constrained caller | Medium | probe (API), code (CLI) |
| R-03 | Sandbox defaults can defeat the broker | High | code |
| R-04 | MCP service tools resolve `secretRef:` in any argument and send to an env-derived destination | Medium to High | code |
| R-05 | `Grimoire.resolve()` returns plaintext in-process; SEC-23 "resolved" is narrower than its text | Medium | probe |
| R-06 | Audit ledger is tamper-evident only against partial edits; two audit stores; fail-soft writes | Medium | probe, code |
| R-07 | Target/action binding is self-referential; `accessRole` is never enforced | Medium to Low | code |
| R-08 | Release channel drift: the README quickstart installs v0.4.5 | Medium | probe (registry query) |
| R-09 | Canary design weaknesses | Low | code |
| R-10 | Broker v1 coverage is narrow; test seams in production code | Low | code |
| R-11 | Structural debt: stack-era code, domain bleed, duplicated guard logic, divergent ID grammars | n/a | code |
| R-12 | Claims and documentation hygiene | n/a | doc |
| R-13 | The evidence runner proves the filters, not the authority model | n/a | code |

Ratings and evidence above are as of the review basis. See section 7 for current status.

### R-01 Broker policy authority (High)

`hetzer exec --allow <id>` automatically loads `.hetzer/brokers/<id>.json` from the workspace. That file names the HTTPS origin the broker will send the real credential to. Three properties combine:

- The vault stores no per-credential list of allowed destinations, so nothing cross-checks the policy against what the credential owner intended.
- The policy's integrity hash is carried inside the policy itself (`integrity.sha256`), so whoever writes the file writes the hash. An external hash is checked only if the caller passes one on the command line.
- The upstream guard (`assertSafeUpstreamHost`) blocks private and metadata addresses. It does not restrict which public origin is used.

**Probe result**: with a synthetic credential, a policy written into the workspace naming an arbitrary public HTTPS origin was accepted, and the broker attached the real credential to the outbound request for that origin. No human approval step was involved. File-permission checks in `loadBrokerPolicy` run only on POSIX.

Effect: a process that can write to the workspace can decide where a brokered credential is sent. This undermines the main reason to prefer the broker over raw injection.

### R-02 Constraints supplied by the constrained caller (Medium)

Raw injection fails closed by default (`ERR_RAW_UNMEDIATED_FORBIDDEN`), which is good. The opt-out is, however, a flag on the same command line the caller controls. `--policy`, `--policy-hash`, `--host`, `--no-sandbox`, `--allow-sensitive-paths` and `--allow-untrusted-downloaders` work the same way. `cli.mjs` applies a policy only when `--policy` is passed, and `HETZER_AUTO_SANDBOX` is opt-in. The machinery for stricter control exists (`allowedCredentials`, `allowRawUnmediated` in the policy) but nothing makes a policy mandatory or anchors it somewhere the caller cannot edit.

**Probe result** (library level): the same call is denied without the raw opt-out and accepted with it. The CLI wiring was confirmed by reading, not by running the CLI.

### R-03 Sandbox defaults (High)

`hetzer exec --sandbox` is the only OS-level boundary in the product, so its defaults matter. By reading `sandbox.mjs` and `cli.mjs`:

- `hetzer init` writes the master key into the instance `.env`, beside `data/hetzer-vault.db`. Key isolation to `~/.hetzer/grimoire.key` is opt-in.
- The sandbox mounts the resolved instance root read-write at `/workspace`. That directory contains `.env`, the vault database, `.hetzer/` policies and the audit log. A sandboxed process can therefore read both the key and the vault, which bypasses the broker.
- When no `--root` or `HETZER_ROOT` is given and the current directory is not recognised as a Hetzer workspace (the check looks for a Compose file mentioning Hetzer or 9Router), the root falls back to `~/.hetzer`. The mounted directory is then the Hetzer home itself, which also holds the isolated key file, so opt-in key isolation does not help. It also means the project being worked on is not the mounted directory.
- Environment values, including raw-injected credentials when opted in, are passed as `-e NAME=value` arguments to the container engine, which places them in the host process command line.
- No network is specified unless `--sandbox-network` is given, so the engine default (outbound access) applies.
- In sandbox mode the broker binds `0.0.0.0` and accepts any RFC 1918 client. It is still capability-gated.
- The default image is a floating tag, not a digest.

`docs/agent-sandbox-threat-model.md` describes the outcome as the real secret never entering container memory and outbound leaks failing. Given the defaults above, those statements hold only for a hardened configuration, not for the default one.

### R-04 MCP service tools (Medium to High)

By reading `cli/mcp/catalog.mjs`:

- For service tools, any string argument (payload, headers, path) containing `secretRef:<id>` is replaced with the plaintext before the request is sent.
- The destination comes from the module registry plus a URL variable read from the process environment or the workspace `.env`. There is no origin or private-address check on that fetch.
- The authorization check is that the credential's `projectId` equals the service or module id, or is `global` or `shared`. Any credential filed under `global` or `shared` is sendable to any service tool.
- `hetzer_sniffer_redact` is agent-callable and writes to the vault (auto-vaulting arbitrary text). `hetzer_vault_list` gives the agent the full credential inventory.
- The server's `instructions` string says the tools are read-only; service tools can POST.

This is the same class of gap as R-01: the destination is not bound to the credential in the vault.

### R-05 In-process plaintext (Medium)

`Grimoire.reveal()` is guarded by TTY, environment-marker and process-ancestry heuristics. `resolve(id, { targetId })` returns the same plaintext with no guard, and `targetId` is available from `list()`. The master key is readable by the same OS user.

**Probe result**: `reveal()` was blocked without a TTY; `resolve()` with the credential's own target returned the plaintext in-process.

`docs/audit-batch-5.md` (SEC-23) and `docs/system-logic-and-progress.md` describe direct imports as unable to reveal credentials without a TTY. That is true of `reveal()` and not of `resolve()`. The boundary statements elsewhere ("heuristic, same-user") are accurate; the specific sentences should be narrowed. Note also that AegisBrain's `scripts/mikrotik-client.mjs` already re-implements decryption against the on-disk format (see section 3), which shows the guard is bypassed in practice by a sibling tool.

### R-06 Audit (Medium)

- **Tamper evidence**: the ledger chains entries with plain SHA-256 and keeps its head anchor in a file beside it. No key or external anchor is involved.
  **Probe result**: a same-user rewrite that removed a canary event, renumbered the entries, recomputed the chain and rewrote the head file still passed `verifyAuditLedger`. It detects partial edits and truncation, not a coordinated rewrite.
- **Two stores**: a file ledger (`.hetzer/audit.log`) and an unchained SQLite table (`vault_audit_events`) record overlapping events with different schemas.
- **Fail-soft**: audit write failures are swallowed on the exec path, including under `--strict`.
- **Coverage**: the broker records lease issued, expired, invalid-capability and SSRF-blocked events, but not allowed requests (method, path, status).
- **RFC mismatch (Resolved)**: `docs/rfc-exfil-hardening-backlog.md` (B2) originally listed `BROKER_LIMIT_REACHED` as implemented before the code had it. As of 2026-10-10, `BROKER_LIMIT_REACHED` is implemented in `cli/vault/http-broker.mjs` and verified with unit tests in `cli/vault/http-broker.test.mjs`.

### R-07 Self-referential binding (Medium to Low)

`exec`, the broker and `secret-env` resolve with `targetId` read from the credential's own record, so the target check always passes. The effective gate is `allowed_actions` containing `process.start`, if set. `accessRole` (`reader`, `operator`, `admin`) is stored on every credential but is never checked anywhere (every writer sets `operator`).

### R-08 Release channel drift (Medium)

The README quickstart uses `npx hetzer ...`. The unscoped npm package `hetzer` is at v0.4.5 (checked against the registry on the review date), while the repository is at v0.5.12. The scoped `@agunggnn/hetzer` is published to GitHub Packages only. A user following the README runs a build that predates the same-user reveal guard, the exfil-hardening work and the SDK. The README also lists `curl | bash` and `irm | iex` installers, which the product itself treats as risky patterns elsewhere. Jagdpanzer's worker probes install locations for both package names, so the dual identity is already leaking into consumers.

### R-09 Canary (Low)

- Canary IDs are recognised by naming convention (`canary-`, `decoy-` prefixes) in public source.
- Any string matching the canary token pattern in child output terminates the child, not only the token that was issued, so attacker-influenced output can force a kill.
- The alert path opens the vault with a placeholder master key to write its audit row, and writes an incident log into the workspace `data/` directory.

### R-10 Broker coverage and seams (Low)

Broker v1 supports HTTPS upstreams, empty or Bearer auth schemes, text and JSON responses only, no redirects and no streaming (responses are buffered up to a limit). Credentials that need Basic auth, request signing, database protocols or streaming responses fall back to raw injection, so the "broker by default" posture covers a minority of real credentials. `startHttpCredentialBroker` contains a resolver shortcut for `.test` and `.example` hosts when a custom fetch is supplied, which is a test seam in production code.

### R-11 Structural debt

- **Stack-era code still shipped**: `cli/modules/*` (about 1,100 lines of registry, toggle, resolve, create, validate and runtime logic for a `builtin.json` that lists two modules), `compose-runner`, `reasoner` (9Router LLM analysis), `verifier` and `docker` helpers, `docker-compose.yml`, `templates/modules`, nine `up`/`update`/`down`/`status`/`logs`/`modules`/`install`/`remove`/`module` commands marked deprecated in `help`, and `init` still generating `NINE_ROUTER_*` secrets and copying Compose files.
- **Domain bleed in the vault schema**: `vault_targets` (host, port, source path), `vault_audit_findings` (vulnerability type, exploitation vector), six `REALMS`, a `SHADOW_GRIMOIRE_KEY` alias and a legacy `vault.json` migration. These come from an earlier pentest-tooling lineage and are not credential-vault concepts.
- **Duplicated guard logic**: `creds.mjs` re-implements the agent-ancestry and interactive-session checks that also live in `human-guard.mjs`.
- **Divergent identifier grammars**: the vault accepts `[a-z0-9-]` ids, `SECRET_REF_PATTERN` allows `.` and `_`, the SDK uses a third pattern, `credential-request.mjs` allows uppercase, and consumers use others (section 3).
- **God module and import cycles**: `exec.mjs` (about 1,000 lines) holds the stream sanitizer, process control, environment preparation, broker orchestration, policy application and argument parsing. `exec.mjs`, `sandbox.mjs`, `exec-policy.mjs` and `http-broker.mjs` import each other in cycles.
- **Release and developer tooling inside the product CLI**: `publish`, `npm-auth`, `upgrade` and `version-check`. `upgrade.mjs` and the release scripts use a shell on Windows, so "no shell" holds for the exec, broker and sandbox paths only.
- **Misplaced code**: the TUI (1,377 lines plus tests) lives in `cli/modules/` and reports Docker state.

### R-12 Claims and documentation hygiene

- The threat-model document cites a social-media post as a "verified" incident and uses unconditional matrix wording (for example the real key "never enters container memory").
- `README.md` and `docs/enterprise-readiness.md` carry banking and compliance sections (PCI DSS, SOC 2, ISO 27001, OJK, Bank Indonesia). They are caveated, but the project is about four weeks old (first commit 2026-08-30) and has not been independently reviewed.
- `AGENTS.md` still lists PRs #29 and #31 as pending although they are merged. Version strings in several docs and in three MCP source files lag or are hardcoded.
- `docs/hardware-root-of-trust-roadmap.md` (265 lines) specifies TPM, TEE and HSM work that has no runtime adapter.
- `docs/rfc-exfil-hardening-backlog.md` is written in Indonesian while the rest of the docs are English.

### R-13 Evidence runner scope

`scripts/verify-evidence.mjs` runs seven protocols (stream redactor, strict scoping and broker boundary, ancestry heuristic, Git scanner, sanitizer latency, canary, sensitive-path guard). None exercises who is allowed to author a broker policy, whether a caller can widen its own grants, in-process resolution, sandbox mount contents, or MCP destination binding. The runner is good evidence for the filters. It does not yet cover the authority model.

## 3. Consumer ground truth

The sibling projects were inspected read-only under `E:\GitHub\`, limited to code and docs. No `.env` file was opened.

| Project | What it is | How it uses Hetzer today | What it asks of Hetzer |
|---|---|---|---|
| **AegisBrain** | Cloudflare Workers + D1 control plane | A local script (`scripts/mikrotik-client.mjs`) reads the Hetzer SQLite file and key and **decrypts it directly**, reproducing the HKDF salt, info string and AAD format. A `/api/v1/vault/sync` endpoint stores encrypted credential entries in D1 using its own per-entry scheme. Its DLP matches `secretRef:[a-zA-Z0-9_-]+`. | `hetzer exec --allow <ref> --host <host-id>` (host binding); `hetzer vault export --encrypted --passphrase-env`; unlock "master Hetzer passphrase" on a fresh machine for disaster recovery |
| **Jagdpanzer** | Command orchestrator and worker (JCP v2) | Shells out to the `hetzer` CLI: `creds`, `sniffer`, `canary`, `exec`, `protect`. Its worker wraps `npm install` in `hetzer exec --` (no `--allow`, no `--strict`). Probes both `@agunggnn/hetzer` and `hetzer` install paths. Module manifests name `secretRef:` credentials. | Stable CLI contract; credentials for module install and host bootstrap |
| **Brumm** | Governance and blast-radius engine (status: research and architecture) | Documentation only. Treats Hetzer as one of several secret providers (Vault, 1Password, cloud secret managers) and uses `secretRef:prod/aws` / `secretRef://prod/aws` style references. States explicitly that absolute zero plaintext must not be claimed. | A policy and lease handshake, not yet specified |
| **9Router** | Third-party AI router (not owned here) | Shipped as a Hetzer compose module; `init` generates its secrets | Nothing the vault needs; it belongs with the orchestrator |

Observations used by the ADR:

1. The on-disk vault format is already a de facto public API, consumed without any guard. It has no version negotiation or documented contract.
2. At least five `secretRef` grammars are in use across the four repositories.
3. A "passphrase" recovery flow is assumed by AegisBrain, but the vault master key is a random 48-byte value with no passphrase mode and no key-derivation stretching.
4. Centralisation is already happening in the form of encrypted-entry sync to D1. `docs/sdk-library-roadmap.md` explicitly rules out a hosted control plane for Hetzer, so the two designs disagree today.

## 4. Coverage and limits of this review

| Depth | Areas |
|---|---|
| **Read in full** | `hetzer-vault.mjs`, `human-guard.mjs`, `audit.mjs`, `secret-env.mjs`, `exec.mjs`, `exec-policy.mjs`, `http-broker.mjs`, `sandbox.mjs`, `canary.mjs`, `sdk/client.mjs`, `cli/mcp/{server,protocol,catalog}.mjs`, `AGENTS.md`, `docs/architecture.md`, `docs/system-logic-and-progress.md`, `docs/sdk-library-roadmap.md`, `docs/rfc-exfil-hardening-backlog.md`, `docs/agent-sandbox-threat-model.md` |
| **Skimmed or searched** | `cli/core/cli.mjs` (init, help, `exec` and `broker` dispatch), `creds.mjs`, `credential-request.mjs`, `doctor`, `upgrade`, `version-check`, `npm-auth`, `reasoner`, `verifier` (headers only), module registry (`builtin.json`, file sizes), skills installer (target table), TUI (exports and searches), README, hardware roadmap, enterprise and value docs, `audit-batch-5.md`, `verify-evidence.mjs` (protocol names), sibling repositories (searches and targeted reads) |
| **Not reviewed** | TUI rendering, `skills/audit.mjs`, `git-hook.mjs`, `sniffer.mjs` internals, `migrate-env.mjs`, `snapshot.mjs`, `compose-runner.mjs` body, module `create`/`validate`/`toggle`/`registry` logic, most of `creds.mjs`, `mcp/{call,ping,configure,synthesis}.mjs`, the test files (only counts and a full run), `scripts/publish*.mjs`, `verify-evidence.mjs` internals, `install.sh` / `install.ps1`, CI workflows, `docs/{installation,vibe-coders,mcp-guide,http-credential-broker,banner-spec}.md` |

Other limits: no fuzzing, no dynamic analysis on Linux or macOS, no review of the Cognee or hardware-roadmap designs, and no attempt to attack the sandbox itself. Ratings are the reviewer's judgement against the threat model described in section 1.

## 5. Disclosure note

This repository is public. The findings above are written at design level and the probe scripts are not committed. Decide on timing before pushing this document, in particular for R-01, R-03 and R-04, and consider fixing the first two (ADR-0001 Gate G0 and G1) before or together with publishing the details.

## 6. AGY Complementary Review & Resolved Backlog (2026-10-10)

> **Reviewer**: Google Antigravity (AGY)  
> **Status**: Resolved uncommitted items & audited previously unreviewed areas

### 6.1 Backlog Resolution: RFC Exfil-Hardening (B2)
- **Implemented & Verified**: `BROKER_LIMIT_REACHED` audit event is now implemented in `cli/vault/http-broker.mjs` (lines 782–797) when child request quota reaches `policy.maxRequests`.
- **Test Coverage**: Added test case in `cli/vault/http-broker.test.mjs` verifying all 4 broker audit event types (`BROKER_LEASE_ISSUED`, `BROKER_CAPABILITY_INVALID`, `BROKER_LIMIT_REACHED`, `BROKER_LEASE_EXPIRED`). All 28 broker tests pass.

### 6.2 Audit of Previously Unreviewed Areas

| Component | Path | AGY Findings & Verdict |
|---|---|---|
| **Git Hooks** | `cli/core/git-hook.mjs` | **Keep**. Clean and lightweight pre-commit and commit-msg hooks. Effectively scans staged diff additions and commit messages via sniffer with zero external dependencies. Test files and fixtures are properly exempted (`isTestOrFixtureFile`). Overall hook latency is dominated by Git/Node startup. |
| **Sniffer Internals** | `cli/vault/sniffer.mjs` | **Keep with Gate G0 MCP fix**. Regex tokens and Shannon entropy heuristic (`shannonEntropy >= 4.3`) are fast and effective. **Confirms R-04**: `redactAndVault` allows untrusted agents to trigger arbitrary secret persistence into SQLite vault via MCP tool `hetzer_sniffer_redact`. Must be gated or removed in MCP. |
| **Creds & 9Router Leftovers** | `cli/vault/creds.mjs` | **Keep and refactor**. Still contains 4 hardcoded `nine-router-*` credentials (8 occurrences) in `KNOWN_CREDENTIALS`. Duplicates `checkProcessAncestors` and `detectAgentAncestor` from `human-guard.mjs`. |
| **Migrate Env** | `cli/vault/migrate-env.mjs` | **Keep and clean**. Auto-ingests `.env` secrets into vault; still carries hardcoded `nine-router` bindings. |
| **TUI Monitor** | `cli/modules/tui.mjs` | **Freeze**. 1,378 lines monitoring vault posture, audit events, and Docker Compose status. Recommend freezing and eventually separating Docker views to Jagdpanzer while merging vault/audit posture into `hetzer doctor`. |
| **CI Workflows** | `.github/workflows/` | `release-main.yml` and `publish-package.yml` only publish `@agunggnn/hetzer` to GitHub Packages (`npm.pkg.github.com`). Public npm registry (`registry.npmjs.org/hetzer`) relies on manual maintainer invocation of `npm run publish:npm` (via `scripts/publish.mjs`). Note: `npm run publish-pkg` aliases GitHub Packages releases, not public npm. |

### 6.3 Root Cause Analysis & Fix: Installer and Upgrade Failures (R-08 Deep Dive)

**Problem Reported**: Users experience stale versions when installing or updating (e.g. stuck on v0.4.5), or upgrades do not take effect unless manually uninstalled first.

**Root Causes**:
1. **Public NPM Registry Drift**: Unscoped package `hetzer` on npm is at `0.4.5`, while repo is `0.5.12` (`@agunggnn/hetzer`). Because `install.ps1` and `install.sh` ran `npm install -g hetzer@latest`, npm fetched the 0.4.5 release. Releasing to public npm requires maintainer execution of `npm run publish:npm`.
2. **Release Asset Filename Mismatch & Substring Collision in `upgrade.mjs`**:
   - `upgrade.mjs` fetched `SHASUMS256.txt` from GitHub release assets, whereas `scripts/build-package.mjs` generated `checksums.txt`.
   - `upgrade.mjs` searched for `line.includes("hetzer-X.tgz")`. Because `checksums.txt` lists `agunggnn-hetzer-X.tgz` first, the substring matched the scoped tarball hash instead of the unscoped download, causing an integrity mismatch.
3. **NPM Global Shim Collision**: On Windows, npm global shims (`hetzer.cmd`) may fail to update cleanly without explicit re-invocation.

**Fixes Applied**:
- `scripts/build-package.mjs`: Now generates both `checksums.txt` and `SHASUMS256.txt`.
- `cli/core/upgrade.mjs`: Added fallback lookup for `checksums.txt`, exact token filename matching (`parts[1] === targetFilename`), and verified with a multi-line test in `cli/core/upgrade.test.mjs`.
- `install.ps1` & `install.sh`: Maintained safe, standard npm installation flow without unconditional uninstalls or unpinned HEAD git fallbacks, with actionable guidance on error.
- `README.md`: Pointed upgrade guidance directly to `hetzer upgrade`.

## 7. Resolution status after Gate G0 and G0.1 (2026-10-10)

Sections 1 to 6 describe the repository as reviewed at `c2e85cd` and are kept unchanged so the findings stay traceable. This section records what the follow-up work changed. It was checked by re-running the original probes against the branch that contains `feat(vault): implement Gate G0 authority model...` and `fix(vault): make grant and approval signatures fail closed`, and by reading the code for items that cannot be probed.

| ID | Status | What changed, and what is left |
|---|---|---|
| R-01 | **Mitigated** | The broker refuses a policy whose origin is not in the credential's vault grant (`ERR_BROKER_ORIGIN_NOT_GRANTED`) or whose SHA-256 is not an operator-approved policy (`ERR_BROKER_POLICY_NOT_APPROVED`). The self-declared `integrity` hash is no longer a trust input. Grants and approvals are signed with master-key subkeys, so a writer without the master key can neither change them nor clear the signature (`VERIFY-SEC-007`, `-011`, `-012`). **Left:** a writer who can read the master key can still forge grants, and a previously valid signed grant can be replayed from an old copy of the database. |
| R-02 | **Partly mitigated** | `--allow-raw-unmediated` is now a request that the vault grant must permit (`ERR_RAW_UNMEDIATED_DENIED_BY_GRANT`, `VERIFY-SEC-008`). **Left:** `--policy`, `--host`, `--no-sandbox`, `--allow-sensitive-paths` and `--allow-untrusted-downloaders` are still caller-supplied flags, and no execution policy is mandatory. |
| R-03 | **Partly mitigated** | Gate G1: the sandbox mounts an explicit project directory (not the instance root) and refuses unsafe targets; Hetzer-owned paths inside the mount are hidden; only injected variables are forwarded, by name, so values are off the engine command line and the host `PATH`, `HETZER_ROOT` and master key are not forwarded; the default image is digest-pinned; the network mode is stated (`VERIFY-SEC-013`, plus a Docker Desktop for Windows check of the masks). **Left:** outbound network is still open by default; `init` still writes the master key beside the vault (isolation by default was deferred because a single key path would be overwritten by a second instance); the broker still binds `0.0.0.0` in sandbox mode, which could not be validated because the container could not reach any host listener on the test machine; files that appear after the container starts are not hidden; `docker inspect` shows container environment values. |
| R-04 | **Mitigated** | `hetzer_sniffer_redact` is removed, and `secretRef:` substitution is allowed only when the tool's destination origin is in the credential's grant and the credential has the `mcp.tools/call` action (`VERIFY-SEC-010`). **Left:** the service URL is still read from the environment or workspace `.env`; it is now only usable with credentials already granted to that origin. `hetzer_vault_list` still exposes the credential inventory. |
| R-05 | **Open (partial mitigation)** | `resolve()` requires an action that the grant lists (`VERIFY-SEC-009`). A caller with the master key that passes a granted action still receives plaintext. Closing this needs the out-of-process boundary planned for Gate G2. |
| R-06 | **Partly mitigated** | Added `BROKER_LEASE_ISSUED`, `BROKER_LEASE_EXPIRED`, `BROKER_CAPABILITY_INVALID`, `BROKER_LIMIT_REACHED` and `BROKER_REQUEST_ALLOWED`, which also closes the RFC/code mismatch. Gate G2 (audit): entries are versioned and the hash now covers the actor; entries carry an HMAC when a master key is available; verification rejects edits, truncation, wrong keys, unkeyed entries after keyed ones and a version downgrade; a writer without the key cannot extend a keyed ledger; a damaged tail stops writes instead of restarting the chain; vault events are mirrored into the same ledger (the SQLite table stays as a frozen mirror); `--strict` does not start if the exec start event cannot be recorded; and concurrent writers no longer lose events (`VERIFY-SEC-014`). A probe before the change found that with 4 or more concurrent writers most events were lost, silently: 8 writers of 25 events each wrote 25 of 200. The mean cost was about 101 ms per event over 20 sequential events on this Windows machine (single run, not a p50/p95), which is consistent with the two permission-hardening process spawns per write against the 5 s lock timeout; after limiting hardening to file creation the same 50-event probe averaged 9 ms and 4, 8 and 12 concurrent writers lost nothing. Only Windows was measured; Linux and macOS are untested. **Left:** a consistent rewrite of the whole chain without any MAC still passes default verification and needs `--require-mac`, which fails for any ledger that was not keyed from its first entry; anyone who can read the master key can forge; the head anchor is a file the same attacker can rewrite, so there is no external anchor yet; the SQLite table is not dropped (schema v2, ADR item 12); non-exec writers (broker, credential requests) are still fail-soft; a ledger written by a process without the key stops accepting events from that process instead of recording them unkeyed; and the refusal states (damaged tail, missing key, different key, entries removed behind the anchor) stop `hetzer exec --strict` until a person runs `hetzer audit rotate --yes` (gated by the human-session heuristic, so an agent session does not clear its own refusal by following the error text), which archives the three ledger files together and records the old head, the old verification result and the archive hash in entry #1 of the new ledger. The gate is a heuristic, and anyone with shell access can still move the files by hand or call the function in-process; deleting the archive together with the rotation entry is not detected. |
| R-07 | **Partly mitigated** | `resolve()` no longer treats an empty action list as "any action". **Left:** `exec`, the broker and `secret-env` still pass the credential's own `projectId` as `targetId`, so the target check is self-referential, and `accessRole` is still never enforced. |
| R-08 | **Partly mitigated** | `hetzer upgrade` now matches the checksum entry by exact filename and falls back to `checksums.txt` (the earlier substring match selected the scoped tarball's hash). **Left:** the unscoped `hetzer` package on npm is still 0.4.5 when checked on the date above, and the installers and README quickstart still install it. Publishing is a maintainer decision. |
| R-09 | **Open** | `canary.mjs` is unchanged. |
| R-10 | **Open** | Broker v1 coverage is unchanged, and the `.test` / `.example` lookup shortcut is still present in `http-broker.mjs`. |
| R-11 | **Open** | Stack-era code, domain bleed in the vault schema, the duplicated guard logic in `creds.mjs` and the divergent identifier grammars are unchanged (Gate G2 and G3). |
| R-12 | **Partly addressed** | The git-hook false positive on lockfile integrity digests is fixed. Banking positioning, the threat-model wording and the hardware roadmap are unchanged. |
| R-13 | **Partly addressed** | Evidence protocols `VERIFY-SEC-007` to `-012` now exercise the authority model: workspace-authored broker policy, caller-supplied raw opt-out, action-granted `resolve()`, MCP destination binding, grant signatures, signature clearing, forged approvals and update laundering. Sandbox mounts and audit rewrite are still not covered. |

### 7.1 Why replay of an old signed grant is not fixed at this layer

A signed grant protects the values it covers. It does not tell the vault that a newer value exists. An attacker holding an earlier copy of the database can restore the whole earlier row, signature included, and the vault will accept it. Adding a version number to the signed payload does not help, because the old version number is restored together with the old row. A fix needs a counter that lives where the attacker cannot roll it back together with the database, for example a hardware-backed or remote monotonic counter. Anything stored on the same machine under the same user can be rolled back as well. This is listed as a known limit and belongs with the OS keyring and out-of-process work in ADR-0001, not with a further schema change.

### 7.2 Operational changes introduced by G0 and G0.1

- Credentials created before grant signing are unusable until an operator runs `hetzer creds grant --sign-existing`, which lists them and asks for a typed confirmation.
- A broker policy must be approved with `hetzer broker approve <policy-file>` after any edit, because the approval is bound to the policy's hash.
- `--allow-raw-unmediated` has no effect until `hetzer creds grant <id> --raw allow` has been run by an operator.
- `hetzer_sniffer_redact` no longer exists in the MCP server.

### 7.3 Not re-checked in this section

The sandbox, the audit ledger, the canary and the human-session guard were confirmed unchanged by comparing them with `main`, not by re-running probes. The Linux and macOS behaviour of the new operator commands was not tested.
