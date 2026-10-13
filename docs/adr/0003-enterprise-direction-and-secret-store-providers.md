# ADR-0003: Enterprise direction: local-first fleet visibility and external secret-store providers

**Status:** Proposed. Draft for maintainer review. Nothing here authorizes implementation, a release, a hosted service,
a price or a sales claim.
**Date:** 2026-10-13
**Deciders:** Maintainer (`agunggnn`).
**Related:** [ADR-0001](0001-authority-model-and-engine-boundary.md) (authority model and the feature freeze),
[ADR-0002](0002-landing-the-gate-stack.md), [enterprise-requirements.md](../enterprise-requirements.md) (what buyers and
secret-store vendors require, with sources), [enterprise-readiness.md](../enterprise-readiness.md),
[sdk-library-roadmap.md](../sdk-library-roadmap.md), and findings R-05 and R-06 of the
[architecture review](../architecture-review-2026-10.md).

## Context

Hetzer 0.6 is a local-first credential layer for developers and AI coding agents: an encrypted vault with signed
grants, a stream redactor, an HTTP broker, canary tripwires, a sandbox and a tamper-evident audit ledger. It is
published on npmjs with provenance. It is not independently audited, and its documented boundary is the local OS user
(R-05 stays open for same-user code).

The maintainer wants to explore a paid, enterprise-facing direction: central visibility ("insights") over how agents use
credentials, integration with external secret stores such as HashiCorp Vault, and detection of risky behavior on
developer devices. Three facts shape what is sensible.

1. **The market moved.** 1Password has launched Unified Access, aimed at credentials used by AI agents, and announced a
   Codex integration in May 2026 so that vaulted credentials can be referenced without appearing in code, terminals or
   model context. It names Anthropic, Cursor, GitHub and Vercel among partners. These are vendor and trade-press
   statements that could not be checked against primary pages from the authoring environment (see "Sources" in
   enterprise-requirements.md). Hetzer therefore cannot present "a layer between agents and secrets" as unique. What
   remains different is that it is open source, local-first, has no runtime dependencies, and can be inspected and
   run without an account.
2. **Hetzer's own commitments limit the design.** The SDK roadmap rules out a hosted control plane. ADR-0001 D3 says
   central planes never resolve secrets. ADR-0001 freezes new feature surface until its gates pass, and its status is
   still "Proposed" although AGENTS.md records gates G0 to G3 as complete.
3. **Device monitoring is limited by the threat model.** A Node.js CLI running as the user cannot stop that user, and
   cannot prove it was not bypassed (git hooks can be skipped, the process can be killed). Preventing that needs an agent
   with OS privileges the user cannot remove, which is the endpoint security and MDM category, a different product with
   a different team and audit burden.

## Decision (proposed)

### D1. Stay local-first: central systems store and observe, the execution host resolves

- A secret value is released only on the execution host, by the local engine, under a grant in the local vault.
- Nothing Hetzer operates, now or in this plan, receives secret values.
- A central component, if built, receives **metadata only** and can be run by the customer.

### D2. Add external secret stores as providers behind the engine, starting with OpenBao and Vault (read-only KV v2)

- The local vault keeps a **reference entry** for a provider-backed credential: an id, a provider URI and signed grants
  (`allowedOrigins`, `allowedActions`, `rawInjection`, `bindHosts`, expiry). The grants stay the authority, as in
  ADR-0001 D1. The value is fetched at resolve time and is never stored by Hetzer.
- A provider can only widen where a value comes from. It cannot widen where the value may go.
- OpenBao (MPL 2.0) is the first target, because its license allows a paid product to depend on it without the
  questions the Vault license raises. HashiCorp Vault follows through the same HTTP API after a legal read of its
  license (see enterprise-requirements.md, part C).
- Providers beyond that (cloud secret managers, 1Password) are separate decisions that follow evidence from design
  partners. Treating a competitor's product as a provider is allowed and may be the better choice than competing with it.

### D3. Fleet visibility is a metadata export plus a collector the customer can run

- Export selected audit events (canary trips, blocked reveals, denied raw injection, sandbox refusals, broker
  denials) in the existing schema ([audit-event-schema.md](../audit-event-schema.md)). The export carries the ledger hash
  chain, so a collector can detect edits and gaps. The collector holding the latest head hash also acts as the external
  anchor that R-06 lists as missing. The MAC key never leaves the device, so a collector verifies the chain, not the MAC.
- Policy distribution uses signed bundles that can only **narrow** local access (ADR-0001 rule 1). Signing uses
  `node:crypto`, so the zero-dependency rule holds.
- What this can show: activity that went through Hetzer. What it cannot show: activity that did not. Gaps in
  reporting are themselves a signal ("device stopped reporting"), and server-side controls (CI scanning, protected
  branches) remain the enforcement point.

### D4. Explicit non-goals

- No malware detection, EDR or kernel-level agent, and no claim to resemble those products.
- No claim to prevent a determined same-user actor. Detection and reporting only.
- No hosted multi-tenant secret store.
- No per-employee productivity or content monitoring. Collected fields are limited to security events and device
  identity, are documented, and need a notice and a lawful basis in each customer's jurisdiction.

### D5. Validate demand before building the platform

- The open-source core stays Apache-2.0.
- The first commercial activity is a paid **assessment** for teams that use AI coding agents, run with the existing
  tool. It needs no new product surface and fits the maintainer's consulting goal.
- Platform work (D2, D3) starts only after the entry criteria of gate E1 hold, and a dashboard UI is built only after
  design partners ask for what it shows.
- Kill criterion: if the pilots in gate E3 produce no paid engagement, Hetzer stays an open-source tool with consulting
  around it, and nothing in this ADR is kept running.

## Options considered

| Option | Summary | Verdict |
|---|---|---|
| A. Stay a CLI, sell consulting only | No new surface; fastest | Keep as the floor and as the validation path in D5 |
| B. Open core: providers, signed policy, metadata export, self-hosted collector | This ADR | Proposed |
| C. Hosted SaaS control plane | One place for policy, audit and billing | Rejected for now: contradicts the local-first commitments, adds a high-value target, and brings the vendor's own SOC 2 or ISO 27001 burden before any revenue |
| D. Integrate with 1Password or others as the product's backend instead of competing | Smaller scope, borrows trust | Compatible with B; decided per provider, with evidence |
| E. Become an endpoint security agent | Matches the "Sentinel-like" idea | Rejected: different category, team and certification path |

## Consequences

- Provider support is new feature surface. It stays blocked by ADR-0001's freeze until ADR-0001 is accepted (its gates
  are recorded as done) and this ADR is accepted.
- The commercial license is open: an open-core model needs clear copyright ownership. With outside contributors, a CLA
  or DCO is needed before a commercial module is offered (enterprise-requirements.md, part D).
- Enterprise buyers will ask for artifacts Hetzer does not have yet (independent review, SBOM, support terms).
  Gate E0 produces them and is useful whether or not E1 to E3 happen.
- A customer-run collector means customers operate it. Support scope and a data-processing position must be written
  before a pilot.

## Gates

Each gate states what must be true, not a date. Estimates are deliberately omitted until E0 scope is agreed.

| Gate | Purpose | Exit criteria |
|---|---|---|
| E0. Credibility | Make an evaluation possible | ADR-0001 accepted or amended. Independent security review of the 0.6.x line with the report published (scope agreed first). Audit-ledger concurrency measured on macOS and Linux. R-03 default network decision and R-07 target binding resolved or documented as accepted risk. SBOM attached to releases. Vulnerability disclosure response time stated. Branch protection and CODEOWNERS in place |
| E1. Provider interface | Prove D2 on OpenBao | Provider contract documented and frozen like the SDK contract. A new evidence protocol shows a provider-fetched value is never written to disk, argv, logs or the audit ledger. Integration test against an OpenBao dev server in CI. Fails closed when the store is sealed, unreachable or denies the read. Legal read of the Vault license recorded before Vault is advertised |
| E2. Fleet metadata | Prove D3 without a hosted service | Export schema and collector reference implementation. Chain verification and gap detection tested against tampering. Signed policy bundle that only narrows, with downgrade and replay tests. Data inventory and privacy notice template |
| E3. Design partners | Decide whether anyone pays | Three to five teams using AI coding agents run a pilot. Each pilot records which findings mattered. At least one paid engagement or written purchase intent, otherwise the kill criterion in D5 applies. Only now: dashboard design |

## Open questions for the maintainer

1. Accept ADR-0001 as written, or amend it first? Everything here depends on it.
2. The bootstrap problem ("secret zero"): a provider-backed credential still needs one credential to reach the store.
   Candidates are workload identity from CI (OIDC/JWT), the OS keychain, or a local agent socket. Which is acceptable
   for a developer laptop?
3. Contribution policy: DCO or CLA, and who owns the copyright of past commits?
4. Appetite for the independent review in E0, and a budget range. This is the largest single credibility item.
5. Is the assessment offer (D5) something to run under a personal business now, in parallel with E0?
