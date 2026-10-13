# Enterprise requirements reference

> **Status:** Working reference for [ADR-0003](adr/0003-enterprise-direction-and-secret-store-providers.md). Not legal,
> audit or compliance advice, and not a statement that Hetzer meets any item below.
> **Date:** 2026-10-13

This document lists what enterprise buyers and secret-store vendors typically require, how that maps to Hetzer today,
and what a Vault or OpenBao integration has to do. Each fact carries a verification tag:

- **[primary]** read from the owner's own text on the date above.
- **[secondary]** from trade press, vendor summaries or search summaries; check the primary source before relying on it.
- **[practice]** common industry practice described from general knowledge; every buyer sets its own list, so ask each
  one for it.

## Part A. How an enterprise purchase usually proceeds [practice]

| Stage | What happens | What the vendor needs ready |
|---|---|---|
| 1. Champion and pilot | A developer or security engineer tries the tool, often on a free tier | Install works in one command, honest docs, a way to run it without an account |
| 2. Security review | The buyer's security team scores the vendor | Questionnaire answers, architecture and data-flow diagram, vulnerability disclosure policy, SBOM, release provenance, penetration test or code-review summary |
| 3. Legal and procurement | Contracts and risk acceptance | Master services agreement, data processing agreement if any personal data is handled, support terms, liability and insurance statements, license terms |
| 4. Rollout | Pilot becomes a purchase | Support channel, upgrade policy, an owner on the vendor side |

Security questionnaires commonly follow the SIG (Shared Assessments) or CAIQ (Cloud Security Alliance) formats, or are
custom. A local-only tool is asked fewer hosting questions than a SaaS, but the supply-chain and support questions
remain.

## Part B. Where Hetzer stands today

| Buyer expectation | Status in this repository | Gap |
|---|---|---|
| Source available, permissive license | Apache-2.0, no runtime dependencies | None |
| Signed or attested releases | npm provenance from a GitHub Actions trusted-publishing job, checksums attached to GitHub Releases, SHA-pinned workflow actions | No SBOM attached to releases |
| Vulnerability disclosure policy | `SECURITY.md` with private reporting | No stated response time |
| Independent security assessment | None. The October 2026 architecture review is an internal review and says it is not an audit | **Largest gap** |
| Documented threat model and limits | `docs/agent-sandbox-threat-model.md`, the boundary tables, ADR-0001 | Maintain as the product changes |
| Cross-platform evidence | CI on Linux, macOS and Windows | Audit-ledger concurrency measured on Windows only |
| Support terms, SLA, named owner | None | Needed before any paid pilot |
| Code ownership for dual licensing | Single maintainer; no CLA or DCO | Needed before accepting outside contributions to a commercial module |
| Process certifications (SOC 2, ISO/IEC 27001) | None | Only required if Hetzer operates a service that holds customer data. A customer-run tool does not need them to start, but buyers will ask |

## Part C. Integrating with HashiCorp Vault and OpenBao

### C1. Do you need HashiCorp's permission? No, to call the HTTP API. Yes, to be listed as a partner integration.

A client that talks to a customer's own Vault over its public HTTP API does not need an agreement. HashiCorp runs a
Technology Partner program for integrations it will verify and list. Per its program page: **[secondary]** (summary of
https://developer.hashicorp.com/vault/docs/partners/program; the page itself could not be opened from the authoring
environment)

1. Fill out an integration intake form (a mutual NDA is optional).
2. Send documentation and test results; HashiCorp needs test credentials for the underlying infrastructure and a live
   demo.
3. HashiCorp tests against self-managed Vault and HCP Vault Dedicated. Review is iterative.
4. Resolve all concerns, sign the HashiCorp Technology Partner Agreement, review logo guidelines and the listing, and
   describe how you will support customers.
5. After HashiCorp verifies code, documentation and support plan, the integration can be released.
6. Partners support the integration under SLAs; a 48-hour target for critical issues was reported.

Treat partner listing as optional marketing, to be considered after gate E1 and a paying customer who asks for it.

### C2. License position [primary]

The `LICENSE` file of `hashicorp/vault` (retrieved 2026-10-13) licenses Vault 1.15.0 or later under the Business Source
License 1.1, with IBM as licensor, change license MPL 2.0 and a change date four years after each version is published.
Its Additional Use Grant allows production use provided the use does not include offering the Licensed Work to third
parties on a hosted or embedded basis in order to compete with the paid versions. Terms that matter here:

- A **"competitive offering"** is a paid product, including through paid support arrangements, that **significantly
  overlaps** with the capabilities of the paid versions of Vault.
- **"Embedded"** includes packaging a competitive offering so that **the Licensed Work must be accessed or downloaded for
  it to operate**.
- Hosting or using Vault for **internal purposes** is not a competitive offering.

What this means for the plan, to be confirmed by counsel before any Vault claim is made:

- A paid Hetzer module that is a policy, audit and runtime-protection layer, and that works against a customer's own
  Vault or OpenBao, overlaps little with Vault's secret storage and issuance. Building a **central secret store** would
  overlap, which is a further reason ADR-0003 D1 rules it out.
- Making Vault mandatory for a paid feature to work is the risky pattern. OpenBao as a first, optional provider avoids
  the question for now.
- OpenBao is a fork of the last MPL 2.0 version of Vault, hosted under the Linux Foundation. **[secondary]**
  Check the OpenBao project's own pages for current governance and API differences before depending on it.

### C3. Technical contract for a read-only KV v2 provider [practice]

Verify every item against the Vault or OpenBao version in use; behavior differs by version, auth mount and namespace.

| Topic | Requirement |
|---|---|
| Read | KV v2: `GET /v1/<mount>/data/<path>`; the value is under `data.data.<field>`, version under `data.metadata.version`. Request one field, never list or dump a tree |
| Token header | `X-Vault-Token`. Never put the token in argv, URLs, logs, the audit ledger or the child environment |
| Namespaces | `X-Vault-Namespace` for Vault Enterprise and HCP Vault Dedicated. Out of scope for the first release |
| Auth methods | Support in this order: token supplied by the operator for tests; AppRole (`/v1/auth/approle/login`); JWT/OIDC (`/v1/auth/jwt/login`) for CI workload identity. Kubernetes and cloud IAM later |
| Token lifetime | Treat the login token as short-lived: fetch, use, then `POST /v1/auth/token/revoke-self`. Do not cache past the child process |
| Secret zero | The credential that reaches the store must itself come from workload identity or an OS-protected source. Decision pending (ADR-0003, open question 2) |
| TLS | HTTPS only except loopback; verify certificates; allow an operator-supplied CA bundle; no option to disable verification |
| Failure handling | Fail closed. Sealed store (HTTP 503), permission denied (403), missing path (404), timeout and malformed body each produce a distinct error that never contains a value |
| Least privilege | The role used by Hetzer gets read-only capability on the specific paths, for example a policy granting only `read` on one KV v2 data path |
| Dynamic secrets | Out of scope for the first release. If added later, record the lease, renew within its TTL and revoke on exit |
| Caching | None. A value lives only for the child process that requested it |
| Audit | Record provider, path, outcome and credential id. Never record the value or the token |
| Test environment | Run an OpenBao dev server in CI. Do not use a production-like Vault in tests |

### C4. Where the provider reference lives

The local vault stores `id`, `provider`, `uri` and the signed grants. Changing the URI is a grant change and needs the
operator signing step, exactly like changing `allowedOrigins`. A workspace file must not be able to repoint a credential
at a different secret.

## Part D. Legal and compliance notes [practice; confirm with counsel]

| Topic | Note |
|---|---|
| Personal data at a collector | Event metadata can identify a person (user name, hostname, repository). Minimize fields, document them, and give customers a data-processing agreement if you operate anything |
| Indonesia | The Personal Data Protection Law (Law No. 27 of 2022) has applied since its transition period ended in October 2024; processing needs a lawful basis and notice. Monitoring staff devices in a customer's jurisdiction needs that customer's lawful basis and notice to its staff |
| EU customers | GDPR applies to personal data of people in the EU. The EU Cyber Resilience Act sets obligations for commercial products with digital elements; reporting duties start in September 2026 and the main obligations in December 2027. Confirm the dates and whether open source stewardship or monetization puts Hetzer in scope |
| Open core and IP | Offering commercial modules next to an Apache-2.0 core needs clear ownership of every contribution: sole authorship, a CLA, or a DCO plus a license that permits it |
| Trademarks | Register or at least document the use of the name before selling under it |
| Claims | The repository's rule against absolute, compliance or benchmark claims applies to sales material. Evidence packs state versions, methods and limits |
| Insurance | Enterprise contracts often ask for cyber liability and professional indemnity cover |

SOC 2 and ISO/IEC 27001 **[practice]**: SOC 2 is an attestation by an independent audit firm against the AICPA Trust
Services Criteria. A Type I report covers the design of controls at a point in time; a Type II report covers whether
they operated over a period. ISO/IEC 27001 certifies an information security management system through an accredited
body. Both concern the organization and its service, not the source code, and both take months of operating evidence.
Do not start either before there is a service that holds customer data.

## Part E. Order of work

1. **Decide the open questions** in ADR-0003 and accept or amend ADR-0001 (documents only).
2. **Gate E0**: commission the independent review; add an SBOM to releases; measure the audit ledger on macOS and Linux;
   state a vulnerability response time; add CODEOWNERS and branch protection; choose DCO or CLA.
3. **Start the assessment offer** under a personal business in parallel. It needs a scope document, a report template
   and a fixed price, and it produces the evidence for gate E3.
4. **Gate E1** only after step 1 is done. Build against OpenBao first.
5. **Gate E2**, then **E3**. Design the dashboard only when partners ask for what it shows.

## Sources and verification status

| Item | Source | Status |
|---|---|---|
| Vault license text, competitive-offering definition | https://raw.githubusercontent.com/hashicorp/vault/main/LICENSE | **primary**, retrieved 2026-10-13 |
| Vault partner program steps and SLA | https://developer.hashicorp.com/vault/docs/partners/program | **secondary** (search summary; page not opened) |
| OpenBao license and governance | Trade-press and comparison pages found by search (2026) | **secondary** |
| 1Password Unified Access and Codex integration | https://1password.com/blog/introducing-1password-unified-access and press pages found by search (May 2026) | **secondary** (primary pages could not be opened) |
| npm trusted publishing and provenance | npm documentation source in `npm/documentation` on GitHub, and the registry's own attestation for `hetzer@0.6.2` | **primary** |
| Everything tagged [practice] | General industry knowledge | **unverified**; confirm with the buyer, auditor or counsel concerned |
