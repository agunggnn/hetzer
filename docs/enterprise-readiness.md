# Enterprise readiness and deployment boundaries

Hetzer is a local credential-handling component. It has not been independently audited or certified, and the repository alone does not establish PCI DSS, SOC 2, ISO/IEC 27001, OJK, Bank Indonesia, NIST SSDF, or SLSA compliance.

## Suitable role

Hetzer can be evaluated as a developer-workstation defense layer for:

- replacing selected `.env` values with vault references;
- encrypting local vault values at rest;
- resolving approved references for a child process;
- scanning supported credential patterns in explicit text and staged Git additions;
- exposing MCP tools that list credential metadata without a plaintext reveal operation.

It is not a centralized secrets manager, identity provider, hardware-backed key store, endpoint-detection system, data-loss-prevention gateway, prompt firewall, or payment-page script manager.

## Security boundary

| Concern | Implemented control | Residual risk |
|---|---|---|
| Vault copied without key | AES-256-GCM encrypted values and authenticated metadata | A same-user or privileged process that obtains the key and database can decrypt entries |
| Child receives too many credentials | `--allow` filters vault references; `--strict` uses a minimal inherited environment | Resolved values exist in child memory and may be used by hostile child code |
| Child prints a credential | Bounded rolling sanitizer recognizes known injected values and supported candidates across chunks | Encodings, transformations, unsupported formats, and outputs outside `hetzer exec` may evade detection |
| Accidental Git commit | Hook checks staged `.env` names and added content | Hooks are local and bypassable; add server-side scanning for enforcement |
| Programmatic CLI reveal | TTY, environment-marker, and up-to-five-ancestor checks | Heuristics are not authentication or OS isolation |
| Canary reference resolution | Guarded resolution/reveal aborts and returns CLI exit code 43; incident is logged | Arbitrary file access and accesses outside guarded code paths are not detected |
| Agent integration | Installed guidance plus metadata-only vault MCP tools | An unrestricted agent can use other local tools and processes |

## Production prerequisites

Before organizational deployment:

1. Perform a threat model for local users, administrators, malware, build runners, backups, and agent tool permissions.
2. Review the exact release and build provenance. The CLI has no third-party runtime npm packages, but Node.js, installers, source artifacts, and container images remain dependencies.
3. Protect the master key with OS access controls or an organization-managed secret/key service. Moving it to `~/.hetzer/grimoire.key` only separates it from the workspace.
4. Enforce server-side secret scanning and protected branches because local Git hooks can be skipped.
5. Restrict agent filesystem, shell, debugger, and process access at the OS or sandbox layer.
6. Define log retention, incident routing, backup protection, credential rotation, revocation, and break-glass procedures.
7. Validate Linux, macOS, and Windows behavior in the intended fleet.
8. Run independent security testing before handling regulated or production credentials.

## Compliance evaluation

A qualified assessor must map a deployed system, policies, people, evidence, and operating history to applicable controls. Cryptography or a Git hook can support individual controls but cannot make the product or deploying organization compliant on its own.

PCI DSS requirement 6.4.3 addresses authorization, integrity, and inventory of scripts on payment pages. Hetzer's pre-commit scanner is not a payment-page script-management control. Do not cite it as proof of 6.4.3 compliance.

For any claimed control contribution, retain:

- the exact Hetzer and Node versions;
- configuration and scoped architecture diagrams;
- test and benchmark methodology with raw results;
- access-control and key-custody evidence;
- hook and server-side scanner enforcement records;
- incident, rotation, backup, and recovery records;
- documented residual risks and accepted exceptions.

See [the measurement guide](value-benchmark.md) for rules governing performance, competitor, cost, and compliance statements.
