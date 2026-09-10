# Hetzer measurement and evaluation guide

> Version: 0.4.9

This repository does not contain evidence for vendor-wide speed comparisons, annual cost savings, or regulatory certification. Treat earlier figures for competitor latency, memory, vulnerability counts, and 92% TCO reduction as withdrawn unless they are reintroduced with reproducible data and dated sources.

## What can be measured locally

| Area | Measurement | Important boundary |
|---|---|---|
| Scanner | Call `scanText` over representative clean and credential-bearing inputs | Report input size, candidate count, CPU, OS, Node version, warmup, iterations, and percentiles |
| Git guard | Time `hetzer hook check` in repositories of documented sizes | Includes two Git subprocesses; do not substitute scanner-only latency |
| Vault crypto | Run `node benchmarks/vault-bench.mjs` | This is a synthetic encryption loop, not end-to-end credential retrieval |
| Process redaction | Exercise `hetzer exec` with synthetic values split across writes | Report buffering delay, throughput, output size, and maximum retained window |
| Memory | Record RSS for the actual CLI command and workload | An installed text skill consumes disk but no process memory until a client or CLI loads it |

Publish the benchmark harness, fixtures, raw results, and date with every numeric claim. Compare other products only with equivalent features and current, primary-source configurations.

## Current technical evidence

- The package declares no third-party runtime npm dependencies. Node.js, Hetzer source and release artifacts, installation channels, and pinned container images remain supply-chain inputs.
- Vault values use AES-256-GCM with random 12-byte IVs, authentication tags, and authenticated metadata. This does not prove hardware acceleration on every supported machine.
- `hetzer exec --strict` starts with a minimal inherited environment and resolves only allowed `secretRef` bindings. Resolved values exist in child-process memory.
- Output sanitation uses a bounded rolling buffer so known injected values can be recognized across stream chunks. Streaming filters suppress supported long structured values and normalize terminal controls, while deliberately transformed or unsupported values can still evade pattern scanning and false positives remain possible.
- The Git hook scans staged `.env` filenames and added text. Git hooks can be bypassed and are not a replacement for server-side scanning.

Run `npm run check` for syntax and the public-file credential-pattern scan, then run `npm test` for the unit suite. The default test reporter is intentionally concise; use `npm run test:verbose` when investigating failures. Passing these checks is implementation evidence, not an independent security audit.

## Compliance claims

Hetzer can support parts of an organization's credential-handling and secure-development controls. The repository by itself cannot be declared PCI DSS, SOC 2, ISO/IEC 27001, OJK, or Bank Indonesia compliant.

Any formal mapping must identify the exact product version, deployed configuration, system boundary, control owner, operating evidence, compensating controls, and assessor. In particular, PCI DSS requirement 6.4.3 concerns management of payment-page scripts; a pre-commit credential scanner does not establish that control.

## Cost claims

Apache-2.0 licensing means Hetzer has no repository license fee. Deployment, review, incident response, support, training, Node maintenance, container operation, and compliance work still have costs. A TCO comparison must state workload, staffing, support level, infrastructure, time horizon, vendor quotes, and sensitivity ranges. This repository currently provides no validated TCO model.
