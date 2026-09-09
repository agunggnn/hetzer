# Hetzer boundary analysis and isolation roadmap

> **Status:** Engineering analysis, not a product-comparison benchmark
> **Date:** September 2026

This document describes Hetzer's implemented security boundary and possible future isolation work. It does not claim feature parity with StrongDM, Delinea, or another commercial access platform. Vendor capabilities, licensing, architecture, and certifications change over time and require dated primary-source research before comparison or publication.

## Implemented boundary

Hetzer is a local credential-safety layer for developer and AI-assisted workflows. Its current implementation provides:

- encrypted local credential storage using SQLite and AES-256-GCM;
- `secretRef:<id>` configuration references;
- allowlisted credential resolution for guarded child processes;
- a strict child environment that removes unapproved inherited credentials and the vault master key;
- bounded UTF-8 stdout and stderr sanitation for guarded processes;
- credential-pattern scanning for supported formats;
- staged Git-addition scanning;
- guarded reveal checks and native user confirmation; and
- canary detection on guarded resolution and reveal paths; and
- a bounded HTTP credential broker that keeps the selected long-lived credential out of compatible child environments.

These controls are tested by `npm test` and the six protocols in `npm run verify`. Passing tests are implementation evidence, not an independent security audit or compliance certification.

## Current limitations

An approved command launched through `hetzer exec` receives each resolved credential in its environment and process memory. That command can deliberately transform or transmit the credential without writing it to its piped UTF-8 stdout or stderr.

Hetzer does not presently provide:

- arbitrary process containment;
- general filesystem isolation;
- mandatory network-egress enforcement;
- kernel-level syscall interception;
- protection from processes with sufficient access to the same OS account;
- universal prompt, tool, terminal-device, file, IPC, debugger, or network interception; or
- proof of regulatory compliance.

The reveal ancestry checks are heuristics and user-presence safeguards. The Git hook can be bypassed. The scanner supports documented credential formats but can produce false positives and false negatives.

## Different product categories

Hetzer should not be presented as a replacement for an enterprise privileged-access-management or infrastructure-access platform. Those systems may address centralized identity, session authorization, infrastructure connectivity, policy administration, audit retention, and organizational controls that are outside Hetzer's current scope.

Any public comparison must:

1. use dated primary sources for the compared product;
2. distinguish shipped behavior from proposed work;
3. state the tested operating system, version, and configuration;
4. avoid unsupported performance, cost, compliance, and security percentages; and
5. avoid absolute terms such as "unbreakable," "complete protection," or "zero leakage."

## Possible future work

The following items are design candidates, not implemented claims.

### HTTP credential broker (implemented, bounded)

For selected HTTP APIs, `hetzer broker` gives a compatible child a short-lived capability and injects the real credential only into requests allowed by a reviewed policy. Broker v1 enforces an HTTPS origin, method and path prefixes, bounded bodies, selected headers, blocked redirects, lifecycle cleanup, and exact response redaction.

It does not automatically support arbitrary tools or protocols, streaming or binary responses, and it does not prevent other network paths unless the operating system or sandbox enforces egress restrictions. A same-user process may still alter the policy or access the vault, key, or broker process.

### Network policy integration

A future execution profile could declare allowed destinations. Proxy environment variables alone are not enforcement because software may ignore them or open direct sockets. A meaningful boundary would require platform-specific controls and adversarial verification.

### Filesystem and process isolation

Platform-specific sandboxing could restrict child access to workspace files and sensitive user directories. Linux, macOS, and Windows expose different primitives and guarantees. No cross-platform equivalence should be claimed until each implementation has native integration tests and documented fallback behavior.

### Declarative capability policies

A policy file could declare allowed credential references, actions, destinations, and filesystem areas. Such a policy would improve reviewability, but enforcement would remain limited to the mechanisms actually implemented on the host platform.

## Evaluation requirements

Before promoting any roadmap item to an implemented feature:

- define its threat model and explicit non-goals;
- add unit, integration, adversarial, and failure-path tests;
- verify Windows, Linux, and macOS behavior independently;
- measure complete workflows rather than isolated microbenchmarks;
- document fallback and bypass conditions; and
- update `docs/verification-evidence.json` through `npm run verify`.

Hetzer remains useful as defense in depth when credentials are referenced rather than pasted into prompts, commands are trusted and narrowly authorized, `--strict` is used, and external OS/network controls match the risk of the target environment.
