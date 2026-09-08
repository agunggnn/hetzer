# Security policy

## Supported versions

Security fixes are applied to the latest tagged release and the `main` branch.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability or exposed credential.
Use GitHub's private vulnerability reporting for this repository. Include the
affected version, operating system, reproduction steps, and likely impact.

## Deployment & Security Boundary

- **Credential Reference Policy**: Managed configuration should use `secretRef:<id>`. Hetzer does not intercept arbitrary files or prompts. Resolved values exist in child-process memory during `hetzer exec`.
- **Master Key Workspace Separation**: The master key `HETZER_GRIMOIRE_KEY` can be relocated out of workspace directories to `~/.hetzer/grimoire.key` (POSIX mode `0600`) via `hetzer creds isolate-key`. Same-user and privileged processes may still read it.
- **Loopback Enforcement**: Hetzer binds all daemon services and container ports to `127.0.0.1` by default. Any non-loopback binding requires explicit TLS, firewall, and reverse-proxy authentication.
- **7-Layer Defense Shield**:
  1. Regex and Shannon-entropy Secret Sniffer (`scanText` / `redactAndVault`).
  2. Bounded rolling and structured stream redactors on guarded child and Compose stdout/stderr.
  3. Anti-reflection command execution blocker (`isReflectionCommand`).
  4. Interactive TTY and up-to-five-generation process tree ancestry inspection (`checkProcessAncestors`).
  5. Required native OS modal confirmation for every plaintext reveal.
  6. Dynamic Canary Honey-Tokens intrusion tripwires (`hetzer canary setup`).
  7. Master Key workspace isolation outside project root.
- **Canary Tripwire Intrusion Response**:
  - Guarded reveal or reference resolution targeting `canary-token` or `HETZER_CANARY_TOKEN` throws a canary error, maps to CLI exit code 43, logs details to `data/hetzer-incidents.log`, and attempts to record an audit event in SQLite. Arbitrary file access is outside this tripwire.
- **Supply-Chain Scope**: The CLI declares zero third-party runtime npm dependencies. Node.js, Hetzer artifacts, installers, and container images remain supply-chain inputs.
- **Container Digest Pinning**: Container images are strictly pinned by immutable SHA-256 digests. Review digest upgrades in accordance with organization supply-chain policies.
