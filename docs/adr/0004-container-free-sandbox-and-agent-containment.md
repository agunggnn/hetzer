# ADR-0004: Container-free sandbox engine and agent containment

**Status:** Accepted by the maintainer on 2026-10-20; implemented in 0.7.0
**Relates to:** [ADR-0001](0001-authority-model-and-engine-boundary.md) D2 (Gate G1) and the Freeze table entry for
`cli/vault/sandbox.mjs` ("Fix, do not extend")

## Context

A backdoored model, a malicious dependency or a prompt injection runs as the user. Tested on a simulated workspace
before this change:

- `hetzer exec` blocked a direct read of `~/.ssh` and `curl | sh`, because those match its command-text guards.
- A downloaded script that read `~/.ssh/id_ed25519`, the workspace `.env` and the vault file ran to completion.
  `--strict` did not change that: it narrows which credentials Hetzer resolves, not what the child can read.
- `hetzer init` had written the master key into the workspace `.env`, next to `data/hetzer-vault.db`.
  `hetzer creds isolate-key` moved it to `~/.hetzer/grimoire.key`, readable by the same user and shared by every
  workspace (the reason ADR-0001 item 7 deferred isolating the key by default).
- The canary fired only when something asked Hetzer for it.
- The only OS boundary, `--sandbox`, needed Docker or Podman. On a laptop that is a daemon and a virtual machine many
  users do not run, so the boundary was off in practice. It contains the command Hetzer starts, not the agent.

ADR-0001 freezes the sandbox until G1 passes. This ADR records why 0.7.0 extends it anyway, and what G1 still lacks.

## Decision

1. **Per-instance key outside the workspace (closes the deferral in ADR-0001 item 7).** `hetzer init` writes the key
   to `~/.hetzer/keys/<instance-id>.key`; `.env` records only `HETZER_INSTANCE_ID`. A new workspace does not adopt
   the shared `grimoire.key`; init refuses to replace a missing key over an existing vault.
2. **A second engine, not a new boundary type.** `srt` ([Anthropic sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime),
   Apache-2.0) is invoked as an external program, like `docker`. Hetzer keeps zero runtime dependencies and pins the
   version it was tested against (0.0.78) in docs and `doctor`. Hetzer generates the policy (deny-read home and Hetzer
   files, re-allow the project, writes only in the project and a per-run temporary directory, network only to listed
   hosts) and checks it against a real srt in tests.
3. **Build on an existing sandbox instead of writing one.** Writing Seatbelt profiles and bubblewrap/seccomp argv in
   Hetzer would be a second implementation of a security boundary maintained by a much larger audience. The cost is
   a dependency on its behaviour and release cadence, recorded in the tests that run it.
4. **Agent containment.** `hetzer agent -- <agent>` runs the agent process itself in the sandbox, srt by default, with
   no credentials unless named. It is the same engine and policy as `exec --sandbox`, with an interactive terminal.
5. **External decoys.** `hetzer canary plant` places a decoy issued by an outside alerting service in a bait file and
   keeps only fingerprints outside the workspace. Hetzer makes no network call.

## Why this does not wait for G1

G1's purpose is "make the one OS-level boundary real by default". A boundary that needs a container engine most
laptops do not run is not on by default. The srt engine changes what is reachable for users who could not use the
container path, and the key move closes the G1 item that was blocked. It adds no new authority: the engines read the
same grants, and srt refuses brokered credentials rather than widening the network to reach the broker.

## Consequences

- G1 item 7 is complete. G1 item 8 stays open: a broker-only network profile, and srt reaching the broker. The
  container default network remains open unless `--sandbox-network none`.
- New surface to maintain: four `--sandbox-*` options, `hetzer agent`, `canary plant|list|remove`, and the srt
  settings contract. The srt tests pin its behaviour; a srt release that changes it shows up there.
- Interactive agent sessions are not redacted. They start with no credential so that is the safe default.
- What stays outside: kernel and sandbox vulnerabilities, paths and hosts the user re-opens, project files that other
  tools execute later (srt 0.0.78 cannot deny a missing path on Linux), and processes started without the sandbox.
  [docs/agent-sandbox.md](../agent-sandbox.md) lists them.

## Evidence

`VERIFY-SEC-016` (key outside the workspace), `VERIFY-SEC-017` (srt settings and engine selection, enforced against a
real srt when installed), `VERIFY-SEC-018` (agent defaults and refusals), `VERIFY-SEC-019` (external decoys), and
`cli/vault/srt-sandbox.test.mjs` with the CI job that installs srt on Linux and macOS.
