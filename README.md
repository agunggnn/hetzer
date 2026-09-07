# Hetzer 🛡️

<p align="center">
  <img src="assets/hetzer-banner.jpg" alt="Hetzer Zero-Plaintext Armor" width="100%" />
</p>

<p align="center">
  <strong>Local Credential Vault and Leak-Reduction Tools for AI Agents</strong><br>
  <em>Regex and entropy scanner • AES-256-GCM Grimoire Vault • Git pre-commit guard • Agent integration skills.</em>
</p>

<p align="center">
  <a href="https://github.com/agunggnn/hetzer/packages"><img src="https://img.shields.io/badge/GitHub%20Packages-%40agunggnn%2Fhetzer-blue?style=flat-square&logo=github" alt="GitHub Packages" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-%3E%3D22.5.0-brightgreen.svg?style=flat-square" alt="Node.js version" /></a>
  <a href="package.json"><img src="https://img.shields.io/badge/dependencies-0%20(pure%20Node%20stdlib)-success.svg?style=flat-square" alt="Zero External Dependencies" /></a>
  <a href="SECURITY.md"><img src="https://img.shields.io/badge/security-AES--256--GCM%20Vault-orange.svg?style=flat-square" alt="AES-256-GCM Vault" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square" alt="License" /></a>
</p>

---

## ⚡ Quickstart (Zero-Install via `npx`)

Hetzer runs instantly on any machine with Node.js installed without requiring global installation:

```bash
# 🔥 The 1-Command Speedrun for Vibe Coders: Arms skills, git hook, and vaults .env in 1.5s
npx hetzer protect

# Or perform individual actions:
# 1. Install credential-safety guidance for supported AI agents
npx hetzer skill install

# 2. Install Git Pre-Commit Guard (blocks supported token patterns and .env files)
npx hetzer hook install

# 3. Store credentials & API keys into encrypted Grimoire Vault (AES-256-GCM)
npx hetzer creds set openai-api-key
```

### Permanent Installation Options:

- **One-Line Script (Linux & macOS)**:
  ```bash
  curl -fsSL https://raw.githubusercontent.com/agunggnn/hetzer/main/install.sh | bash
  ```
- **One-Line Script (Windows PowerShell)**:
  ```powershell
  irm https://raw.githubusercontent.com/agunggnn/hetzer/main/install.ps1 | iex
  ```
- **Via GitHub Packages (Direct from this repo)**:
  ```bash
  npm install -g @agunggnn/hetzer --registry=https://npm.pkg.github.com
  ```
- **Via NPM Registry**:
  ```bash
  npm install -g @agunggnn/hetzer
  ```

---

## 📑 Modular Documentation

For structured navigation and deep architectural insights, explore the dedicated documentation guides:

| Guide | Summary & Topics |
|---|---|
| ⚡ **[Vibe Coder's Guide (`docs/vibe-coders.md`)](docs/vibe-coders.md)** | Zero-overhead, 1-command armor for developers building fast with Cursor, Claude, and Antigravity. |
| 🚀 **[Installation Guide (`docs/installation.md`)](docs/installation.md)** | Multi-OS setup (Ubuntu, Debian, CentOS, Windows WSL2, macOS, VPS), Docker requirements, and troubleshooting. |
| 🏛️ **[System Architecture (`docs/architecture.md`)](docs/architecture.md)** | Grimoire Vault (AES-256-GCM), 7-layer defense shield, 9Router Gateway, Cognee Memory, and network boundaries. |
| 🔬 **[System Logic & Progress Tracker (`docs/system-logic-and-progress.md`)](docs/system-logic-and-progress.md)** | Deep subsystem implementation specs, execution flows, test coverage status, and upcoming roadmap. |
| 📊 **[Measurement & Evaluation Guide (`docs/value-benchmark.md`)](docs/value-benchmark.md)** | Reproducible local measurements, comparison rules, and limits on compliance/TCO claims. |
| 🏦 **[Enterprise & Banking Readiness (`docs/enterprise-readiness.md`)](docs/enterprise-readiness.md)** | Regulatory compliance evaluation (PCI-DSS 4.0, SOC 2, ISO 27001, OJK, Bank Indonesia), threat models, and financial hardening guide. |
| 🌐 **[Model Context Protocol Guide (`docs/mcp-guide.md`)](docs/mcp-guide.md)** | Connect Hetzer to Claude Desktop, Cursor, Cline, OpenCode, `[OFFLINE]`/`[HYBRID]`/`[LLM]` classification, and CLI testing. |
| 🧠 **[Cognee Persistent Memory Module (`docs/modules/cognee.md`)](docs/modules/cognee.md)** | Graph and vector persistent memory, local Ollama integration, and memory tools. |

---

## ⚡ What is Hetzer?

**Hetzer** is a local-first credential vault and command-line defense layer. It reduces accidental credential exposure in supported workflows; it is not a complete security boundary for an OS user or an AI agent with unrestricted file and process access.

With Hetzer, you get:
1. **Secret scanner**: Scans explicitly supplied text for supported provider tokens, credentialed database URLs, bounded private-key blocks, and high-entropy candidates.
2. **Grimoire Vault (AES-256-GCM)**: SQLite-backed encrypted credential storage. Configuration can use `secretRef:<id>` in place of plaintext values.
3. **Agent integrations**: Installs guidance and MCP configuration for Hermes Agent, Google Antigravity, OpenCode, CommandCode, Cursor, Claude, Cline, Codex, and Gemini. These integrations do not intercept unrelated agent actions.
4. **Git Pre-Commit Guard**: Inspects staged filenames and added text before a commit. Runtime depends on repository size and Git startup cost.
5. **9Router AI Gateway & Cognee Memory (Optional Full-Stack)**: Multi-provider model routing with automatic fallback and tri-layer relational/vector/graph persistent memory in ~1.4 GiB RAM.

All built with **0 external npm dependencies** (100% Node.js standard library: `node:crypto`, `node:sqlite`, `node:fs`, `node:perf_hooks`).

---

## Security boundary

| Control | Covered | Boundary |
|---|---|---|
| Vault at rest | AES-256-GCM encryption with a unique random IV and authenticated metadata | A process that can read both the database and master-key file can decrypt entries |
| `hetzer exec` | Resolves allowed references and sanitizes child stdout/stderr with a bounded rolling buffer | Child memory contains resolved values; unrelated processes and tools are outside this path |
| Scanner | Supported patterns, database URLs, private-key blocks up to 16 KiB, and high-entropy candidates | Pattern matching can produce false positives and false negatives |
| Git hook | Staged `.env` filenames and supported candidates in added text | Hooks can be skipped and do not scan repository history |
| Agent skills | Instructions and MCP metadata-only vault tools | Instructions do not enforce access control against the local OS user |

---

## 🏛️ System Topology

```mermaid
flowchart TB
    subgraph Clients["AI Clients & Developer Interfaces"]
        CLI["Hetzer CLI\n(hetzer up / creds / mcp)"]
        TUI["Terminal Live Monitor\n(hetzer tui)"]
        Claude["Claude Desktop / Code"]
        Cursor["Cursor IDE"]
        Hermes["Hermes Agent"]
        AGY["Google Antigravity (AGY)"]
        OpenCode["OpenCode / CommandCode"]
        GitCommit["Git Commit Guard Hook\n(.git/hooks/pre-commit)"]
    end

    subgraph HostPlane["Hetzer Command Plane (Host Process)"]
        SecretSniffer["Secret Scanner\n(Regex Rules + Entropy Detector)"]
        GrimoireVault[("Grimoire Vault\nSQLite WAL + AES-256-GCM\ndata/hetzer-vault.db")]
        MCPBridge["Universal MCP Bridge\n(stdio & JSON-RPC Protocol)"]
        ModuleResolver["Module & Profile Resolver\n(Docker Compose Merger)"]
        HealthVerifier["Active Healthcheck & Probe Engine"]
    end

    subgraph DockerPlane["Docker Isolated Network (127.0.0.1 Loopback)"]
        subgraph NineRouter["9Router AI Gateway (:20140)"]
            RouterProxy["Multi-Provider Model Router & Fallback"]
        end

        subgraph CogneeSvc["Cognee Memory Engine (:8001)"]
            MCPEndpoint["MCP Server (:8001/mcp)"]
            RelationalDB[("SQLite WAL\nRelational Metadata")]
            VectorDB[("LanceDB\nVector Embeddings")]
            GraphDB[("Kùzu Graph DB\nKnowledge Graph")]
        end
    end

    CLI --> GrimoireVault
    CLI --> ModuleResolver
    CLI --> MCPBridge
    GitCommit --> SecretSniffer
    TUI --> HealthVerifier
    Claude -.->|"stdio MCP"| MCPBridge
    Cursor -.->|"stdio MCP"| MCPBridge
    Hermes -.->|"stdio MCP"| MCPBridge
    AGY -.->|"Native Skill"| GrimoireVault
    OpenCode -.->|"Native Skill"| GrimoireVault

    ModuleResolver -->|"docker compose up\n(Ephemeral Credential Injection)"| DockerPlane
    MCPBridge -->|"Direct Probe & Call"| MCPEndpoint
```

---

## Credential defense layers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     HETZER SEVEN-LAYER DEFENSE MATRIX                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 1: Explicit Secret Scanner                                            │
│  ► Scans input passed to the CLI/MCP scanner and staged Git additions.       │
│  ► Redaction reports whether each detected value was successfully vaulted.  │
│  ► Agent prompts outside integrated paths are not intercepted.               │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 2: Real-Time Stream Sanitizer & Ephemeral Scoping (hetzer exec)      │
│  ► Intercepts child process stdout/stderr in memory before terminal emit.   │
│  ► Uses a bounded rolling buffer to redact values across output chunks.      │
│  ► --strict starts with a minimal environment and injects approved refs.     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3: Anti-Reflection Execution Guard                                   │
│  ► Blocks reflection commands ('printenv', 'env', 'export', 'docker inspect'│
│    and inline 'os.environ' scripts) before process spawning.                │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 4: TTY and Process Ancestry Safeguards                               │
│  ► Validates process.stdin.isTTY and sniffs autonomous agent env flags.     │
│  ► Traverses 5 generations of parent processes (PPID) to block autonomous   │
│    recognized agent processes before allowing 'hetzer creds reveal'.         │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 5: Out-of-Band (OOB) Human Presence Proof (--confirm-ui)              │
│  ► Launches native OS modal dialogs (Windows Forms / AppleScript / Zenity). │
│  ► Optional modal confirmation is enabled with --confirm-ui.                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 6: Dynamic Canary Honey-Tokens (Intrusion Tripwires)                 │
│  ► Deploys enticing decoy canary tokens ('HETZER_CANARY_TOKEN') into .env.  │
│  ► Guarded resolution/reveal attempts abort with exit code 43 and log an     │
│    incident. Arbitrary file reads are outside this tripwire.                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 7: Master Key Workspace Isolation (~/.hetzer/grimoire.key)           │
│  ► 'hetzer creds isolate-key' relocates master key out of project directory │
│    with 0600 POSIX permissions. Same-user processes may still read it.       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Performance measurement

Scanner latency varies with input length, candidate count, CPU, Node version, and cold-start effects. The Git hook also starts Git subprocesses, so scanner microbenchmarks must not be presented as end-to-end hook latency. Run `node benchmarks/vault-bench.mjs` and measure `hetzer hook check` on the target repository before setting a performance objective.

---

## 🏦 Enterprise & Banking Readiness (PCI-DSS, SOC 2, ISO 27001, OJK)

Hetzer can contribute technical evidence to a broader security program, but this repository has not been independently audited or certified against the frameworks below.

### 🎯 Strategic Enterprise Role: The "Agent Sidecar Armor"
Banks deploying AI coding agents (Claude Code, Cursor, Copilot, Antigravity) face an acute compliance threat: **engineers accidentally leaking core-banking API keys, staging database URLs, or customer PII into third-party LLM context windows**.

Hetzer acts as a client-side **Defense-in-Depth Armor**:
- **0 runtime npm dependencies** reduces one source of dependency risk. Node.js, Hetzer itself, container images, and installers remain in the supply chain.
- **Explicit scanning and guarded execution** reduce exposure in the paths that invoke them.
- **Git Pre-Commit Guard** blocks supported patterns and `.env` filenames when the hook runs.
- **AES-256-GCM encryption** protects vault values at rest while the master key remains separate and protected.

### 📋 Compliance Quick Reference

| Framework / Regulation | Control Scope | Hetzer Capability & Verdict |
|---|---|:---:|
| **PCI DSS v4.x** | Vault encryption and development leak detection may support selected controls | Requires a scoped assessment; the Git hook does not establish payment-page script control 6.4.3 |
| **SOC 2** | Audit records and credential handling may support control evidence | Compliance applies to an audited organization and system, not this component alone |
| **ISO/IEC 27001:2022** | Cryptography and secure-development features may support selected controls | Certification requires an assessed information-security management system |
| **OJK / Bank Indonesia** | Local storage and leak-reduction controls may form part of an implementation | Applicability and sufficiency require qualified legal and regulatory review |

> 📖 **Read the Complete Technical Whitepaper**: For full regulatory analysis, threat vector models, and enterprise deployment blueprints, see **[Enterprise & Banking Readiness Guide (`docs/enterprise-readiness.md`)](docs/enterprise-readiness.md)**.

---

## Universal AI Agent Skills (no Docker required)

Install credential-handling guidance across the supported AI coding agents. The installed files consume disk space and the CLI uses memory when invoked.

```bash
# Install to all detected agents on your system:
hetzer skill install

# Or run instantly via npx:
npx hetzer skill install
```

### Supported Platforms:
- **Hermes Agent**: Installed to `~/.hermes/skills/hetzer/SKILL.md` (`globalOnly: true`) and hooked into `~/.hermes/config.yaml`.
- **Google Antigravity (AGY)**: Installed to `.agents/skills/hetzer/SKILL.md` (workspace), `~/.gemini/config/skills/` (global), and `AGENTS.md`.
- **OpenCode & CommandCode**: Installed to `.opencode/skills/hetzer/` and `.commandcode/skills/hetzer/` with `AGENTS.md` entry pointers.
- **Cursor IDE**: Installed to `.cursor/rules/hetzer.mdc`, `.cursor/skills/hetzer/`, and `.cursorrules`.
- **Claude Desktop & Code**: Configured in `claude_desktop_config.json` via native stdio MCP and `.claude/skills/`.
- **Cline / Roo Code**: Configured in `cline_mcp_settings.json` and `.clinerules`.

Check the installation status of all agents on your machine:
```bash
hetzer skill status
```

---

## 🛡️ Git Pre-Commit Guard Hook

Prevent accidental credential leaks before they ever reach GitHub:

```bash
# Install the hook to .git/hooks/pre-commit
hetzer hook install

# Check staged changes manually
hetzer hook check

# Uninstall the hook if no longer needed
hetzer hook uninstall
```

When the installed hook runs, it blocks supported credential patterns and `.env` files in staged changes. The reported latency includes Git startup and varies by repository:
```text
================================================================================
  🛑 HETZER ARMOR: GIT COMMIT BLOCKED (TOKEN LEAK DETECTED!)
================================================================================
  Scan Latency : 183.00 ms
  Violations   : Detected 1 raw credential in staged changes:

  * src/config.js:14 -> [OPENAI_API_KEY] OpenAI secret key

  HOW TO FIX:
  1. Save credential to Vault : hetzer creds set openai-api-key <secret>
  2. Replace in your code with: secretRef:openai-api-key
================================================================================
```

---

## 🛠️ CLI Command Cheat Sheet

All Hetzer commands are executed via the `hetzer` CLI:

| Command | Description |
|---|---|
| `hetzer doctor [--fix]` | Validates system prerequisites, Node.js version, and Docker socket permissions |
| `hetzer init [dir]` | Initializes a new Hetzer instance, creates Grimoire Vault, and secures `.env` |
| `hetzer up [srv\|all] [--wait]` | Launches containers with active healthcheck polling and HTTP smoke tests |
| `hetzer down [-v]` | Stops services (`-v` removes persistent data volumes for clean teardown) |
| `hetzer status` | Displays live container states, forwarded ports, and image digests |
| `hetzer logs [service]` | Streams container logs in real time |
| `hetzer tui` | Opens the interactive terminal operations dashboard |
| `hetzer creds [list]` | Lists all stored credential references in Grimoire Vault |
| `hetzer creds reveal <id> [--confirm-ui]` | Decrypts and prints plaintext secret (guarded by TTY, process tree, & OS modal) |
| `hetzer creds set <id> [val]` | Encrypts and saves a credential via AES-256-GCM (masked prompt) |
| `hetzer creds isolate-key` | Moves master key outside workspace to `~/.hetzer/grimoire.key` (mode 0600) |
| `hetzer canary [setup]` | Deploys decoy canary honey-tokens to catch prompt injection & extraction |
| `hetzer exec [--allow <ids>] [--strict] -- <c>` | Runs a command with scoped secret injection and buffered stream sanitization |
| `hetzer sniffer [scan\|redact]` | Scans or redacts supported credential candidates from input text |
| `hetzer skill [install\|status]`| Deploys Universal AI Agent Skills to Hermes, AGY, OpenCode, Cursor, Claude |
| `hetzer hook [install\|check]` | Installs or tests the Git pre-commit credential leak guard |
| `hetzer modules` | Displays available and active native extension modules |
| `hetzer install <module>` | Enables and configures an extension module (e.g. `cognee`, `9router`) |
| `hetzer remove <module>` | Disables an extension module without deleting persistent data |
| `hetzer module create <id>` | Generates a new module recipe using 9Router AI code analysis |
| `hetzer mcp ping [service]` | Diagnoses JSON-RPC handshake and latency for MCP endpoints |
| `hetzer mcp tools [service]` | Lists MCP tools and their execution classification |
| `hetzer mcp call <srv> <tool>` | Invokes an MCP tool directly from the terminal without an AI client |
| `hetzer publish` | Builds, verifies test suite, and publishes package to public npm |

---

## ❓ Frequently Asked Questions (FAQ)

### 1. Can I reveal and inspect credentials stored in the Vault?
**Yes, absolutely.** As the machine owner and terminal administrator, you have full authority to inspect and decrypt your secrets anytime:
```bash
# List all stored credential IDs and status
hetzer creds list

# Decrypt and reveal the actual secret value (AES-256-GCM)
hetzer creds reveal npm-token
hetzer creds reveal nine-router-initial-password
```

### 2. Can AI Agents (Claude, Cursor, Cline, GPT) see these credentials?
Hetzer keeps plaintext out of MCP vault-list and vault-existence responses, and `hetzer exec` injects approved values directly into a child process. This does not guarantee that an unrestricted agent can never access a credential:
- The MCP tools exposed to AI (`hetzer_vault_has` and `hetzer_vault_list`) **only return metadata** and abstract reference strings (`secretRef:<id>`).
- **No `reveal` tool is exposed by Hetzer's MCP server**. This limits that interface; it does not restrict other tools or same-user file/process access.
- Credentials injected into a child exist in that process environment and memory. `hetzer exec` blocks common reflection commands and sanitizes supported output, but these are application safeguards rather than OS isolation.
- Agent instructions do not intercept arbitrary prompts, files, debuggers, alternate processes, or tools. Use OS account separation and a centrally managed secret system for hostile-code boundaries.

### 3. What credential scenarios does Hetzer support?
Grimoire Vault can store arbitrary values up to its configured size limit. Automatic scanning recognizes a narrower set:
- **Provider tokens**: OpenAI, Anthropic, Google Gemini, npm, GitHub, Slack, AWS access-key IDs, and JWT-shaped strings.
- **Service & Database Passwords**: 9Router admin passwords, PostgreSQL, Redis, MySQL credentials.
- **Private keys**: PKCS#8 and algorithm-prefixed PEM private-key blocks up to 16 KiB.
- **Database Connection URIs**: `postgresql://user:pass@host:5432/db`, `mongodb+srv://...`, `redis://...`.
- **High-entropy candidates**: 24–512 character candidate strings above the entropy threshold. Review false positives and false negatives.

### 4. Who does Hetzer protect you from?
- **Third-party AI vendors**: References reduce exposure when users and agents follow the installed guidance and use the integrated scanner paths.
- **Accidental Git exposure**: The hook catches supported candidates and staged `.env` filenames unless hooks are bypassed.
- **Other OS accounts**: POSIX mode `0600` restricts ordinary cross-account access. Administrators, the same account, backups, and platform-specific ACL behavior remain in scope.

### 5. How do I achieve maximum security on production servers?
If you prefer not to store `HETZER_GRIMOIRE_KEY` on disk, omit it from `.env` and provide it strictly via the in-memory terminal environment:
```bash
export HETZER_GRIMOIRE_KEY="your-private-master-key"
```
Under this model, zero decryption keys exist on disk. Anyone copying the database cannot decrypt its contents without your in-memory master key.

---

## 🗑️ Complete Uninstallation & Teardown

To cleanly remove Hetzer from your machine:

```bash
# 1. Stop containers and remove persistent volumes (if using Docker services)
hetzer down -v

# 2. Uninstall global CLI binary
npm uninstall -g hetzer

# 3. Clean up project files
cd .. && rm -rf hetzer
```

## 🙏 Acknowledgements & Inspirations

Hetzer stands on the shoulders of giants. We express our deepest gratitude and respect to the pioneering tools, architectures, and open-source communities that inspired Hetzer's design:

- 🏛️ **[HashiCorp Vault](https://github.com/hashicorp/vault)** (*HashiCorp / Mitchell Hashimoto*): The gold standard in secret management, transit encryption, and decoupled credential architecture that inspired the Grimoire Vault and `secretRef:` design.
- ⚡ **[1Password CLI (`op run`)](https://developer.1password.com/docs/cli/)** & **[Doppler](https://github.com/DopplerHQ/cli)**: Pioneers of out-of-band ephemeral secret injection into child processes without ever storing secrets in plaintext files.
- 🔍 **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** (*Truffle Security*) & **[Gitleaks](https://github.com/gitleaks/gitleaks)** (*Zachary Rice*): High-speed regex and Shannon entropy scanners that defined modern Git credential leakage prevention.
- 🌐 **[Model Context Protocol (MCP)](https://github.com/modelcontextprotocol)** (*Anthropic*): The open standard that enables autonomous AI clients to seamlessly and safely consume local tools and defense boundaries.
- 🚦 **[9Router](https://github.com/decolua/9router)** (*Decolua*): High-performance multi-provider local AI model router, fallback balancer, and reverse proxy.
- 🧠 **[Cognee](https://github.com/topoteretes/cognee)** (*Topoteretes*): Advanced tri-layer relational, vector, and knowledge graph persistent memory engine for autonomous agents.
- 🛡️ **[LLM-Guard](https://github.com/protectai/llm-guard)** (*Protect AI*): Pioneered real-time LLM input/output scanning and token redaction before context transmission.
- 🤖 **Autonomous AI Agent Ecosystems**:
  - **[Hermes Agent](https://github.com/NousResearch/Hermes-Function-Calling)** (*NousResearch*)
  - **[Google Antigravity (AGY)](https://github.com/google)**
  - **[Cursor IDE](https://cursor.com)**
  - **[Cline](https://github.com/cline/cline)** (*Roo Code*)
  - **OpenCode & CommandCode**  
  Their ground-breaking work on agentic developer workflows made the urgent necessity of client-side Zero-Plaintext Armor evident.

---

## 📄 License

Distributed under the **Apache-2.0** License. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for complete legal details.
