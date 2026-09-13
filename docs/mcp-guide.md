# Model Context Protocol (MCP) Guide & Integration

> **Version**: v0.5.1  
> **Status**: Production Reference Guide  
> **Target Audiences**: AI Engineers, Agent Developers, DevOps

---

## 📑 Table of Contents
1. [Overview](#1-overview)
2. [Tool Classification Taxonomy](#2-tool-classification-taxonomy)
3. [Client Configuration](#3-client-configuration)
   - [Claude Desktop](#31-claude-desktop)
   - [Cursor IDE](#32-cursor-ide)
   - [Cline / Roo Code](#33-cline--roo-code)
   - [Windsurf & OpenCode](#34-windsurf--opencode)
4. [Testing & Calling Tools via CLI](#4-testing--calling-tools-via-cli)
5. [Hetzer Native Defense Tools Reference](#5-hetzer-native-defense-tools-reference)
6. [Real-Time Tool Output Sanitization & Virtual Proxy](#6-real-time-tool-output-sanitization--virtual-proxy)
7. [Jagdpanzer Multi-Container & Cognitive Memory Integration](#7-jagdpanzer-multi-container--cognitive-memory-integration)
8. [Troubleshooting & Diagnostics](#8-troubleshooting--diagnostics)

---

## 1. Overview

The **Model Context Protocol (MCP)** standardizes how AI applications connect to external tools, databases, and context servers. Hetzer acts as an **autonomous MCP orchestrator and security bridge**, providing:
- **Embedded Stdio FastMCP Server** (`hetzer mcp serve`): Direct high-speed JSON-RPC bridge for Claude Desktop, Cursor, and Cline.
- **Native Defense Tools**: Explicit text scanning (`hetzer_sniffer_scan`), redaction with per-item vault status (`hetzer_sniffer_redact`), and credential existence checks (`hetzer_vault_has`, `hetzer_vault_list`).
- **Virtual Credential Proxy & Just-In-Time Secret Resolution**: Transparently resolves `secretRef:<id>` parameters just-in-time while enforcing capability bindings.
- **MCP Output Sanitization**: Scans serialized tool return values and error messages via `sanitizeStreamOutput` before return, preventing credential reflection.
- **Operational Tool Classification**: Automated labeling as `[OFFLINE]`, `[HYBRID]`, and `[LLM REASONING]`.

---

## 2. Tool Classification Taxonomy

In high-throughput AI agent environments, knowing whether a tool call consumes cloud tokens or executes locally is critical for latency, cost control, and privacy. Hetzer tags all discovered tools:

### `[OFFLINE]` (Local Operation)
- **Execution**: Implemented by a local process without intended model inference.
- **Latency**: Sub-millisecond to low milliseconds.
- **Cost**: 0 tokens.
- **Privacy**: Text and data remain entirely on the local host.
- **Use Cases**: System health probes, local cache lookups, credential redaction, secret existence probes.

### `[HYBRID]` (Local Indexing & Search)
- **Execution**: Local embedded engines (vector databases, graph traversals, SQLite queries).
- **Latency**: Low milliseconds depending on index size and host resources.
- **Cost**: 0 generation tokens (may use local embeddings if configured with Ollama).
- **Privacy**: Keeps data on the machine unless remote embedding APIs are configured.
- **Use Cases**: Semantic retrieval, subgraph relationship queries, index scanning.

### `[LLM REASONING]` (Cognitive Synthesis)
- **Execution**: Requires model inference (OpenAI, Anthropic, Gemini, or local Ollama).
- **Latency**: Upstream provider round-trip time.
- **Cost**: Incurs token usage on upstream model provider.
- **Privacy**: Text payloads routed securely through configured upstream endpoint.
- **Use Cases**: Knowledge graph distillation, code reasoning, automated remediation.

---

## 3. Client Configuration

### 3.1 Claude Desktop

Add Hetzer's MCP stdio server to your Claude Desktop configuration:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "hetzer": {
      "command": "hetzer",
      "args": ["mcp", "serve"]
    }
  }
}
```

### 3.2 Cursor IDE

Inside your project root or workspace settings, create or update `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "hetzer": {
      "command": "hetzer",
      "args": ["mcp", "serve"]
    }
  }
}
```

### 3.3 Cline / Roo Code (VS Code Extension)

In VS Code, open Settings or edit `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "hetzer": {
      "command": "hetzer",
      "args": ["mcp", "serve"],
      "disabled": false,
      "autoApprove": [
        "hetzer_sniffer_scan",
        "hetzer_vault_has"
      ]
    }
  }
}
```

### 3.4 Windsurf & OpenCode

In Windsurf (`~/.codeium/windsurf/mcp_config.json`) or OpenCode settings:

```json
{
  "mcpServers": {
    "hetzer": {
      "command": "hetzer",
      "args": ["mcp", "serve"]
    }
  }
}
```

---

## 4. Testing & Calling Tools via CLI

Hetzer allows developers to interact with MCP tools directly from the terminal without opening an AI IDE:

### 4.1 Ping and Health Diagnostics
Test protocol handshake and roundtrip response latency for active MCP endpoints:
```bash
hetzer mcp ping <service>
```
*Output:*
```text
[v] MCP Endpoint: http://127.0.0.1:<port>/mcp
[v] Protocol: JSON-RPC 2.0 (SSE streaming enabled)
[v] Latency: 12ms
[v] Server Info: hetzer-mcp v0.5.1
```

### 4.2 List Discovered Tools
Inspect tools with their parameter schemas and operational classifications:
```bash
hetzer mcp tools <service>
```

### 4.3 Direct Tool Execution (`hetzer mcp call`)
Execute tools synchronously with JSON arguments:
```bash
# Execute an MCP tool securely
hetzer mcp call <service> <tool-name> '{"arg": "value"}'
```

---

## 5. Hetzer Native Defense Tools Reference

When connected to Hetzer's stdio FastMCP server (`hetzer mcp serve`), AI agents gain access to local defense utilities designed to inspect and secure credentials without exposing plaintext values:

### `hetzer_sniffer_scan` `[OFFLINE]`
- **Description**: Scans provided text or code snippets for supported API-key patterns, private-key blocks up to 16 KiB, credentialed database URLs, and bounded high-entropy candidates.
- **Parameters**:
  - `text` *(string, required)*: The text payload to scan.

### `hetzer_sniffer_redact` `[OFFLINE]`
- **Description**: Automatically vaults detected credentials into Grimoire Vault and returns sanitized text replacing raw keys with `secretRef:<id>`.
- **Parameters**:
  - `text` *(string, required)*: The text payload to sanitize.

### `hetzer_vault_has` `[OFFLINE]`
- **Description**: Safely probes whether a specific credential reference exists in Grimoire Vault without decrypting or exposing the underlying secret.
- **Parameters**:
  - `id` *(string, required)*: The credential identifier (e.g., `openai-api-key` or `secretRef:npm-token`).

### `hetzer_vault_list` `[OFFLINE]`
- **Description**: Lists all stored credential IDs, descriptions, and authentication types. Strictly omits secret values.

### `hetzer_modules_list` `[OFFLINE]`
- **Description**: Lists installed modules, lifecycle states, and active service configurations.

---

## 6. Real-Time Tool Output Sanitization & Virtual Proxy

To eliminate accidental credential exposure in agent workflows:
1. **Just-in-Time Resolution**: When an agent sends a tool payload containing `secretRef:<id>`, Hetzer's virtual proxy resolves the secret just-in-time before passing it to the target tool.
2. **Output Sanitization**: The MCP protocol handler (`cli/mcp/protocol.mjs`) pipes serialized `tools/call` responses through `sanitizeStreamOutput`. If a tool reflects or echoes raw secret values, Hetzer automatically redacts them back to `secretRef:<id>`.
3. **Multi-Representation Redaction**: Redacts raw plaintext, JSON-escaped strings (`\"`), URL-encoded strings (`%2F`), and Unicode-escaped characters (`\u002F`).

---

## 7. Jagdpanzer Multi-Container & Cognitive Memory Integration

Multi-container stack orchestration (persistent graph and vector memory engines like Cognee, Mem0, LanceDB, and multi-service Docker Compose networks) is decoupled from Hetzer and maintained in [**Jagdpanzer**](https://github.com/agunggnn/jagdpanzer).

When deploying cognitive memory stacks with Jagdpanzer:
- Jagdpanzer exposes memory MCP endpoints (e.g. `remember`, `recall`, `improve`) via loopback or container networks.
- Hetzer acts as the client-side armor and security proxy, mediating all credentials (`secretRef:<id>`) passed into cognitive memory endpoints and sanitizing responses.

---

## 8. Troubleshooting & Diagnostics

### Issue: `HTTP 406: Not Acceptable`
- **Root Cause**: The client did not supply `Accept: text/event-stream` or `Accept: application/json` headers required by MCP SSE servers.
- **Solution**: Handled automatically in Hetzer (`cli/mcp/call.mjs` and `cli/mcp/ping.mjs`).

### Issue: Stdio MCP Server Fails to Connect
- **Root Cause**: `hetzer` binary is not in your system `PATH`, or Node.js >= 18 is not accessible.
- **Solution**: Test manually in terminal:
  ```bash
  hetzer mcp serve
  ```
  Ensure JSON-RPC messages are emitted cleanly over stdio.

---

*For full architectural details, refer to [docs/architecture.md](architecture.md).*
