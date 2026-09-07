# Model Context Protocol (MCP) Guide & Integration

> **Version**: 1.0.0-rc  
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
5. [Cognee Memory Tools Reference](#5-cognee-memory-tools-reference)
6. [Troubleshooting & Diagnostics](#6-troubleshooting--diagnostics)

---

## 1. Overview

The **Model Context Protocol (MCP)** standardizes how AI applications connect to external tools, databases, and context servers. Hetzer acts as an **autonomous MCP orchestrator and security bridge**, providing:
- **Embedded Stdio FastMCP Server** (`hetzer mcp serve`): Direct high-speed JSON-RPC bridge for Claude Desktop, Cursor, and Cline.
- **Native Defense Tools**: Explicit text scanning (`hetzer_sniffer_scan`), redaction with per-item vault status (`hetzer_sniffer_redact`), and credential existence checks (`hetzer_vault_has`, `hetzer_vault_list`).
- **MCP Output Sanitization**: Scans serialized Hetzer tool return values and error messages via `sanitizeStreamOutput` before return. Other MCP servers and client tools are outside this path.
- **Automated Loopback Networking**: Zero-plaintext API key injection and port bindings (`127.0.0.1:8001/mcp`) for Cognee and active modules.
- **Operational Tool Classification**: Automated labeling as `[OFFLINE]`, `[HYBRID]`, and `[LLM REASONING]`.

---

## 2. Tool Classification Taxonomy

In high-throughput AI agent environments, knowing whether a tool call consumes cloud tokens or executes locally is critical for latency, cost control, and privacy. Hetzer tags all discovered tools:

### `[OFFLINE]` (Zero Cost, Zero Latency)
- **Execution**: 100% on localhost machine.
- **Latency**: < 5 ms.
- **Cost**: 0 LLM tokens, 0 network bandwidth.
- **Privacy**: No data leaves the local machine.
- **Use Cases**: System health probes, local cache lookups, database status checks.

### `[HYBRID]` (Local Indexing & Graph Search)
- **Execution**: Local embedded engines (LanceDB vector search, Kùzu graph traversal, SQLite queries).
- **Latency**: 10 ms – 50 ms.
- **Cost**: 0 generation tokens (may use local embeddings if configured with Ollama).
- **Privacy**: Fully contained within Docker volumes on local disk.
- **Use Cases**: Semantic retrieval (`recall`), subgraph relationship queries.

### `[LLM REASONING]` (Cognitive Synthesis)
- **Execution**: Requires model inference (OpenAI, Anthropic, Gemini, or local Ollama).
- **Latency**: 500 ms – 3000 ms.
- **Cost**: Incurs token usage on upstream model provider.
- **Privacy**: Text payloads routed securely through 9Router or configured upstream endpoint.
- **Use Cases**: Knowledge graph distillation (`remember`), memory summarization (`improve`).

---

## 3. Client Configuration

### 3.1 Claude Desktop

Add Hetzer's MCP endpoint to your Claude Desktop configuration file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "hetzer-cognee": {
      "url": "http://127.0.0.1:8001/mcp"
    }
  }
}
```

### 3.2 Cursor IDE

Inside your project root or workspace settings, create or update `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "hetzer-memory": {
      "url": "http://127.0.0.1:8001/mcp"
    }
  }
}
```

### 3.3 Cline / Roo Code (VS Code Extension)

In VS Code, open Settings or edit `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "hetzer-core-memory": {
      "url": "http://127.0.0.1:8001/mcp",
      "disabled": false,
      "autoApprove": [
        "recall"
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
    "hetzer-memory": {
      "serverUrl": "http://127.0.0.1:8001/mcp"
    }
  }
}
```

---

## 4. Testing & Calling Tools via CLI

Hetzer allows developers to interact with MCP tools directly from the terminal without opening an AI IDE:

### 4.1 Ping and Health Diagnostics
Test protocol handshake and roundtrip response latency:
```bash
hetzer mcp ping cognee
```
*Output:*
```text
[v] MCP Endpoint: http://127.0.0.1:8001/mcp
[v] Protocol: JSON-RPC 2.0 (SSE streaming enabled)
[v] Latency: 12ms
[v] Server Info: cognee-mcp v0.1.2
```

### 4.2 List Discovered Tools
Inspect tools with their parameter schemas and operational classifications:
```bash
hetzer mcp tools cognee
```

### 4.3 Direct Tool Execution (`hetzer mcp call`)
Execute tools synchronously with JSON arguments:
```bash
# Save information to persistent memory
hetzer mcp call cognee remember '{"text": "Production DB host is 10.0.0.45 on port 5432"}'

# Search memory
hetzer mcp call cognee recall '{"query": "production database host"}'
```

---

## 5. Cognee Memory Tools Reference

When the `cognee` module is active, the following cognitive tools are exposed:

### `remember` `[LLM REASONING]`
- **Description**: Ingests unstructured text, documents, or conversation history into memory. Executes entity extraction, builds graph nodes, and indexes vector embeddings.
- **Parameters**:
  - `text` *(string, required)*: The text or document content to store.

### `recall` `[HYBRID]`
- **Description**: Semantically searches the vector and graph stores for relevant context matching the query.
- **Parameters**:
  - `query` *(string, required)*: Natural language question or search phrase.

### `improve` `[LLM REASONING]`
- **Description**: Refines, consolidates, and resolves conflicting memories across historical knowledge graphs.
- **Parameters**:
  - `context` *(string, optional)*: Specific domain or focus area to optimize.

### `forget_memory` `[OFFLINE]`
- **Description**: Deletes specific nodes or memory scopes from the local database.
- **Parameters**:
  - `memory_id` *(string, required)*: The identifier of the memory entity to purge.

---

## 6. Hetzer Native Defense Tools Reference

When connected to Hetzer's stdio FastMCP server (`hetzer mcp serve`), AI agents gain access to local defense utilities designed to inspect and secure credentials without exposing plaintext values:

### `hetzer_sniffer_scan` `[OFFLINE]`
- **Description**: Scans provided text or code snippets for supported API-key patterns, private-key blocks up to 16 KiB, credentialed database URLs, and bounded high-entropy candidates. Runtime depends on input and environment.
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

## 7. Real-Time Tool Output Sanitization

To reduce accidental credential exposure in Hetzer tool output, the MCP protocol handler (`cli/mcp/protocol.mjs`) pipes serialized `tools/call` responses through `sanitizeStreamOutput`:
- If an upstream tool or database query accidentally returns a known secret, Hetzer detects the plaintext string in memory and redacts it back into `secretRef:<id>`.
- Structured JSON outputs and error messages are symmetrically sanitized.
- **Result**: Third-party LLM providers never ingest plaintext credentials even if a backend tool dumps raw configurations.

---

## 8. Troubleshooting & Diagnostics

### Issue: `HTTP 406: Not Acceptable`
- **Root Cause**: The client did not supply `Accept: text/event-stream` or `Accept: application/json` headers required by MCP SSE servers.
- **Solution**: Handled automatically in Hetzer v0.3.0 (`cli/mcp/call.mjs` and `cli/mcp/ping.mjs`). If using custom curl, ensure:
  ```bash
  curl -H "Accept: application/json, text/event-stream" http://127.0.0.1:8001/mcp
  ```

### Issue: `ECONNREFUSED 127.0.0.1:8001`
- **Root Cause**: The Cognee container is not running or still initializing.
- **Solution**: Run `hetzer status` to verify container health. If unhealthy, execute:
  ```bash
  hetzer up --wait cognee
  ```

---

*For full architectural details, refer to [docs/architecture.md](architecture.md) and [docs/system-logic-and-progress.md](system-logic-and-progress.md).*
