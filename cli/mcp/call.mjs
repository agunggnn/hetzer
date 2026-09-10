import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { loadModuleRegistry } from "../modules/registry.mjs";
import { Grimoire, resolveMasterKey, resolveVaultPath } from "../vault/hetzer-vault.mjs";
import { resolveSecretRefsInPayload, sanitizeMcpValue } from "./protocol.mjs";

function environmentValue(fileEnv, name, fallback = "") {
    return process.env[name] || fileEnv[name] || fallback;
}

function serviceUrl(service, fileEnv) {
    const configured = service.urlEnv ? environmentValue(fileEnv, service.urlEnv) : "";
    if (configured && !configured.startsWith("secretRef:")) return configured.replace(/\/+$/, "");
    const port = service.portEnv ? environmentValue(fileEnv, service.portEnv) : "";
    const selected = port || String(service.fallbackPort || "");
    return /^\d+$/.test(selected) ? `http://127.0.0.1:${selected}` : "";
}

function resolveServiceEndpoint(root, targetService) {
    const envFile = path.join(root, ".env");
    const fileEnv = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const here = path.dirname(fileURLToPath(import.meta.url));
    const registry = loadModuleRegistry({
        builtinFile: path.resolve(here, "..", "modules", "builtin.json"),
        root,
        disabledModules: environmentValue(fileEnv, "HETZER_DISABLED_MODULES"),
        enabledModules: environmentValue(fileEnv, "HETZER_ENABLED_MODULES"),
    });

    let mcpServices = registry.modules.flatMap((m) =>
        m.services.map((s) => ({ ...s, moduleEnabled: m.enabled }))
    ).filter((s) => s.mcpServer);

    let found = mcpServices.find(
        (s) => s.id === targetService || s.moduleId === targetService || s.mcpServer.name === targetService
    );

    if (!found) {
        const fallbackDir = path.resolve(here, "..", "templates");
        if (fs.existsSync(path.join(fallbackDir, "modules"))) {
            const fallbackRegistry = loadModuleRegistry({
                builtinFile: path.resolve(here, "..", "modules", "builtin.json"),
                root: fallbackDir,
                disabledModules: environmentValue(fileEnv, "HETZER_DISABLED_MODULES"),
                enabledModules: environmentValue(fileEnv, "HETZER_ENABLED_MODULES"),
            });
            const fallbackMcp = fallbackRegistry.modules.flatMap((m) =>
                m.services.map((s) => ({ ...s, moduleEnabled: true }))
            ).filter((s) => s.mcpServer);
            found = fallbackMcp.find(
                (s) => s.id === targetService || s.moduleId === targetService || s.mcpServer.name === targetService
            );
            if (found) {
                mcpServices = fallbackMcp;
            }
        }
    }

    if (!found) {
        throw new Error(`MCP service '${targetService}' not found. Available services: ${mcpServices.map((s) => s.mcpServer.name).join(", ")}`);
    }

    const baseUrl = serviceUrl(found, fileEnv);
    if (!baseUrl) {
        throw new Error(`Service '${found.id}' does not have a valid port or URL configured.`);
    }

    return {
        service: found,
        endpointUrl: new URL(found.mcpServer.path, `${baseUrl}/`).href,
    };
}

export function classifyToolNature(toolName, description = "") {
    const lowerName = toolName.toLowerCase();
    const lowerDesc = description.toLowerCase();

    if (
        lowerName.includes("forget")
        || lowerName.includes("delete")
        || lowerName.includes("remove")
        || lowerName.includes("clear")
    ) {
        return { tag: "OFFLINE", note: "Local operation (no LLM)" };
    }

    if (
        lowerName.includes("recall")
        || lowerName.includes("search")
        || lowerName.includes("find")
        || lowerName.includes("get")
        || lowerName.includes("read")
        || lowerName.includes("list")
    ) {
        return { tag: "HYBRID", note: "Local / vector search" };
    }

    if (
        lowerName.includes("remember")
        || lowerName.includes("improve")
        || lowerName.includes("generate")
        || lowerName.includes("extract")
        || lowerDesc.includes("llm")
    ) {
        return { tag: "LLM REASONING", note: "Requires 9Router / LLM" };
    }

    return { tag: "NATIVE", note: "Module native function" };
}

async function parseMcpResponse(res) {
    const contentType = res.headers?.get ? (res.headers.get("content-type") || "") : "";
    if (contentType.includes("text/event-stream")) {
        const text = await res.text();
        const lines = text.split("\n")
            .filter((l) => l.startsWith("data:"))
            .map((l) => l.replace(/^data:\s*/, "").trim())
            .filter(Boolean);
        const lastLine = lines[lines.length - 1] || "{}";
        return JSON.parse(lastLine);
    }
    if (typeof res.json === "function") {
        return await res.json();
    }
    const text = await res.text();
    return JSON.parse(text);
}

async function sendMcpRequest({ endpointUrl, payload, fetchFn, timeoutMs = 15000, sessionId = null }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream, */*",
        };
        if (sessionId) {
            headers["mcp-session-id"] = sessionId;
        }

        const res = await fetchFn(endpointUrl, {
            method: "POST",
            headers,
            body: JSON.stringify(payload),
            signal: controller.signal,
        });

        if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        }

        const newSessionId = res.headers?.get ? res.headers.get("mcp-session-id") : null;
        const data = await parseMcpResponse(res);
        return { data, sessionId: newSessionId || sessionId };
    } finally {
        clearTimeout(timer);
    }
}

async function ensureMcpSession({ endpointUrl, fetchFn }) {
    try {
        const initPayload = {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
                protocolVersion: "2024-11-05",
                capabilities: {},
                clientInfo: { name: "hetzer-cli", version: "0.4.11" },
            },
        };
        const { data, sessionId } = await sendMcpRequest({
            endpointUrl,
            payload: initPayload,
            fetchFn,
            timeoutMs: 5000,
        });

        try {
            await sendMcpRequest({
                endpointUrl,
                payload: { jsonrpc: "2.0", method: "notifications/initialized", params: {} },
                fetchFn,
                timeoutMs: 3000,
                sessionId,
            });
        } catch {
            // notifications are non-blocking
        }

        return sessionId;
    } catch {
        return null;
    }
}

export async function listMcpTools({ root = process.cwd(), targetService, fetchFn = globalThis.fetch, timeoutMs = 10000 }) {
    const { endpointUrl, service } = resolveServiceEndpoint(root, targetService);

    const payload = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
    };

    let data;
    try {
        const result = await sendMcpRequest({ endpointUrl, payload, fetchFn, timeoutMs });
        data = result.data;
    } catch {
        const sessionId = await ensureMcpSession({ endpointUrl, fetchFn });
        const result = await sendMcpRequest({ endpointUrl, payload, fetchFn, timeoutMs, sessionId });
        data = result.data;
    }

    const tools = (data.result?.tools || []).map((t) => ({
        ...t,
        classification: classifyToolNature(t.name, t.description),
    }));

    return {
        ok: true,
        serviceName: service.mcpServer.name,
        endpointUrl,
        tools,
    };
}

export async function callMcpTool({
    root = process.cwd(),
    targetService,
    toolName,
    args = {},
    fetchFn = globalThis.fetch,
    timeoutMs = 30000,
}) {
    if (!targetService) throw new Error("MCP service name is required.");
    if (!toolName) throw new Error("MCP tool name is required.");

    const { endpointUrl, service } = resolveServiceEndpoint(root, targetService);

    let resolvedArgs = typeof args === "string" ? JSON.parse(args || "{}") : (args || {});
    const envFile = path.join(root, ".env");
    const fileEnv = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const masterKey = resolveMasterKey({ root, envValues: fileEnv });
    if (masterKey) {
        const envVault = resolveVaultPath(root);
        const dbPath = envVault || path.join(root, "data", "hetzer-vault.db");
        if (fs.existsSync(dbPath)) {
            const vault = new Grimoire({ dbPath, masterKey });
            try {
                resolvedArgs = resolveSecretRefsInPayload(resolvedArgs, (id) => vault.resolve(id));
            } finally {
                vault.close();
            }
        }
    }

    const payload = {
        jsonrpc: "2.0",
        id: Date.now(),
        method: "tools/call",
        params: {
            name: toolName,
            arguments: resolvedArgs,
        },
    };

    let data;
    try {
        const result = await sendMcpRequest({ endpointUrl, payload, fetchFn, timeoutMs });
        data = result.data;
    } catch {
        const sessionId = await ensureMcpSession({ endpointUrl, fetchFn });
        const result = await sendMcpRequest({ endpointUrl, payload, fetchFn, timeoutMs, sessionId });
        data = result.data;
    }

    if (data.error) {
        return {
            ok: false,
            isError: true,
            error: sanitizeMcpValue(data.error.message || JSON.stringify(data.error)),
            endpointUrl,
        };
    }

    const result = sanitizeMcpValue(data.result || {});
    const contentText = (result.content || [])
        .map((item) => item.text || JSON.stringify(item))
        .join("\n") || JSON.stringify(result, null, 2);

    return {
        ok: !result.isError,
        isError: result.isError || false,
        content: contentText,
        rawResult: result,
        endpointUrl,
        serviceName: service.mcpServer.name,
    };
}

export async function runMcpToolCommand({
    root = process.cwd(),
    targetService,
    toolName,
    argsJson = "{}",
    out = process.stdout,
    fetchFn = globalThis.fetch,
}) {
    try {
        out.write(`Invoking tool '${toolName}' on service '${targetService}'...\n`);
        const result = await callMcpTool({
            root,
            targetService,
            toolName,
            args: argsJson,
            fetchFn,
        });

        out.write("================================================================================\n");
        out.write(`  MCP TOOL EXECUTION RESULT: ${toolName} (${targetService})\n`);
        out.write("================================================================================\n");
        if (result.ok) {
            out.write(result.content + "\n");
        } else {
            out.write(`[x] Error: ${result.error || result.content}\n`);
        }
        out.write("================================================================================\n");
        return result.ok;
    } catch (err) {
        out.write(`[x] Failed to execute tool: ${err.message}\n`);
        return false;
    }
}
