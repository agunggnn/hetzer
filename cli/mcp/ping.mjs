import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { loadModuleRegistry } from "../modules/registry.mjs";

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

export async function pingMcpServer({ url, timeoutMs = 5000, fetchFn = globalThis.fetch }) {
    const start = Date.now();
    const initPayload = {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "hetzer-cli", version: "0.4.7" },
        },
    };

    let response;
    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            response = await fetchFn(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream, */*",
                },
                body: JSON.stringify(initPayload),
                signal: controller.signal,
            });
        } finally {
            clearTimeout(timer);
        }
    } catch (err) {
        return {
            ok: false,
            url,
            latencyMs: Date.now() - start,
            error: err.name === "AbortError" ? "Request timeout" : err.message,
        };
    }

    const latencyMs = Date.now() - start;
    if (!response.ok) {
        return {
            ok: false,
            url,
            latencyMs,
            status: response.status,
            error: `HTTP ${response.status} ${response.statusText}`,
        };
    }

    let initData;
    try {
        const ct = response.headers?.get ? (response.headers.get("content-type") || "") : "";
        if (ct.includes("text/event-stream")) {
            const rawText = await response.text();
            const lines = rawText.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.replace(/^data:\s*/, "").trim());
            initData = JSON.parse(lines[lines.length - 1] || "{}");
        } else {
            initData = await response.json();
        }
    } catch (err) {
        return {
            ok: false,
            url,
            latencyMs,
            error: `Response is not valid JSON: ${err.message}`,
        };
    }

    let tools = [];
    try {
        const toolsPayload = {
            jsonrpc: "2.0",
            id: 2,
            method: "tools/list",
            params: {},
        };
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const toolsRes = await fetchFn(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream, */*",
                },
                body: JSON.stringify(toolsPayload),
                signal: controller.signal,
            });
            if (toolsRes.ok) {
                const ct2 = toolsRes.headers?.get ? (toolsRes.headers.get("content-type") || "") : "";
                let toolsData;
                if (ct2.includes("text/event-stream")) {
                    const rawText = await toolsRes.text();
                    const lines = rawText.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.replace(/^data:\s*/, "").trim());
                    toolsData = JSON.parse(lines[lines.length - 1] || "{}");
                } else {
                    toolsData = await toolsRes.json();
                }
                tools = toolsData.result?.tools || [];
            }
        } finally {
            clearTimeout(timer);
        }
    } catch {
        // Optional tools failure doesn't block initialize success
    }

    return {
        ok: true,
        url,
        latencyMs,
        protocolVersion: initData.result?.protocolVersion || "unknown",
        serverInfo: initData.result?.serverInfo || { name: "unknown", version: "unknown" },
        tools,
    };
}

export async function diagnoseMcpService({ root, targetService, out = process.stdout, fetchFn = globalThis.fetch }) {
    const envFile = path.join(root, ".env");
    const fileEnv = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const here = path.dirname(fileURLToPath(import.meta.url));
    const registry = loadModuleRegistry({
        builtinFile: path.resolve(here, "..", "modules", "builtin.json"),
        root,
        disabledModules: environmentValue(fileEnv, "HETZER_DISABLED_MODULES"),
        enabledModules: environmentValue(fileEnv, "HETZER_ENABLED_MODULES"),
    });

    const allMcpServices = registry.modules.flatMap((m) =>
        m.services.map((s) => ({ ...s, moduleEnabled: m.enabled }))
    ).filter((s) => s.mcpServer);

    if (!allMcpServices.length) {
        out.write("No services with MCP endpoints registered in Hetzer Core.\n");
        return { ok: false, checked: 0 };
    }

    if (targetService) {
        const found = allMcpServices.find((s) => s.id === targetService || s.moduleId === targetService || s.mcpServer.name === targetService);
        if (found && !found.moduleEnabled) {
            out.write(`[!] Module '${found.moduleId}' is not enabled.\n`);
            out.write(`    Run 'hetzer install ${found.moduleId} && hetzer up ${found.moduleId}' to enable this MCP service.\n`);
            return { ok: false, checked: 0 };
        }
        if (!found) {
            out.write(`MCP service '${targetService}' not found.\n`);
            out.write(`Available MCP services: ${allMcpServices.map((s) => s.mcpServer.name).join(", ")}\n`);
            return { ok: false, checked: 0 };
        }
    }

    const targets = targetService
        ? allMcpServices.filter((s) => (s.id === targetService || s.moduleId === targetService || s.mcpServer.name === targetService) && s.moduleEnabled)
        : allMcpServices.filter((s) => s.moduleEnabled);

    if (!targets.length) {
        out.write("No active MCP services found in Hetzer Core.\n");
        out.write(`Available MCP modules: ${allMcpServices.map((s) => s.moduleId).join(", ")}\n`);
        out.write("Run 'hetzer install <module> && hetzer up <module>' to enable.\n");
        return { ok: false, checked: 0 };
    }

    out.write("================================================================================\n");
    out.write("  HETZER CORE - MCP DIAGNOSTIC & PING\n");
    out.write("================================================================================\n");

    let allOk = true;

    for (const service of targets) {
        const baseUrl = serviceUrl(service, fileEnv);
        if (!baseUrl) {
            out.write(`[-] ${service.id}: Port or Base URL not configured.\n\n`);
            allOk = false;
            continue;
        }

        const endpointUrl = new URL(service.mcpServer.path, `${baseUrl}/`).href;
        out.write(`Checking: ${service.mcpServer.name} (${endpointUrl})\n`);
        out.write("--------------------------------------------------------------------------------\n");

        const result = await pingMcpServer({ url: endpointUrl, fetchFn });

        if (result.ok) {
            out.write(`  [v] Connection     : OK (Latency: ${result.latencyMs}ms)\n`);
            out.write(`  [v] Server Info    : ${result.serverInfo.name} v${result.serverInfo.version}\n`);
            out.write(`  [v] Protocol       : v${result.protocolVersion}\n`);
            if (result.tools.length > 0) {
                out.write(`  [v] Active Tools   : ${result.tools.length} tools available\n`);
                for (const tool of result.tools) {
                    const desc = tool.description ? tool.description.replace(/\n.*/s, "").slice(0, 70) : "No description";
                    out.write(`      - ${tool.name.padEnd(16)} : ${desc}\n`);
                }
            } else {
                out.write("  [i] Active Tools   : No tools exposed by this server yet\n");
            }
            out.write(`\nStatus: MCP endpoint '${service.mcpServer.name}' OPERATIONAL.\n`);
        } else {
            out.write(`  [x] Connection     : FAILED (${result.error})\n`);
            out.write(`  [!] Guide          : Ensure the container service is running.\n`);
            out.write(`                       Run      : hetzer up ${service.moduleId}\n`);
            out.write(`                       Check log: hetzer logs ${service.composeService || service.id}\n`);
            out.write(`\nStatus: MCP endpoint '${service.mcpServer.name}' UNREACHABLE.\n`);
            allOk = false;
        }
        out.write("================================================================================\n");
    }

    return { ok: allOk, checked: targets.length };
}
