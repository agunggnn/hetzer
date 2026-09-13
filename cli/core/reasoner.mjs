import fs from "node:fs";
import path from "node:path";
import { parseEnv } from "./env.mjs";

function get9RouterBaseUrl(root) {
    const envFile = path.join(root, ".env");
    const fileEnv = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const configured = process.env.NINE_ROUTER_BASE_URL || fileEnv.NINE_ROUTER_BASE_URL;
    if (configured) return configured.replace(/\/+$/, "");
    const port = process.env.NINE_ROUTER_PORT || fileEnv.NINE_ROUTER_PORT || "20140";
    return `http://127.0.0.1:${port}`;
}

export async function checkReasonerStatus({ root, timeoutMs = 3000, fetchFn = globalThis.fetch } = {}) {
    const baseUrl = get9RouterBaseUrl(root || process.cwd());
    const healthUrl = `${baseUrl}/api/health`;

    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            const res = await fetchFn(healthUrl, { signal: controller.signal });
            return {
                available: res.ok,
                url: baseUrl,
                status: res.status,
            };
        } finally {
            clearTimeout(timer);
        }
    } catch (err) {
        return {
            available: false,
            url: baseUrl,
            error: err.name === "AbortError" ? "Timeout" : err.message,
        };
    }
}

export async function askReasoner({
    prompt,
    systemPrompt = "You are Hetzer Core's DevOps AI assistant. Provide concise, accurate technical advice.",
    root = process.cwd(),
    model = "openai/gpt-4o-mini",
    timeoutMs = 30000,
    fetchFn = globalThis.fetch,
}) {
    const baseUrl = get9RouterBaseUrl(root);
    const chatUrl = `${baseUrl}/v1/chat/completions`;

    const payload = {
        model,
        messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: prompt },
        ],
        temperature: 0.2,
    };

    try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let res;
        try {
            res = await fetchFn(chatUrl, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: "Bearer hetzer-default",
                },
                body: JSON.stringify(payload),
                signal: controller.signal,
            });
        } finally {
            clearTimeout(timer);
        }

        if (!res.ok) {
            return {
                ok: false,
                error: `9Router HTTP ${res.status}: ${res.statusText}`,
            };
        }

        const data = await res.json();
        const content = data.choices?.[0]?.message?.content || "";
        return {
            ok: true,
            content,
            model: data.model || model,
        };
    } catch (err) {
        return {
            ok: false,
            error: err.name === "AbortError" ? "9Router timeout" : err.message,
        };
    }
}

export async function analyzeContainerFailure({
    serviceId,
    logs = "",
    composeContent = "",
    root = process.cwd(),
    fetchFn = globalThis.fetch,
}) {
    // 1. Static pattern analyzer (instant fallback if 9Router is offline)
    const staticMatches = [];
    if (logs.includes("Permission denied") || logs.includes("PermissionError")) {
        staticMatches.push({
            cause: "File or directory permission issue (Permission Denied). The container likely runs as a non-root user (UID 1000) while the volume mount is owned by root.",
            suggestion: "Ensure the volume mount point points to an existing directory with proper ownership in the image, or use upstream named volumes.",
        });
    }
    if (logs.includes("address already in use") || logs.includes("bind: address already in use")) {
        staticMatches.push({
            cause: "Port conflict. The requested port is already in use by another process on the host.",
            suggestion: "Change the port mapping in .env or docker-compose to another available port.",
        });
    }
    if (logs.includes("API key not set") || logs.includes("KeyError: 'API_KEY'") || logs.includes("API_KEY is missing")) {
        staticMatches.push({
            cause: "API key or credential environment variable not configured.",
            suggestion: "Run 'hetzer creds set <id>' to store the required API key in Grimoire Vault.",
        });
    }

    // 2. Check if 9Router is available for deep LLM reasoning
    const reasonerStatus = await checkReasonerStatus({ root, timeoutMs: 2000, fetchFn });
    if (!reasonerStatus.available) {
        if (staticMatches.length > 0) {
            return {
                ok: true,
                source: "static-heuristics",
                cause: staticMatches[0].cause,
                suggestion: staticMatches[0].suggestion,
            };
        }
        return {
            ok: false,
            error: "9Router gateway is offline for automatic AI analysis.",
            source: "none",
        };
    }

    // 3. Ask 9Router AI Engine
    const prompt = `Analyze container failure for '${serviceId}':
RECENT LOGS:
"""
${logs.slice(-2000)}
"""

COMPOSE CONFIGURATION:
"""
${composeContent.slice(-1500)}
"""

Provide your analysis in this exact JSON format:
{
  "cause": "Primary root cause in 1-2 concise sentences (English)",
  "suggestion": "Concrete step-by-step resolution advice (English)"
}`;

    const aiRes = await askReasoner({
        prompt,
        systemPrompt: "You are Hetzer Core's autonomous DevOps SRE. Return ONLY a valid JSON object with 'cause' and 'suggestion' keys.",
        root,
        fetchFn,
    });

    if (aiRes.ok && aiRes.content) {
        try {
            const jsonMatch = aiRes.content.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                return {
                    ok: true,
                    source: "9router-ai",
                    cause: parsed.cause,
                    suggestion: parsed.suggestion,
                };
            }
        } catch {
            // fallback to raw content
            return {
                ok: true,
                source: "9router-ai",
                cause: "Failure analysis detected.",
                suggestion: aiRes.content,
            };
        }
    }

    if (staticMatches.length > 0) {
        return {
            ok: true,
            source: "static-heuristics",
            cause: staticMatches[0].cause,
            suggestion: staticMatches[0].suggestion,
        };
    }

    return {
        ok: false,
        error: aiRes.error || "Failed to retrieve analysis from AI.",
    };
}

export async function analyzeModuleSource({
    sourceContent = "",
    sourceUrl = "",
    root = process.cwd(),
    fetchFn = globalThis.fetch,
}) {
    // 1. Static pattern extraction fallback
    let detectedPort = 8080;
    const portMatch = sourceContent.match(/(?:EXPOSE|port|listening on|bind|localhost:)\s*[:=]?\s*(\d{4,5})/i);
    if (portMatch) {
        const p = parseInt(portMatch[1], 10);
        if (p > 1024 && p < 65535) detectedPort = p;
    }

    const hasMcp = /mcp|model context protocol|model-context-protocol|tools\/list|json-rpc/i.test(sourceContent);
    const hasWebUi = /dashboard|web\s*ui|interface|browser|frontend|gui/i.test(sourceContent);
    const nonRoot = /1000:1000|uid 1000|non-root|appuser/i.test(sourceContent) ? 1000 : null;

    const envVarMatches = sourceContent.match(/\b[A-Z0-9_]{3,}_(?:API_KEY|KEY|SECRET|TOKEN|ENDPOINT|URL|PORT|HOST)\b/g) || [];
    const uniqueEnvs = [...new Set(envVarMatches)].map((name) => ({
        name,
        isSecret: /KEY|SECRET|TOKEN|PASS/i.test(name),
        defaultVal: /PORT/i.test(name) ? String(detectedPort) : "",
    }));

    const staticResult = {
        ok: true,
        source: "static-heuristics",
        label: "",
        port: detectedPort,
        webUi: hasWebUi,
        mcp: hasMcp,
        mcpPath: "/mcp",
        envVars: uniqueEnvs,
        volumes: [{ containerPath: "/data", hostVolume: "data" }],
        healthPath: "/health",
        nonRootUid: nonRoot,
        sourceUrl: sourceUrl || "",
        description: "Third-party module integrated into Hetzer Core.",
    };

    // 2. Check 9Router availability
    const reasonerStatus = await checkReasonerStatus({ root, timeoutMs: 2000, fetchFn });
    if (!reasonerStatus.available) {
        return staticResult;
    }

    // 3. Ask 9Router AI
    const prompt = `Analyze documentation / source for the new module to generate a Hetzer Core recipe:
SOURCE URL: ${sourceUrl || "N/A"}
REPOSITORY CONTENT / DOCUMENTATION:
"""
${sourceContent.slice(0, 4000)}
"""

Task: Extract module technical specifications as a single JSON object matching this schema:
{
  "label": "Module display name (e.g. Mem0, SearXNG, Neo4j)",
  "port": 8080,
  "webUi": true,
  "mcp": false,
  "mcpPath": "/mcp",
  "description": "Short 1-sentence description of what this module does",
  "envVars": [
    { "name": "SERVICE_API_KEY", "defaultVal": "", "isSecret": true, "description": "Upstream API key" }
  ],
  "volumes": [
    { "containerPath": "/data", "hostVolume": "data" }
  ],
  "healthPath": "/health",
  "nonRootUid": null
}`;

    const aiRes = await askReasoner({
        prompt,
        systemPrompt: "You are Hetzer Core's AI Software Architect. Extract precise technical specs for Docker and MCP integration. Return ONLY a valid JSON object.",
        root,
        fetchFn,
    });

    if (aiRes.ok && aiRes.content) {
        try {
            const jsonMatch = aiRes.content.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                return {
                    ok: true,
                    source: "9router-ai",
                    label: parsed.label || staticResult.label,
                    port: parseInt(parsed.port, 10) || staticResult.port,
                    webUi: typeof parsed.webUi === "boolean" ? parsed.webUi : staticResult.webUi,
                    mcp: typeof parsed.mcp === "boolean" ? parsed.mcp : staticResult.mcp,
                    mcpPath: parsed.mcpPath || "/mcp",
                    description: parsed.description || staticResult.description,
                    envVars: Array.isArray(parsed.envVars) && parsed.envVars.length > 0 ? parsed.envVars : staticResult.envVars,
                    volumes: Array.isArray(parsed.volumes) && parsed.volumes.length > 0 ? parsed.volumes : staticResult.volumes,
                    healthPath: parsed.healthPath || staticResult.healthPath,
                    nonRootUid: parsed.nonRootUid || staticResult.nonRootUid,
                    sourceUrl: sourceUrl || "",
                };
            }
        } catch {
            // Fallback to static
        }
    }

    return staticResult;
}
