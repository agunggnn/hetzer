import { sanitizeStreamOutput } from "../vault/exec.mjs";
import { isCanaryCredential, triggerCanaryAlert } from "../vault/canary.mjs";
import { SECRET_REF_PATTERN } from "../vault/hetzer-vault.mjs";

const MODERN_VERSION = "2026-07-28";
const LEGACY_VERSION = "2025-11-25";

function modernRequest(request) {
    return request.method === "server/discover"
        || request.params?._meta?.["io.modelcontextprotocol/protocolVersion"] === MODERN_VERSION;
}

function result(id, value) {
    return { jsonrpc: "2.0", id, result: value };
}

function error(id, code, message) {
    return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

export function expandSecretVariants(secretsToRedact = []) {
    const variants = [];
    for (const item of secretsToRedact) {
        const secret = typeof item === "string" ? item : item?.secret;
        const id = typeof item === "string" ? "credential" : (item?.id || "credential");
        if (!secret || typeof secret !== "string") continue;

        const reps = new Set();
        reps.add(secret);

        try {
            const jsonEscaped = JSON.stringify(secret).slice(1, -1);
            if (jsonEscaped) reps.add(jsonEscaped);
        } catch { /* ignore */ }

        try {
            const urlEscaped = encodeURIComponent(secret);
            if (urlEscaped) {
                reps.add(urlEscaped);
                reps.add(urlEscaped.toLowerCase());
            }
        } catch { /* ignore */ }

        try {
            const unicodeEscaped = secret.replace(/["\\/<>&\x00-\x1f]/g, (c) =>
                "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")
            );
            if (unicodeEscaped) {
                reps.add(unicodeEscaped);
                reps.add(unicodeEscaped.toUpperCase());
            }
        } catch { /* ignore */ }

        for (const rep of reps) {
            if (rep) variants.push({ id, secret: rep });
        }
    }
    return variants.sort((a, b) => b.secret.length - a.secret.length);
}

function sanitizeMcpValueInner(value, expandedSecrets) {
    if (typeof value === "string") return sanitizeStreamOutput(value, expandedSecrets);
    if (Array.isArray(value)) return value.map((item) => sanitizeMcpValueInner(item, expandedSecrets));
    if (value && typeof value === "object") {
        return Object.fromEntries(
            Object.entries(value).map(([key, item]) => [
                sanitizeStreamOutput(key, expandedSecrets),
                sanitizeMcpValueInner(item, expandedSecrets),
            ])
        );
    }
    return value;
}

export function sanitizeMcpValue(value, secretsToRedact = []) {
    const expanded = expandSecretVariants(secretsToRedact);
    return sanitizeMcpValueInner(value, expanded);
}

export function resolveSecretRefsInPayload(value, resolver, collectedSecrets = []) {
    if (typeof value === "string") {
        const exactMatch = SECRET_REF_PATTERN.exec(value.trim());
        if (exactMatch) {
            const id = exactMatch[1];
            if (isCanaryCredential(id)) {
                triggerCanaryAlert({ id, actor: "mcp-agent", action: "mcp.tools/call" });
            }
            if (typeof resolver === "function") {
                const resolved = resolver(id);
                if (resolved !== null && resolved !== undefined) {
                    if (typeof resolved === "string") {
                        collectedSecrets.push({ id, secret: resolved });
                    }
                    return resolved;
                }
                throw new Error(`Credential 'secretRef:${id}' not found in Grimoire Vault.`);
            }
            return value;
        }
        if (value.includes("secretRef:")) {
            return value.replace(/secretRef:([a-z0-9]+(?:[._-][a-z0-9]+)*)/g, (match, id) => {
                if (isCanaryCredential(id)) {
                    triggerCanaryAlert({ id, actor: "mcp-agent", action: "mcp.tools/call" });
                }
                if (typeof resolver === "function") {
                    const resolved = resolver(id);
                    if (resolved !== null && resolved !== undefined) {
                        if (typeof resolved === "string") {
                            collectedSecrets.push({ id, secret: resolved });
                        }
                        return resolved;
                    }
                    throw new Error(`Credential 'secretRef:${id}' not found in Grimoire Vault.`);
                }
                return match;
            });
        }
        return value;
    }
    if (Array.isArray(value)) {
        return value.map((item) => resolveSecretRefsInPayload(item, resolver, collectedSecrets));
    }
    if (value && typeof value === "object") {
        return Object.fromEntries(
            Object.entries(value).map(([k, v]) => [k, resolveSecretRefsInPayload(v, resolver, collectedSecrets)])
        );
    }
    return value;
}

export async function handleMcpRequest(request, catalog) {
    if (!request || request.jsonrpc !== "2.0" || typeof request.method !== "string") {
        return error(request?.id, -32600, "Invalid Request");
    }
    if (request.id === undefined) return null;
    const modern = modernRequest(request);
    if (request.method === "server/discover") {
        return result(request.id, {
            resultType: "complete",
            supportedVersions: [MODERN_VERSION, LEGACY_VERSION],
            capabilities: { tools: {} },
            _meta: { "io.modelcontextprotocol/serverInfo": { name: "hetzer-fastmcp", version: "0.4.18" } },
            instructions: "Read-only tools expose enabled Hetzer modules and approved local service telemetry.",
            ttlMs: 300000,
            cacheScope: "private",
        });
    }
    if (request.method === "initialize") {
        const requested = request.params?.protocolVersion;
        return result(request.id, {
            protocolVersion: requested === LEGACY_VERSION ? requested : LEGACY_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "hetzer-fastmcp", version: "0.4.18" },
            instructions: "Read-only tools expose enabled Hetzer modules and approved local service telemetry.",
        });
    }
    if (request.method === "ping") return result(request.id, {});
    if (request.method === "tools/list") {
        return result(request.id, modern
            ? { resultType: "complete", tools: catalog.definitions, ttlMs: 300000, cacheScope: "private" }
            : { tools: catalog.definitions });
    }
    if (request.method === "tools/call") {
        const name = request.params?.name;
        if (typeof name !== "string") return error(request.id, -32602, "Tool name is required.");
        try {
            const value = await catalog.call(name, request.params?.arguments || {});
            const rawJson = JSON.stringify(value);
            if (rawJson === undefined) throw new Error("Tool returned a non-serializable value.");
            const sanitizedStructured = sanitizeMcpValue(JSON.parse(rawJson));
            const sanitizedText = JSON.stringify(sanitizedStructured);
            return result(request.id, {
                ...(modern ? { resultType: "complete" } : {}),
                content: [{ type: "text", text: sanitizedText }],
                structuredContent: sanitizedStructured,
                isError: false,
            });
        } catch (cause) {
            if (String(cause.message).startsWith("Unknown tool")) return error(request.id, -32602, cause.message);
            const sanitizedMessage = sanitizeStreamOutput(cause.message || "Tool execution error");
            return result(request.id, {
                ...(modern ? { resultType: "complete" } : {}),
                content: [{ type: "text", text: sanitizedMessage }],
                isError: true,
            });
        }
    }
    return error(request.id, -32601, `Method not found: ${request.method}`);
}

export function parseError() {
    return error(null, -32700, "Parse error");
}
