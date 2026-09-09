import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { loadModuleRegistry, publicModuleSummary } from "../modules/registry.mjs";
import { Grimoire, resolveMasterKey, resolveVaultPath } from "../vault/hetzer-vault.mjs";
import { isCanaryCredential, triggerCanaryAlert } from "../vault/canary.mjs";
import { scanText, redactAndVault } from "../vault/sniffer.mjs";
import { resolveSecretRefsInPayload } from "./protocol.mjs";
import { synthesizeServiceTools } from "./synthesis.mjs";

const EMPTY_SCHEMA = { type: "object", additionalProperties: false };

function readEnvironment(root) {
    const file = path.join(root, ".env");
    return fs.existsSync(file) ? parseEnv(fs.readFileSync(file, "utf8")) : {};
}

function getEnvironment(fileEnv, name, fallback = "") {
    return process.env[name] || fileEnv[name] || fallback;
}

function serviceUrl(service, fileEnv) {
    const configured = service.urlEnv ? getEnvironment(fileEnv, service.urlEnv) : "";
    if (configured && !configured.startsWith("secretRef:")) return configured.replace(/\/+$/, "");
    const port = service.portEnv ? getEnvironment(fileEnv, service.portEnv) : "";
    const selected = port || String(service.fallbackPort || "");
    return /^\d+$/.test(selected) ? `http://127.0.0.1:${selected}` : "";
}

export function createToolCatalog({ root = process.env.HETZER_ROOT || process.cwd() } = {}) {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const fileEnv = readEnvironment(root);
    const registry = loadModuleRegistry({
        builtinFile: path.resolve(here, "..", "modules", "builtin.json"),
        root,
        disabledModules: getEnvironment(fileEnv, "HETZER_DISABLED_MODULES"),
        enabledModules: getEnvironment(fileEnv, "HETZER_ENABLED_MODULES"),
    });

    let vault;
    const getVault = () => {
        if (!vault) {
            const envVault = resolveVaultPath(root);
            vault = new Grimoire({
                dbPath: envVault || path.join(root, "data", "hetzer-vault.db"),
                legacyFile: path.join(root, "data", "vault.json"),
                masterKey: resolveMasterKey({ root, envValues: fileEnv }),
            });
        }
        return vault;
    };

    const tools = [
        {
            name: "hetzer_modules_list",
            title: "Hetzer modules",
            description: "List core and outpost recipes, including dependency and enablement state.",
            inputSchema: EMPTY_SCHEMA,
            annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
            execute: async () => ({ modules: publicModuleSummary(registry), warnings: registry.warnings }),
        },
        {
            name: "hetzer_vault_has",
            title: "Check Vault Secret",
            description: "Check if a credential or secretRef exists in Grimoire Vault without exposing the raw secret.",
            inputSchema: {
                type: "object",
                properties: {
                    id: { type: "string", description: "The credential identifier to check (e.g. 'npm-token')" },
                },
                required: ["id"],
            },
            annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
            execute: async ({ id }) => {
                const targetId = String(id).replace(/^secretRef:/, "");
                if (isCanaryCredential(targetId)) {
                    triggerCanaryAlert({ id: targetId, actor: "mcp-agent", action: "mcp.hetzer_vault_has" });
                }
                const entry = getVault().find(targetId);
                return { id: targetId, exists: Boolean(entry), ref: `secretRef:${targetId}` };
            },
        },
        {
            name: "hetzer_vault_list",
            title: "List Vault Secrets",
            description: "List all configured credential IDs and descriptions in Grimoire Vault without exposing plaintext secrets.",
            inputSchema: EMPTY_SCHEMA,
            annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
            execute: async () => {
                const list = getVault().list();
                return {
                    credentials: list.map((item) => ({
                        id: item.id,
                        label: item.label,
                        authType: item.authType,
                        ref: `secretRef:${item.id}`,
                    })),
                };
            },
        },
        {
            name: "hetzer_sniffer_scan",
            title: "Scan Secrets in Text",
            description: "Inspect text for supported sensitive credential patterns and high-entropy candidates.",
            inputSchema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Text content to analyze for exposed credentials" },
                },
                required: ["text"],
            },
            annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true },
            execute: async ({ text }) => scanText(text),
        },
        {
            name: "hetzer_sniffer_redact",
            title: "Redact and Auto-Vault Secrets",
            description: "Scans text, auto-vaults any detected raw credentials into Grimoire Vault, and returns sanitized text with secretRef references.",
            inputSchema: {
                type: "object",
                properties: {
                    text: { type: "string", description: "Text content containing potential raw credentials" },
                },
                required: ["text"],
            },
            annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false },
            execute: async ({ text }) => redactAndVault(text, { root }),
        },
    ];

    const addServiceTool = (service, definition) => {
        const hasSchemaProps = Boolean(definition.inputSchema?.properties && Object.keys(definition.inputSchema.properties).length > 0);
        tools.push({
            name: definition.name,
            title: definition.title,
            description: definition.description,
            inputSchema: definition.inputSchema || EMPTY_SCHEMA,
            annotations: {
                readOnlyHint: definition.annotations?.readOnlyHint ?? !hasSchemaProps,
                destructiveHint: definition.annotations?.destructiveHint ?? false,
                idempotentHint: definition.annotations?.idempotentHint ?? !hasSchemaProps,
                openWorldHint: definition.annotations?.openWorldHint ?? true,
            },
            execute: async (args = {}) => {
                const base = serviceUrl(service, fileEnv);
                if (!base) throw new Error(`${service.label} has no configured local URL.`);
                const headers = { accept: "application/json" };
                if (service.auth) {
                    const injected = getVault().portalHeaders(service.auth.secretRef, {
                        targetId: service.auth.targetId || service.id,
                        action: service.auth.action,
                    });
                    if (injected) Object.assign(headers, injected);
                }

                let targetPath = definition.path;
                let method = definition.method || "GET";
                let body;

                if (definition.argumentMode === "json-body" && hasSchemaProps) {
                    headers["content-type"] = "application/json";
                    body = JSON.stringify(args);
                }

                if (definition.argumentMode !== "json-body" && args.path) {
                    const subPath = String(args.path).replace(/^\/+/, "");
                    targetPath = subPath.startsWith("webhook/") || subPath.startsWith("webhook-test/")
                        ? `/${subPath}`
                        : `${definition.path.replace(/\/+$/, "")}/${subPath}`;
                }
                if (definition.argumentMode !== "json-body" && args.method) {
                    method = String(args.method).toUpperCase();
                }
                if (definition.argumentMode !== "json-body" && args.headers && typeof args.headers === "object") {
                    Object.assign(headers, args.headers);
                }
                if (definition.argumentMode !== "json-body" && args.payload !== undefined) {
                    if (!args.method) method = "POST";
                    if (!headers["content-type"] && !headers["Content-Type"]) {
                        headers["content-type"] = "application/json";
                    }
                    body = typeof args.payload === "string" ? args.payload : JSON.stringify(args.payload);
                }

                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 10000);
                try {
                    const response = await fetch(new URL(targetPath, base), {
                        method,
                        headers,
                        body,
                        signal: controller.signal,
                    });
                    const contentType = response.headers.get("content-type") || "";
                    const payload = contentType.includes("application/json")
                        ? await response.json()
                        : { text: (await response.text()).slice(0, 4000) };
                    if (!response.ok) throw new Error(`${service.label} returned HTTP ${response.status}.`);
                    return { service: service.id, status: response.status, payload };
                } finally {
                    clearTimeout(timeout);
                }
            },
        });
    };

    for (const service of registry.services) {
        for (const definition of synthesizeServiceTools(service)) addServiceTool(service, definition);
    }

    tools.sort((a, b) => a.name.localeCompare(b.name));

    // Per-tool rate limiting — generous for E2E workloads; prevents tight loops only.
    const callBuckets = new Map();
    function allowToolCall(name) {
        const now = Date.now();
        let bucket = callBuckets.get(name);
        if (!bucket || now - bucket.start > 60000) {
            bucket = { start: now, count: 0 };
            callBuckets.set(name, bucket);
        }
        bucket.count += 1;
        return bucket.count <= 100;
    }

    function validateArgsAgainstSchema(toolName, args, schema) {
        if (!schema || typeof schema !== "object") return;
        const props = schema.properties;
        if (!props || typeof props !== "object") {
            if (schema.additionalProperties === false && Object.keys(args || {}).length) {
                throw new Error(`Tool '${toolName}' does not accept arguments.`);
            }
            return;
        }
        const required = Array.isArray(schema.required) ? schema.required : [];
        for (const key of required) {
            if (args[key] === undefined || args[key] === null || String(args[key]).trim() === "") {
                throw new Error(`Missing required argument '${key}'.`);
            }
        }
        for (const key of Object.keys(args || {})) {
            const value = args[key];
            // Skip optional undefined payloads (e.g. GET without payload)
            if (value === undefined) continue;
            if (!(key in props) && schema.additionalProperties === false) {
                throw new Error(`Unknown argument '${key}'.`);
            }
            const def = props[key];
            if (!def) continue;
            if (def.type === "string" && typeof value !== "string") {
                throw new Error(`Argument '${key}' must be a string.`);
            }
            if (def.type === "object" && value !== null && typeof value !== "object") {
                // payload is polymorphic: allow string JSON as well as objects/arrays
                if (key === "payload" && typeof value === "string") continue;
                throw new Error(`Argument '${key}' must be an object.`);
            }
            if (def.enum && value !== undefined) {
                const normalized = key === "method" && typeof value === "string" ? value.toUpperCase() : value;
                if (!def.enum.includes(normalized)) {
                    throw new Error(`Argument '${key}' must be one of ${def.enum.join(", ")}.`);
                }
            }
        }
    }

    return {
        definitions: tools.map(({ execute, ...definition }) => definition),
        async call(name, args = {}) {
            const tool = tools.find((candidate) => candidate.name === name);
            if (!tool) throw new Error(`Unknown tool '${name}'.`);
            if (!allowToolCall(name)) throw new Error(`Tool '${name}' rate limit exceeded (100/min).`);
            const normalizedArgs = args && typeof args === "object" ? args : {};
            validateArgsAgainstSchema(name, normalizedArgs, tool.inputSchema);
            const acceptsArgs = Boolean(tool.inputSchema?.properties && Object.keys(tool.inputSchema.properties).length > 0);
            if (!acceptsArgs && Object.keys(normalizedArgs).length) {
                throw new Error(`Tool '${name}' does not accept arguments.`);
            }
            let finalArgs = normalizedArgs;
            if (!["hetzer_vault_has", "hetzer_sniffer_scan", "hetzer_sniffer_redact"].includes(name)) {
                finalArgs = resolveSecretRefsInPayload(normalizedArgs, (id) => getVault().resolve(id));
            }
            return tool.execute(finalArgs);
        },
        close() { vault?.close(); },
    };
}
