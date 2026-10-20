#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { loadModuleRegistry } from "./service-loader.mjs";

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

export function configureMcp(root) {
    const file = path.join(root, ".mcp.json");
    const envFile = path.join(root, ".env");
    const fileEnv = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const here = path.dirname(fileURLToPath(import.meta.url));
    const registry = loadModuleRegistry({
        builtinFile: path.resolve(here, "..", "modules", "builtin.json"),
        root,
        disabledModules: environmentValue(fileEnv, "HETZER_DISABLED_MODULES"),
        enabledModules: environmentValue(fileEnv, "HETZER_ENABLED_MODULES"),
    });
    let config = {};
    if (fs.existsSync(file)) {
        const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) config = parsed;
    }
    config.mcpServers = config.mcpServers && typeof config.mcpServers === "object"
        ? config.mcpServers
        : {};
    config.mcpServers.hetzer = {
        command: "hetzer",
        args: ["mcp", "serve"],
        env: { HETZER_ROOT: root },
    };
    const managedNames = new Set(registry.modules.flatMap((module) =>
        module.services.map((service) => service.mcpServer?.name).filter(Boolean)
    ));
    const activeServers = registry.services.filter((service) => service.mcpServer);
    const activeNames = new Set(activeServers.map((service) => service.mcpServer.name));
    for (const name of managedNames) {
        if (!activeNames.has(name)) delete config.mcpServers[name];
    }
    // Hetzer up to 0.7.0 registered a placeholder "sample-mod" server that nothing listens on. Remove it only
    // when it is exactly that placeholder and no module in this workspace defines the name.
    const stale = config.mcpServers["sample-mod"];
    if (!managedNames.has("sample-mod") && stale && Object.keys(stale).length === 2
        && stale.type === "http" && stale.url === "http://127.0.0.1:8001/mcp") {
        delete config.mcpServers["sample-mod"];
    }
    for (const service of activeServers) {
        const baseUrl = serviceUrl(service, fileEnv);
        if (!baseUrl) continue;
        config.mcpServers[service.mcpServer.name] = {
            type: service.mcpServer.transport,
            url: new URL(service.mcpServer.path, `${baseUrl}/`).href,
        };
    }
    fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, "utf8");
    return file;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const index = process.argv.indexOf("--root");
        const root = path.resolve(index >= 0 ? process.argv[index + 1] : process.cwd());
        process.stdout.write(`Registered Hetzer MCP bridge in ${configureMcp(root)}\n`);
    } catch (error) {
        process.stderr.write(`Unable to configure .mcp.json: ${error.message}\n`);
        process.exitCode = 1;
    }
}
