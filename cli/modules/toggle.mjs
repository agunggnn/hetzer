#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { loadModuleRegistry } from "./registry.mjs";

function csv(value) {
    return new Set(String(value || "").split(",").map((item) => item.trim()).filter(Boolean));
}

function setEnvValue(text, name, value) {
    const line = `${name}=${value}`;
    const pattern = new RegExp(`^${name}=.*$`, "m");
    return pattern.test(text) ? text.replace(pattern, line) : `${text.trimEnd()}\n${line}\n`;
}

export const MODULE_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function assertValidModuleId(id) {
    if (typeof id !== "string" || !MODULE_ID_PATTERN.test(id)) {
        const err = new Error(`Invalid module ID: ${JSON.stringify(id)}. Must be lowercase alphanumeric with hyphens.`);
        err.code = "ERR_INVALID_MODULE_ID";
        throw err;
    }
}

export function setModuleEnabled({ root, envFile, moduleId, enabled, builtinFile }) {
    assertValidModuleId(moduleId);
    if (moduleId === "core" && !enabled) throw new Error("Hetzer core cannot be removed.");
    let text = "";
    if (envFile && fs.existsSync(envFile)) {
        text = fs.readFileSync(envFile, "utf8");
    } else if (envFile) {
        fs.mkdirSync(path.dirname(envFile), { recursive: true });
    }
    const values = parseEnv(text);
    const registry = loadModuleRegistry({ builtinFile, root, enabledModules: moduleId });
    if (!registry.modules.some((module) => module.id === moduleId)) {
        throw new Error(`Module '${moduleId}' is not installed under modules/${moduleId}/.`);
    }
    const enabledModules = csv(values.HETZER_ENABLED_MODULES);
    const disabledModules = csv(values.HETZER_DISABLED_MODULES);
    if (enabled) {
        disabledModules.delete(moduleId);
        enabledModules.add(moduleId);
    } else {
        enabledModules.delete(moduleId);
        disabledModules.add(moduleId);
    }
    text = setEnvValue(text, "HETZER_ENABLED_MODULES", [...enabledModules].sort().join(","));
    text = setEnvValue(text, "HETZER_DISABLED_MODULES", [...disabledModules].sort().join(","));
    fs.writeFileSync(envFile, text, "utf8");
    try { fs.chmodSync(envFile, 0o600); } catch { /* Windows */ }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const [action, moduleId] = process.argv.slice(2);
        if (!["install", "remove"].includes(action) || !moduleId) {
            throw new Error("Usage: toggle <install|remove> <module>");
        }
        const here = path.dirname(fileURLToPath(import.meta.url));
        const root = path.resolve(process.env.HETZER_ROOT || process.cwd());
        const envFile = path.resolve(process.env.HETZER_ENV_FILE || path.join(root, ".env"));
        setModuleEnabled({
            root,
            envFile,
            moduleId,
            enabled: action === "install",
            builtinFile: path.join(here, "builtin.json"),
        });
        process.stdout.write(`Module '${moduleId}' ${action === "install" ? "installed" : "removed from the active roster"}.\n`);
    } catch (error) {
        process.stderr.write(`${error.message}\n`);
        process.exitCode = 1;
    }
}
