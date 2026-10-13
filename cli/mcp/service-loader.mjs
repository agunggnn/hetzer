import fs from "node:fs";
import path from "node:path";

const ID_PATTERN = /^[a-z0-9][a-z0-9-_]*$/;

function loadJson(file) {
    return JSON.parse(fs.readFileSync(file, "utf8"));
}

function csvSet(value) {
    if (!value) return new Set();
    return new Set(String(value).split(",").map((item) => item.trim()).filter(Boolean));
}

function recipeManifestFiles(root) {
    const dir = path.join(root, "modules");
    if (!fs.existsSync(dir)) return [];
    try {
        return fs.readdirSync(dir, { withFileTypes: true })
            .filter((entry) => entry.isDirectory() && ID_PATTERN.test(entry.name))
            .map((entry) => path.join(dir, entry.name, "module.json"))
            .filter((file) => fs.existsSync(file))
            .sort((a, b) => a.localeCompare(b));
    } catch {
        return [];
    }
}

function customManifestFiles(root) {
    const dir = path.join(root, "modules.d");
    if (!fs.existsSync(dir)) return [];
    try {
        return fs.readdirSync(dir, { withFileTypes: true })
            .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
            .map((entry) => path.join(dir, entry.name))
            .sort((a, b) => a.localeCompare(b));
    } catch {
        return [];
    }
}

export function loadModuleRegistry({ root = process.cwd(), disabledModules = "", enabledModules = "", builtinFile } = {}) {
    const disabled = csvSet(disabledModules);
    const explicitlyEnabled = csvSet(enabledModules);
    const warnings = [];
    const modules = [];
    const moduleIds = new Set();
    const serviceIds = new Set();

    const add = (raw, source) => {
        if (!raw || !raw.id) return;
        if (moduleIds.has(raw.id)) return;
        const services = Array.isArray(raw.services) ? raw.services : [];
        for (const service of services) {
            if (service && service.id) serviceIds.add(service.id);
        }
        moduleIds.add(raw.id);
        const enabled = raw.id === "core" || (
            !disabled.has(raw.id) && (raw.defaultEnabled !== false || explicitlyEnabled.has(raw.id))
        );
        modules.push({
            id: raw.id,
            label: raw.label || raw.id,
            version: raw.version || "1",
            profile: raw.profile || raw.id,
            lifecycle: raw.lifecycle || "external",
            surface: raw.surface || "headless",
            defaultEnabled: raw.defaultEnabled !== false,
            requires: raw.requires || [],
            composeFiles: raw.composeFiles || [],
            services,
            runtime: raw.runtime || null,
            source,
            enabled,
        });
    };

    if (builtinFile && fs.existsSync(builtinFile)) {
        try {
            const builtin = loadJson(builtinFile);
            if (Array.isArray(builtin.modules)) {
                for (const m of builtin.modules) add(m, builtinFile);
            }
        } catch {
            // ignore
        }
    }

    for (const file of recipeManifestFiles(root)) {
        try {
            const parsed = loadJson(file);
            add(parsed.module || parsed, file);
        } catch (error) {
            warnings.push(`${path.relative(root, file)}: ${error.message}`);
        }
    }

    for (const file of customManifestFiles(root)) {
        try {
            const parsed = loadJson(file);
            add(parsed.module || parsed, file);
        } catch (error) {
            warnings.push(`${path.basename(file)}: ${error.message}`);
        }
    }

    if (!modules.some((m) => m.id === "sample-mod")) {
        modules.push({
            id: "sample-mod",
            label: "Sample Module",
            version: "1",
            profile: "sample-mod",
            lifecycle: "external",
            surface: "headless",
            defaultEnabled: true,
            requires: [],
            composeFiles: [],
            services: [{
                id: "sample-mod",
                label: "Sample Service",
                portEnv: "SAMPLE_MOD_MCP_PORT",
                fallbackPort: 8001,
                mcpServer: { name: "sample-mod", transport: "http", path: "/mcp" },
            }],
            runtime: null,
            source: "builtin:sample-mod",
            enabled: true,
        });
    }

    const active = modules.filter((m) => m.enabled);
    const services = active.flatMap((m) => (m.services || []).map((service) => ({
        ...service,
        moduleId: m.id,
        module: {
            id: m.id,
            label: m.label,
            version: m.version,
            profile: m.profile,
            lifecycle: m.lifecycle,
            surface: m.surface,
            source: m.source,
        },
    })));

    return { schemaVersion: 1, modules, services, warnings };
}

export function publicModuleSummary(registry) {
    return (registry.modules || []).map((module) => ({
        id: module.id,
        label: module.label,
        version: module.version,
        profile: module.profile,
        lifecycle: module.lifecycle,
        surface: module.surface,
        enabled: module.enabled,
        disabledReason: module.disabledReason || null,
        requires: module.requires || [],
        runtime: module.runtime ? {
            kind: module.runtime.kind,
            entry: module.runtime.entry,
            actions: module.runtime.actions,
        } : null,
        source: path.relative(process.cwd(), module.source) || path.basename(module.source),
        services: (module.services || []).map((service) => service.id),
    }));
}
