import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadModuleRegistry, publicModuleSummary } from "./registry.mjs";

const builtinFile = path.resolve("cli", "modules", "builtin.json");

test("public registry contains built-in core and 9router", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-reg-empty-"));
    try {
        const registry = loadModuleRegistry({ builtinFile, root: tempDir });
        assert.deepEqual(publicModuleSummary(registry).map((module) => module.id), ["core", "9router"]);
        assert.equal(registry.services.find((service) => service.id === "9router").surface, "iframe");
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("registry loads and validates dynamic module with HTTP MCP endpoint when enabled", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-reg-mcp-"));
    try {
        const modDir = path.join(tempDir, "modules", "custom-mcp");
        fs.mkdirSync(modDir, { recursive: true });
        fs.writeFileSync(path.join(modDir, "module.json"), JSON.stringify({
            schemaVersion: 1,
            id: "custom-mcp",
            label: "Custom MCP Service",
            version: "1",
            profile: "custom-mcp",
            lifecycle: "compose",
            surface: "headless",
            requires: ["core"],
            composeFiles: ["docker-compose.custom-mcp.yml"],
            services: [{
                id: "custom-mcp",
                label: "Custom MCP",
                composeService: "custom-mcp",
                profile: "custom-mcp",
                mcpServer: { name: "custom-mcp", transport: "http", path: "/mcp" },
            }],
        }, null, 2));
        fs.writeFileSync(path.join(modDir, "docker-compose.custom-mcp.yml"), "services:\n  custom-mcp:\n    image: test\n");

        const registry = loadModuleRegistry({ builtinFile, root: tempDir, enabledModules: "custom-mcp" });
        const service = registry.services.find((entry) => entry.id === "custom-mcp");
        assert.deepEqual(service.mcpServer, { name: "custom-mcp", transport: "http", path: "/mcp" });
        assert.ok(registry.composeFiles.some((f) => f.includes("docker-compose.custom-mcp.yml")));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
