import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { configureMcp } from "./configure.mjs";

test("MCP configure preserves other servers and registers Hetzer", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-config-"));
    fs.writeFileSync(path.join(root, ".mcp.json"), JSON.stringify({ mcpServers: { existing: { command: "existing" } } }));
    configureMcp(root);
    const config = JSON.parse(fs.readFileSync(path.join(root, ".mcp.json"), "utf8"));
    assert.equal(config.mcpServers.existing.command, "existing");
    assert.deepEqual(config.mcpServers.hetzer.args, ["mcp", "serve"]);
    assert.equal(config.mcpServers.hetzer.env.HETZER_ROOT, root);
    fs.rmSync(root, { recursive: true, force: true });
});

test("MCP configure registers enabled module HTTP servers", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-module-"));
    const recipe = path.join(root, "modules", "sample-mod");
    fs.mkdirSync(recipe, { recursive: true });
    fs.writeFileSync(path.join(recipe, "docker-compose.sample-mod.yml"), "services: {}\n");
    fs.writeFileSync(path.join(recipe, "module.json"), JSON.stringify({
        id: "sample-mod",
        label: "Sample Module",
        lifecycle: "compose",
        surface: "headless",
        defaultEnabled: false,
        requires: ["core"],
        composeFiles: ["docker-compose.sample-mod.yml"],
        services: [{
            id: "sample-mod",
            label: "Sample Service",
            portEnv: "SAMPLE_MOD_MCP_PORT",
            fallbackPort: 8001,
            mcpServer: { name: "sample-mod", transport: "http", path: "/mcp" },
        }],
    }));
    fs.writeFileSync(path.join(root, ".env"), "HETZER_ENABLED_MODULES=sample-mod\nSAMPLE_MOD_MCP_PORT=8111\n");

    configureMcp(root);
    const config = JSON.parse(fs.readFileSync(path.join(root, ".mcp.json"), "utf8"));
    assert.deepEqual(config.mcpServers["sample-mod"], {
        type: "http",
        url: "http://127.0.0.1:8111/mcp",
    });
    fs.rmSync(root, { recursive: true, force: true });
});
