import assert from "node:assert/strict";
import test from "node:test";

import { handleMcpRequest, resolveSecretRefsInPayload } from "./protocol.mjs";

const catalog = {
    definitions: [{ name: "hetzer_test", description: "Test", inputSchema: { type: "object" } }],
    async call(name) {
        if (name !== "hetzer_test") throw new Error(`Unknown tool '${name}'.`);
        return { ok: true };
    },
};

test("MCP bridge supports stateless discovery and tool calls", async () => {
    const discover = await handleMcpRequest({ jsonrpc: "2.0", id: 1, method: "server/discover", params: {} }, catalog);
    assert.ok(discover.result.supportedVersions.length > 0);
    const called = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "hetzer_test", arguments: {} },
    }, catalog);
    assert.deepEqual(called.result.structuredContent, { ok: true });
});

test("MCP bridge automatically sanitizes raw credentials in tool outputs", async () => {
    const sensitiveGhToken = ["ghp", "_", "123456789012345678901234567890123456"].join("");
    const leakingCatalog = {
        definitions: [{ name: "leak_tool", description: "Leaky tool", inputSchema: { type: "object" } }],
        async call(name) {
            return { status: "error", token: sensitiveGhToken, note: "sensitive connection" };
        },
    };
    const response = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "leak_tool", arguments: {} },
    }, leakingCatalog);

    assert.equal(response.result.isError, false);
    assert.ok(response.result.content[0].text.includes("secretRef:github-token"));
    assert.ok(!response.result.content[0].text.includes(sensitiveGhToken));
    assert.equal(response.result.structuredContent.token, "secretRef:github-token");
});

test("MCP bridge sanitizes structured values without parsing redacted JSON text", async () => {
    const databaseUrl = ["postgres", "://", "user", ":", "pass", "@", "host", "/db"].join("");
    const leakingCatalog = {
        definitions: [{ name: "database_tool", description: "Database tool", inputSchema: { type: "object" } }],
        async call() {
            return { payload: databaseUrl, adjacent: "preserved" };
        },
    };
    const response = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 4,
        method: "tools/call",
        params: { name: "database_tool", arguments: {} },
    }, leakingCatalog);

    assert.equal(response.result.structuredContent.payload, "secretRef:database-url");
    assert.equal(response.result.structuredContent.adjacent, "preserved");
    assert.equal(response.result.content[0].text.includes(databaseUrl), false);
});

test("resolveSecretRefsInPayload resolves exact, inline, and nested secretRef references", () => {
    const syntheticKey = ["sk-ant-", "api03-sample-mcp-key-12345"].join("");
    const syntheticDb = "postgresql://user:pass@localhost:5432/mcp";
    const resolver = (id) => {
        if (id === "anthropic-key") return syntheticKey;
        if (id === "db-url") return syntheticDb;
        return null;
    };

    const input = {
        exact: "secretRef:anthropic-key",
        inlineHeader: "Bearer secretRef:anthropic-key",
        nested: {
            database: "secretRef:db-url",
            plain: "normal-value",
            list: ["item1", "secretRef:anthropic-key"],
        },
    };

    const resolved = resolveSecretRefsInPayload(input, resolver);
    assert.equal(resolved.exact, syntheticKey);
    assert.equal(resolved.inlineHeader, `Bearer ${syntheticKey}`);
    assert.equal(resolved.nested.database, syntheticDb);
    assert.equal(resolved.nested.plain, "normal-value");
    assert.equal(resolved.nested.list[1], syntheticKey);

    // Throws on missing credential
    assert.throws(
        () => resolveSecretRefsInPayload("secretRef:non-existent", resolver),
        /not found in Grimoire Vault/
    );

    // Canary tripwire triggered on decoy references
    assert.throws(
        () => resolveSecretRefsInPayload("secretRef:canary-token", resolver),
        (err) => err.code === "ERR_CANARY_TRIPWIRE_TRIGGERED" && err.exitCode === 43
    );
});
