import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { Grimoire } from "../vault/hetzer-vault.mjs";
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

test("MCP bridge redacts custom vault secrets reflected in tool results or errors", async () => {
    const customPass = "CustomSuperSecretPassword!#123";
    const leakingCatalog = {
        definitions: [{ name: "vault_tool", description: "Vault tool", inputSchema: { type: "object" } }],
        async call(name, args, requestContext) {
            requestContext.secretsToRedact = [{ id: "db-password", secret: customPass }];
            if (args.fail) throw new Error(`Connection failed with password: ${customPass}`);
            return { connected: true, reflected: `Using password: ${customPass}` };
        },
    };

    // Output reflection
    const successRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: { name: "vault_tool", arguments: {} },
    }, leakingCatalog);
    assert.equal(successRes.result.isError, false);
    assert.ok(!successRes.result.content[0].text.includes(customPass));
    assert.ok(successRes.result.content[0].text.includes("secretRef:db-password"));
    assert.equal(successRes.result.structuredContent.reflected, "Using password: secretRef:db-password");

    // Error reflection
    const failRes = await handleMcpRequest({
        jsonrpc: "2.0",
        id: 11,
        method: "tools/call",
        params: { name: "vault_tool", arguments: { fail: true } },
    }, leakingCatalog);
    assert.equal(failRes.result.isError, true);
    assert.ok(!failRes.result.content[0].text.includes(customPass));
    assert.ok(failRes.result.content[0].text.includes("secretRef:db-password"));
});

test("MCP bridge keeps custom-secret redaction request-local during concurrent calls", async () => {
    const secretA = "ConcurrentCustomSecretA!123";
    const secretB = "ConcurrentCustomSecretB!456";
    const concurrentCatalog = {
        definitions: [{ name: "race_tool", description: "Race tool", inputSchema: { type: "object" } }],
        async call(name, args, requestContext) {
            const secret = args.which === "a" ? secretA : secretB;
            const id = args.which === "a" ? "credential-a" : "credential-b";
            requestContext.secretsToRedact = [{ id, secret }];
            return new Promise((resolve) => setTimeout(() => resolve({ reflected: secret }), args.which === "a" ? 40 : 5));
        },
    };

    const [responseA, responseB] = await Promise.all([
        handleMcpRequest({
            jsonrpc: "2.0",
            id: 12,
            method: "tools/call",
            params: { name: "race_tool", arguments: { which: "a" } },
        }, concurrentCatalog),
        handleMcpRequest({
            jsonrpc: "2.0",
            id: 13,
            method: "tools/call",
            params: { name: "race_tool", arguments: { which: "b" } },
        }, concurrentCatalog),
    ]);

    assert.equal(responseA.result.structuredContent.reflected, "secretRef:credential-a");
    assert.equal(responseB.result.structuredContent.reflected, "secretRef:credential-b");
    assert.ok(!responseA.result.content[0].text.includes(secretA));
    assert.ok(!responseB.result.content[0].text.includes(secretB));
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

    // Collects resolved credentials into inventory
    const collected = [];
    resolveSecretRefsInPayload(input, resolver, collected);
    assert.equal(collected.length, 4);
    assert.equal(collected[0].id, "anthropic-key");
    assert.equal(collected[0].secret, syntheticKey);
    assert.equal(collected[1].id, "anthropic-key");
    assert.equal(collected[2].id, "db-url");
    assert.equal(collected[3].id, "anthropic-key");
});

test("expandSecretVariants generates raw, JSON, URL, and unicode representations", async () => {
    const { expandSecretVariants, sanitizeMcpValue } = await import("./protocol.mjs");
    const complexSecret = 'my"custom\\secret/token';
    const variants = expandSecretVariants([{ id: "test-cred", secret: complexSecret }]);

    assert.ok(variants.some((v) => v.secret === complexSecret));
    assert.ok(variants.some((v) => v.secret === 'my\\"custom\\\\secret/token'));
    assert.ok(variants.some((v) => v.secret === encodeURIComponent(complexSecret)));
    assert.ok(variants.some((v) => v.secret.includes("\\u0022")));

    assert.ok(variants.some((v) => v.secret === Buffer.from(complexSecret).toString("base64")));

    const echoedPayload = {
        literal: `raw: ${complexSecret}`,
        jsonEscaped: `json: ${JSON.stringify(complexSecret).slice(1, -1)}`,
        urlEscaped: `url: ${encodeURIComponent(complexSecret)}`,
        base64: Buffer.from(complexSecret).toString("base64"),
    };

    const sanitized = sanitizeMcpValue(echoedPayload, [{ id: "test-cred", secret: complexSecret }]);
    assert.doesNotMatch(sanitized.literal, /my"custom/);
    assert.match(sanitized.literal, /secretRef:test-cred/);
    assert.doesNotMatch(sanitized.jsonEscaped, /my\\"custom/);
    assert.match(sanitized.jsonEscaped, /secretRef:test-cred/);
    assert.doesNotMatch(sanitized.urlEscaped, /my%22custom/);
    assert.match(sanitized.urlEscaped, /secretRef:test-cred/);
    assert.doesNotMatch(sanitized.base64, new RegExp(Buffer.from(complexSecret).toString("base64")));
    assert.match(sanitized.base64, /secretRef:test-cred/);
});

test("synthesized service tools enforce traversal defense, header safety, credential scoping, and clean state", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-cat-test-"));
    const masterKey = "12345678901234567890123456789012";
    try {
        fs.mkdirSync(path.join(tempDir, "data"), { recursive: true });
        fs.mkdirSync(path.join(tempDir, "modules", "test-sec"), { recursive: true });

        fs.writeFileSync(path.join(tempDir, ".env"), [
            `HETZER_GRIMOIRE_KEY=${masterKey}`,
            "TEST_SEC_URL=http://127.0.0.1:9876",
        ].join("\n"));

        fs.writeFileSync(path.join(tempDir, "modules", "test-sec", "module.json"), JSON.stringify({
            schemaVersion: 1,
            id: "test-sec",
            label: "Test Security Module",
            version: "1",
            profile: "test",
            lifecycle: "external",
            surface: "headless",
            defaultEnabled: true,
            requires: ["core"],
            services: [{
                id: "test-sec",
                label: "Test Sec Service",
                surface: "headless",
                lifecycle: "external",
                urlEnv: "TEST_SEC_URL",
                auth: {
                    secretRef: "secretRef:portal-auth-cred",
                    targetId: "test-sec",
                    action: "mcp.tools.call",
                },
                mcpTools: [{
                    name: "test_sec_tool",
                    title: "Test Security Tool",
                    description: "Tool for security testing",
                    path: "/api/v1/resource",
                    method: "POST",
                    argumentMode: "legacy",
                    inputSchema: {
                        type: "object",
                        properties: {
                            path: { type: "string" },
                            headers: { type: "object" },
                            payload: { type: "object" },
                        },
                    },
                }],
            }],
        }, null, 2));

        const vault = new Grimoire({
            dbPath: path.join(tempDir, "data", "hetzer-vault.db"),
            masterKey,
        });
        vault.create({
            id: "portal-auth-cred",
            projectId: "test-sec",
            authType: "bearer",
            secret: "real-portal-bearer-secret",
            allowedActions: ["mcp.tools.call"],
        });
        vault.create({
            id: "permitted-tool-cred",
            projectId: "test-sec",
            authType: "api-key",
            secret: "permitted-inner-secret-123",
            allowedActions: ["mcp.tools/call"],
        });
        vault.create({
            id: "forbidden-tool-cred",
            projectId: "other-unauthorized-target",
            authType: "api-key",
            secret: "forbidden-secret-456",
            allowedActions: ["mcp.tools/call"],
        });
        vault.close();

        const { createToolCatalog } = await import("./catalog.mjs");
        const testCatalog = createToolCatalog({ root: tempDir });

        // 1. Finding 1: Route traversal bypasses (backslash, percent-encoded, double-encoded)
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "../../rest/admin" }),
            /Path traversal outside route prefix is forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "..\\..\\rest\\admin" }),
            /Path traversal outside route prefix is forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "%2e%2e/%2e%2e/rest/admin" }),
            /Path traversal outside route prefix is forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "%2e%2e%2f%2e%2e%2frest%2fadmin" }),
            /Encoded delimiters are forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "%252e%252e/%252e%252e/rest/admin" }),
            /Path traversal outside route prefix is forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "%2525252e%2525252e/rest" }),
            /Path traversal outside route prefix is forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "%2525252525252e%2525252525252e/rest" }),
            /Excessive percent-encoding layers/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "subpath%25252ftest" }),
            /Nested encoded delimiters are forbidden/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "valid\0evil" }),
            /Unsafe characters in path/
        );
        await assert.rejects(
            () => testCatalog.call("test_sec_tool", { path: "valid?query=1" }),
            /Unsafe characters in path/
        );

        // 2. Finding 2: Auth header overwrite ambiguity & proxy-* header stripping
        const originalFetch = globalThis.fetch;
        let capturedRequest = null;
        globalThis.fetch = async (url, options) => {
            capturedRequest = { url: String(url), options };
            return new Response(JSON.stringify({ ok: true }), {
                status: 200,
                headers: { "content-type": "application/json" },
            });
        };

        try {
            await testCatalog.call("test_sec_tool", {
                path: "subpath",
                headers: {
                    "Authorization": "Bearer attacker-injected",
                    "authorization": "Bearer attacker-injected-lower",
                    "x-api-key": "evil-key",
                    "X-Api-Key": "evil-key-upper",
                    "Proxy-Authorization": "evil-proxy",
                    "proxy-custom-header": "leak",
                    "X-Safe-Header": "legit-value",
                },
            });

            const sentHeaders = capturedRequest.options.headers;
            assert.equal(sentHeaders["authorization"], "Bearer real-portal-bearer-secret");
            assert.equal(sentHeaders["x-api-key"], undefined);
            assert.equal(sentHeaders["proxy-authorization"], undefined);
            assert.equal(sentHeaders["proxy-custom-header"], undefined);
            assert.equal(sentHeaders["x-safe-header"], "legit-value");

            // 3. Finding 3: MCP credential scoping enforcement
            await assert.rejects(
                () => testCatalog.call("test_sec_tool", {
                    payload: { token: "secretRef:forbidden-tool-cred" },
                }),
                /Credential 'secretRef:forbidden-tool-cred' \(target 'other-unauthorized-target'\) is not permitted for service 'test-sec'/
            );

            // Permitted credential succeeds
            const okRes = await testCatalog.call("test_sec_tool", {
                payload: { token: "secretRef:permitted-tool-cred" },
            });
            assert.equal(okRes.status, 200);
            assert.ok(capturedRequest.options.body.includes("permitted-inner-secret-123"));

            // 4. Finding 5: Raw secrets are not retained on catalog object state
            assert.equal(testCatalog.lastResolvedSecrets, undefined);
        } finally {
            globalThis.fetch = originalFetch;
            testCatalog.close();
        }
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("handleMcpRequest rethrows ERR_CANARY_TRIPWIRE_TRIGGERED for tools/call", async () => {
    const mockCatalog = {
        call: async () => {
            const err = new Error("Canary honey-token accessed!");
            err.code = "ERR_CANARY_TRIPWIRE_TRIGGERED";
            err.exitCode = 43;
            throw err;
        },
        close: () => {},
    };

    await assert.rejects(
        () => handleMcpRequest({
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: { name: "test_tool", arguments: {} },
        }, mockCatalog),
        (err) => err.code === "ERR_CANARY_TRIPWIRE_TRIGGERED" && err.exitCode === 43
    );
});

test("catalog.close and Grimoire.close are idempotent and do not throw on double close", async () => {
    const { createToolCatalog } = await import("./catalog.mjs");
    const catalog = createToolCatalog();
    assert.doesNotThrow(() => {
        catalog.close();
        catalog.close();
    });
});
