import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    callMcpTool,
    classifyToolNature,
    listMcpTools,
    runMcpToolCommand,
} from "./call.mjs";

test("classifyToolNature classifies tools into OFFLINE, HYBRID, LLM REASONING, and NATIVE", () => {
    assert.equal(classifyToolNature("forget_memory").tag, "OFFLINE");
    assert.equal(classifyToolNature("delete_data").tag, "OFFLINE");
    assert.equal(classifyToolNature("search_memory").tag, "HYBRID");
    assert.equal(classifyToolNature("recall").tag, "HYBRID");
    assert.equal(classifyToolNature("remember_fact").tag, "LLM REASONING");
    assert.equal(classifyToolNature("custom_tool", "Uses LLM to summarize").tag, "LLM REASONING");
    assert.equal(classifyToolNature("ping").tag, "NATIVE");
});

test("listMcpTools retrieves and classifies tools from MCP service", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-call-test-"));
    try {
        fs.writeFileSync(path.join(root, ".env"), "COGNEE_MCP_PORT=8001\n");

        const mockFetch = async (url, opts) => {
            const body = JSON.parse(opts.body);
            assert.equal(body.method, "tools/list");
            return {
                ok: true,
                json: async () => ({
                    result: {
                        tools: [
                            { name: "forget_memory", description: "Delete local graph node" },
                            { name: "search", description: "Search memory vectors" },
                            { name: "remember", description: "Ingest with LLM reasoning" },
                        ],
                    },
                }),
            };
        };

        const result = await listMcpTools({
            root,
            targetService: "cognee",
            fetchFn: mockFetch,
        });

        assert.equal(result.ok, true);
        assert.equal(result.tools.length, 3);
        assert.equal(result.tools[0].classification.tag, "OFFLINE");
        assert.equal(result.tools[1].classification.tag, "HYBRID");
        assert.equal(result.tools[2].classification.tag, "LLM REASONING");
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("callMcpTool invokes tool with JSON-RPC payload and handles response", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-call-test-"));
    try {
        fs.writeFileSync(path.join(root, ".env"), "COGNEE_MCP_PORT=8001\n");

        const mockFetch = async (url, opts) => {
            const body = JSON.parse(opts.body);
            assert.equal(body.method, "tools/call");
            assert.equal(body.params.name, "search");
            assert.deepEqual(body.params.arguments, { query: "test query" });
            return {
                ok: true,
                json: async () => ({
                    result: {
                        content: [{ type: "text", text: "Found 1 memory record." }],
                    },
                }),
            };
        };

        const result = await callMcpTool({
            root,
            targetService: "cognee",
            toolName: "search",
            args: { query: "test query" },
            fetchFn: mockFetch,
        });

        assert.equal(result.ok, true);
        assert.equal(result.isError, false);
        assert.equal(result.content, "Found 1 memory record.");
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("runMcpToolCommand executes tool and writes output to stream", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-call-test-"));
    try {
        fs.writeFileSync(path.join(root, ".env"), "COGNEE_MCP_PORT=8001\n");

        let output = "";
        const mockOut = { write: (c) => { output += c; } };

        const mockFetch = async () => ({
            ok: true,
            json: async () => ({
                result: {
                    content: [{ type: "text", text: "Operation successful!" }],
                },
            }),
        });

        const ok = await runMcpToolCommand({
            root,
            targetService: "cognee",
            toolName: "ping",
            argsJson: "{}",
            out: mockOut,
            fetchFn: mockFetch,
        });

        assert.equal(ok, true);
        assert.match(output, /MCP TOOL EXECUTION RESULT: ping/);
        assert.match(output, /Operation successful!/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("callMcpTool resolves secretRef in arguments and sanitizes sensitive responses", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-mcp-call-vault-"));
    const dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(path.join(root, ".env"), `COGNEE_MCP_PORT=8001\nHETZER_GRIMOIRE_KEY=${masterKey}\n`);

    const rawSecret = ["sk-ant-", "api03-secret-value-token-998877"].join("");
    const leakedReturnedSecret = ["ghp", "_", "123456789012345678901234567890123456"].join("");

    const GrimoireModule = await import("../vault/hetzer-vault.mjs");
    const vault = new GrimoireModule.Grimoire({
        dbPath: path.join(dataDir, "hetzer-vault.db"),
        masterKey,
    });
    vault.create({ id: "my-service-key", secret: rawSecret, projectId: "test-service" });
    vault.close();

    try {
        let sentArguments = null;
        const mockFetch = async (url, opts) => {
            const body = JSON.parse(opts.body);
            sentArguments = body.params.arguments;
            return {
                ok: true,
                json: async () => ({
                    result: {
                        content: [{ type: "text", text: `Success: connected with key ${leakedReturnedSecret}` }],
                    },
                }),
            };
        };

        const result = await callMcpTool({
            root,
            targetService: "cognee",
            toolName: "search",
            args: { apiKey: "secretRef:my-service-key" },
            fetchFn: mockFetch,
        });

        assert.equal(result.ok, true);
        assert.equal(sentArguments.apiKey, rawSecret);
        assert.ok(!result.content.includes(leakedReturnedSecret));
        assert.ok(result.content.includes("secretRef:github-token"));
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});