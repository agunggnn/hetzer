import assert from "node:assert/strict";
import test from "node:test";

import {
    analyzeContainerFailure,
    analyzeModuleSource,
    askReasoner,
    checkReasonerStatus,
} from "./reasoner.mjs";

test("checkReasonerStatus detects running 9Router server", async () => {
    const mockFetch = async (url) => {
        if (url.includes("/api/health")) {
            return { ok: true, status: 200 };
        }
        return { ok: false, status: 404 };
    };

    const status = await checkReasonerStatus({
        root: ".",
        fetchFn: mockFetch,
    });
    assert.equal(status.available, true);
    assert.equal(status.status, 200);
});

test("askReasoner calls chat completions endpoint and returns content", async () => {
    const mockFetch = async (url, options) => {
        const body = JSON.parse(options.body);
        assert.equal(body.messages[1].content, "ping");
        return {
            ok: true,
            status: 200,
            json: async () => ({
                model: "openai/gpt-4o-mini",
                choices: [{ message: { content: "pong" } }],
            }),
        };
    };

    const res = await askReasoner({
        prompt: "ping",
        root: ".",
        fetchFn: mockFetch,
    });
    assert.equal(res.ok, true);
    assert.equal(res.content, "pong");
});

test("analyzeContainerFailure uses static heuristics fallback when 9Router offline", async () => {
    const mockOfflineFetch = async () => {
        throw new Error("ECONNREFUSED");
    };

    const res = await analyzeContainerFailure({
        serviceId: "sample-srv",
        logs: "PermissionError: [Errno 13] Permission denied: '/sample-data/system'",
        composeContent: "volumes: - sample_data:/sample-data",
        root: ".",
        fetchFn: mockOfflineFetch,
    });

    assert.equal(res.ok, true);
    assert.equal(res.source, "static-heuristics");
    assert.match(res.cause, /Permission Denied/);
    assert.match(res.suggestion, /volume mount point/);
});

test("analyzeContainerFailure parses AI JSON response from 9Router", async () => {
    const mockAiFetch = async (url) => {
        if (url.includes("/api/health")) {
            return { ok: true, status: 200 };
        }
        return {
            ok: true,
            status: 200,
            json: async () => ({
                choices: [{
                    message: {
                        content: JSON.stringify({
                            cause: "Container kehabisan memory RAM.",
                            suggestion: "Naikkan nilai mem_limit di compose menjadi 4g.",
                        }),
                    },
                }],
            }),
        };
    };

    const res = await analyzeContainerFailure({
        serviceId: "test-srv",
        logs: "Killed (OOM)",
        composeContent: "mem_limit: 100m",
        root: ".",
        fetchFn: mockAiFetch,
    });

    assert.equal(res.ok, true);
    assert.equal(res.source, "9router-ai");
    assert.match(res.cause, /memory/);
});

test("analyzeModuleSource extracts specs via static heuristics when offline", async () => {
    const mockOfflineFetch = async () => {
        throw new Error("ECONNREFUSED");
    };

    const sampleReadme = `
# My Memory Service
A local vector and graph service.
EXPOSE 8085
Provides an MCP endpoint for AI agents.
Required environment variables:
- MEMORY_API_KEY
- MEMORY_ENDPOINT
Runs as non-root user (UID 1000:1000).
    `;

    const res = await analyzeModuleSource({
        sourceContent: sampleReadme,
        sourceUrl: "https://github.com/example/my-memory",
        root: ".",
        fetchFn: mockOfflineFetch,
    });

    assert.equal(res.ok, true);
    assert.equal(res.source, "static-heuristics");
    assert.equal(res.port, 8085);
    assert.equal(res.mcp, true);
    assert.equal(res.nonRootUid, 1000);
    assert.equal(res.sourceUrl, "https://github.com/example/my-memory");
    assert.ok(res.envVars.some((e) => e.name === "MEMORY_API_KEY" && e.isSecret));
});

test("analyzeModuleSource parses AI extracted JSON specs when 9Router online", async () => {
    const mockAiFetch = async (url) => {
        if (url.includes("/api/health")) {
            return { ok: true, status: 200 };
        }
        return {
            ok: true,
            status: 200,
            json: async () => ({
                choices: [{
                    message: {
                        content: JSON.stringify({
                            label: "Mem0 Engine",
                            port: 8888,
                            webUi: true,
                            mcp: true,
                            mcpPath: "/mcp",
                            description: "Engine memori cerdas untuk agen AI.",
                            envVars: [{ name: "MEM0_API_KEY", isSecret: true, description: "Key" }],
                            volumes: [{ containerPath: "/mem0/data", hostVolume: "data" }],
                            healthPath: "/healthz",
                            nonRootUid: null,
                        }),
                    },
                }],
            }),
        };
    };

    const res = await analyzeModuleSource({
        sourceContent: "Docs for Mem0",
        sourceUrl: "https://github.com/mem0ai/mem0",
        root: ".",
        fetchFn: mockAiFetch,
    });

    assert.equal(res.ok, true);
    assert.equal(res.source, "9router-ai");
    assert.equal(res.label, "Mem0 Engine");
    assert.equal(res.port, 8888);
    assert.equal(res.webUi, true);
    assert.equal(res.mcp, true);
    assert.equal(res.healthPath, "/healthz");
});
