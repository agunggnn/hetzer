import assert from "node:assert/strict";
import test from "node:test";

import { verifyModuleDeployment } from "./verifier.mjs";

test("verifyModuleDeployment handles running container without explicit healthcheck", async () => {
    let output = "";
    const mockOut = { write: (c) => { output += c; } };
    const mockExec = (cmd, args) => {
        if (args.includes("inspect")) {
            return {
                status: 0,
                stdout: JSON.stringify([{ State: { Running: true, Status: "running", ExitCode: 0 } }]),
            };
        }
        if (args.includes("logs")) {
            return { status: 0, stdout: "Server running at http://0.0.0.0:8000\n" };
        }
        return { status: 0 };
    };

    const res = await verifyModuleDeployment({
        serviceId: "test-srv",
        exec: mockExec,
        out: mockOut,
        timeoutMs: 50,
        pollIntervalMs: 10,
    });

    assert.equal(res.ok, true);
    assert.match(output, /is running stably with status RUNNING/);
});

test("verifyModuleDeployment polls until Docker healthcheck reaches healthy", async () => {
    let output = "";
    const mockOut = { write: (c) => { output += c; } };
    let callCount = 0;
    const mockExec = (cmd, args) => {
        if (args.includes("inspect")) {
            callCount++;
            const status = callCount === 1 ? "starting" : "healthy";
            return {
                status: 0,
                stdout: JSON.stringify([{
                    State: {
                        Running: true,
                        Status: "running",
                        ExitCode: 0,
                        Health: { Status: status },
                    },
                }]),
            };
        }
        return { status: 0, stdout: "" };
    };

    const res = await verifyModuleDeployment({
        serviceId: "sample-mcp",
        exec: mockExec,
        out: mockOut,
        timeoutMs: 500,
        pollIntervalMs: 10,
    });

    assert.equal(res.ok, true);
    assert.equal(res.healthStatus, "healthy");
    assert.match(output, /HEALTHY/);
});

test("verifyModuleDeployment performs HTTP smoketest when endpointUrl provided", async () => {
    let output = "";
    const mockOut = { write: (c) => { output += c; } };
    const mockExec = (cmd, args) => {
        if (args.includes("inspect")) {
            return {
                status: 0,
                stdout: JSON.stringify([{ State: { Running: true, Status: "running", ExitCode: 0 } }]),
            };
        }
        return { status: 0, stdout: "" };
    };

    const mockFetch = async () => ({
        ok: true,
        status: 200,
    });

    const res = await verifyModuleDeployment({
        serviceId: "sample-mcp",
        endpointUrl: "http://127.0.0.1:8001/mcp",
        exec: mockExec,
        out: mockOut,
        fetchFn: mockFetch,
        timeoutMs: 500,
        pollIntervalMs: 10,
    });

    assert.equal(res.ok, true);
    assert.equal(res.smoketest, true);
    assert.match(output, /Smoketest for HTTP endpoint/);
});

test("verifyModuleDeployment detects failure and provides diagnosis", async () => {
    let output = "";
    const mockOut = { write: (c) => { output += c; } };
    const mockExec = (cmd, args) => {
        if (args.includes("inspect")) {
            return {
                status: 0,
                stdout: JSON.stringify([{ State: { Running: false, Status: "exited", ExitCode: 13 } }]),
            };
        }
        if (args.includes("logs")) {
            return { status: 0, stderr: "PermissionError: [Errno 13] Permission denied: '/data'\n" };
        }
        return { status: 0 };
    };

    const res = await verifyModuleDeployment({
        serviceId: "sample-mcp",
        exec: mockExec,
        out: mockOut,
        timeoutMs: 10,
    });

    assert.equal(res.ok, false);
    assert.match(output, /stopped abnormally/);
    assert.match(output, /Problem Analysis/);
});
