import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { composeInvocation, runComposeChild } from "./compose-runner.mjs";

const root = path.resolve(".");
const envFile = path.join(root, ".env.example");

test("core Compose invocation excludes the disabled Cognee recipe", () => {
    const invocation = composeInvocation({ root, envFile, composeArgs: ["--profile", "core", "config"] });
    const serialized = invocation.args.join(" ");
    assert.match(serialized, /docker-compose\.yml/);
    assert.doesNotMatch(serialized, /docker-compose\.cognee\.yml/);
    assert.ok(invocation.secretNames.includes("NINE_ROUTER_JWT_SECRET"));
    assert.ok(!invocation.secretNames.includes("COGNEE_LLM_API_KEY"));
});

test("Cognee profile includes only its declared public recipe", () => {
    const invocation = composeInvocation({
        root,
        envFile,
        composeArgs: ["--profile", "core", "--profile", "cognee", "config"],
    });
    assert.match(invocation.args.join(" "), /docker-compose\.cognee\.yml/);
    assert.ok(invocation.secretNames.includes("COGNEE_LLM_API_KEY"));
});

test("Compose child output sanitizes both stdout and stderr", async () => {
    const secret = "synthetic-compose-secret-987654321";
    let stdout = "";
    let stderr = "";
    const outStream = { write(chunk) { stdout += chunk; return true; } };
    const errStream = { write(chunk) { stderr += chunk; return true; } };
    const spawnProcess = () => {
        const child = new EventEmitter();
        child.stdout = new PassThrough();
        child.stderr = new PassThrough();
        queueMicrotask(() => {
            child.stdout.write(`service output: ${secret}`);
            child.stderr.write(`service error: ${secret}`);
            child.stdout.end();
            child.stderr.end();
            child.emit("close", 0);
        });
        return child;
    };

    const result = await runComposeChild({ file: "docker", args: ["compose", "logs"] }, {}, {
        spawnProcess,
        outStream,
        errStream,
        secretsToRedact: [{ id: "compose-secret", secret }],
    });

    assert.equal(result.status, 0);
    assert.equal(stdout, "service output: secretRef:compose-secret");
    assert.equal(stderr, "service error: secretRef:compose-secret");
});
