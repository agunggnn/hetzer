import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import fs from "node:fs";
import os from "node:os";
import { composeInvocation, runComposeChild } from "./compose-runner.mjs";

test("core Compose invocation excludes unselected recipes and profiles include declared recipes", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-compose-runner-"));
    try {
        const modDir = path.join(tempDir, "modules", "custom");
        fs.mkdirSync(modDir, { recursive: true });
        fs.writeFileSync(path.join(modDir, "module.json"), JSON.stringify({
            schemaVersion: 1,
            id: "custom",
            label: "Custom Module",
            version: "1",
            profile: "custom",
            lifecycle: "compose",
            surface: "headless",
            defaultEnabled: true,
            requires: ["core"],
            composeFiles: ["docker-compose.custom.yml"],
            services: [{ id: "custom", composeService: "custom", profile: "custom" }],
        }, null, 2));
        fs.writeFileSync(path.join(tempDir, "docker-compose.yml"), "services:\n  core:\n    image: test\n    environment:\n      - NINE_ROUTER_JWT_SECRET=${NINE_ROUTER_JWT_SECRET}\n");
        fs.writeFileSync(path.join(modDir, "docker-compose.custom.yml"), "services:\n  custom:\n    image: test\n    environment:\n      - CUSTOM_API_KEY=${CUSTOM_API_KEY}\n");
        const envFile = path.join(tempDir, ".env");
        fs.writeFileSync(envFile, "NINE_ROUTER_JWT_SECRET=test\nCUSTOM_API_KEY=test\n");

        const invocationCore = composeInvocation({ root: tempDir, envFile, composeArgs: ["--profile", "core", "config"] });
        const serialized = invocationCore.args.join(" ");
        assert.match(serialized, /docker-compose\.yml/);
        assert.doesNotMatch(serialized, /docker-compose\.custom\.yml/);
        assert.ok(invocationCore.secretNames.includes("NINE_ROUTER_JWT_SECRET"));
        assert.ok(!invocationCore.secretNames.includes("CUSTOM_API_KEY"));

        const invocationCustom = composeInvocation({
            root: tempDir,
            envFile,
            composeArgs: ["--profile", "core", "--profile", "custom", "config"],
        });
        assert.match(invocationCustom.args.join(" "), /docker-compose\.custom\.yml/);
        assert.ok(invocationCustom.secretNames.includes("CUSTOM_API_KEY"));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
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

test("composeInvocation correctly handles default envFile path", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-compose-env-"));
    try {
        const defaultEnv = path.join(tempDir, ".env");
        fs.writeFileSync(path.join(tempDir, "docker-compose.yml"), "services:\n  app:\n    image: test\n");
        const invocation = composeInvocation({ root: tempDir, envFile: defaultEnv, composeArgs: ["ps"] });
        assert.ok(invocation.args.includes(defaultEnv));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
