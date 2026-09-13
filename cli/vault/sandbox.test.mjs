import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    buildSandboxDockerArgs,
    checkDockerAvailable,
    executeSandboxedProcess,
} from "./sandbox.mjs";

test("buildSandboxDockerArgs constructs isolated docker execution parameters", () => {
    const root = path.resolve("/tmp/test-project");
    const env = {
        OPENAI_BASE_URL: "http://127.0.0.1:54321/v1",
        LOCAL_SERVICE: "http://localhost:8080",
        PROJECT_NAME: "demo",
    };

    const args = buildSandboxDockerArgs({
        root,
        env,
        image: "node:22-alpine",
        network: "bridge",
        readOnly: false,
        containerName: "test-sandbox-01",
        command: "node.exe",
        commandArgs: ["index.js"],
    });

    // 1. Ephemeral and interactive flags
    assert.ok(args.includes("--rm"));
    assert.ok(args.includes("-i"));
    assert.ok(args.includes("--name"));
    assert.equal(args[args.indexOf("--name") + 1], "test-sandbox-01");

    // 2. Linux capability dropping and privilege mitigation
    assert.ok(args.includes("--cap-drop=ALL"));
    assert.ok(args.includes("--security-opt=no-new-privileges"));
    assert.ok(args.includes("--pids-limit=100"));

    // 3. Workspace mount and working directory
    assert.ok(args.includes("-w"));
    assert.equal(args[args.indexOf("-w") + 1], "/workspace");
    const mountIndex = args.indexOf("-v");
    assert.ok(mountIndex >= 0);
    assert.equal(args[mountIndex + 1], `${root}:/workspace:rw`);

    // 4. Broker loopback address translation to host.docker.internal
    assert.ok(args.includes("-e"));
    const envEntries = args.filter((_, i) => args[i - 1] === "-e");
    assert.ok(envEntries.includes("OPENAI_BASE_URL=http://host.docker.internal:54321/v1"));
    assert.ok(envEntries.includes("LOCAL_SERVICE=http://host.docker.internal:8080"));
    assert.ok(envEntries.includes("PROJECT_NAME=demo"));

    // 5. Normalization of Windows node.exe to node
    const imageIndex = args.indexOf("node:22-alpine");
    assert.ok(imageIndex >= 0);
    assert.equal(args[imageIndex + 1], "node");
    assert.equal(args[imageIndex + 2], "index.js");
});

test("checkDockerAvailable inspects Docker CLI and daemon connectivity", () => {
    // 1. Successful check
    const mockSuccessExec = (cmd, args) => {
        if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.2.0\n" };
        if (args.includes("info")) return { status: 0, stdout: "Server Version: 27.2.0\n" };
        return { status: 0 };
    };
    const successRes = checkDockerAvailable(mockSuccessExec);
    assert.equal(successRes.ok, true);

    // 2. Missing CLI
    const mockMissingCli = (cmd, args) => {
        if (args.includes("--version")) return { status: 127, stderr: "docker: not found\n" };
        return { status: 0 };
    };
    const missingRes = checkDockerAvailable(mockMissingCli);
    assert.equal(missingRes.ok, false);
    assert.match(missingRes.error, /Docker CLI is not installed/);

    // 3. Stopped daemon
    const mockStoppedDaemon = (cmd, args) => {
        if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.2.0\n" };
        if (args.includes("info")) return { status: 1, stderr: "Is the docker daemon running?\n" };
        return { status: 0 };
    };
    const stoppedRes = checkDockerAvailable(mockStoppedDaemon);
    assert.equal(stoppedRes.ok, false);
    assert.match(stoppedRes.error, /Docker daemon is not running/);
});

test("executeSandboxedProcess fails closed when Docker is unavailable", async () => {
    const mockMissingExec = () => ({ status: 1, stderr: "Cannot connect to Docker daemon\n" });

    await assert.rejects(
        () => executeSandboxedProcess({
            root: process.cwd(),
            command: "npm",
            commandArgs: ["test"],
        }, {
            execSyncFn: mockMissingExec,
        }),
        (err) => {
            assert.equal(err.code, "ERR_DOCKER_SANDBOX_UNAVAILABLE");
            assert.equal(err.exitCode, 1);
            assert.match(err.message, /Docker sandbox unavailable/);
            return true;
        }
    );
});
