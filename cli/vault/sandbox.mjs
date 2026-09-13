#!/usr/bin/env node

import "../core/suppress-warnings.mjs";
import { spawn, spawnSync } from "node:child_process";
import path from "node:path";
import { parseDuration, pipeSanitizedChild, prepareExecutionEnvironment } from "./exec.mjs";

export function checkDockerAvailable(exec = spawnSync) {
    try {
        const cliResult = exec("docker", ["--version"], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
        if (cliResult.status !== 0) {
            return { ok: false, error: "Docker CLI is not installed or not in PATH." };
        }
        const daemonResult = exec("docker", ["info"], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
        if (daemonResult.status !== 0) {
            return { ok: false, error: "Docker daemon is not running. Start Docker Desktop / daemon service." };
        }
        return { ok: true };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

export function buildSandboxDockerArgs({
    root = process.cwd(),
    env = {},
    image = "node:22-alpine",
    network,
    readOnly = false,
    containerName,
    command,
    commandArgs = [],
} = {}) {
    const resolvedRoot = path.resolve(root);
    const args = ["run", "--rm", "-i"];

    if (containerName) {
        args.push("--name", containerName);
    }

    // Security isolation boundaries: drop all Linux capabilities and prevent privilege escalation
    args.push(
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=100",
    );

    if (network) {
        args.push("--network", network);
    }

    // Host mapping on Linux for loopback HTTP credential broker access
    if (process.platform === "linux") {
        args.push("--add-host=host.docker.internal:host-gateway");
    }

    // Strictly mount project workspace; host AppData/home directory is unmounted
    args.push(
        "-v", `${resolvedRoot}:/workspace${readOnly ? ":ro" : ":rw"}`,
        "-w", "/workspace",
    );

    // Pass environment variables with loopback translated to host.docker.internal
    if (env && typeof env === "object") {
        for (const [key, val] of Object.entries(env)) {
            if (val === undefined || val === null) continue;
            let containerVal = String(val);
            if (containerVal.includes("127.0.0.1") || containerVal.includes("localhost")) {
                containerVal = containerVal.replace(/\b(?:127\.0\.0\.1|localhost)\b/g, "host.docker.internal");
            }
            args.push("-e", `${key}=${containerVal}`);
        }
    }

    let normalizedCmd = command;
    const baseCmd = path.basename(command || "").toLowerCase();
    if (baseCmd === "node.exe" || baseCmd === "node") {
        normalizedCmd = "node";
    } else if (baseCmd === "npm.exe" || baseCmd === "npm" || baseCmd === "npm.cmd") {
        normalizedCmd = "npm";
    } else if (baseCmd === "npx.exe" || baseCmd === "npx" || baseCmd === "npx.cmd") {
        normalizedCmd = "npx";
    } else if (baseCmd === "python.exe" || baseCmd === "python3.exe") {
        normalizedCmd = "python3";
    }

    args.push(image, normalizedCmd, ...(commandArgs || []));

    return args;
}

export async function executeSandboxedProcess(options, {
    outStream = process.stdout,
    errStream = process.stderr,
    baseEnv = process.env,
    brokerFetchFn = globalThis.fetch,
    brokerRandomBytes,
    execSyncFn = spawnSync,
    spawnFn = spawn,
} = {}) {
    const dockerCheck = checkDockerAvailable(execSyncFn);
    if (!dockerCheck.ok) {
        const err = new Error(
            `Docker sandbox unavailable: ${dockerCheck.error}\n` +
            "To run untrusted agent processes in an isolated container, start Docker Desktop or Docker service, or run without '--sandbox'."
        );
        err.code = "ERR_DOCKER_SANDBOX_UNAVAILABLE";
        err.exitCode = 1;
        throw err;
    }

    const effectiveOptions = { ...options };
    const { env, secretsToRedact, brokers } = await prepareExecutionEnvironment(
        effectiveOptions,
        { baseEnv, brokerFetchFn, brokerRandomBytes },
    );

    try {
        const dockerArgs = buildSandboxDockerArgs({
            root: effectiveOptions.root,
            env,
            image: effectiveOptions.sandboxImage || (typeof effectiveOptions.sandbox === "string" ? effectiveOptions.sandbox : "node:22-alpine"),
            network: effectiveOptions.sandboxNetwork,
            readOnly: Boolean(effectiveOptions.sandboxRo),
            command: effectiveOptions.command,
            commandArgs: effectiveOptions.commandArgs,
        });

        const child = spawnFn("docker", dockerArgs, {
            stdio: ["inherit", "pipe", "pipe"],
            windowsHide: true,
            shell: false,
        });

        const timeoutMs = effectiveOptions.timeoutMs ?? (effectiveOptions.timeout ? parseDuration(effectiveOptions.timeout) : undefined);
        return await pipeSanitizedChild(child, secretsToRedact, {
            outStream,
            errStream,
            root: effectiveOptions.root,
            timeoutMs,
        });
    } finally {
        await Promise.all(brokers.map(async (opened) => {
            await opened.broker.close();
            opened.secret = "";
        }));
    }
}
