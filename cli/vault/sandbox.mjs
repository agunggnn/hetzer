#!/usr/bin/env node

import "../core/suppress-warnings.mjs";
import { spawn, spawnSync } from "node:child_process";
import path from "node:path";
import { recordAuditEvent } from "./audit.mjs";
import { parseDuration, pipeSanitizedChild, prepareExecutionEnvironment } from "./exec.mjs";
import { strictBaseEnvironment } from "./secret-env.mjs";

// Variables forwarded to the container besides the ones Hetzer injected itself. Everything else in
// the host environment (PATH, USERPROFILE, tokens, the vault master key) stays on the host.
const CONTAINER_PASSTHROUGH = new Set(["TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ"]);
const NEVER_IN_CONTAINER = new Set([
    "HETZER_GRIMOIRE_KEY", "SHADOW_GRIMOIRE_KEY", "HETZER_ROOT", "HETZER_HOME", "HETZER_ENV_FILE",
    "HETZER_VAULT_PATH", "NODE_OPTIONS",
]);
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
// Host variables the container engine's own CLI process needs to find its daemon and configuration.
const ENGINE_CLI_PASSTHROUGH = /^(?:DOCKER_|CONTAINER_|PODMAN_|XDG_RUNTIME_DIR$|XDG_CONFIG_HOME$|REGISTRY_AUTH_FILE$)/i;

function translateLoopbackForContainer(value) {
    return String(value).replace(/\b(?:127\.0\.0\.1|localhost)\b/g, "host.docker.internal");
}

/**
 * Choose the environment a sandboxed process receives. Only variables Hetzer injected (raw bindings,
 * broker URL and capability, canary token) and a small terminal/locale allowlist are forwarded, so host
 * paths and unrelated host secrets do not enter the container. Loopback addresses are rewritten for the
 * broker URL variables only, never for credential values.
 */
export function selectContainerEnv({ env = {}, injectedNames = [], brokerUrlNames = [] } = {}) {
    const brokerUrls = new Set(brokerUrlNames);
    const values = {};
    const consider = (name, translate) => {
        if (NEVER_IN_CONTAINER.has(name.toUpperCase())) return;
        if (!ENV_NAME_PATTERN.test(name)) {
            throw Object.assign(new Error(`Refusing to pass invalid environment variable name to the sandbox: ${JSON.stringify(name)}.`), {
                code: "ERR_SANDBOX_ENV_INVALID",
            });
        }
        const raw = env[name];
        if (raw === undefined || raw === null) return;
        const value = String(raw);
        if (value.includes("\0")) {
            throw Object.assign(new Error(`Environment variable '${name}' contains a NUL byte and cannot be passed to the sandbox.`), {
                code: "ERR_SANDBOX_ENV_INVALID",
            });
        }
        values[name] = translate ? translateLoopbackForContainer(value) : value;
    };
    for (const name of injectedNames) consider(name, brokerUrls.has(name));
    for (const name of Object.keys(env)) {
        if (CONTAINER_PASSTHROUGH.has(name.toUpperCase()) || /^LC_[A-Z_]+$/i.test(name)) {
            if (!Object.hasOwn(values, name)) consider(name, false);
        }
    }
    return { values, names: Object.keys(values) };
}

/**
 * Environment for the container engine's CLI process. Values are handed over here and referenced by name
 * (`-e NAME`) so they never appear in the process command line. The host master key is never included.
 */
export function buildContainerCliEnv({ baseEnv = process.env, containerValues = {} } = {}) {
    const cliEnv = { ...strictBaseEnvironment(baseEnv) };
    for (const [name, value] of Object.entries(baseEnv)) {
        if (ENGINE_CLI_PASSTHROUGH.test(name) && typeof value === "string") cliEnv[name] = value;
    }
    const reserved = new Set(Object.keys(cliEnv).map((name) => name.toUpperCase()));
    for (const name of Object.keys(containerValues)) {
        const isPassthrough = CONTAINER_PASSTHROUGH.has(name.toUpperCase()) || /^LC_[A-Z_]+$/i.test(name);
        if (!isPassthrough && reserved.has(name.toUpperCase())) {
            throw Object.assign(new Error(
                `Environment variable '${name}' collides with a variable the container engine CLI needs and cannot be injected into the sandbox.`,
            ), { code: "ERR_SANDBOX_ENV_COLLISION" });
        }
    }
    return { ...cliEnv, ...containerValues };
}

export function detectContainerEngine(exec = spawnSync) {
    const preferred = process.env.HETZER_CONTAINER_ENGINE?.trim();
    const candidates = preferred ? [preferred] : ["docker", "podman"];

    for (const engine of candidates) {
        try {
            const cliResult = exec(engine, ["--version"], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
            if (cliResult.status !== 0) continue;

            const daemonResult = exec(engine, ["info"], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
            if (daemonResult.status === 0) {
                return {
                    ok: true,
                    engine,
                    type: engine.toLowerCase().includes("podman") ? "podman" : "docker",
                };
            }
        } catch {
            // continue probe
        }
    }

    return {
        ok: false,
        error: "Neither Docker nor Podman is installed and running.",
    };
}

export function checkDockerAvailable(exec = spawnSync) {
    const res = detectContainerEngine(exec);
    if (res.ok) return { ok: true, engine: res.engine };
    return { ok: false, error: res.error };
}

export const OCI_IMAGE_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]*(?:\/[a-zA-Z0-9_.:-]+)*(?:@[a-zA-Z0-9_.-]+:[a-fA-F0-9]+)?$/;

export function buildSandboxDockerArgs({
    root = process.cwd(),
    env,
    envNames = [],
    image = "node:22-alpine",
    network,
    readOnly = false,
    containerName,
    command,
    commandArgs = [],
    engine = "docker",
    platform = process.platform,
} = {}) {
    if (env !== undefined) {
        // Values on the engine command line are visible to every local process and to `docker inspect`.
        throw new Error("buildSandboxDockerArgs no longer accepts environment values; pass variable names via envNames and hand the values to the engine CLI process environment.");
    }
    const rawImage = String(image || "").trim();
    if (!rawImage || rawImage.startsWith("-") || !OCI_IMAGE_PATTERN.test(rawImage)) {
        throw new Error(`Invalid sandbox image: '${image}'. Image name must be a valid OCI reference and cannot start with '-'.`);
    }

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
    if (platform === "linux") {
        args.push("--add-host=host.docker.internal:host-gateway");
        if (engine.toLowerCase().includes("podman")) {
            args.push("--add-host=host.containers.internal:host-gateway");
        }
    }

    // Strictly mount project workspace; host AppData/home directory is unmounted
    // For rootless Podman on Linux, add :Z to grant container SELinux context
    const isPodmanLinux = engine.toLowerCase().includes("podman") && platform === "linux";
    const mountSuffix = isPodmanLinux ? (readOnly ? ":ro,Z" : ":rw,Z") : (readOnly ? ":ro" : ":rw");
    args.push(
        "-v", `${resolvedRoot}:/workspace${mountSuffix}`,
        "-w", "/workspace",
    );

    // Forward variables by name only. The engine reads each value from its own process environment.
    for (const name of envNames) {
        if (!ENV_NAME_PATTERN.test(String(name))) {
            throw new Error(`Invalid sandbox environment variable name: ${JSON.stringify(name)}.`);
        }
        args.push("-e", String(name));
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
    const engineCheck = detectContainerEngine(execSyncFn);
    if (!engineCheck.ok) {
        const err = new Error(
            `Container sandbox unavailable: ${engineCheck.error}\n` +
            "To run untrusted agent processes in an isolated container, install and start Docker or Podman, or run without '--sandbox'."
        );
        err.code = "ERR_DOCKER_SANDBOX_UNAVAILABLE";
        err.exitCode = 1;
        throw err;
    }

    const effectiveOptions = { ...options };
    const { env, secretsToRedact, brokers, injectedNames, brokerUrlNames } = await prepareExecutionEnvironment(
        effectiveOptions,
        { baseEnv, brokerFetchFn, brokerRandomBytes },
    );

    try {
        const containerEnv = selectContainerEnv({ env, injectedNames, brokerUrlNames });
        const dockerArgs = buildSandboxDockerArgs({
            root: effectiveOptions.root,
            envNames: containerEnv.names,
            image: effectiveOptions.sandboxImage || (typeof effectiveOptions.sandbox === "string" ? effectiveOptions.sandbox : "node:22-alpine"),
            network: effectiveOptions.sandboxNetwork,
            readOnly: Boolean(effectiveOptions.sandboxRo),
            command: effectiveOptions.command,
            commandArgs: effectiveOptions.commandArgs,
            engine: engineCheck.engine,
        });

        try {
            recordAuditEvent({
                eventType: "SANDBOX_EXEC",
                target: path.basename(effectiveOptions.command || "unknown"),
                result: "ALLOW",
                details: {
                    engine: engineCheck.engine,
                    image: effectiveOptions.sandboxImage || "node:22-alpine",
                    command: effectiveOptions.command,
                },
                root: effectiveOptions.root,
            });
        } catch {
            // Fail soft on audit write
        }

        const child = spawnFn(engineCheck.engine, dockerArgs, {
            stdio: ["inherit", "pipe", "pipe"],
            env: buildContainerCliEnv({ baseEnv, containerValues: containerEnv.values }),
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
