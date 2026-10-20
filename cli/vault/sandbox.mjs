#!/usr/bin/env node

import "../core/suppress-warnings.mjs";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getAuditLogPath, recordAuditEvent } from "./audit.mjs";
import { parseDuration, pipeSanitizedChild, prepareExecutionEnvironment } from "./exec.mjs";
import { getIsolatedKeyPath, resolveVaultPath } from "./hetzer-vault.mjs";
import { strictBaseEnvironment } from "./secret-env.mjs";
import { buildSrtArgs, buildSrtSettings, createSrtRunDir, detectSrt, validateSandboxHosts, writeSrtSettings } from "./srt-sandbox.mjs";

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

export function detectContainerEngine(exec = spawnSync, preferred = process.env.HETZER_CONTAINER_ENGINE?.trim()) {
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

const CONTAINER_WORKDIR = "/workspace";

// Default sandbox image, pinned by its multi-platform index digest so the tag cannot move underneath a run.
// A pin does not receive base-image security updates on its own. Refresh it deliberately:
//   docker pull node:22-alpine
//   docker image inspect node:22-alpine --format '{{index .RepoDigests 0}}'
// then update the digest below. Override per run with --sandbox <image> or HETZER_SANDBOX_IMAGE.
export const DEFAULT_SANDBOX_IMAGE = "node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402";

export function resolveSandboxImage(options = {}, env = process.env) {
    const requested = options.sandboxImage || (typeof options.sandbox === "string" ? options.sandbox : "");
    return String(requested || env.HETZER_SANDBOX_IMAGE || "").trim() || DEFAULT_SANDBOX_IMAGE;
}

function sandboxError(code, message) {
    return Object.assign(new Error(message), { code, exitCode: 1 });
}

function realPathOrResolved(target) {
    try {
        return fs.realpathSync.native(target);
    } catch {
        return path.resolve(target);
    }
}

function isSamePath(a, b) {
    return path.relative(a, b) === "";
}

function isInsidePath(child, parent) {
    const relative = path.relative(parent, child);
    return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function toContainerPath(mountReal, hostPath) {
    return `${CONTAINER_WORKDIR}/${path.relative(mountReal, hostPath).split(path.sep).join("/")}`;
}

/**
 * Decide what a sandbox may mount and which Hetzer-owned paths inside it must be hidden.
 *
 * The mount directory is an explicit input (the project being worked on), never the Hetzer instance root.
 * It is refused when it is the filesystem root, the home directory, the Hetzer home or any ancestor of
 * those, or when it lies inside the Hetzer home. Hetzer-owned paths that sit inside the mount (the env
 * file, vault database and its journals, key file, audit and incident logs, `.hetzer/`, credential
 * requests) are hidden with an empty read-only file or a read-only tmpfs. Only paths that exist are masked,
 * because a bind target that does not exist would be created inside the host project.
 */
export function resolveSandboxMount({
    mountDir,
    root,
    envFile,
    vaultPath,
    homeDir = os.homedir(),
    hetzerHome: hetzerHomeOverride,
    platform = process.platform,
} = {}) {
    if (typeof mountDir !== "string" || !mountDir.trim()) {
        throw sandboxError("ERR_SANDBOX_MOUNT_REQUIRED",
            "A sandbox needs an explicit directory to mount (the project to work on). Pass --sandbox-mount <dir> or run from the project directory.");
    }
    const requested = path.resolve(mountDir);
    let stats;
    try {
        stats = fs.statSync(requested);
    } catch {
        throw sandboxError("ERR_SANDBOX_MOUNT_INVALID", `Sandbox mount directory does not exist: '${requested}'.`);
    }
    if (!stats.isDirectory()) {
        throw sandboxError("ERR_SANDBOX_MOUNT_INVALID", `Sandbox mount path is not a directory: '${requested}'.`);
    }
    const mountReal = realPathOrResolved(requested);

    // `-v host:container` splits on ':' (a Windows drive letter is the only legitimate one) and on newlines.
    const afterDrive = platform === "win32" ? mountReal.slice(2) : mountReal;
    if (/[\0\r\n]/.test(mountReal) || afterDrive.includes(":")) {
        throw sandboxError("ERR_SANDBOX_MOUNT_INVALID",
            `Sandbox mount path contains characters that change mount semantics: ${JSON.stringify(mountReal)}.`);
    }

    const resolvedRoot = path.resolve(root || process.cwd());
    const hetzerHome = realPathOrResolved(hetzerHomeOverride
        || (process.env.HETZER_HOME ? path.resolve(process.env.HETZER_HOME) : path.join(homeDir, ".hetzer")));
    const home = realPathOrResolved(homeDir);
    if (isSamePath(mountReal, path.parse(mountReal).root)) {
        throw sandboxError("ERR_SANDBOX_MOUNT_UNSAFE", "Refusing to mount the filesystem root into a sandbox.");
    }
    for (const [label, protectedPath] of [["the home directory", home], ["the Hetzer home", hetzerHome]]) {
        if (isSamePath(mountReal, protectedPath) || isInsidePath(protectedPath, mountReal)) {
            throw sandboxError("ERR_SANDBOX_MOUNT_UNSAFE",
                `Refusing to mount '${mountReal}' into a sandbox: it is or contains ${label}. Mount the project directory instead.`);
        }
    }
    if (isInsidePath(mountReal, hetzerHome)) {
        throw sandboxError("ERR_SANDBOX_MOUNT_UNSAFE",
            `Refusing to mount '${mountReal}' into a sandbox: it lies inside the Hetzer home, which holds the vault and key material.`);
    }

    const vaultFile = resolveVaultPath(resolvedRoot, vaultPath) || path.join(resolvedRoot, "data", "hetzer-vault.db");
    const auditLog = getAuditLogPath({ root: resolvedRoot });
    const sensitiveFiles = new Set();
    for (const base of [vaultFile === ":memory:" ? "" : vaultFile, ...(envFile ? [envFile] : []), getIsolatedKeyPath(homeDir)]) {
        if (!base) continue;
        sensitiveFiles.add(base);
    }
    for (const suffix of ["-wal", "-shm", "-journal"]) {
        if (vaultFile && vaultFile !== ":memory:") sensitiveFiles.add(`${vaultFile}${suffix}`);
    }
    for (const suffix of ["", ".head", ".state", ".lock"]) sensitiveFiles.add(`${auditLog}${suffix}`);
    sensitiveFiles.add(path.join(resolvedRoot, "data", "hetzer-incidents.log"));
    sensitiveFiles.add(path.join(resolvedRoot, "data", "vault.json"));
    sensitiveFiles.add(path.join(resolvedRoot, ".env"));
    const sensitiveDirs = new Set([
        path.join(resolvedRoot, ".hetzer"),
        path.join(resolvedRoot, "data", "credential-requests"),
        hetzerHome,
        path.join(homeDir, ".hetzer", "keys"),
    ]);

    const files = [];
    const dirs = [];
    const seen = new Set();
    for (const [candidate, expected] of [...[...sensitiveFiles].map((p) => [p, "file"]), ...[...sensitiveDirs].map((p) => [p, "dir"])]) {
        let stat;
        try {
            stat = fs.statSync(candidate);
        } catch {
            continue; // Not present: nothing to hide, and a missing bind target would be created inside the project.
        }
        const real = realPathOrResolved(candidate);
        if (!isInsidePath(real, mountReal) && !isSamePath(real, mountReal)) continue;
        if (isSamePath(real, mountReal)) {
            throw sandboxError("ERR_SANDBOX_SENSITIVE_PATH_IN_MOUNT",
                `The sandbox mount '${mountReal}' is itself a Hetzer-owned location and cannot be hidden. Mount the project directory instead.`);
        }
        if (seen.has(real)) continue;
        seen.add(real);
        if (stat.isFile() && expected === "file") {
            files.push({ hostPath: real, containerPath: toContainerPath(mountReal, real) });
        } else if (stat.isDirectory() && expected === "dir") {
            dirs.push({ hostPath: real, containerPath: toContainerPath(mountReal, real) });
        } else {
            throw sandboxError("ERR_SANDBOX_SENSITIVE_PATH_IN_MOUNT",
                `Cannot hide '${real}' inside the sandbox mount (unexpected file type). Move it outside '${mountReal}' or mount a different directory.`);
        }
    }
    return { mountDir: mountReal, masks: { files, dirs } };
}

export function buildSandboxDockerArgs({
    mountDir,
    masks = { files: [], dirs: [] },
    maskFile,
    env,
    envNames = [],
    image = DEFAULT_SANDBOX_IMAGE,
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

    if (typeof mountDir !== "string" || !mountDir.trim()) {
        throw sandboxError("ERR_SANDBOX_MOUNT_REQUIRED", "buildSandboxDockerArgs requires an explicit mountDir.");
    }
    if (masks.files?.length && (typeof maskFile !== "string" || !maskFile)) {
        throw sandboxError("ERR_SANDBOX_MASK_INVALID", "File masks require the path of an empty host file (maskFile).");
    }
    const resolvedMount = path.resolve(mountDir);
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
        "-v", `${resolvedMount}:${CONTAINER_WORKDIR}${mountSuffix}`,
        "-w", CONTAINER_WORKDIR,
    );
    // Hide Hetzer-owned paths that sit inside the mount. Masks come after the main mount so they take precedence.
    for (const file of masks.files || []) {
        args.push("-v", `${maskFile}:${file.containerPath}:ro`);
    }
    for (const dir of masks.dirs || []) {
        args.push("--tmpfs", `${dir.containerPath}:ro,noexec,nosuid,size=4k`);
    }

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

export const SANDBOX_ENGINES = ["auto", "docker", "podman", "srt"];

/**
 * Picks the sandbox engine for a run. `--sandbox-engine` (or HETZER_SANDBOX_ENGINE) names one; otherwise
 * Docker, then Podman, then srt. Options only srt implements (--sandbox-allow-host, --sandbox-allow-read,
 * --sandbox-allow-write) select srt, and an image selects a container engine; asking for both is refused.
 */
export function selectSandboxEngine(options = {}, { execSyncFn = spawnSync, baseEnv = process.env, platform = process.platform } = {}) {
    const requested = String(options.sandboxEngine || baseEnv.HETZER_SANDBOX_ENGINE || "auto").trim().toLowerCase();
    if (!SANDBOX_ENGINES.includes(requested)) {
        throw sandboxError("ERR_SANDBOX_ENGINE_INVALID", `Unknown sandbox engine '${requested}'. Use one of: ${SANDBOX_ENGINES.join(", ")}.`);
    }
    const srtOnly = [
        ["--sandbox-allow-host", options.sandboxAllowHosts],
        ["--sandbox-allow-read", options.sandboxAllowRead],
        ["--sandbox-allow-write", options.sandboxAllowWrite],
    ].filter(([, list]) => Array.isArray(list) && list.length).map(([flag]) => flag);
    const image = options.sandboxImage || (typeof options.sandbox === "string" ? options.sandbox : "");
    const network = String(options.sandboxNetwork || "").trim().toLowerCase();
    if (srtOnly.length && image) {
        throw sandboxError("ERR_SANDBOX_OPTIONS_CONFLICT",
            `${srtOnly.join(", ")} need the srt engine, and a sandbox image needs a container engine. Use one or the other.`);
    }
    const wantsSrt = requested === "srt" || (requested === "auto" && srtOnly.length > 0);
    if (wantsSrt) {
        if (image) throw sandboxError("ERR_SANDBOX_OPTIONS_CONFLICT", "The srt engine runs on the host file system and does not take an image.");
        if (network && network !== "none") {
            throw sandboxError("ERR_SANDBOX_OPTIONS_CONFLICT",
                `The srt engine denies network access except for --sandbox-allow-host entries; --sandbox-network '${network}' does not apply to it.`);
        }
        const srt = detectSrt(execSyncFn, baseEnv, platform);
        if (!srt.ok) throw sandboxError("ERR_SANDBOX_ENGINE_UNAVAILABLE", `Sandbox unavailable: ${srt.error}`);
        return srt;
    }
    if (srtOnly.length) {
        throw sandboxError("ERR_SANDBOX_OPTIONS_CONFLICT",
            `${srtOnly.join(", ")} need the srt engine; the ${requested} engine cannot restrict by host name or path. Use --sandbox-engine srt, or --sandbox-network none with ${requested}.`);
    }
    const container = detectContainerEngine(execSyncFn, requested === "auto" ? baseEnv.HETZER_CONTAINER_ENGINE?.trim() : requested);
    if (container.ok) return container;
    if (requested === "auto" && !image) {
        const srt = detectSrt(execSyncFn, baseEnv, platform);
        if (srt.ok) return srt;
        const err = sandboxError("ERR_DOCKER_SANDBOX_UNAVAILABLE",
            `Sandbox unavailable: ${container.error} ${srt.error}\n`
            + "Install Docker or Podman, or the srt engine (no container needed), or run without '--sandbox'.");
        throw err;
    }
    const err = sandboxError("ERR_DOCKER_SANDBOX_UNAVAILABLE",
        `Container sandbox unavailable: ${container.error}\n`
        + "To run untrusted agent processes in an isolated container, install and start Docker or Podman, or run without '--sandbox'.");
    throw err;
}

function recordSandboxStart(effectiveOptions, baseEnv, details) {
    try {
        recordAuditEvent({
            eventType: "SANDBOX_EXEC",
            target: path.basename(effectiveOptions.command || "unknown"),
            result: "ALLOW",
            details: { ...details, command: effectiveOptions.command, ...(effectiveOptions.agent ? { agent: true } : {}) },
            root: effectiveOptions.root,
            baseEnv,
            envFile: effectiveOptions.envFile,
        });
    } catch (error) {
        // Same rule as host exec: under --strict a run without its start record does not start.
        if (effectiveOptions.strict) {
            const failure = new Error(`Audit event could not be recorded and --strict requires it: ${error.message}`);
            failure.code = "ERR_AUDIT_WRITE_FAILED";
            throw failure;
        }
        process.stderr.write(`[hetzer] warning: audit event not recorded (${error.code || error.message})\n`);
    }
}

/**
 * Interactive runs (an agent's terminal UI) need the terminal itself, so their output is not piped through the
 * redactor; they are started without injected credentials unless a raw-injection grant was asked for.
 */
function waitForInteractiveChild(child, { timeoutMs } = {}) {
    return new Promise((resolve, reject) => {
        let timer;
        if (timeoutMs) {
            timer = setTimeout(() => { try { child.kill("SIGTERM"); } catch { /* already gone */ } }, timeoutMs);
        }
        child.once("error", (error) => {
            if (timer) clearTimeout(timer);
            reject(error);
        });
        child.once("close", (code, signal) => {
            if (timer) clearTimeout(timer);
            resolve({ status: code ?? (signal ? 128 : 1), signal: signal || null });
        });
    });
}

function runSandboxChild(spawnFn, file, args, { env, interactive, secretsToRedact, outStream, errStream, root, timeoutMs }) {
    const child = spawnFn(file, args, {
        stdio: interactive ? "inherit" : ["inherit", "pipe", "pipe"],
        env,
        windowsHide: true,
        shell: false,
    });
    if (interactive) return waitForInteractiveChild(child, { timeoutMs });
    return pipeSanitizedChild(child, secretsToRedact, { outStream, errStream, root, timeoutMs });
}

async function runSrtSandbox({
    engineCheck, effectiveOptions, mountPlan, env, secretsToRedact, injectedNames, brokerUrlNames,
    outStream, errStream, baseEnv, spawnFn,
}) {
    const allowHosts = validateSandboxHosts(effectiveOptions.sandboxAllowHosts || []);
    const run = createSrtRunDir();
    try {
        writeSrtSettings(run.settingsFile, buildSrtSettings({
            mountDir: mountPlan.mountDir,
            masks: mountPlan.masks,
            hetzerHome: process.env.HETZER_HOME ? path.resolve(process.env.HETZER_HOME) : undefined,
            allowHosts,
            allowRead: effectiveOptions.sandboxAllowRead || [],
            allowWrite: effectiveOptions.sandboxAllowWrite || [],
            readOnly: Boolean(effectiveOptions.sandboxRo),
            tmpDir: run.tmpDir,
            settingsFile: run.settingsFile,
        }));
        // srt hands its own environment to the command: the base names (PATH, HOME, locale), the run's own
        // temporary directory and the variables Hetzer injected. The master key and unrelated host variables stay out.
        const childEnv = {
            ...strictBaseEnvironment(baseEnv),
            TMPDIR: run.tmpDir,
            TMP: run.tmpDir,
            TEMP: run.tmpDir,
            ...selectContainerEnv({ env, injectedNames, brokerUrlNames }).values,
        };
        errStream.write(
            `[hetzer] sandbox (srt ${engineCheck.version || "unknown version"}): project ${mountPlan.mountDir}${effectiveOptions.sandboxRo ? " (read-only)" : " (read-write)"}; `
            + `home directory and Hetzer files unreadable; hidden Hetzer paths in the project: ${mountPlan.masks.files.length + mountPlan.masks.dirs.length}; `
            + `network: ${allowHosts.length ? `only ${allowHosts.join(", ")}` : "none"}\n`,
        );
        recordSandboxStart(effectiveOptions, baseEnv, { engine: "srt", engineVersion: engineCheck.version, allowHosts });
        const timeoutMs = effectiveOptions.timeoutMs ?? (effectiveOptions.timeout ? parseDuration(effectiveOptions.timeout) : undefined);
        return await runSandboxChild(spawnFn, engineCheck.bin, buildSrtArgs({
            settingsFile: run.settingsFile,
            command: effectiveOptions.command,
            commandArgs: effectiveOptions.commandArgs,
        }), {
            env: childEnv,
            interactive: Boolean(effectiveOptions.interactive),
            secretsToRedact,
            outStream,
            errStream,
            root: effectiveOptions.root,
            timeoutMs,
        });
    } finally {
        try { fs.rmSync(run.dir, { recursive: true, force: true }); } catch { /* temp dir only */ }
    }
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
    const engineCheck = selectSandboxEngine(options, { execSyncFn, baseEnv });
    const effectiveOptions = { ...options };
    if (engineCheck.type === "srt" && effectiveOptions.brokerPolicyFiles?.length) {
        throw sandboxError("ERR_SANDBOX_BROKER_UNSUPPORTED",
            "The srt engine does not reach the host credential broker yet. Use a container engine for brokered credentials, or a raw-injection grant.");
    }
    // Validate the mount before any credential is resolved or any broker is started.
    const mountPlan = resolveSandboxMount({
        mountDir: effectiveOptions.sandboxMountDir,
        root: effectiveOptions.root,
        envFile: effectiveOptions.envFile,
        vaultPath: effectiveOptions.vaultPath,
    });
    const { env, secretsToRedact, brokers, injectedNames, brokerUrlNames } = await prepareExecutionEnvironment(
        effectiveOptions,
        { baseEnv, brokerFetchFn, brokerRandomBytes },
    );

    if (engineCheck.type === "srt") {
        try {
            if (brokers.length) {
                throw sandboxError("ERR_SANDBOX_BROKER_UNSUPPORTED",
                    "The srt engine does not reach the host credential broker yet. Use a container engine for brokered credentials, or a raw-injection grant.");
            }
            return await runSrtSandbox({
                engineCheck, effectiveOptions, mountPlan, env, secretsToRedact, injectedNames, brokerUrlNames,
                outStream, errStream, baseEnv, spawnFn,
            });
        } finally {
            await Promise.all(brokers.map(async (opened) => {
                await opened.broker.close();
                opened.secret = "";
            }));
        }
    }

    let maskDir = null;
    try {
        let maskFile;
        if (mountPlan.masks.files.length) {
            maskDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sandbox-mask-"));
            maskFile = path.join(maskDir, "empty");
            fs.writeFileSync(maskFile, "", { mode: 0o600 });
        }
        const containerEnv = selectContainerEnv({ env, injectedNames, brokerUrlNames });
        const sandboxImage = resolveSandboxImage(effectiveOptions, baseEnv);
        const networkMode = String(effectiveOptions.sandboxNetwork || "").trim();
        if (networkMode.toLowerCase() === "none" && brokers.length > 0) {
            throw sandboxError("ERR_SANDBOX_NETWORK_BROKER_UNREACHABLE",
                "--sandbox-network none cannot be combined with a brokered credential: the container could not reach the host broker. Use a raw-injection grant or a different network.");
        }
        errStream.write(
            `[hetzer] sandbox: mount ${mountPlan.mountDir} -> ${CONTAINER_WORKDIR}${effectiveOptions.sandboxRo ? " (read-only)" : " (read-write)"}; `
            + `hidden Hetzer paths: ${mountPlan.masks.files.length + mountPlan.masks.dirs.length}; `
            + `network: ${networkMode || "engine default (outbound access is allowed)"}\n`,
        );
        const dockerArgs = buildSandboxDockerArgs({
            mountDir: mountPlan.mountDir,
            masks: mountPlan.masks,
            maskFile,
            envNames: containerEnv.names,
            image: sandboxImage,
            network: effectiveOptions.sandboxNetwork,
            readOnly: Boolean(effectiveOptions.sandboxRo),
            command: effectiveOptions.command,
            commandArgs: effectiveOptions.commandArgs,
            engine: engineCheck.engine,
        });

        recordSandboxStart(effectiveOptions, baseEnv, { engine: engineCheck.engine, image: sandboxImage });

        const timeoutMs = effectiveOptions.timeoutMs ?? (effectiveOptions.timeout ? parseDuration(effectiveOptions.timeout) : undefined);
        return await runSandboxChild(spawnFn, engineCheck.engine, dockerArgs, {
            env: buildContainerCliEnv({ baseEnv, containerValues: containerEnv.values }),
            interactive: Boolean(effectiveOptions.interactive),
            secretsToRedact,
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
        if (maskDir) {
            try { fs.rmSync(maskDir, { recursive: true, force: true }); } catch { /* temp dir only */ }
        }
    }
}
