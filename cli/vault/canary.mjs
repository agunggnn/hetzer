#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { setCredential } from "./creds.mjs";
import { recordAuditEvent } from "./audit.mjs";
import { secureFilePermissions } from "./hetzer-vault.mjs";

export const CANARY_DEFAULT_ID = "canary-token";
export const CANARY_TOKEN_PATTERN = /\bcanary_trap_[0-9a-f]{16,64}\b/i;

export function isCanaryToken(text) {
    if (typeof text !== "string") return false;
    return CANARY_TOKEN_PATTERN.test(text);
}

export function generateCanaryToken() {
    return `canary_trap_${crypto.randomBytes(16).toString("hex")}`;
}

export function isCanaryCredential(id) {
    const norm = String(id || "").toLowerCase();
    return norm === CANARY_DEFAULT_ID || norm.startsWith("canary-") || norm.startsWith("decoy-");
}

export function triggerCanaryAlert({
    id = CANARY_DEFAULT_ID,
    actor = "autonomous-agent",
    action = "vault.reveal",
    root = process.cwd(),
} = {}) {
    const timestamp = new Date().toISOString();
    const threatVector = "Unauthorized Credential Scraping / Agent Prompt Injection";
    const alertMessage = [
        "🚨 ============================================================================",
        "🚨 HETZER CRITICAL SECURITY ALERT: CANARY HONEY-TOKEN TRIGGERED!",
        "🚨 ============================================================================",
        `🚨 Target Decoy    : ${id}`,
        `🚨 Incident Time   : ${timestamp}`,
        `🚨 Suspected Actor : ${actor} (${action})`,
        `🚨 Threat Vector   : ${threatVector}`,
        "🚨 Action Taken    : Guarded operation aborted.",
        "🚨 ============================================================================",
    ].join("\n");

    // Write to audit log and incident log file
    try {
        const incidentsFile = path.join(root, "data", "hetzer-incidents.log");
        fs.mkdirSync(path.dirname(incidentsFile), { recursive: true });
        fs.appendFileSync(incidentsFile, `[${timestamp}] CRITICAL: Canary '${id}' triggered by ${actor} during ${action}\n`);
    } catch {
        // Fail soft on disk error
    }

    try {
        recordAuditEvent({
            eventType: "CANARY_TRIGGER",
            target: id,
            result: "TRIGGERED",
            actor: { actor, action },
            details: { threatVector, timestamp },
            root,
        });
    } catch {
        // Fail soft
    }

    process.stderr.write(`\n${alertMessage}\n\n`);
    const error = new Error(
        `CRITICAL SECURITY VIOLATION: Accessing canary decoy credential '${id}' is forbidden.\n` +
        "This honey-token is a tripwire for detecting prompt injection and automated credential scraping."
    );
    error.code = "ERR_CANARY_TRIPWIRE_TRIGGERED";
    error.exitCode = 43;
    throw error;
}

export function setupCanaryTrap({ root = process.cwd(), envFile, id = CANARY_DEFAULT_ID } = {}) {
    const targetEnv = envFile || path.join(root, ".env");
    const decoyToken = generateCanaryToken();
    
    setCredential({
        root,
        envFile: targetEnv,
        id,
        secret: decoyToken,
    });

    return {
        id,
        decoyToken,
        ref: `secretRef:${id}`,
        envFile: targetEnv,
    };
}


// -----------------------------------------------------------------------------
// External canaries: decoy credentials issued by an outside alerting service
// -----------------------------------------------------------------------------
//
// The local canary above fires only when something asks Hetzer for it. Code that reads files directly never
// does. An external canary is a decoy credential issued by a service that alerts its owner when the credential
// is used anywhere (for example an AWS key from canarytokens.org). Hetzer does not create these and makes no
// network call: it plants the value a person supplies in a bait file where a scraper would look, keeps the
// file out of Git, and records only a fingerprint of each value outside the workspace, so the registry does
// not tell a reader of the workspace which values are decoys.

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const EXTERNAL_ID = /^decoy-[a-z0-9]+(?:-[a-z0-9]+)*$/;

function canaryError(code, message) {
    return Object.assign(new Error(message), { code, exitCode: 1 });
}

function fingerprint(value) {
    return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function realOrResolved(target) {
    try {
        return fs.realpathSync.native(target);
    } catch {
        return path.resolve(target);
    }
}

function isSameOrInside(child, parent) {
    const relative = path.relative(parent, child);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/** `~/.hetzer/canaries/<hash of the workspace path>.json`: outside the workspace and hidden by the sandbox. */
export function externalCanaryRegistryPath(root, homeDir = os.homedir()) {
    const name = fingerprint(realOrResolved(root)).slice(0, 32);
    return path.join(homeDir, ".hetzer", "canaries", `${name}.json`);
}

function readRegistry(file) {
    try {
        const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
        return Array.isArray(parsed.canaries) ? parsed : { canaries: [] };
    } catch {
        return { canaries: [] };
    }
}

function writeRegistry(file, registry) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, JSON.stringify(registry, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
    secureFilePermissions(file);
}

function gitTopLevel(dir, exec) {
    try {
        const result = exec("git", ["-C", dir, "rev-parse", "--show-toplevel", "--git-path", "info/exclude"], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
        if (result.error || result.status !== 0) return null;
        const [top, exclude] = String(result.stdout).trim().split(/\r?\n/);
        return top ? { top: realOrResolved(top), exclude: path.isAbsolute(exclude) ? exclude : path.join(dir, exclude) } : null;
    } catch {
        return null;
    }
}

/**
 * Plants an external canary. `entries` are `{ name, value }` pairs written as `NAME=value` lines to `file`.
 * Refuses the workspace .env (Hetzer would vault and inject it), anything inside the Hetzer home, a file Git
 * tracks, and a name the file already has. Adds the file to the repository's local `.git/info/exclude`
 * (not `.gitignore`, which would be committed and would point at the bait).
 */
export function plantExternalCanary({
    root = process.cwd(),
    file,
    entries = [],
    id,
    label = "",
    homeDir = os.homedir(),
    exec = spawnSync,
    now = () => new Date(),
} = {}) {
    if (!file) throw canaryError("ERR_CANARY_FILE_REQUIRED", "Name the bait file to plant the decoy in.");
    if (!entries.length) throw canaryError("ERR_CANARY_VALUE_REQUIRED", "Give at least one variable name for the decoy (--var NAME).");
    const target = realOrResolved(path.resolve(file));
    const workspaceEnv = realOrResolved(path.join(root, ".env"));
    if (target === workspaceEnv) {
        throw canaryError("ERR_CANARY_FILE_UNSAFE",
            "Refusing to plant a decoy in the workspace .env: Hetzer would move it into the vault and inject it. Use another file, such as .env.backup.");
    }
    for (const protectedDir of [path.join(homeDir, ".hetzer"), realOrResolved(path.join(root, ".hetzer")), realOrResolved(path.join(root, "data"))]) {
        if (isSameOrInside(target, realOrResolved(protectedDir))) {
            throw canaryError("ERR_CANARY_FILE_UNSAFE", `Refusing to plant a decoy inside '${protectedDir}', which Hetzer hides from sandboxes; a scraper would not find it there.`);
        }
    }
    const canaryId = id || `decoy-${crypto.randomBytes(4).toString("hex")}`;
    if (!EXTERNAL_ID.test(canaryId)) throw canaryError("ERR_CANARY_ID_INVALID", `Canary id '${canaryId}' must look like 'decoy-<name>'.`);

    const existing = fs.existsSync(target) ? fs.readFileSync(target, "utf8") : "";
    const presentNames = new Set(existing.split(/\r?\n/).map((line) => line.split("=")[0].trim()).filter(Boolean));
    for (const { name, value } of entries) {
        if (!ENV_NAME.test(String(name || ""))) throw canaryError("ERR_CANARY_NAME_INVALID", `Invalid variable name ${JSON.stringify(name)}.`);
        if (!value || /[\r\n\0]/.test(String(value))) throw canaryError("ERR_CANARY_VALUE_INVALID", `The value for ${name} is empty or spans lines.`);
        if (presentNames.has(name)) throw canaryError("ERR_CANARY_NAME_EXISTS", `'${target}' already sets ${name}. Pick another variable or file.`);
    }

    const registryFile = externalCanaryRegistryPath(root, homeDir);
    const registry = readRegistry(registryFile);
    if (registry.canaries.some((entry) => entry.id === canaryId)) throw canaryError("ERR_CANARY_ID_EXISTS", `Canary '${canaryId}' already exists.`);

    const git = gitTopLevel(path.dirname(target), exec);
    let excluded = "";
    if (git && isSameOrInside(target, git.top)) {
        const rel = path.relative(git.top, target).split(path.sep).join("/");
        const tracked = exec("git", ["-C", git.top, "ls-files", "--error-unmatch", "--", rel], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
        if (tracked.status === 0) {
            throw canaryError("ERR_CANARY_FILE_TRACKED", `'${rel}' is tracked by Git; a decoy there would be committed. Use an untracked file.`);
        }
        const excludeText = fs.existsSync(git.exclude) ? fs.readFileSync(git.exclude, "utf8") : "";
        if (!excludeText.split(/\r?\n/).includes(`/${rel}`)) {
            fs.mkdirSync(path.dirname(git.exclude), { recursive: true });
            fs.appendFileSync(git.exclude, `${excludeText && !excludeText.endsWith("\n") ? "\n" : ""}/${rel}\n`);
        }
        excluded = git.exclude;
    }

    const lines = entries.map(({ name, value }) => `${name}=${value}`).join("\n");
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, `${existing}${existing && !existing.endsWith("\n") ? "\n" : ""}${lines}\n`, { encoding: "utf8", mode: 0o600 });

    const record = {
        id: canaryId,
        label: String(label || ""),
        file: target,
        names: entries.map(({ name }) => name),
        fingerprints: entries.map(({ value }) => fingerprint(value)),
        gitExclude: excluded,
        createdAt: now().toISOString(),
    };
    registry.canaries.push(record);
    writeRegistry(registryFile, registry);
    try {
        recordAuditEvent({
            eventType: "CANARY_PLANTED",
            target: canaryId,
            result: "ALLOW",
            details: { file: target, names: record.names, label: record.label },
            root,
        });
    } catch {
        // fail soft: the registry is the record of the decoy
    }
    return { ...record, registryFile };
}

export function listExternalCanaries({ root = process.cwd(), homeDir = os.homedir() } = {}) {
    return readRegistry(externalCanaryRegistryPath(root, homeDir)).canaries.map((entry) => {
        let present;
        try {
            const lines = fs.readFileSync(entry.file, "utf8").split(/\r?\n/);
            present = entry.names.every((name, index) => lines.some((line) => {
                const [key, ...rest] = line.split("=");
                return key === name && fingerprint(rest.join("=")) === entry.fingerprints[index];
            }));
        } catch {
            present = false;
        }
        return { id: entry.id, label: entry.label, file: entry.file, names: entry.names, createdAt: entry.createdAt, present };
    });
}

/** Removes the decoy lines whose value still matches the recorded fingerprint, and the registry entry. */
export function removeExternalCanary({ root = process.cwd(), id, homeDir = os.homedir() } = {}) {
    const registryFile = externalCanaryRegistryPath(root, homeDir);
    const registry = readRegistry(registryFile);
    const entry = registry.canaries.find((candidate) => candidate.id === id);
    if (!entry) throw canaryError("ERR_CANARY_NOT_FOUND", `No external canary '${id}' is registered for this workspace.`);
    let removedLines = 0;
    if (fs.existsSync(entry.file)) {
        const kept = fs.readFileSync(entry.file, "utf8").split(/\r?\n/).filter((line) => {
            const [key, ...rest] = line.split("=");
            const index = entry.names.indexOf(key);
            const match = index !== -1 && fingerprint(rest.join("=")) === entry.fingerprints[index];
            if (match) removedLines += 1;
            return !match;
        });
        const text = kept.join("\n").replace(/\n+$/, "");
        if (text) fs.writeFileSync(entry.file, `${text}\n`, { encoding: "utf8", mode: 0o600 });
        else fs.rmSync(entry.file, { force: true });
    }
    registry.canaries = registry.canaries.filter((candidate) => candidate.id !== id);
    writeRegistry(registryFile, registry);
    try {
        recordAuditEvent({ eventType: "CANARY_REMOVED", target: id, result: "ALLOW", details: { file: entry.file, removedLines }, root });
    } catch {
        // fail soft
    }
    return { id, file: entry.file, removedLines };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const args = process.argv.slice(2);
        const action = args[0] || "setup";
        const root = path.resolve(process.env.HETZER_ROOT || process.cwd());
        const envFile = path.resolve(process.env.HETZER_ENV_FILE || path.join(root, ".env"));

        if (action === "setup" || action === "enable") {
            const trap = setupCanaryTrap({ root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - CANARY HONEY-TOKEN TRAP DEPLOYED\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Honey-Token ID : ${trap.id}\n`);
            process.stdout.write(`  [v] Decoy Binding  : HETZER_CANARY_TOKEN=${trap.ref}\n`);
            process.stdout.write(`  [v] Protection     : Guarded reveal or environment resolution of this ID\n`);
            process.stdout.write(`                       logs an incident and aborts with exit code 43.\n`);
            process.stdout.write("================================================================================\n");
        } else {
            throw new Error(`Unknown canary action '${action}'. Use 'setup'.`);
        }
    } catch (err) {
        process.stderr.write(`[hetzer canary error] ${err.message}\n`);
        process.exitCode = err.exitCode || 1;
    }
}
