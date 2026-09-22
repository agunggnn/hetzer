#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

import { parseDockerJson } from "../core/docker.mjs";
import { parseEnv } from "../core/env.mjs";
import { findGitDir, checkStagedDiff } from "../core/git-hook.mjs";
import { createToolCatalog } from "../mcp/catalog.mjs";
import { getCanaryStatus, isCanaryCredential, sanitizeCanaryText } from "../vault/canary.mjs";
import { listCredentials } from "../vault/creds.mjs";
import { getIsolatedKeyPath } from "../vault/hetzer-vault.mjs";
import { scanText } from "../vault/sniffer.mjs";
import { verifyAuditLedger, readAuditEvents } from "../vault/audit.mjs";
import { detectContainerEngine } from "../vault/sandbox.mjs";
import { loadModuleRegistry } from "./registry.mjs";
import { getUpdateCachePath, isNewerVersion, readUpdateCache } from "../core/version-check.mjs";

const ANSI = {
    reset: "\x1b[0m",
    dim: "\x1b[2m",
    bold: "\x1b[1m",
    cyan: "\x1b[36m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    red: "\x1b[31m",
    magenta: "\x1b[35m",
};

export const ASCII_LOGO = [
    " _   _ _____ _____ _____ _____ ____  ",
    "| | | | ____|_   _|__  /| ____|  _ \\ ",
    "| |_| |  _|   | |   / / |  _| | |_) |",
    "|  _  | |___  | |  / /_ | |___|  _ < ",
    "|_| |_|_____| |_| /____|_____|_| \\_\\ ",
];

export function getBoxWidth() {
    if (!process.stdout.columns) return 77;
    return Math.max(60, Math.min(process.stdout.columns - 3, 120));
}

export let BOX_WIDTH = 77;
export let INNER_WIDTH = BOX_WIDTH - 4; // 73

export function refreshDimensions() {
    BOX_WIDTH = getBoxWidth();
    INNER_WIDTH = BOX_WIDTH - 4;
}

export function stripAnsi(text) {
    return String(text || "").replace(/\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))/g, "");
}

export function boxTop(title = "") {
    if (!title) return `┌${"─".repeat(BOX_WIDTH - 2)}┐`;
    const cleanTitle = stripAnsi(title);
    const prefix = "┌─ ";
    const suffix = " ";
    const used = prefix.length + cleanTitle.length + suffix.length;
    const remaining = Math.max(0, (BOX_WIDTH - 1) - used);
    return `${prefix}${title}${suffix}${"─".repeat(remaining)}┐`;
}

export function boxDivider() {
    return `├${"─".repeat(BOX_WIDTH - 2)}┤`;
}

export function boxBottom() {
    return `└${"─".repeat(BOX_WIDTH - 2)}┘`;
}

export function boxLine(content = "") {
    const visible = stripAnsi(content).length;
    const pad = Math.max(0, INNER_WIDTH - visible);
    return `│ ${content}${" ".repeat(pad)} │`;
}

export function bounded(value, width) {
    const text = String(value ?? "");
    if (text.length <= width) return text.padEnd(width);
    return `${text.slice(0, Math.max(0, width - 1))}…`;
}

export function colorState(state, enabled) {
    const value = String(state || "unknown").toUpperCase();
    if (!enabled) return value;
    const color = ["READY", "RUNNING", "ARMED", "ACTIVE", "CLEAN", "ISOLATED", "SECURE", "ENFORCING"].includes(value)
        ? ANSI.green
        : ["DEGRADED", "LOCKED", "UNARMED", "EXPOSED", "EXTERNAL", "TRIPPED"].includes(value)
            ? ANSI.yellow
            : ["OFFLINE", "STOPPED", "DEAD", "EXITED", "MISSING", "VIOLATIONS", "CRITICAL"].includes(value)
                ? ANSI.red
                : ANSI.dim;
    return `${color}${value}${ANSI.reset}`;
}

export function padColor(colored, raw, width, enabled) {
    if (!enabled) return String(raw).toUpperCase().padEnd(width);
    const visibleLength = stripAnsi(colored).length;
    const pad = Math.max(0, width - visibleLength);
    return colored + " ".repeat(pad);
}

function option(name, fallback = "") {
    const index = process.argv.indexOf(name);
    return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

function environmentValue(fileEnv, name, fallback = "") {
    return process.env[name] || fileEnv[name] || fallback;
}

function serviceUrl(service, fileEnv) {
    const configured = service.urlEnv ? environmentValue(fileEnv, service.urlEnv) : "";
    if (configured && !configured.startsWith("secretRef:")) return configured.replace(/\/+$/, "");
    const port = service.portEnv ? environmentValue(fileEnv, service.portEnv) : "";
    const selected = port || String(service.fallbackPort || "");
    return /^\d+$/.test(selected) ? `http://127.0.0.1:${selected}` : "";
}

async function probeJson(url, timeoutMs = 1500) {
    if (!url) return { state: "n/a", detail: "no health endpoint" };
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, {
            headers: { accept: "application/json" },
            signal: controller.signal,
        });
        return response.ok
            ? { state: "ready", detail: `HTTP ${response.status}` }
            : { state: "degraded", detail: `HTTP ${response.status}` };
    } catch (error) {
        const reason = error?.name === "AbortError" ? "timeout" : "unreachable";
        return { state: "offline", detail: reason };
    } finally {
        clearTimeout(timeout);
    }
}

function dockerSnapshot(root, envFile, registry, fileEnv) {
    const composeFiles = registry.composeFiles
        .map((file) => path.resolve(root, file))
        .filter((file) => fs.existsSync(file));
    if (!composeFiles.length) return { state: "n/a", detail: "no Compose files", rows: [] };

    const args = ["compose", "--project-name", environmentValue(fileEnv, "HETZER_PROJECT_NAME", "hetzer")];
    if (fs.existsSync(envFile)) args.push("--env-file", envFile);
    for (const file of composeFiles) args.push("-f", file);
    args.push("--profile", "*", "ps", "--all", "--format", "json");

    const result = spawnSync("docker", args, {
        cwd: root,
        encoding: "utf8",
        timeout: 3500,
        windowsHide: true,
    });
    if (result.error) {
        const detail = result.error.code === "ENOENT" ? "Docker not installed" : result.error.message;
        return { state: "offline", detail, rows: [] };
    }
    if (result.status !== 0) {
        const detail = String(result.stderr || "Docker Compose unavailable").trim().split(/\r?\n/).at(-1);
        return { state: "offline", detail: detail.slice(0, 120), rows: [] };
    }
    return { state: "ready", detail: "Compose reachable", rows: parseDockerJson(result.stdout) };
}

export function threatSnapshot(root, vaultItems = [], { canaryBinding = false } = {}) {
    const incidentsFile = path.join(root, "data", "hetzer-incidents.log");
    let incidentCount = 0;
    let recentIncidents = [];
    if (fs.existsSync(incidentsFile)) {
        try {
            const content = fs.readFileSync(incidentsFile, "utf8");
            const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
            incidentCount = lines.length;
            recentIncidents = lines.slice(-5).map((line) => sanitizeCanaryText(line));
        } catch {
            // fail soft
        }
    }
    const canaryCount = Array.isArray(vaultItems)
        ? vaultItems.filter((item) => isCanaryCredential(item.id)).length
        : 0;

    let state = "UNARMED";
    let detail = "no canary trap configured";
    if (canaryCount > 0) {
        if (incidentCount > 0) {
            state = "TRIPPED";
            detail = `${canaryCount} canary active; ${incidentCount} incident(s) logged!`;
        } else {
            state = "ARMED";
            detail = `${canaryCount} canary honeytoken deployed (exitCode 43)`;
        }
    } else if (canaryBinding) {
        state = "UNKNOWN";
        detail = "canary binding detected; vault metadata is unavailable or inconsistent";
    } else if (incidentCount > 0) {
        state = "TRIPPED";
        detail = `${incidentCount} incident(s) recorded in hetzer-incidents.log`;
    }

    return {
        state,
        detail,
        incidentCount,
        recentIncidents,
        canaryCount,
    };
}

export function auditLedgerSnapshot(root) {
    try {
        const verified = verifyAuditLedger({ root });
        const events = readAuditEvents({ root, limit: 10 });
        let state = "CLEAN";
        let detail = "0 events; hash-chain intact";
        if (!verified.ok) {
            state = "CORRUPTED";
            detail = `tampered at #${verified.tamperedIndex}: ${verified.error}`;
        } else if (verified.count > 0) {
            state = "VERIFIED";
            detail = `${verified.count} event(s); SHA-256 chain intact`;
        }
        return {
            state,
            detail,
            count: verified.count || 0,
            latestHash: verified.latestHash || "",
            recentEvents: events,
        };
    } catch (err) {
        return {
            state: "ERROR",
            detail: err.message,
            count: 0,
            latestHash: "",
            recentEvents: [],
        };
    }
}


export function vaultPostureSnapshot(root, fileEnv = {}) {
    const configured = environmentValue(fileEnv, "HETZER_VAULT_PATH");
    const dbPath = configured
        ? (path.isAbsolute(configured) ? configured : path.join(root, configured))
        : path.join(root, "data", "hetzer-vault.db");
    const exists = dbPath !== ":memory:" && fs.existsSync(dbPath);

    const isolatedPath = getIsolatedKeyPath();
    let hasIsolatedKey = false;
    if (isolatedPath && fs.existsSync(isolatedPath)) {
        try {
            const val = fs.readFileSync(isolatedPath, "utf8").trim();
            if (val && !val.startsWith("secretRef:")) hasIsolatedKey = true;
        } catch {
            // fail soft
        }
    }

    const envKey = environmentValue(fileEnv, "HETZER_GRIMOIRE_KEY") || environmentValue(fileEnv, "SHADOW_GRIMOIRE_KEY");
    const hasEnvKey = Boolean(envKey && !String(envKey).startsWith("secretRef:"));
    const unlocked = hasIsolatedKey || hasEnvKey;

    let keyIsolation = "MISSING";
    let keyDetail = "key not found; run hetzer init";
    if (hasIsolatedKey) {
        keyIsolation = "ISOLATED";
        keyDetail = "~/.hetzer/grimoire.key (isolated from workspace)";
    } else if (hasEnvKey) {
        keyIsolation = "EXPOSED";
        keyDetail = ".env (unsafe for agent workspace; run hetzer init)";
    }

    let credentials = [];
    let state = "n/a";
    let detail = "not initialized";

    if (exists) {
        if (!unlocked) {
            state = "locked";
            detail = "database present; key unavailable";
        } else {
            try {
                const envFile = path.join(root, ".env");
                credentials = listCredentials({ root, envFile });
                state = "ready";
                detail = "database present; key available";
            } catch {
                state = "degraded";
                detail = "vault unreadable with current key";
            }
        }
    }

    let secretRefCount = 0;
    let rawSecretCount = 0;
    const envFile = path.join(root, ".env");
    if (fs.existsSync(envFile)) {
        try {
            const content = fs.readFileSync(envFile, "utf8");
            const matches = content.match(/secretRef:[a-zA-Z0-9._-]+/g);
            secretRefCount = matches ? matches.length : 0;
            const sniffer = scanText(content);
            rawSecretCount = sniffer.matches.length;
        } catch {
            // fail soft
        }
    }

    return {
        state,
        detail,
        dbPath,
        dbExists: exists,
        keyIsolation,
        keyDetail,
        totalStored: credentials.filter((c) => c.configured).length,
        credentials,
        secretRefCount,
        rawSecretCount,
    };
}

export function shieldSnapshot(root) {
    const gitDir = findGitDir(root);
    let preCommitState = "MISSING";
    let preCommitDetail = "not installed";
    let commitMsgState = "MISSING";
    let commitMsgDetail = "not installed";

    if (gitDir) {
        const preCommit = path.join(gitDir, "hooks", "pre-commit");
        if (fs.existsSync(preCommit)) {
            try {
                const text = fs.readFileSync(preCommit, "utf8");
                preCommitState = text.includes("Hetzer") ? "ACTIVE" : "EXTERNAL";
                preCommitDetail = text.includes("Hetzer") ? "staged diff secret sniffer installed" : "custom hook present";
            } catch {
                preCommitState = "UNKNOWN";
            }
        }
        const commitMsg = path.join(gitDir, "hooks", "commit-msg");
        if (fs.existsSync(commitMsg)) {
            try {
                const text = fs.readFileSync(commitMsg, "utf8");
                commitMsgState = text.includes("Hetzer") ? "ACTIVE" : "EXTERNAL";
                commitMsgDetail = text.includes("Hetzer") ? "commit message token blocker installed" : "custom hook present";
            } catch {
                commitMsgState = "UNKNOWN";
            }
        }
    } else {
        preCommitDetail = "not a git repository";
        commitMsgDetail = "not a git repository";
    }

    const detectedAgents = [];
    if (fs.existsSync(path.join(root, ".cursor")) || fs.existsSync(path.join(root, ".cursorrules"))) {
        detectedAgents.push("Cursor IDE");
    }
    if (fs.existsSync(path.join(root, "CLAUDE.md")) || fs.existsSync(path.join(root, ".claude"))) {
        detectedAgents.push("Claude Code");
    }
    if (fs.existsSync(path.join(root, "AGENTS.md")) || fs.existsSync(path.join(root, "GEMINI.md"))) {
        detectedAgents.push("Antigravity");
    }
    if (fs.existsSync(path.join(root, "hermes.json"))) {
        detectedAgents.push("Hermes");
    }
    if (fs.existsSync(path.join(root, "opencode.json"))) {
        detectedAgents.push("OpenCode");
    }

    return {
        gitDir: Boolean(gitDir),
        preCommit: { state: preCommitState, detail: preCommitDetail },
        commitMsg: { state: commitMsgState, detail: commitMsgDetail },
        detectedAgents,
    };
}

export function runtimeArmorSnapshot(root) {
    let container = { state: "offline", detail: "Neither Docker nor Podman available" };
    try {
        const engineCheck = detectContainerEngine(spawnSync);
        if (engineCheck.ok) {
            const versionRes = spawnSync(engineCheck.engine, ["--version"], { encoding: "utf8", timeout: 1500, windowsHide: true });
            const firstLine = (versionRes.status === 0 && versionRes.stdout)
                ? versionRes.stdout.trim().split(/\r?\n/)[0]
                : engineCheck.engine;
            container = { state: "ready", detail: `${firstLine} (Ready for --sandbox)` };
        } else {
            container = { state: "offline", detail: engineCheck.error || "Container engine not running" };
        }
    } catch {
        // fail soft
    }

    return {
        container,
        broker: { state: "available", detail: "Available for guarded brokered executions" },
        redactor: { state: "available", detail: "Available for guarded child streams" },
        policy: { state: "available", detail: "Available for policy-controlled executions" },
    };
}

export function quickSniffSnapshot(root = process.cwd()) {
    try {
        const diffRes = checkStagedDiff(root);
        const violations = Array.isArray(diffRes?.violations) ? diffRes.violations : [];
        return {
            status: violations.length === 0 ? "CLEAN" : "VIOLATIONS",
            count: violations.length,
            violations,
        };
    } catch (err) {
        return {
            status: "CLEAN",
            count: 0,
            violations: [],
            detail: err.message,
        };
    }
}

function mcpSnapshot(root) {
    let catalog;
    try {
        catalog = createToolCatalog({ root });
        return { state: "ready", detail: `${catalog.definitions.length} registered tools` };
    } catch (error) {
        return { state: "degraded", detail: error.message };
    } finally {
        catalog?.close();
    }
}

function composeState(row) {
    if (!row) return { state: "stopped", detail: "no container" };
    const state = String(row.State || row.state || "unknown").toLowerCase();
    const health = String(row.Health || row.health || "").toLowerCase();
    if (health === "unhealthy" || ["dead", "exited"].includes(state)) {
        return { state: "degraded", detail: health || state };
    }
    if (state === "running") return { state: "running", detail: health || "container running" };
    return { state: state || "unknown", detail: String(row.Status || row.status || "unknown") };
}

export async function collectStatus({ root = process.env.HETZER_ROOT || process.cwd() } = {}) {
    const resolvedRoot = path.resolve(root);
    const envFile = path.join(resolvedRoot, ".env");
    const fileEnv = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const registry = loadModuleRegistry({
        builtinFile: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "builtin.json"),
        root: resolvedRoot,
        disabledModules: environmentValue(fileEnv, "HETZER_DISABLED_MODULES"),
        enabledModules: environmentValue(fileEnv, "HETZER_ENABLED_MODULES"),
    });
    const docker = dockerSnapshot(resolvedRoot, envFile, registry, fileEnv);
    const byService = new Map(docker.rows.map((row) => [row.Service || row.service, row]));

    const services = await Promise.all(registry.services.map(async (service) => {
        const baseUrl = serviceUrl(service, fileEnv);
        const container = composeState(service.composeService ? byService.get(service.composeService) : null);
        const probe = service.healthPath && baseUrl
            ? await probeJson(new URL(service.healthPath, `${baseUrl}/`).href)
            : { state: "n/a", detail: "no direct probe" };
        let observed = container;
        if (probe.state === "ready") observed = { state: "ready", detail: probe.detail };
        else if (container.state === "running" && probe.state === "offline") {
            observed = { state: "degraded", detail: probe.detail };
        } else if (service.external && probe.state !== "n/a") observed = probe;
        return {
            id: service.id,
            label: service.label || service.id,
            endpoint: baseUrl || "N/A",
            state: observed.state,
            detail: observed.detail,
        };
    }));

    const vaultPosture = vaultPostureSnapshot(resolvedRoot, fileEnv);
    const canaryStatus = getCanaryStatus({ root: resolvedRoot });
    const threat = threatSnapshot(resolvedRoot, vaultPosture.credentials, {
        canaryBinding: canaryStatus.hasCanaryBinding,
    });
    const audit = auditLedgerSnapshot(resolvedRoot);
    const shield = shieldSnapshot(resolvedRoot);
    const runtime = runtimeArmorSnapshot(resolvedRoot);
    const mcp = mcpSnapshot(resolvedRoot);

    return {
        root: resolvedRoot,
        generatedAt: new Date().toISOString(),
        docker: { state: docker.state, detail: docker.detail },
        vault: vaultPosture,
        threat,
        audit,
        shield,
        runtime,
        mcp,
        services,
        warnings: registry.warnings,
    };
}

export function analyzeIssues(snapshot = {}) {
    const issues = [];
    const root = snapshot.root || process.cwd();

    // 1. Staged Secret Leaks (Pre-commit)
    const sniff = snapshot.sniff || (snapshot.root ? quickSniffSnapshot(snapshot.root) : null);
    if (sniff && sniff.status === "VIOLATIONS") {
        const fileList = Array.isArray(sniff.violations)
            ? [...new Set(sniff.violations.map((v) => v.file).filter(Boolean))].join(", ")
            : "staged files";
        issues.push({
            id: "STAGED_SECRET_LEAK",
            category: "GIT_SAFETY",
            severity: "CRITICAL",
            title: "Plaintext secrets detected in staged Git diff",
            detail: `${sniff.count} secret violation(s) in staged files (${fileList || "staged files"})`,
            action: "Unstage files immediately to prevent credential leak in Git history",
            command: "git restore --staged <file>",
        });
    }

    // 2. Canary Honeytoken & Tripwires
    const threat = snapshot.threat;
    if (threat) {
        if (threat.incidentCount > 0 || threat.state === "TRIPPED") {
            issues.push({
                id: "CANARY_TRIPWIRE_TRIGGERED",
                category: "THREAT_RADAR",
                severity: "CRITICAL",
                title: "Canary honeytoken triggered / incident logged",
                detail: `${threat.incidentCount} incident(s) recorded in data/hetzer-incidents.log`,
                action: "Inspect incident log, identify compromised token, and rotate secrets",
                command: "hetzer canary list",
            });
        } else if (threat.state === "UNKNOWN") {
            issues.push({
                id: "CANARY_STATUS_UNAVAILABLE",
                category: "THREAT_RADAR",
                severity: "MEDIUM",
                title: "Canary binding detected but status is unavailable",
                detail: threat.detail,
                action: "Unlock or repair the vault before relying on canary posture",
                command: "hetzer creds list",
            });
        } else if (threat.canaryCount === 0 || threat.state === "UNARMED") {
            issues.push({
                id: "CANARY_TRAP_UNARMED",
                category: "THREAT_RADAR",
                severity: "WARNING",
                title: "No canary honeytokens armed in vault",
                detail: "Zero honeytokens active to catch scraping or prompt-injection attacks",
                action: "Deploy a canary tripwire honeytoken into the vault",
                command: "hetzer creds set canary-token",
            });
        }
    }

    // 3. Vault & Key Security
    const vault = snapshot.vault;
    if (vault) {
        if (vault.keyIsolation === "EXPOSED") {
            issues.push({
                id: "MASTER_KEY_EXPOSED",
                category: "VAULT_SECURITY",
                severity: "HIGH",
                title: "Master encryption key exposed in workspace .env",
                detail: "HETZER_GRIMOIRE_KEY is in .env; AI agents reading workspace files can exfiltrate it",
                action: "Migrate master key to ~/.hetzer/grimoire.key with 0600 user-only permissions",
                command: "hetzer init (or hetzer creds isolate-key)",
            });
        } else if (vault.keyIsolation === "MISSING" || vault.state === "locked") {
            issues.push({
                id: "VAULT_LOCKED_OR_KEY_MISSING",
                category: "VAULT_SECURITY",
                severity: "HIGH",
                title: "Vault is locked or master encryption key is missing",
                detail: vault.detail || "Vault database present but key unavailable",
                action: "Initialize vault or restore master key to unlock encrypted credentials",
                command: "hetzer init",
            });
        } else if (vault.state === "degraded") {
            issues.push({
                id: "VAULT_DEGRADED",
                category: "VAULT_SECURITY",
                severity: "HIGH",
                title: "Vault unreadable with current key",
                detail: vault.detail || "Corrupted key or mismatched passphrase",
                action: "Verify master key in ~/.hetzer/grimoire.key matches vault database",
                command: "hetzer init",
            });
        }

        if (vault.rawSecretCount > 0) {
            issues.push({
                id: "RAW_SECRETS_IN_ENV",
                category: "VAULT_SECURITY",
                severity: "HIGH",
                title: "Plaintext secrets detected in workspace .env",
                detail: `${vault.rawSecretCount} plaintext token(s) found in .env instead of secretRef: pointers`,
                action: "Migrate plaintext secrets into encrypted vault and replace with secretRef:<id>",
                command: "hetzer creds set <id>",
            });
        }
    }

    // 4. Git Guards & Hooks
    const shield = snapshot.shield;
    if (shield) {
        if (shield.preCommit && shield.preCommit.state === "MISSING") {
            issues.push({
                id: "PRE_COMMIT_HOOK_MISSING",
                category: "AGENT_SHIELD",
                severity: "MEDIUM",
                title: "Git pre-commit secret sniffer hook not installed",
                detail: "Accidental commits of API keys or private keys will not be blocked",
                action: "Install Hetzer pre-commit secret sniffer hook into .git/hooks",
                command: "hetzer hook install",
            });
        }
        if (shield.commitMsg && shield.commitMsg.state === "MISSING") {
            issues.push({
                id: "COMMIT_MSG_HOOK_MISSING",
                category: "AGENT_SHIELD",
                severity: "MEDIUM",
                title: "Git commit-msg token blocker hook not installed",
                detail: "Commit messages containing raw credentials will not be blocked",
                action: "Install Hetzer commit-msg hook into .git/hooks",
                command: "hetzer hook install",
            });
        }
    }

    // 5. Cryptographic Audit Ledger
    const audit = snapshot.audit;
    if (audit) {
        if (audit.state === "CORRUPTED" || audit.state === "ERROR") {
            issues.push({
                id: "AUDIT_LEDGER_TAMPERED",
                category: "AUDIT_TRAIL",
                severity: "CRITICAL",
                title: "Audit ledger hash-chain broken or corrupted",
                detail: audit.detail || "Tampering detected in .hetzer/audit.log",
                action: "Verify cryptographic SHA-256 chain and inspect tampered log entries",
                command: "hetzer audit verify",
            });
        }
    }

    // 6. Runtime Armor & Sandbox
    const runtime = snapshot.runtime;
    if (runtime && runtime.container && runtime.container.state === "offline") {
        issues.push({
            id: "CONTAINER_ENGINE_OFFLINE",
            category: "RUNTIME_ARMOR",
            severity: "LOW",
            title: "Container sandbox engine (Docker/Podman) offline",
            detail: runtime.container.detail || "Cannot isolate untrusted agent tools in --sandbox",
            action: "Start Docker Desktop daemon or install Podman for container isolation",
            command: "docker info",
        });
    }

    // 7. MCP Virtual Proxy
    const mcp = snapshot.mcp;
    if (mcp && mcp.state === "degraded") {
        issues.push({
            id: "MCP_CATALOG_DEGRADED",
            category: "MCP_SERVICES",
            severity: "MEDIUM",
            title: "MCP virtual tool catalog degraded",
            detail: mcp.detail || "Tool definition error",
            action: "Inspect MCP module manifests and service configurations",
            command: "hetzer mcp list",
        });
    }

    // 8. Service Health
    if (Array.isArray(snapshot.services)) {
        for (const svc of snapshot.services) {
            if (svc.state === "degraded" || svc.state === "offline") {
                issues.push({
                    id: `SERVICE_${String(svc.id).toUpperCase()}_${String(svc.state).toUpperCase()}`,
                    category: "SERVICES",
                    severity: "MEDIUM",
                    title: `Service '${svc.label || svc.id}' is ${svc.state}`,
                    detail: `${svc.endpoint || "N/A"} - ${svc.detail || "unreachable"}`,
                    action: `Inspect container status and launch service with 'hetzer up'`,
                    command: `hetzer up ${svc.id}`,
                });
            }
        }
    }

    // 9. Warnings from registry
    if (Array.isArray(snapshot.warnings)) {
        for (const warn of snapshot.warnings) {
            issues.push({
                id: "REGISTRY_WARNING",
                category: "CONFIGURATION",
                severity: "LOW",
                title: "Module registry configuration warning",
                detail: warn,
                action: "Review module registry configuration in builtin.json or module manifests",
                command: "hetzer validate",
            });
        }
    }

    return issues;
}

export function renderIssuesView(lines, snapshot, color) {
    const issues = analyzeIssues(snapshot);
    const title = `${color ? ANSI.bold : ""}SECURITY POSTURE & ACTIONABLE REMEDIATION GUIDE${color ? ANSI.reset : ""}`;
    lines.push(boxLine(title));

    if (issues.length === 0) {
        lines.push(boxLine(""));
        const secureMsg = color
            ? `${ANSI.green}${ANSI.bold}[v] NO ISSUES OBSERVED IN AVAILABLE POSTURE CHECKS${ANSI.reset}`
            : "[v] NO ISSUES OBSERVED IN AVAILABLE POSTURE CHECKS";
        lines.push(boxLine(`  ${secureMsg}`));
        lines.push(boxLine(""));
        lines.push(boxLine("  No remediation is indicated by the checks that completed."));
        lines.push(boxLine("  This is not proof of absence of vulnerabilities or safe execution."));
        lines.push(boxLine(""));
        lines.push(boxLine("  [Tip] Press [i] to toggle back to Overview."));
        return;
    }

    const critCount = issues.filter((i) => i.severity === "CRITICAL").length;
    const highCount = issues.filter((i) => i.severity === "HIGH").length;
    const warnCount = issues.filter((i) => i.severity === "WARNING" || i.severity === "MEDIUM").length;
    const lowCount = issues.filter((i) => i.severity === "LOW" || i.severity === "INFO").length;

    const countsStr = `Detected ${issues.length} issue(s): ${critCount} Critical, ${highCount} High, ${warnCount} Warning/Med, ${lowCount} Low`;
    lines.push(boxLine(`  ${color ? ANSI.yellow : ""}${countsStr}${color ? ANSI.reset : ""}`));
    lines.push(boxLine(""));

    for (let idx = 0; idx < issues.length; idx++) {
        const item = issues[idx];
        const sevColor = ["CRITICAL", "HIGH"].includes(item.severity)
            ? ANSI.red
            : item.severity === "WARNING"
                ? ANSI.yellow
                : ANSI.cyan;
        const sevBadge = color ? `${sevColor}[${item.severity}]${ANSI.reset}` : `[${item.severity}]`;
        const itemNum = `${idx + 1}.`;

        lines.push(boxLine(`  ${itemNum} ${sevBadge} ${color ? ANSI.bold : ""}${bounded(item.title, 56)}${color ? ANSI.reset : ""}`));
        lines.push(boxLine(`     Category : ${item.category}`));
        lines.push(boxLine(`     Problem  : ${bounded(item.detail, 57)}`));
        lines.push(boxLine(`     Action   : ${bounded(item.action, 57)}`));
        const cmdText = color ? `${ANSI.green}${item.command}${ANSI.reset}` : item.command;
        lines.push(boxLine(`     Resolve  : ${cmdText}`));
        if (idx < issues.length - 1) {
            lines.push(boxLine(""));
        }
    }

    lines.push(boxLine(""));
    lines.push(boxLine("  [Tip] Press [i] to toggle back to Overview. Press [r] to refresh."));
}

function renderOverview(lines, snapshot, color) {
    // 0. Active Issues & Remediation Actions (if any issues detected)
    const issues = analyzeIssues(snapshot);
    if (issues.length > 0) {
        lines.push(boxLine(`${color ? ANSI.bold : ""}${color ? ANSI.red : ""}ACTIVE ISSUES & ACTIONS REQUIRED (${issues.length})${color ? ANSI.reset : ""}`));
        for (const item of issues.slice(0, 3)) {
            const sevColor = ["CRITICAL", "HIGH"].includes(item.severity) ? ANSI.red : ANSI.yellow;
            const badge = color ? `${sevColor}[${item.severity}]${ANSI.reset}` : `[${item.severity}]`;
            const cmdText = color ? `${ANSI.green}${item.command}${ANSI.reset}` : item.command;
            lines.push(boxLine(`  ! ${badge} ${bounded(item.title, 34)} -> ${cmdText}`));
        }
        if (issues.length > 3) {
            lines.push(boxLine(`  ... and ${issues.length - 3} more issue(s). Press [i] for full remediation guide.`));
        }
        lines.push(boxDivider());
    }

    // 1. Threat & Tripwire Radar
    lines.push(boxLine(`${color ? ANSI.bold : ""}THREAT & TRIPWIRE RADAR${color ? ANSI.reset : ""}`));
    const threat = snapshot.threat || {
        state: "UNARMED",
        detail: "no canary trap configured",
        incidentCount: 0,
        recentIncidents: [],
    };
    const threatState = colorState(threat.state, color);
    lines.push(boxLine(`  Canary Trap     ${padColor(threatState, threat.state, 10, color)}  ${bounded(threat.detail, 41)}`));
    const incidentText = threat.incidentCount > 0
        ? (color ? `${ANSI.red}${threat.incidentCount} CRITICAL INCIDENT(S) RECORDED${ANSI.reset}` : `${threat.incidentCount} CRITICAL INCIDENT(S) RECORDED`)
        : `0 critical triggers (data/hetzer-incidents.log)`;
    lines.push(boxLine(`  Incident Radar  ${bounded(incidentText, 53)}`));
    const audit = snapshot.audit || auditLedgerSnapshot(snapshot.root);
    const auditState = colorState(audit.state, color);
    lines.push(boxLine(`  Audit Ledger    ${padColor(auditState, audit.state, 10, color)}  ${bounded(audit.detail, 41)}`));
    if (threat.incidentCount > 0) {
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}[!] Tripwire alarm active! Action: Run 'hetzer canary list' and rotate secrets.${color ? ANSI.reset : ""}`));
    } else if (threat.canaryCount === 0) {
        lines.push(boxLine(`  ${color ? ANSI.dim : ""}-> Action: Run 'hetzer creds set canary-token' to deploy honeytoken.${color ? ANSI.reset : ""}`));
    }

    // 2. Vault & Credential Posture
    lines.push(boxDivider());
    lines.push(boxLine(`${color ? ANSI.bold : ""}VAULT & CREDENTIAL POSTURE${color ? ANSI.reset : ""}`));
    const vault = snapshot.vault || { state: "n/a", detail: "not initialized" };
    const vaultState = colorState(vault.state, color);
    lines.push(boxLine(`  Storage Engine  ${padColor(vaultState, vault.state, 10, color)}  ${bounded(vault.detail, 41)}`));

    const keyIsolation = vault.keyIsolation || (vault.state === "ready" ? "ISOLATED" : "N/A");
    const keyState = colorState(keyIsolation, color);
    const keyDetail = vault.keyDetail || "run hetzer init to isolate master key";
    lines.push(boxLine(`  Key Isolation   ${padColor(keyState, keyIsolation, 10, color)}  ${bounded(keyDetail, 41)}`));

    if (vault.totalStored !== undefined || vault.secretRefCount !== undefined) {
        const storedCount = vault.totalStored ?? 0;
        const refCount = vault.secretRefCount ?? 0;
        const rawCount = vault.rawSecretCount ?? 0;
        const rawText = rawCount > 0
            ? (color ? `${ANSI.red}${rawCount} plaintext in .env!${ANSI.reset}` : `${rawCount} plaintext in .env!`)
            : "0 plaintext in .env";
        lines.push(boxLine(`  Safety Ratio    ${storedCount} vaulted   ${refCount} secretRef: pointers   ${rawText}`));
    }
    if (vault.keyIsolation === "EXPOSED") {
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}-> Action: Run 'hetzer init' or 'hetzer creds isolate-key' to isolate master key to ~/.hetzer/grimoire.key${color ? ANSI.reset : ""}`));
    }
    if (vault.rawSecretCount > 0) {
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}-> Action: Run 'hetzer creds set <id>' and replace raw secrets with secretRef:<id>${color ? ANSI.reset : ""}`));
    }

    // 3. Agent Shield & Git Guards
    lines.push(boxDivider());
    lines.push(boxLine(`${color ? ANSI.bold : ""}AGENT SHIELD & GIT GUARDS${color ? ANSI.reset : ""}`));
    const shield = snapshot.shield || {
        preCommit: { state: "N/A", detail: "not evaluated" },
        commitMsg: { state: "N/A", detail: "not evaluated" },
        detectedAgents: [],
    };
    const preCommitState = colorState(shield.preCommit.state, color);
    lines.push(boxLine(`  Git Pre-Commit  ${padColor(preCommitState, shield.preCommit.state, 10, color)}  ${bounded(shield.preCommit.detail, 41)}`));
    const commitMsgState = colorState(shield.commitMsg.state, color);
    lines.push(boxLine(`  Git Commit-Msg  ${padColor(commitMsgState, shield.commitMsg.state, 10, color)}  ${bounded(shield.commitMsg.detail, 41)}`));

    const mcp = snapshot.mcp || { state: "n/a", detail: "catalog not loaded" };
    const mcpState = colorState(mcp.state, color);
    lines.push(boxLine(`  MCP Bridge      ${padColor(mcpState, mcp.state, 10, color)}  ${bounded(mcp.detail, 41)}`));

    const agents = shield.detectedAgents && shield.detectedAgents.length
        ? shield.detectedAgents.join(", ")
        : "None detected in workspace";
    lines.push(boxLine(`  Detected Agents ${bounded(agents, 53)}`));

    // Quick staged diff status
    try {
        const sniff = snapshot.sniff || (snapshot.root ? quickSniffSnapshot(snapshot.root) : null);
        if (sniff) {
            const sniffState = sniff.status === "CLEAN" ? "CLEAN" : "VIOLATIONS";
            const sniffStateC = colorState(sniffState, color);
            const sniffDetail = sniff.status === "CLEAN"
                ? "staged diff is clean"
                : `${sniff.count} secret(s) in staged diff!`;
            lines.push(boxLine(`  Staged Diff     ${padColor(sniffStateC, sniffState, 10, color)}  ${bounded(sniffDetail, 41)}`));
            if (sniff.status === "VIOLATIONS") {
                lines.push(boxLine(`  ${color ? ANSI.red : ""}-> Action: Run 'git restore --staged <file>' to unstage leaked secret!${color ? ANSI.reset : ""}`));
            }
        }
    } catch {
        // fail soft
    }
    if (shield.preCommit.state === "MISSING" || shield.commitMsg.state === "MISSING") {
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}-> Action: Run 'hetzer hook install' to activate git pre-commit sniffer.${color ? ANSI.reset : ""}`));
    }

    // 4. Runtime Armor & Container Sandbox
    lines.push(boxDivider());
    lines.push(boxLine(`${color ? ANSI.bold : ""}RUNTIME ARMOR & CONTAINER SANDBOX${color ? ANSI.reset : ""}`));
    const runtime = snapshot.runtime || {
        container: snapshot.docker || { state: "offline", detail: "Docker not installed" },
        broker: { state: "available", detail: "Available for guarded brokered executions" },
        redactor: { state: "available", detail: "Available for guarded child streams" },
        policy: { state: "available", detail: "Available for policy-controlled executions" },
    };
    const container = runtime.container || snapshot.docker || { state: "offline", detail: "Docker not installed" };
    const containerState = colorState(container.state, color);
    lines.push(boxLine(`  Container Box   ${padColor(containerState, container.state, 10, color)}  ${bounded(container.detail, 41)}`));
    const brokerState = colorState(runtime.broker?.state || "READY", color);
    lines.push(boxLine(`  HTTP Broker     ${padColor(brokerState, runtime.broker?.state || "READY", 10, color)}  ${bounded(runtime.broker?.detail || "Loopback broker active", 41)}`));
    const redactorState = colorState(runtime.redactor?.state || "READY", color);
    lines.push(boxLine(`  Stream Redactor ${padColor(redactorState, runtime.redactor?.state || "READY", 10, color)}  ${bounded(runtime.redactor?.detail || "Sub-ms sliding window", 41)}`));
    if (container.state === "offline") {
        lines.push(boxLine(`  ${color ? ANSI.dim : ""}-> Action: Start Docker or Podman daemon to enable 'hetzer exec --sandbox'${color ? ANSI.reset : ""}`));
    }

    // 5. Services (if services present)
    if (snapshot.services && snapshot.services.length > 0) {
        lines.push(boxDivider());
        lines.push(boxLine(`${color ? ANSI.bold : ""}SERVICES${color ? ANSI.reset : ""}`));
        lines.push(boxLine(`  ${bounded("SERVICE", 18)} ${bounded("STATE", 10)} ${bounded("ENDPOINT", 28)} ${bounded("DETAIL", 12)}`));
        for (const service of snapshot.services) {
            const label = bounded(service.label || service.id, 18);
            const stateStr = bounded(String(service.state).toUpperCase(), 10);
            const renderedState = colorState(stateStr.trim(), color);
            const padState = color ? 10 + (renderedState.length - stateStr.trim().length) : 10;
            const endpoint = bounded(service.endpoint || "N/A", 28);
            const detail = bounded(service.detail || "", 12);
            lines.push(boxLine(`  ${label} ${renderedState.padEnd(padState)} ${endpoint} ${detail}`));
        }
    }

    // 6. Warnings (if any)
    if (snapshot.warnings && snapshot.warnings.length > 0) {
        lines.push(boxDivider());
        lines.push(boxLine(`${color ? ANSI.yellow : ""}WARNINGS${color ? ANSI.reset : ""}`));
        for (const warning of snapshot.warnings) {
            lines.push(boxLine(`  ! ${bounded(warning, 69)}`));
        }
    }
}

function wrapText(text, width) {
    const words = String(text).split(" ");
    const lines = [];
    let current = "";
    for (const word of words) {
        if (!current) {
            current = word;
        } else if (current.length + 1 + word.length <= width) {
            current += " " + word;
        } else {
            lines.push(current);
            current = word;
        }
    }
    if (current) lines.push(current);
    return lines;
}

function renderCanaryView(lines, snapshot, color) {
    lines.push(boxLine(`${color ? ANSI.bold : ""}CANARY HONEYTOKEN & INCIDENT LOG${color ? ANSI.reset : ""}`));
    const threat = snapshot.threat || {
        state: "UNARMED",
        detail: "no canary trap configured",
        incidentCount: 0,
        recentIncidents: [],
        canaryCount: 0,
    };
    if (threat.state === "UNKNOWN") {
        lines.push(boxLine("  Canary binding detected, but vault status is unavailable."));
        lines.push(boxLine("  Do not rely on the canary posture until the vault is repaired."));
        lines.push(boxLine("  Remediation: hetzer creds list"));
    } else if (threat.recentIncidents.length === 0) {
        lines.push(boxLine("  No canary incidents recorded in the observed log."));
        lines.push(boxLine(`  Honeytokens armed: ${threat.canaryCount || 0}`));
        lines.push(boxLine(""));
        lines.push(boxLine("  Canary honeytokens trigger exit code 43 (ERR_CANARY_TRIPWIRE_TRIGGERED)"));
        lines.push(boxLine("  and terminate execution if leaked to agent streams."));
        if (threat.canaryCount === 0) {
            lines.push(boxLine(""));
            lines.push(boxLine(`  ${color ? ANSI.yellow : ""}Notice: Zero honeytokens deployed.${color ? ANSI.reset : ""}`));
            const cmd = color ? `${ANSI.green}hetzer creds set canary-token${ANSI.reset}` : "hetzer creds set canary-token";
            lines.push(boxLine(`  Action: Deploy a honeytoken tripwire via: ${cmd}`));
        }
    } else {
        lines.push(boxLine(`  Total Incidents: ${threat.incidentCount}`));
        lines.push(boxLine("  Recent Incident Log (data/hetzer-incidents.log):"));
        for (const inc of threat.recentIncidents) {
            const safeIncident = sanitizeCanaryText(inc, 240);
            if (safeIncident.length <= 67) {
                lines.push(boxLine(`  ${color ? ANSI.red : ""}> ${safeIncident}${color ? ANSI.reset : ""}`));
            } else {
                const parts = wrapText(safeIncident, 65);
                for (let i = 0; i < parts.length; i++) {
                    const prefix = i === 0 ? "> " : "  ";
                    lines.push(boxLine(`  ${color ? ANSI.red : ""}${prefix}${parts[i]}${color ? ANSI.reset : ""}`));
                }
            }
        }
        lines.push(boxLine(""));
        lines.push(boxLine(`  ${color ? ANSI.red : ""}Action Required: Investigate compromised process and rotate leaked credentials.${color ? ANSI.reset : ""}`));
        const cmd = color ? `${ANSI.green}hetzer canary list${ANSI.reset}` : "hetzer canary list";
        lines.push(boxLine(`  Remediation Command: ${cmd}`));
    }
    lines.push(boxLine(""));
    lines.push(boxLine("  [Tip] Press [c] to toggle back to Overview."));
}

function renderVaultView(lines, snapshot, color) {
    lines.push(boxLine(`${color ? ANSI.bold : ""}VAULT INVENTORY (METADATA ONLY - NO RAW SECRETS)${color ? ANSI.reset : ""}`));
    const creds = snapshot.vault?.credentials || [];
    const configured = creds.filter((c) => c.configured);
    if (!configured.length) {
        lines.push(boxLine("  No credentials currently stored in vault."));
        lines.push(boxLine("  Store credentials using: hetzer creds set <id>"));
    } else {
        lines.push(boxLine("  ID                             MODULE        AUTH TYPE   STATUS"));
        for (const item of configured.slice(0, 10)) {
            const id = bounded(item.id, 30);
            const mod = bounded(item.module || "custom", 12);
            const auth = bounded(item.authType || "api-key", 10);
            const status = colorState("STORED", color);
            lines.push(boxLine(`  ${id} ${mod}  ${auth}  ${status}`));
        }
        if (configured.length > 10) {
            lines.push(boxLine(`  ... and ${configured.length - 10} more credentials`));
        }
    }
    const vault = snapshot.vault || {};
    if (vault.keyIsolation === "EXPOSED") {
        lines.push(boxLine(""));
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}Vulnerability: Master key is exposed in workspace .env!${color ? ANSI.reset : ""}`));
        const cmd = color ? `${ANSI.green}hetzer init${ANSI.reset}` : "hetzer init";
        lines.push(boxLine(`  Remediation: Run '${cmd}' to isolate key to ~/.hetzer/grimoire.key`));
    }
    if (vault.rawSecretCount > 0) {
        lines.push(boxLine(""));
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}Vulnerability: ${vault.rawSecretCount} plaintext secret(s) found in .env!${color ? ANSI.reset : ""}`));
        const cmd = color ? `${ANSI.green}hetzer creds set <id>${ANSI.reset}` : "hetzer creds set <id>";
        lines.push(boxLine(`  Remediation: Store in encrypted vault with '${cmd}' and use secretRef:<id>`));
    }
    lines.push(boxLine(""));
    lines.push(boxLine("  [Tip] Press [v] to toggle back to Overview."));
}

function renderSniffView(lines, snapshot, color) {
    lines.push(boxLine(`${color ? ANSI.bold : ""}STAGED DIFF SECRET SNIFFER SCAN${color ? ANSI.reset : ""}`));
    const sniff = snapshot.sniff || quickSniffSnapshot(snapshot.root);
    if (sniff.status === "CLEAN") {
        lines.push(boxLine(`  ${color ? ANSI.green : ""}CLEAN: No supported secrets detected in staged diff.${color ? ANSI.reset : ""}`));
        lines.push(boxLine("  Scanner result is clean; review documented false-negative limits before committing."));
    } else if (sniff.status === "VIOLATIONS") {
        lines.push(boxLine(`  ${color ? ANSI.red : ""}CRITICAL: ${sniff.count} secret violation(s) detected!${color ? ANSI.reset : ""}`));
        for (const v of sniff.violations.slice(0, 8)) {
            const loc = v.line ? `${v.file}:L${v.line}` : v.file;
            lines.push(boxLine(`  ${color ? ANSI.red : ""}! [${v.type}] ${bounded(loc, 55)}${color ? ANSI.reset : ""}`));
        }
        lines.push(boxLine(""));
        lines.push(boxLine(`  ${color ? ANSI.red : ""}Action Required: Unstage leaked credentials before committing!${color ? ANSI.reset : ""}`));
        const cmd = color ? `${ANSI.green}git restore --staged <file>${ANSI.reset}` : "git restore --staged <file>";
        lines.push(boxLine(`  Remediation Command: ${cmd}`));
    } else {
        lines.push(boxLine(`  Scan result: ${sniff.error || "Git repo not detected or clean"}`));
    }
    lines.push(boxLine(""));
    lines.push(boxLine("  [Tip] Press [s] to toggle back to Overview."));
}

function renderAuditView(lines, snapshot, color) {
    lines.push(boxLine(`${color ? ANSI.bold : ""}CRYPTOGRAPHIC AUDIT LEDGER (.hetzer/audit.log)${color ? ANSI.reset : ""}`));
    const audit = snapshot.audit || auditLedgerSnapshot(snapshot.root);
    const auditState = colorState(audit.state, color);
    lines.push(boxLine(`  Status     : ${auditState}  (${audit.detail})`));
    if (audit.latestHash) {
        lines.push(boxLine(`  Latest Hash: ${bounded(audit.latestHash, 55)}`));
    }
    if (audit.state === "CORRUPTED" || audit.state === "ERROR") {
        lines.push(boxLine(""));
        lines.push(boxLine(`  ${color ? ANSI.red : ""}Action Required: Cryptographic hash-chain mismatch detected!${color ? ANSI.reset : ""}`));
        const cmd = color ? `${ANSI.green}hetzer audit verify${ANSI.reset}` : "hetzer audit verify";
        lines.push(boxLine(`  Remediation Command: Run '${cmd}' to trace tampered entries.`));
    }
    lines.push(boxLine(""));
    if (!audit.recentEvents || audit.recentEvents.length === 0) {
        lines.push(boxLine("  No audit events recorded yet in this workspace."));
    } else {
        lines.push(boxLine(`  ${bounded("TIMESTAMP", 24)}  ${bounded("EVENT TYPE", 20)}  ${bounded("RESULT", 6)}  ${bounded("TARGET", 18)}`));
        for (const ev of audit.recentEvents.slice(-8)) {
            const ts = bounded(ev.timestamp || "", 24);
            const type = bounded(ev.eventType || "", 20);
            const res = colorState(bounded(ev.result || "", 6).trim(), color);
            const padRes = color ? 6 + (res.length - bounded(ev.result || "", 6).trim().length) : 6;
            const target = bounded(ev.target || "", 18);
            lines.push(boxLine(`  ${ts}  ${type}  ${res.padEnd(padRes)}  ${target}`));
        }
    }
    lines.push(boxLine(""));
    lines.push(boxLine("  [Tip] Press [a] to toggle back to Overview."));
}

function renderCompactOverview(lines, snapshot, color) {
    const threat = snapshot.threat || { state: "ARMED", detail: "1 canary honeytoken" };
    const threatState = colorState(threat.state, color);
    const incidentText = threat.incidentCount > 0
        ? (color ? `${ANSI.red}${threat.incidentCount} INCIDENT(S)!${ANSI.reset}` : `${threat.incidentCount} INCIDENT(S)!`)
        : "0 incidents";
    lines.push(boxLine(`  Threat Radar    ${padColor(threatState, threat.state, 10, color)}  ${bounded(threat.detail, 32)}  ${incidentText}`));

    const vault = snapshot.vault || { state: "n/a", detail: "not initialized" };
    const vaultState = colorState(vault.state, color);
    const keyIso = vault.keyIsolation || (vault.state === "ready" ? "ISOLATED" : "N/A");
    const keyState = colorState(keyIso, color);
    const countInfo = `${vault.totalStored ?? 0} vault / ${vault.secretRefCount ?? 0} ref`;
    lines.push(boxLine(`  Vault Posture   ${padColor(vaultState, vault.state, 10, color)}  Key: ${keyState}  ${bounded(countInfo, 25)}`));

    const shield = snapshot.shield || { preCommit: { state: "N/A", detail: "" }, commitMsg: { state: "N/A", detail: "" }, detectedAgents: [] };
    const preCommitState = colorState(shield.preCommit?.state || "N/A", color);
    const commitMsgState = colorState(shield.commitMsg?.state || "N/A", color);
    const agentList = shield.detectedAgents?.length ? shield.detectedAgents.join(", ") : "none";
    lines.push(boxLine(`  Agent Shield    Pre-Commit: ${preCommitState}  Commit-Msg: ${commitMsgState}  Agents: ${bounded(agentList, 18)}`));

    const runtime = snapshot.runtime || {};
    const container = runtime.container || snapshot.docker || { state: "offline", detail: "Docker not installed" };
    const contState = colorState(container.state, color);
    const brokerState = colorState(runtime.broker?.state || "READY", color);
    const redactorState = colorState(runtime.redactor?.state || "READY", color);
    lines.push(boxLine(`  Runtime Armor   Box: ${contState}  Broker: ${brokerState}  Redactor: ${redactorState}`));

    const sniff = snapshot.sniff || (snapshot.root ? quickSniffSnapshot(snapshot.root) : null);
    if (sniff && sniff.status === "VIOLATIONS") {
        const sniffStateC = colorState("VIOLATIONS", color);
        const sniffDetail = `${sniff.count} secret(s) in staged diff!`;
        lines.push(boxLine(`  Staged Diff     ${padColor(sniffStateC, "VIOLATIONS", 10, color)}  ${sniffDetail}`));
    }

    const issues = analyzeIssues(snapshot);
    if (issues.length > 0) {
        const topIssue = issues[0];
        const sevColor = ["CRITICAL", "HIGH"].includes(topIssue.severity) ? ANSI.red : ANSI.yellow;
        const sevBadge = color ? `${sevColor}[${topIssue.severity}]${ANSI.reset}` : `[${topIssue.severity}]`;
        lines.push(boxLine(`  Action Radar    ${sevBadge} ${bounded(topIssue.action, 30)} -> ${topIssue.command}`));
    }
}

export function renderTui(snapshot, {
    color = process.stdout.isTTY && !process.env.NO_COLOR,
    view = "overview",
    compact = Boolean(process.stdout.isTTY && process.stdout.rows && process.stdout.rows < 22),
    banner = undefined,
} = {}) {
    const showBanner = banner !== undefined ? banner : !compact;
    const title = color ? `${ANSI.cyan}HETZER // TACTICAL ARMOR HUD${ANSI.reset}` : "HETZER // TACTICAL ARMOR HUD";
    const lines = [];

    lines.push(boxTop(title));
    if (showBanner) {
        for (const logoLine of ASCII_LOGO) {
            const padLeft = Math.max(0, Math.floor((INNER_WIDTH - logoLine.length) / 2));
            const coloredLogo = color ? `${ANSI.cyan}${ANSI.bold}${logoLine}${ANSI.reset}` : logoLine;
            lines.push(boxLine(" ".repeat(padLeft) + coloredLogo));
        }
        const subtitle = "DEFENSE-IN-DEPTH RUNTIME ARMOR & THREAT REMEDIATION";
        const subPad = Math.max(0, Math.floor((INNER_WIDTH - subtitle.length) / 2));
        const coloredSub = color ? `${ANSI.dim}${subtitle}${ANSI.reset}` : subtitle;
        lines.push(boxLine(" ".repeat(subPad) + coloredSub));
        lines.push(boxDivider());
    }

    lines.push(boxLine(`${color ? ANSI.dim : ""}Values are observed; unavailable values are N/A.${color ? ANSI.reset : ""}`));
    lines.push(boxLine(`ROOT     ${bounded(snapshot.root, 62)}`));
    const modeTag = compact ? "  REFRESH 2s (COMPACT)" : "  REFRESH 2s";
    lines.push(boxLine(`UPDATED  ${bounded(snapshot.generatedAt, 36)}${modeTag}`));

    // Version update indicator (cache-only, zero network calls)
    try {
        const pkgPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "package.json");
        if (fs.existsSync(pkgPath)) {
            const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
            const cache = readUpdateCache(getUpdateCachePath());
            if (cache?.latestVersion && isNewerVersion(pkg.version, cache.latestVersion)) {
                const updateText = color
                    ? `${ANSI.yellow}UPDATE v${cache.latestVersion} available${ANSI.reset} ${ANSI.dim}(hetzer upgrade)${ANSI.reset}`
                    : `UPDATE v${cache.latestVersion} available (hetzer upgrade)`;
                lines.push(boxLine(updateText));
            }
        }
    } catch {
        // fail soft
    }

    lines.push(boxDivider());

    if (view === "canary") {
        renderCanaryView(lines, snapshot, color);
    } else if (view === "vault") {
        renderVaultView(lines, snapshot, color);
    } else if (view === "sniff") {
        renderSniffView(lines, snapshot, color);
    } else if (view === "audit") {
        renderAuditView(lines, snapshot, color);
    } else if (view === "issues") {
        renderIssuesView(lines, snapshot, color);
    } else if (compact) {
        renderCompactOverview(lines, snapshot, color);
    } else {
        renderOverview(lines, snapshot, color);
    }

    lines.push(boxDivider());
    const issues = analyzeIssues(snapshot);
    const issuesBadge = issues.length > 0
        ? (color ? `${ANSI.yellow}[i] Issues (${issues.length})${ANSI.reset}` : `[i] Issues (${issues.length})`)
        : "[i] Issues (0)";
    const hotkeys = `[r] Refresh   ${issuesBadge}   [c] Canary Log   [a] Audit Log   [v] Vault Keys   [s] Sniff   [q] Exit`;
    lines.push(boxLine(color ? `${ANSI.dim}${hotkeys}${ANSI.reset}` : hotkeys));
    lines.push(boxBottom());

    return lines.join("\n");
}

let currentView = "overview";
let lastSnapshot = null;
let inAltScreen = false;
let activeTimer = null;
let cleanupRegistered = false;

export function enterAltScreen(stream = process.stdout) {
    if (stream.isTTY && !inAltScreen) {
        stream.write("\x1b[?1049h\x1b[?25l");
        inAltScreen = true;
    }
}

export function exitAltScreen(stream = process.stdout) {
    if (inAltScreen) {
        stream.write("\x1b[?1049l\x1b[?25h");
        inAltScreen = false;
    }
}

export function drawFrame(output, options = {}) {
    const stream = options.stream || process.stdout;
    const isTTY = options.isTTY !== undefined ? options.isTTY : Boolean(stream.isTTY);
    if (!isTTY || options.singleShot) {
        stream.write(output + "\n");
        return;
    }
    const lines = output.split("\n");
    const maxRows = stream.rows && stream.rows > 10 ? stream.rows : lines.length;
    const renderLines = lines.length > maxRows ? lines.slice(0, maxRows) : lines;
    let frame = "\x1b[H";
    for (const line of renderLines) {
        frame += line + "\x1b[K\n";
    }
    frame += "\x1b[J";
    stream.write(frame);
}

export async function drawTui(options = {}) {
    let output;
    try {
        lastSnapshot = await collectStatus(options);
        output = renderTui(lastSnapshot, { ...options, view: currentView });
    } catch (error) {
        const errorLines = [
            boxTop("HETZER // TACTICAL ARMOR HUD"),
            boxLine(`STATUS   DEGRADED  ${error.message}`),
            boxBottom(),
        ];
        output = errorLines.join("\n");
    }
    drawFrame(output, options);
    return output;
}

function drawCurrent(options = {}) {
    if (lastSnapshot) {
        drawFrame(renderTui(lastSnapshot, { ...options, view: currentView }), options);
    } else {
        drawTui(options);
    }
}

export function registerExitHandlers(cleanupFn) {
    if (cleanupRegistered) return;
    cleanupRegistered = true;
    const doCleanup = () => {
        try {
            cleanupFn();
        } catch { /* ignore */ }
    };
    process.on("exit", doCleanup);
    process.on("SIGINT", () => {
        doCleanup();
        process.exit(0);
    });
    process.on("SIGTERM", () => {
        doCleanup();
        process.exit(0);
    });
}

export async function startTui({ root = process.cwd(), args = [], view = "overview", stream = process.stdout } = {}) {
    const isInteractive = Boolean(stream.isTTY && process.stdin.isTTY);
    const wantsOnce = args.includes("--once") || args.includes("-1") || args.includes("--no-stream");
    const singleShot = wantsOnce || !isInteractive;
    let initialView = option("--view", view || "overview");
    if (args.includes("--issues") || args.includes("-i")) {
        initialView = "issues";
    }
    currentView = initialView;

    if (singleShot) {
        const snapshot = await collectStatus({ root });
        const rendered = renderTui(snapshot, {
            root,
            view: currentView,
            color: Boolean(stream.isTTY && !process.env.NO_COLOR),
            compact: args.includes("--compact"),
        });
        stream.write(rendered + "\n");
        return;
    }

    refreshDimensions();

    registerExitHandlers(() => {
        if (activeTimer) {
            clearInterval(activeTimer);
            activeTimer = null;
        }
        exitAltScreen();
        if (process.stdin.isTTY) {
            try { process.stdin.setRawMode(false); } catch { /* ignore */ }
        }
    });

    enterAltScreen();

    readline.emitKeypressEvents(process.stdin);
    try {
        process.stdin.setRawMode(true);
    } catch { /* ignore */ }

    const onKeypress = async (_input, key) => {
        if (!key) return;
        if ((key.ctrl && key.name === "c") || key.name === "q") {
            exitAltScreen();
            process.exit(0);
        } else if (key.name === "r") {
            await drawTui({ root });
        } else if (key.name === "i") {
            currentView = currentView === "issues" ? "overview" : "issues";
            drawCurrent({ root });
        } else if (key.name === "c") {
            currentView = currentView === "canary" ? "overview" : "canary";
            drawCurrent({ root });
        } else if (key.name === "a") {
            currentView = currentView === "audit" ? "overview" : "audit";
            drawCurrent({ root });
        } else if (key.name === "v") {
            currentView = currentView === "vault" ? "overview" : "vault";
            drawCurrent({ root });
        } else if (key.name === "s") {
            currentView = currentView === "sniff" ? "overview" : "sniff";
            if (currentView === "sniff" && lastSnapshot) {
                lastSnapshot.sniff = quickSniffSnapshot(root);
            }
            drawCurrent({ root });
        }
    };

    process.stdin.on("keypress", onKeypress);

    const onResize = () => {
        refreshDimensions();
        drawCurrent({ root });
    };
    process.stdout.on("resize", onResize);

    await drawTui({ root });

    if (activeTimer) clearInterval(activeTimer);
    activeTimer = setInterval(() => {
        if (currentView === "overview") {
            drawTui({ root });
        }
    }, 2000);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
    const root = option("--root", process.env.HETZER_ROOT || process.cwd());
    const initialView = option("--view", "overview");
    startTui({ root, args: process.argv.slice(2), view: initialView });
}
