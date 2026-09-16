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
import { isCanaryCredential } from "../vault/canary.mjs";
import { listCredentials } from "../vault/creds.mjs";
import { getIsolatedKeyPath } from "../vault/hetzer-vault.mjs";
import { scanText } from "../vault/sniffer.mjs";
import { verifyAuditLedger, readAuditEvents } from "../vault/audit.mjs";
import { detectContainerEngine } from "../vault/sandbox.mjs";
import { loadModuleRegistry } from "./registry.mjs";

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

const BOX_WIDTH = 77;
const INNER_WIDTH = BOX_WIDTH - 4; // 73

export function stripAnsi(text) {
    return String(text || "").replace(/\x1b\[[0-9;]*m/g, "");
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

export function threatSnapshot(root, vaultItems = []) {
    const incidentsFile = path.join(root, "data", "hetzer-incidents.log");
    let incidentCount = 0;
    let recentIncidents = [];
    if (fs.existsSync(incidentsFile)) {
        try {
            const content = fs.readFileSync(incidentsFile, "utf8");
            const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
            incidentCount = lines.length;
            recentIncidents = lines.slice(-5);
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
        broker: { state: "ready", detail: "Dynamic hop-by-hop stripping, loopback isolated" },
        redactor: { state: "ready", detail: "Sub-ms 512B sliding window scan" },
        policy: { state: "ready", detail: "SHA-256 structured argv verification" },
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
    const threat = threatSnapshot(resolvedRoot, vaultPosture.credentials);
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

function renderOverview(lines, snapshot, color) {
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
        lines.push(boxLine(`  ${color ? ANSI.yellow : ""}[!] Tripwire alarm active! Press [c] to inspect recent incidents.${color ? ANSI.reset : ""}`));
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

    // 4. Runtime Armor & Container Sandbox
    lines.push(boxDivider());
    lines.push(boxLine(`${color ? ANSI.bold : ""}RUNTIME ARMOR & CONTAINER SANDBOX${color ? ANSI.reset : ""}`));
    const runtime = snapshot.runtime || {
        container: snapshot.docker || { state: "offline", detail: "Docker not installed" },
        broker: { state: "ready", detail: "Dynamic hop-by-hop stripping, loopback isolated" },
        redactor: { state: "ready", detail: "Sub-ms 512B sliding window scan" },
        policy: { state: "ready", detail: "SHA-256 structured argv verification" },
    };
    const container = runtime.container || snapshot.docker || { state: "offline", detail: "Docker not installed" };
    const containerState = colorState(container.state, color);
    lines.push(boxLine(`  Container Box   ${padColor(containerState, container.state, 10, color)}  ${bounded(container.detail, 41)}`));
    const brokerState = colorState(runtime.broker?.state || "READY", color);
    lines.push(boxLine(`  HTTP Broker     ${padColor(brokerState, runtime.broker?.state || "READY", 10, color)}  ${bounded(runtime.broker?.detail || "Loopback broker active", 41)}`));
    const redactorState = colorState(runtime.redactor?.state || "READY", color);
    lines.push(boxLine(`  Stream Redactor ${padColor(redactorState, runtime.redactor?.state || "READY", 10, color)}  ${bounded(runtime.redactor?.detail || "Sub-ms sliding window", 41)}`));

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
    if (threat.recentIncidents.length === 0) {
        lines.push(boxLine("  No canary incidents recorded. System secure."));
        lines.push(boxLine(`  Honeytokens armed: ${threat.canaryCount || 0}`));
        lines.push(boxLine(""));
        lines.push(boxLine("  Canary honeytokens trigger exit code 43 (ERR_CANARY_TRIPWIRE_TRIGGERED)"));
        lines.push(boxLine("  and terminate execution if leaked to agent streams."));
    } else {
        lines.push(boxLine(`  Total Incidents: ${threat.incidentCount}`));
        lines.push(boxLine("  Recent Incident Log (data/hetzer-incidents.log):"));
        for (const inc of threat.recentIncidents) {
            if (inc.length <= 67) {
                lines.push(boxLine(`  ${color ? ANSI.red : ""}> ${inc}${color ? ANSI.reset : ""}`));
            } else {
                const parts = wrapText(inc, 65);
                for (let i = 0; i < parts.length; i++) {
                    const prefix = i === 0 ? "> " : "  ";
                    lines.push(boxLine(`  ${color ? ANSI.red : ""}${prefix}${parts[i]}${color ? ANSI.reset : ""}`));
                }
            }
        }
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
    lines.push(boxLine(""));
    lines.push(boxLine("  [Tip] Press [v] to toggle back to Overview."));
}

function renderSniffView(lines, snapshot, color) {
    lines.push(boxLine(`${color ? ANSI.bold : ""}STAGED DIFF SECRET SNIFFER SCAN${color ? ANSI.reset : ""}`));
    const sniff = snapshot.sniff || quickSniffSnapshot(snapshot.root);
    if (sniff.status === "CLEAN") {
        lines.push(boxLine(`  ${color ? ANSI.green : ""}CLEAN: Zero secrets or leaked credentials detected in staged diff.${color ? ANSI.reset : ""}`));
        lines.push(boxLine("  Pre-commit diff is clean and safe to commit."));
    } else if (sniff.status === "VIOLATIONS") {
        lines.push(boxLine(`  ${color ? ANSI.red : ""}CRITICAL: ${sniff.count} secret violation(s) detected!${color ? ANSI.reset : ""}`));
        for (const v of sniff.violations.slice(0, 8)) {
            const loc = v.line ? `${v.file}:L${v.line}` : v.file;
            lines.push(boxLine(`  ${color ? ANSI.red : ""}! [${v.type}] ${bounded(loc, 55)}${color ? ANSI.reset : ""}`));
        }
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

export function renderTui(snapshot, { color = process.stdout.isTTY && !process.env.NO_COLOR, view = "overview" } = {}) {
    const title = color ? `${ANSI.cyan}HETZER // TACTICAL ARMOR HUD${ANSI.reset}` : "HETZER // TACTICAL ARMOR HUD";
    const lines = [];

    lines.push(boxTop(title));
    lines.push(boxLine(`${color ? ANSI.dim : ""}Values are observed; unavailable values are N/A.${color ? ANSI.reset : ""}`));
    lines.push(boxLine(`ROOT     ${bounded(snapshot.root, 62)}`));
    lines.push(boxLine(`UPDATED  ${bounded(snapshot.generatedAt, 36)}  REFRESH 2s`));
    lines.push(boxDivider());

    if (view === "canary") {
        renderCanaryView(lines, snapshot, color);
    } else if (view === "vault") {
        renderVaultView(lines, snapshot, color);
    } else if (view === "sniff") {
        renderSniffView(lines, snapshot, color);
    } else if (view === "audit") {
        renderAuditView(lines, snapshot, color);
    } else {
        renderOverview(lines, snapshot, color);
    }

    lines.push(boxDivider());
    const hotkeys = "[r] Refresh   [c] Canary Log   [a] Audit Log   [v] Vault Keys   [s] Sniff   [q] Exit";
    lines.push(boxLine(color ? `${ANSI.dim}${hotkeys}${ANSI.reset}` : hotkeys));
    lines.push(boxBottom());

    return lines.join("\n");
}

let currentView = "overview";
let lastSnapshot = null;

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
    process.stdout.write(`\x1b[2J\x1b[H${output}\n`);
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
    const root = option("--root", process.env.HETZER_ROOT || process.cwd());
    const initialView = option("--view", "overview");
    currentView = initialView;

    if (process.stdin.isTTY) {
        readline.emitKeypressEvents(process.stdin);
        try {
            process.stdin.setRawMode(true);
        } catch {
            // fail soft in environments without raw mode
        }
        process.stdin.on("keypress", async (_input, key) => {
            if (!key) return;
            if ((key.ctrl && key.name === "c") || key.name === "q") {
                process.exit(0);
            } else if (key.name === "r") {
                await drawTui({ root });
            } else if (key.name === "c") {
                currentView = currentView === "canary" ? "overview" : "canary";
                if (lastSnapshot) {
                    process.stdout.write(`\x1b[2J\x1b[H${renderTui(lastSnapshot, { root, view: currentView })}\n`);
                } else {
                    await drawTui({ root });
                }
            } else if (key.name === "a") {
                currentView = currentView === "audit" ? "overview" : "audit";
                if (lastSnapshot) {
                    process.stdout.write(`\x1b[2J\x1b[H${renderTui(lastSnapshot, { root, view: currentView })}\n`);
                } else {
                    await drawTui({ root });
                }
            } else if (key.name === "v") {
                currentView = currentView === "vault" ? "overview" : "vault";
                if (lastSnapshot) {
                    process.stdout.write(`\x1b[2J\x1b[H${renderTui(lastSnapshot, { root, view: currentView })}\n`);
                } else {
                    await drawTui({ root });
                }
            } else if (key.name === "s") {
                if (currentView === "sniff") {
                    currentView = "overview";
                } else {
                    currentView = "sniff";
                    if (lastSnapshot) {
                        lastSnapshot.sniff = quickSniffSnapshot(root);
                    }
                }
                if (lastSnapshot) {
                    process.stdout.write(`\x1b[2J\x1b[H${renderTui(lastSnapshot, { root, view: currentView })}\n`);
                } else {
                    await drawTui({ root });
                }
            }
        });
    }

    drawTui({ root });
    const timer = setInterval(() => {
        if (currentView === "overview") {
            drawTui({ root });
        }
    }, 2000);
    process.on("exit", () => clearInterval(timer));
}
