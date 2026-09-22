#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Grimoire, resolveVaultPath } from "./hetzer-vault.mjs";
import { setCredential } from "./creds.mjs";
import { recordAuditEvent } from "./audit.mjs";

export const CANARY_DEFAULT_ID = "canary-token";
export const CANARY_TOKEN_PATTERN = /\bcanary_trap_[0-9a-f]{16,64}\b/i;

export function sanitizeCanaryText(value, maxLength = 240) {
    return String(value ?? "")
        .replace(/[\u0000-\u001f\u007f-\u009f]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, maxLength);
}

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
    const safeId = sanitizeCanaryText(id, 120);
    const safeActor = sanitizeCanaryText(actor, 120);
    const safeAction = sanitizeCanaryText(action, 120);
    const alertMessage = [
        "🚨 ============================================================================",
        "🚨 HETZER CRITICAL SECURITY ALERT: CANARY HONEY-TOKEN TRIGGERED!",
        "🚨 ============================================================================",
        `🚨 Target Decoy    : ${safeId}`,
        `🚨 Incident Time   : ${timestamp}`,
        `🚨 Suspected Actor : ${safeActor} (${safeAction})`,
        `🚨 Threat Vector   : ${threatVector}`,
        "🚨 Action Taken    : Guarded operation aborted.",
        "🚨 ============================================================================",
    ].join("\n");

    // Write to audit log and incident log file
    try {
        const incidentsFile = path.join(root, "data", "hetzer-incidents.log");
        fs.mkdirSync(path.dirname(incidentsFile), { recursive: true });
        fs.appendFileSync(incidentsFile, `[${timestamp}] CRITICAL: Canary '${safeId}' triggered by ${safeActor} during ${safeAction}\n`);
    } catch {
        // Fail soft on disk error
    }

    try {
        recordAuditEvent({
            eventType: "CANARY_TRIGGER",
            target: safeId,
            result: "TRIGGERED",
            actor: { actor: safeActor, action: safeAction },
            details: { threatVector, timestamp },
            root,
        });
    } catch {
        // Fail soft
    }

    try {
        const envVault = resolveVaultPath(root);
        const dbPath = envVault || path.join(root, "data", "hetzer-vault.db");
        if (fs.existsSync(dbPath)) {
            const masterKey = process.env.HETZER_GRIMOIRE_KEY || "incident-audit-mode";
            const vault = new Grimoire({ dbPath, masterKey });
            vault.recordAudit({
                actor: safeActor,
                action: "canary.tripwire",
                target_id: "canary-honeytoken",
                credential_id: safeId,
                reason: "Canary honey-token accessed by untrusted caller",
                outcome: "blocked_canary_tripped",
                metadata: { timestamp },
            });
            vault.close();
        }
    } catch {
        // Fail soft
    }

    process.stderr.write(`\n${alertMessage}\n\n`);
    const error = new Error(
        `CRITICAL SECURITY VIOLATION: Accessing canary decoy credential '${safeId}' is forbidden.\n` +
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

export function getCanaryStatus({ root = process.cwd() } = {}) {
    const incidentsFile = path.join(root, "data", "hetzer-incidents.log");
    let incidentCount = 0;
    let recentIncidents = [];
    if (fs.existsSync(incidentsFile)) {
        try {
            const content = fs.readFileSync(incidentsFile, "utf8");
            const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
            incidentCount = lines.length;
            recentIncidents = lines.slice(-10).map((line) => sanitizeCanaryText(line));
        } catch {
            // fail soft
        }
    }

    const envFile = path.join(root, ".env");
    let hasCanaryBinding = false;
    if (fs.existsSync(envFile)) {
        try {
            const envContent = fs.readFileSync(envFile, "utf8");
            hasCanaryBinding = envContent.includes("HETZER_CANARY_TOKEN") || envContent.includes("canary-token");
        } catch {
            // fail soft
        }
    }

    return {
        incidentCount,
        recentIncidents,
        hasCanaryBinding,
        incidentsFile,
        state: incidentCount > 0 ? "TRIPPED" : (hasCanaryBinding ? "ARMED" : "UNARMED"),
    };
}

export function clearCanaryIncidents({ root = process.cwd() } = {}) {
    const incidentsFile = path.join(root, "data", "hetzer-incidents.log");
    if (fs.existsSync(incidentsFile)) {
        try {
            fs.writeFileSync(incidentsFile, "", "utf8");
        } catch {
            // fail soft
        }
    }
    return { ok: true, incidentsFile };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const args = process.argv.slice(2);
        const action = args[0] || "setup";
        const root = path.resolve(process.env.HETZER_ROOT || process.cwd());
        const envFile = path.resolve(process.env.HETZER_ENV_FILE || path.join(root, ".env"));

        if (action === "setup" || action === "enable" || action === "add") {
            const trap = setupCanaryTrap({ root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - CANARY HONEY-TOKEN TRAP DEPLOYED\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Honey-Token ID : ${trap.id}\n`);
            process.stdout.write(`  [v] Decoy Binding  : HETZER_CANARY_TOKEN=${trap.ref}\n`);
            process.stdout.write(`  [v] Protection     : Guarded reveal or environment resolution of this ID\n`);
            process.stdout.write(`                       logs an incident and aborts with exit code 43.\n`);
            process.stdout.write("================================================================================\n");
        } else if (action === "list" || action === "status" || action === "incidents") {
            const status = getCanaryStatus({ root });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - CANARY HONEY-TOKEN TRAP STATUS\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Status         : ${status.state}\n`);
            process.stdout.write(`  [v] Decoy Binding  : ${status.hasCanaryBinding ? "Active in .env" : "Not configured (run hetzer canary setup)"}\n`);
            process.stdout.write(`  [v] Total Incidents: ${status.incidentCount}\n`);
            process.stdout.write(`  [v] Incident Log   : ${status.incidentsFile}\n`);
            if (status.recentIncidents.length > 0) {
                process.stdout.write("--------------------------------------------------------------------------------\n");
                process.stdout.write("  Recent Incidents (last 10):\n");
                for (const inc of status.recentIncidents) {
                    process.stdout.write(`    > ${inc}\n`);
                }
                process.stdout.write("--------------------------------------------------------------------------------\n");
                process.stdout.write("  Guidance:\n");
                process.stdout.write("    * Rotate leaked credentials: hetzer creds set <id>\n");
                process.stdout.write("    * Reset incident alarm after rotating: hetzer canary clear\n");
            } else {
                process.stdout.write("--------------------------------------------------------------------------------\n");
                process.stdout.write("  Zero security incidents recorded. Honeytoken tripwire is intact.\n");
            }
            process.stdout.write("================================================================================\n");
        } else if (action === "clear" || action === "reset") {
            clearCanaryIncidents({ root });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - CANARY INCIDENTS CLEARED\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write("  [v] Incident log data/hetzer-incidents.log reset to 0.\n");
            process.stdout.write("  [v] Threat radar status restored to ARMED.\n");
            process.stdout.write("================================================================================\n");
        } else {
            throw new Error(`Unknown canary action '${action}'. Use 'setup', 'list', or 'clear'.`);
        }
    } catch (err) {
        process.stderr.write(`[hetzer canary error] ${err.message}\n`);
        process.exitCode = err.exitCode || 1;
    }
}
