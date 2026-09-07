#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Grimoire, resolveVaultPath } from "./hetzer-vault.mjs";
import { setCredential } from "./creds.mjs";

export const CANARY_DEFAULT_ID = "canary-token";

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
    const alertMessage = [
        "🚨 ============================================================================",
        "🚨 HETZER CRITICAL SECURITY ALERT: CANARY HONEY-TOKEN TRIGGERED!",
        "🚨 ============================================================================",
        `🚨 Target Decoy    : ${id}`,
        `🚨 Incident Time   : ${timestamp}`,
        `🚨 Suspected Actor : ${actor} (${action})`,
        `🚨 Threat Vector   : Unauthorized Credential Scraping / Agent Prompt Injection`,
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
        const envVault = resolveVaultPath(root);
        const dbPath = envVault || path.join(root, "data", "hetzer-vault.db");
        if (fs.existsSync(dbPath)) {
            const masterKey = process.env.HETZER_GRIMOIRE_KEY || "incident-audit-mode";
            const vault = new Grimoire({ dbPath, masterKey });
            vault.recordAudit({
                actor,
                action: "canary.tripwire",
                target_id: "canary-honeytoken",
                credential_id: id,
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
        `CRITICAL SECURITY VIOLATION: Accessing canary decoy credential '${id}' is forbidden.\n` +
        "This honey-token is a tripwire for detecting prompt injection and automated credential scraping."
    );
    error.code = "ERR_CANARY_TRIPWIRE_TRIGGERED";
    error.exitCode = 43;
    throw error;
}

export function setupCanaryTrap({ root = process.cwd(), envFile, id = CANARY_DEFAULT_ID } = {}) {
    const targetEnv = envFile || path.join(root, ".env");
    const decoyToken = `canary_trap_${crypto.randomBytes(16).toString("hex")}`;
    
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
            process.stdout.write(`  [v] Protection     : If any AI agent or prompt injection attempts to access\n`);
            process.stdout.write(`                       or dump this token, Hetzer immediately halts execution\n`);
            process.stdout.write(`                       and aborts the guarded operation with exit code 43.\n`);
            process.stdout.write("================================================================================\n");
        } else {
            throw new Error(`Unknown canary action '${action}'. Use 'setup'.`);
        }
    } catch (err) {
        process.stderr.write(`[hetzer canary error] ${err.message}\n`);
        process.exitCode = err.exitCode || 1;
    }
}
