#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { isCanaryCredential, triggerCanaryAlert } from "./canary.mjs";
import { Grimoire, resolveMasterKey, resolveVaultPath } from "./hetzer-vault.mjs";
import {
    assertInteractiveHumanSession,
    checkProcessAncestors,
    detectAgentAncestor,
} from "./human-guard.mjs";

export {
    assertInteractiveHumanSession,
    checkProcessAncestors,
    detectAgentAncestor,
};

export const KNOWN_CREDENTIALS = Object.freeze({
    "nine-router-initial-password": Object.freeze({
        envVar: "NINE_ROUTER_INITIAL_PASSWORD",
        moduleId: "9router",
        targetId: "nine-router",
        keyName: "initial_password",
        authType: "password",
        label: "9Router Initial Password",
        description: "Initial login password for 9Router Web UI (http://127.0.0.1:20140).",
        usage: "Open http://127.0.0.1:20140 in browser and log in with this password. If previously run, execute 'hetzer down -v && hetzer up' to reset volume to new password.",
    }),
    "nine-router-jwt-secret": Object.freeze({
        envVar: "NINE_ROUTER_JWT_SECRET",
        moduleId: "9router",
        targetId: "nine-router",
        keyName: "jwt_secret",
        authType: "api-key",
        label: "9Router JWT Secret",
        description: "Secret key for signing JWT session tokens in 9Router.",
        usage: "Used internally by 9Router for browser and API session validation.",
    }),
    "nine-router-api-key-secret": Object.freeze({
        envVar: "NINE_ROUTER_API_KEY_SECRET",
        moduleId: "9router",
        targetId: "nine-router",
        keyName: "api_key_secret",
        authType: "api-key",
        label: "9Router API Key Secret",
        description: "Secret key for client API key hashing/verification in 9Router.",
        usage: "Used internally by 9Router when authenticating client requests.",
    }),
    "nine-router-machine-id-salt": Object.freeze({
        envVar: "NINE_ROUTER_MACHINE_ID_SALT",
        moduleId: "9router",
        targetId: "nine-router",
        keyName: "machine_id_salt",
        authType: "api-key",
        label: "9Router Machine ID Salt",
        description: "Unique machine identification salt for 9Router instance.",
        usage: "Used internally by 9Router for node fingerprint derivation.",
    }),
    "npm-token": Object.freeze({
        envVar: "NODE_AUTH_TOKEN",
        moduleId: "core",
        targetId: "npm",
        keyName: "auth_token",
        authType: "api-key",
        label: "NPM Registry Auth Token",
        description: "npm registry token, injected as NODE_AUTH_TOKEN for npm commands run through hetzer exec.",
        usage: "Hetzer's own npmjs releases use trusted publishing from the release workflow and need no token.",
    }),
    "npm-auth-token": Object.freeze({
        envVar: "NODE_AUTH_TOKEN",
        moduleId: "core",
        targetId: "npm",
        keyName: "auth_token",
        authType: "api-key",
        label: "NPM Auth Token (Alias)",
        description: "Alias of npm-token: npm registry token, injected as NODE_AUTH_TOKEN for npm commands run through hetzer exec.",
        usage: "Hetzer's own npmjs releases use trusted publishing from the release workflow and need no token.",
    }),
    "github-token": Object.freeze({
        envVar: "GITHUB_TOKEN",
        moduleId: "core",
        targetId: "github",
        keyName: "auth_token",
        authType: "api-key",
        label: "GitHub Personal Access Token",
        description: "GitHub Personal Access Token with write:packages, read:packages permission to publish to GitHub Packages.",
        usage: "Used when publishing to https://npm.pkg.github.com. Run 'npm run publish:github'.",
    }),
});

function replaceEnvValue(text, name, value) {
    const line = `${name}=${value}`;
    const pattern = new RegExp(`^${name}=.*$`, "m");
    return pattern.test(text) ? text.replace(pattern, line) : `${text.trimEnd()}\n${line}\n`;
}

function cleanSecretInput(val) {
    return String(val || "")
        .replace(/\x1b\[200~/g, "")
        .replace(/\x1b\[201~/g, "")
        .replace(/\r/g, "")
        .replace(/\n$/, "");
}

export async function promptSecret(promptText = "Enter secret value: ", { input = process.stdin, output = process.stderr } = {}) {
    if (!input.isTTY || typeof input.setRawMode !== "function") {
        const chunks = [];
        for await (const chunk of input) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        return cleanSecretInput(Buffer.concat(chunks).toString("utf8"));
    }
    return new Promise((resolve) => {
        output.write(promptText);
        const wasRaw = input.isRaw;
        input.setRawMode(true);
        input.resume();

        let secret = "";
        const onData = (chunk) => {
            const str = chunk.toString();
            for (let i = 0; i < str.length; i++) {
                const char = str[i];
                if (char === "\r" || char === "\n" || char === "\u0004") {
                    cleanup();
                    output.write("\n");
                    resolve(cleanSecretInput(secret));
                    return;
                } else if (char === "\u0003") { // Ctrl+C
                    cleanup();
                    output.write("\n");
                    process.exit(130);
                } else if (char === "\b" || char === "\x7f") { // Backspace
                    if (secret.length > 0) {
                        secret = secret.slice(0, -1);
                        output.write("\b \b");
                    }
                } else {
                    secret += char;
                    output.write("*");
                }
            }
        };

        function cleanup() {
            input.removeListener("data", onData);
            if (input.setRawMode) input.setRawMode(wasRaw || false);
            if (typeof input.pause === "function") input.pause();
            if (typeof input.unref === "function") input.unref();
        }

        input.on("data", onData);
    });
}


export function promptNativeOsConfirmation(id, { timeoutMs = 20000, platform = process.platform, run = spawnSync } = {}) {
    const displayId = String(id).replace(/[^a-zA-Z0-9._-]/g, "?");
    try {
        if (platform === "win32") {
            const script = `Add-Type -AssemblyName System.Windows.Forms; $r = [System.Windows.Forms.MessageBox]::Show('Hetzer Vault Guard: Reveal raw secret [${displayId}] to terminal context?','Hetzer Credential Guard',[System.Windows.Forms.MessageBoxButtons]::YesNo,[System.Windows.Forms.MessageBoxIcon]::Warning,[System.Windows.Forms.MessageBoxDefaultButton]::Button2); if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }`;
            const res = run("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
                timeout: timeoutMs,
                windowsHide: false,
                stdio: ["ignore", "ignore", "ignore"],
            });
            return res.status === 0;
        } else if (platform === "darwin") {
            const osa = `set response to display dialog "Hetzer Vault Guard: Reveal raw secret '${displayId}' to terminal context?" with title "Hetzer Credential Guard" buttons {"Deny", "Reveal"} default button "Deny" with icon caution; if button returned of response is not "Reveal" then error number 1`;
            const res = run("osascript", ["-e", osa], { timeout: timeoutMs, stdio: ["ignore", "ignore", "ignore"] });
            return res.status === 0;
        } else {
            const res = run("zenity", ["--question", "--title=Hetzer Credential Guard", `--text=Reveal secret ${displayId}?`], { timeout: timeoutMs, stdio: ["ignore", "ignore", "ignore"] });
            return res.status === 0;
        }
    } catch {
        return false;
    }
}

export function authorizeCredentialReveal(id, {
    input = process.stdin,
    env = process.env,
    ancestor,
    confirm = promptNativeOsConfirmation,
} = {}) {
    assertInteractiveHumanSession({ input, env, ancestor });
    if (!confirm(id)) {
        throw new Error(`Access Denied: Native OS confirmation for '${id}' was rejected, unavailable, or timed out.`);
    }
}

function openVault(root, envFile) {
    const values = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const masterKey = resolveMasterKey({ root, envValues: values });
    if (!masterKey || String(masterKey).startsWith("secretRef:")) {
        throw new Error("HETZER_GRIMOIRE_KEY is not set in ~/.hetzer/grimoire.key, .env, or environment. Run 'hetzer init' first.");
    }
    const envVault = resolveVaultPath(root);
    const dbPath = envVault || path.join(root, "data", "hetzer-vault.db");
    return {
        vault: new Grimoire({ dbPath, masterKey }),
        values,
        envFile,
        root,
    };
}

export function listCredentials({ root, envFile }) {
    const { vault } = openVault(root, envFile);
    try {
        const stored = vault.list();
        const storedMap = new Map(stored.map((item) => [item.id, item]));
        const result = [];

        for (const [id, item] of storedMap.entries()) {
            const known = KNOWN_CREDENTIALS[id];
            result.push({
                id,
                module: known?.moduleId || item.projectId || "custom",
                authType: item.authType,
                configured: true,
                description: known?.description || item.notes || item.label || "Stored credential",
                usage: known?.usage || "",
                allowedOrigins: item.allowedOrigins || [],
                rawInjection: item.rawInjection || "deny",
                bindHosts: item.bindHosts || [],
                allowedActions: item.allowedActions || [],
            });
        }

        for (const [id, known] of Object.entries(KNOWN_CREDENTIALS)) {
            if (!storedMap.has(id)) {
                result.push({
                    id,
                    module: known.moduleId,
                    authType: known.authType,
                    configured: false,
                    description: known.description,
                    usage: known.usage,
                });
            }
        }

        return result;
    } finally {
        vault.close();
    }
}

export function revealCredential({ root, envFile, id }) {
    if (isCanaryCredential(id)) {
        triggerCanaryAlert({ id, actor: "caller", action: "creds.reveal", root });
    }
    const { vault } = openVault(root, envFile);
    try {
        const entry = vault.find(id);
        if (!entry) {
            throw new Error(`Credential '${id}' not found in Grimoire Vault.`);
        }
        const secret = vault.reveal(id);
        if (secret === null) {
            throw new Error(`Failed to decrypt credential '${id}'. Ensure HETZER_GRIMOIRE_KEY matches the database.`);
        }
        const known = KNOWN_CREDENTIALS[id] || null;
        return {
            id,
            secret,
            module: known?.moduleId || entry.projectId || "custom",
            authType: entry.authType,
            description: known?.description || entry.notes || entry.label || "Stored credential",
            usage: known?.usage || "",
            createdAt: entry.createdAt,
            updatedAt: entry.updatedAt,
            allowedOrigins: entry.allowedOrigins || [],
            rawInjection: entry.rawInjection || "deny",
            bindHosts: entry.bindHosts || [],
            allowedActions: entry.allowedActions || [],
        };
    } finally {
        vault.close();
    }
}

export async function ensureCredential({ root, envFile, id, promptMessage }) {
    if (!id) throw new Error("Credential ID is required.");
    try {
        const revealed = revealCredential({ root, envFile, id });
        if (revealed && revealed.secret) {
            return revealed.secret;
        }
    } catch {
        // Not found in vault, prompt JIT
    }

    const promptText = promptMessage || `[!] Credential '${id}' is not yet in Grimoire Vault.\nEnter secret value (masked input): `;
    const secret = await promptSecret(promptText);
    if (!secret) {
        throw new Error(`Credential '${id}' cannot be empty.`);
    }
    setCredential({ root, envFile, id, secret });
    return secret;
}

export function setCredential({
    root,
    envFile,
    id,
    secret,
    allowedActions,
    allowedOrigins,
    rawInjection,
    bindHosts,
}) {
    if (!id || typeof id !== "string") throw new Error("Credential ID is required.");
    if (typeof secret !== "string" || !secret) throw new Error("Secret value is required.");

    const { vault, envFile: targetEnv } = openVault(root, envFile);
    try {
        const known = KNOWN_CREDENTIALS[id];
        const targetId = known?.targetId || id.split("-")[0] || "hetzer";
        const keyName = known?.keyName || id;
        const authType = known?.authType || (id.includes("password") ? "password" : "api-key");
        const label = known?.label || id;
        const DEFAULT_ALLOWED_ACTIONS = ["compose.start", "process.start", "broker.proxy", "mcp.tools/call", "mcp.tools.call"];
        vault.upsertTarget({ id: targetId, name: targetId, target_type: "hetzer-module" });
        const existing = vault.find(id);
        const resolvedAllowedActions = allowedActions || (existing?.allowedActions?.length ? existing.allowedActions : DEFAULT_ALLOWED_ACTIONS);
        const resolvedAllowedOrigins = allowedOrigins !== undefined ? allowedOrigins : (existing?.allowedOrigins || []);
        const resolvedRawInjection = rawInjection !== undefined ? rawInjection : (existing?.rawInjection || "deny");
        const resolvedBindHosts = bindHosts !== undefined ? bindHosts : (existing?.bindHosts || []);

        if (existing) {
            vault.update(id, {
                secret,
                allowedActions: resolvedAllowedActions,
                allowedOrigins: resolvedAllowedOrigins,
                rawInjection: resolvedRawInjection,
                bindHosts: resolvedBindHosts,
            });
        } else {
            vault.create({
                id,
                projectId: targetId,
                keyName,
                label,
                authType,
                scope: "env",
                accessRole: "operator",
                allowedActions: resolvedAllowedActions,
                allowedOrigins: resolvedAllowedOrigins,
                rawInjection: resolvedRawInjection,
                bindHosts: resolvedBindHosts,
                secret,
                source: "cli-creds-set",
            });
        }

        let envText = fs.readFileSync(targetEnv, "utf8");
        const envVar = known?.envVar || id.toUpperCase().replace(/[^A-Z0-9]/g, "_");
        envText = replaceEnvValue(envText, envVar, `secretRef:${id}`);
        fs.writeFileSync(targetEnv, envText, { encoding: "utf8", mode: 0o600 });
        try { fs.chmodSync(targetEnv, 0o600); } catch { /* Windows */ }

        vault.recordAudit({
            actor: "hetzer-cli",
            action: "vault.set-credential",
            target_id: targetId,
            credential_id: id,
            reason: "User updated credential via hetzer creds set",
            outcome: "allowed",
            metadata: { envVar, rawInjection: resolvedRawInjection },
        });

        return {
            id,
            envVar,
            module: known?.moduleId || targetId,
            description: known?.description || label,
            usage: known?.usage || "",
            allowedOrigins: resolvedAllowedOrigins,
            rawInjection: resolvedRawInjection,
            bindHosts: resolvedBindHosts,
            allowedActions: resolvedAllowedActions,
        };
    } finally {
        vault.close();
    }
}

export async function approveBrokerPolicyCommand({
    root,
    envFile,
    policyFile,
    input = process.stdin,
    env = process.env,
    ancestor,
} = {}) {
    assertInteractiveHumanSession({
        input,
        env,
        ancestor,
        operation: "'hetzer broker approve'",
    });

    const { loadBrokerPolicy } = await import("./http-broker.mjs");
    const policy = loadBrokerPolicy(policyFile);
    const { vault } = openVault(root, envFile);
    try {
        const result = vault.approveBrokerPolicy({
            credentialId: policy.credentialId,
            policyHash: policy.policyHash,
            targetOrigin: policy.targetOrigin,
            policyPath: policy.policyFile,
            approvedBy: "operator",
        });
        process.stdout.write("================================================================================\n");
        process.stdout.write("  HETZER - BROKER POLICY APPROVED\n");
        process.stdout.write("================================================================================\n");
        process.stdout.write(`  Policy File   : ${policy.policyFile}\n`);
        process.stdout.write(`  Credential    : ${policy.credentialId}\n`);
        process.stdout.write(`  Target Origin : ${result.targetOrigin}\n`);
        process.stdout.write(`  Policy Hash   : ${result.policyHash}\n`);
        process.stdout.write(`  Approved At   : ${result.approvedAt}\n`);
        process.stdout.write("================================================================================\n");
        return result;
    } finally {
        vault.close();
    }
}

export async function grantCredentialCommand({
    root,
    envFile,
    id,
    args = [],
    origin = null,
    raw = null,
    host = null,
    action = null,
    reset = false,
    input = process.stdin,
    output = process.stdout,
    env = process.env,
    ancestor,
} = {}) {
    assertInteractiveHumanSession({
        input,
        env,
        ancestor,
        operation: "'hetzer creds grant'",
    });

    const originsToAdd = [];
    if (origin) originsToAdd.push(...(Array.isArray(origin) ? origin : [origin]));
    let rawInjection = raw ? String(raw).toLowerCase() : undefined;
    const hostsToAdd = [];
    if (host) hostsToAdd.push(...(Array.isArray(host) ? host : [host]));
    const actionsToAdd = [];
    if (action) actionsToAdd.push(...(Array.isArray(action) ? action : [action]));
    let isReset = reset;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg === "--origin" && args[i + 1]) {
            originsToAdd.push(args[++i]);
        } else if (arg === "--raw" && args[i + 1]) {
            const val = String(args[++i]).toLowerCase();
            if (val !== "allow" && val !== "deny") throw new Error("Flag --raw must be 'allow' or 'deny'.");
            rawInjection = val;
        } else if (arg === "--host" && args[i + 1]) {
            hostsToAdd.push(args[++i]);
        } else if (arg === "--action" && args[i + 1]) {
            actionsToAdd.push(args[++i]);
        } else if (arg === "--reset") {
            isReset = true;
        }
    }

    const { vault } = openVault(root, envFile);
    try {
        const existing = vault.find(id);
        if (!existing) throw new Error(`Credential '${id}' was not found in Grimoire Vault.`);

        const allowedOrigins = isReset ? originsToAdd : [...new Set([...(existing.allowedOrigins || []), ...originsToAdd])];
        const rawVal = rawInjection !== undefined ? rawInjection : (isReset ? "deny" : existing.rawInjection);
        const bindHosts = isReset ? hostsToAdd : [...new Set([...(existing.bindHosts || []), ...hostsToAdd])];
        const allowedActions = isReset
            ? (actionsToAdd.length ? actionsToAdd : ["process.start"])
            : [...new Set([...(existing.allowedActions || []), ...actionsToAdd])];

        vault.update(id, {
            allowedOrigins,
            rawInjection: rawVal,
            bindHosts,
            allowedActions,
        });

        vault.recordAudit({
            actor: "operator",
            action: "vault.grant-credential",
            target_id: existing.projectId,
            credential_id: id,
            reason: "Operator updated credential grants via hetzer creds grant",
            outcome: "allowed",
            metadata: { allowedOrigins, rawInjection: raw, bindHosts, allowedActions },
        });

        output.write("================================================================================\n");
        output.write(`  HETZER - CREDENTIAL GRANTS UPDATED: ${id}\n`);
        output.write("================================================================================\n");
        output.write(`  Allowed Origins : ${allowedOrigins.length ? allowedOrigins.join(", ") : "(none)"}\n`);
        output.write(`  Raw Injection   : ${raw}\n`);
        output.write(`  Bind Hosts      : ${bindHosts.length ? bindHosts.join(", ") : "(unbound)"}\n`);
        output.write(`  Allowed Actions : ${allowedActions.join(", ")}\n`);
        output.write("================================================================================\n");

        return { id, allowedOrigins, rawInjection: raw, bindHosts, allowedActions };
    } finally {
        vault.close();
    }
}

/**
 * Review and sign the grants of credentials that predate grant signing.
 *
 * Unsigned grants are not honored until this runs. It is deliberately an interactive operator step:
 * a missing signature is also what a writer without the master key produces, so Hetzer never
 * signs unsigned grants on its own. Rows that carry a signature that does not verify are reported
 * and left alone; use `hetzer creds grant <id> --reset` for those.
 */
export async function signExistingGrantsCommand({
    root,
    envFile,
    input = process.stdin,
    output = process.stdout,
    env = process.env,
    ancestor,
    confirm,
} = {}) {
    assertInteractiveHumanSession({
        input,
        env,
        ancestor,
        operation: "'hetzer creds grant --sign-existing'",
    });

    const { vault } = openVault(root, envFile);
    try {
        const unsigned = vault.listUnsignedGrants();
        const tampered = vault.list().filter((entry) => entry.grantValid === false)
            .map((entry) => entry.id)
            .filter((id) => !unsigned.some((grant) => grant.id === id));

        if (tampered.length) {
            output.write(`[!] Grants with a signature that does not verify (not signed here): ${tampered.join(", ")}\n`);
            output.write("    Reset each with: hetzer creds grant <id> --reset\n");
        }
        if (!unsigned.length) {
            output.write("No credentials with unsigned grants.\n");
            return { signed: [], tampered };
        }

        output.write("================================================================================\n");
        output.write("  HETZER - UNSIGNED CREDENTIAL GRANTS (REVIEW BEFORE SIGNING)\n");
        output.write("================================================================================\n");
        for (const grant of unsigned) {
            output.write(`  ${grant.id}\n`);
            output.write(`    Actions : ${grant.allowedActions.join(", ") || "(none)"}\n`);
            output.write(`    Origins : ${grant.allowedOrigins.join(", ") || "(none)"}\n`);
            output.write(`    Raw     : ${grant.rawInjection}\n`);
            output.write(`    Hosts   : ${grant.bindHosts.join(", ") || "(unbound)"}\n`);
        }
        output.write("================================================================================\n");

        const ask = confirm || (async (question) => {
            const readline = await import("node:readline/promises");
            const rl = readline.createInterface({ input, output });
            try {
                return await rl.question(question);
            } finally {
                rl.close();
            }
        });
        const answer = String(await ask("Sign these grants exactly as shown? Type 'yes' to continue: ")).trim().toLowerCase();
        if (answer !== "yes") {
            output.write("Cancelled. No grants were signed.\n");
            return { signed: [], tampered, cancelled: true };
        }

        const signed = vault.signLegacyGrants(unsigned.map((grant) => grant.id));
        vault.recordAudit({
            actor: "operator",
            action: "vault.sign-legacy-grants",
            reason: "Operator reviewed and signed legacy credential grants via hetzer creds grant --sign-existing",
            outcome: "allowed",
            metadata: { signed },
        });
        output.write(`Signed grants for ${signed.length} credential(s): ${signed.join(", ")}\n`);
        return { signed, tampered };
    } finally {
        vault.close();
    }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const args = process.argv.slice(2);
        const action = args[0] || "list";
        const root = path.resolve(process.env.HETZER_ROOT || process.cwd());
        const envFile = path.resolve(process.env.HETZER_ENV_FILE || path.join(root, ".env"));

        if (action === "list") {
            const list = listCredentials({ root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - CREDENTIAL VAULT (GRIMOIRE)\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write("ID                            MODULE    STATUS      DESCRIPTION\n");
            process.stdout.write("----------------------------  --------  ----------  ----------------------------\n");
            for (const item of list) {
                const idCol = item.id.padEnd(28);
                const modCol = item.module.padEnd(8);
                const statusCol = (item.configured ? "configured" : "not set").padEnd(10);
                process.stdout.write(`${idCol}  ${modCol}  ${statusCol}  ${item.description}\n`);
            }
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write("Commands:\n");
            process.stdout.write("  - Reveal secret value: hetzer creds reveal <id>\n");
            process.stdout.write("  - Save/update value  : hetzer creds set <id> (masked prompt)\n");
            process.stdout.write("================================================================================\n");
        } else if (action === "reveal" || action === "get") {
            const id = args[1];
            if (!id) throw new Error("Usage: hetzer creds reveal <id>");
            authorizeCredentialReveal(id);
            const cred = revealCredential({ root, envFile, id });
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  CREDENTIAL DETAIL: ${cred.id}\n`);
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  Secret Value : ${cred.secret}\n`);
            process.stdout.write(`  Module       : ${cred.module}\n`);
            process.stdout.write(`  Type         : ${cred.authType}\n`);
            process.stdout.write(`  Description  : ${cred.description}\n`);
            if (cred.usage) {
                process.stdout.write(`  Usage        : ${cred.usage}\n`);
            }
            process.stdout.write("================================================================================\n");
        } else if (action === "set") {
            const id = args[1];
            if (!id) throw new Error("Usage: hetzer creds set <id>");
            if (args[2]) throw new Error("Do not pass a secret as a command-line argument. Run 'hetzer creds set <id>' and use the masked prompt.");
            const secret = await promptSecret(`Enter secret value for '${id}': `);
            if (!secret) throw new Error("Secret value is required.");
            const result = setCredential({ root, envFile, id, secret });
            process.stdout.write("================================================================================\n");
            process.stdout.write(`[v] Credential '${result.id}' successfully saved to Vault (AES-256-GCM)!\n`);
            process.stdout.write(`[v] Updated .env configuration: ${result.envVar}=secretRef:${result.id}\n`);
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  Module      : ${result.module}\n`);
            process.stdout.write(`  Description : ${result.description}\n`);
            if (result.usage) {
                process.stdout.write(`  Usage       : ${result.usage}\n`);
            }
            if (result.id.startsWith("npm-")) {
                process.stdout.write(`  Apply       : After 'hetzer creds grant ${result.id} --raw allow', run 'hetzer exec --allow ${result.id} --allow-raw-unmediated ${result.id} -- npm whoami'.\n`);
            } else {
                const upTarget = result.module && result.module !== "core" ? `hetzer up ${result.module}` : "hetzer up";
                process.stdout.write(`  Apply       : Run '${upTarget}' (or 'hetzer up') to reload services.\n`);
            }
            process.stdout.write("================================================================================\n");
        } else if (action === "grant") {
            const id = args[1];
            if (id === "--sign-existing") {
                await signExistingGrantsCommand({ root, envFile });
            } else {
                if (!id) throw new Error("Usage: hetzer creds grant <id> [--origin <url>] [--raw <allow|deny>] [--host <name>] [--action <name>] [--reset] | hetzer creds grant --sign-existing");
                await grantCredentialCommand({ root, envFile, id, args: args.slice(2) });
            }
        } else {
            throw new Error(`Unknown creds command: '${action}'. Use 'list', 'reveal', 'set', or 'grant'.`);
        }
    } catch (error) {
        process.stderr.write(`[hetzer creds error] ${error.message}\n`);
        process.exitCode = error.exitCode || 1;
    }
}

