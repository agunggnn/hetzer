#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { isCanaryCredential, triggerCanaryAlert } from "./canary.mjs";
import { Grimoire, resolveMasterKey, resolveVaultPath } from "./hetzer-vault.mjs";

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
    "cognee-llm-api-key": Object.freeze({
        envVar: "COGNEE_LLM_API_KEY",
        moduleId: "cognee",
        targetId: "cognee",
        keyName: "llm_api_key",
        authType: "api-key",
        label: "Cognee LLM API Key",
        description: "LLM provider API key (OpenAI, Anthropic, OpenRouter, etc.) for Cognee.",
        usage: "Used by Cognee container for knowledge graph extraction and memory indexing.",
    }),
    "cognee-embedding-api-key": Object.freeze({
        envVar: "COGNEE_EMBEDDING_API_KEY",
        moduleId: "cognee",
        targetId: "cognee",
        keyName: "embedding_api_key",
        authType: "api-key",
        label: "Cognee Embedding API Key",
        description: "Optional API key for dedicated embedding models (if separate from LLM key).",
        usage: "Used by Cognee when using a standalone embedding provider.",
    }),
    "npm-token": Object.freeze({
        envVar: "NODE_AUTH_TOKEN",
        moduleId: "core",
        targetId: "npm",
        keyName: "auth_token",
        authType: "api-key",
        label: "NPM Registry Auth Token",
        description: "NPM authentication token to publish hetzer package to npm registry.",
        usage: "Used when publishing to https://registry.npmjs.org/. Run 'npm run publish-pkg' or 'hetzer publish'.",
    }),
    "npm-auth-token": Object.freeze({
        envVar: "NODE_AUTH_TOKEN",
        moduleId: "core",
        targetId: "npm",
        keyName: "auth_token",
        authType: "api-key",
        label: "NPM Auth Token (Alias)",
        description: "NPM authentication token alias to publish hetzer package to npm registry.",
        usage: "Used when publishing to https://registry.npmjs.org/. Run 'npm run publish-pkg' or 'hetzer publish'.",
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

export async function promptSecret(promptText = "Enter secret value: ", { input = process.stdin, output = process.stderr } = {}) {
    if (!input.isTTY || typeof input.setRawMode !== "function") {
        const chunks = [];
        for await (const chunk of input) {
            chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        }
        return Buffer.concat(chunks).toString("utf8").trim();
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
                    resolve(secret);
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


const AGENT_PROCESS_NAMES = ["agy", "cursor", "electron", "code", "claude", "hermes", "ollama"];

export function detectAgentAncestor(names = []) {
    for (const rawName of names) {
        const name = String(rawName).toLowerCase().trim();
        if (AGENT_PROCESS_NAMES.some((target) => name.includes(target))) {
            return { isAgent: true, processName: name };
        }
    }
    return { isAgent: false };
}

export function checkProcessAncestors({ platform = process.platform, pid = process.pid, run = spawnSync, maxDepth = 5 } = {}) {
    try {
        if (platform === "win32") {
            const script = [
                `$current = Get-CimInstance Win32_Process -Filter "ProcessId = ${Number(pid)}"`,
                `for ($i = 0; $i -lt ${Number(maxDepth)}; $i++) {`,
                "if (-not $current -or $current.ParentProcessId -le 0) { break }",
                "$current = Get-CimInstance Win32_Process -Filter \"ProcessId = $($current.ParentProcessId)\"",
                "if ($current) { Write-Output ($current.ProcessId.ToString() + \"`t\" + $current.Name) }",
                "}",
            ].join("; ");
            const res = run("powershell", [
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ], { encoding: "utf8", timeout: 2500, windowsHide: true });
            if (res.status === 0 && res.stdout) {
                const names = res.stdout.split(/\r?\n/).map((line) => line.split("\t").slice(1).join("\t")).filter(Boolean);
                return detectAgentAncestor(names);
            }
        } else {
            const res = run("ps", ["-axo", "pid=,ppid=,comm="], {
                encoding: "utf8", timeout: 2500, windowsHide: true,
            });
            if (res.status === 0 && res.stdout) {
                const processes = new Map();
                for (const line of res.stdout.split(/\r?\n/)) {
                    const match = /^\s*(\d+)\s+(\d+)\s+(.+?)\s*$/.exec(line);
                    if (match) processes.set(Number(match[1]), { parentPid: Number(match[2]), name: match[3] });
                }
                const names = [];
                let currentPid = Number(pid);
                for (let depth = 0; depth < maxDepth; depth += 1) {
                    const current = processes.get(currentPid);
                    if (!current || current.parentPid <= 0 || current.parentPid === currentPid) break;
                    const parent = processes.get(current.parentPid);
                    if (!parent) break;
                    names.push(parent.name);
                    currentPid = current.parentPid;
                }
                return detectAgentAncestor(names);
            }
        }
    } catch {
        // Ancestor check failed or timed out; continue to env and TTY checks
    }
    return { isAgent: false };
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
            const osa = `display dialog "Hetzer Vault Guard: Reveal raw secret '${displayId}' to terminal context?" with title "Hetzer Credential Guard" buttons {"Deny", "Reveal"} default button "Deny" with icon caution`;
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

export function assertInteractiveHumanSession({ input = process.stdin, env = process.env, ancestor } = {}) {
    if (!input.isTTY) {
        throw new Error(
            "Access Denied: 'hetzer creds reveal' requires a direct human interactive TTY terminal.\n" +
            "Autonomous agent / non-interactive programmatic secret revelation is blocked to prevent context window leakage."
        );
    }
    const agentIndicators = [
        ["ANTIGRAVITY_AGENT", "Antigravity Agent runtime detected"],
        ["CURSOR_PROJECT_DIR", "Cursor IDE Agent runtime detected"],
        ["CURSOR_TRACE_ID", "Cursor Agent session detected"],
        ["CLAUDE_CODE", "Claude Code session detected"],
        ["VSCODE_PID", "VS Code agent process runner detected"],
        ["HERMES_AGENT", "Hermes Agent session detected"],
        ["CI", "Continuous Integration / non-interactive pipeline detected"],
    ];
    for (const [envVar, desc] of agentIndicators) {
        if (env[envVar]) {
            throw new Error(
                `Access Denied: 'hetzer creds reveal' blocked by Zero-Plaintext Agent Guard.\n` +
                `Reason: ${desc} ($${envVar} is set).\n` +
                `Autonomous agents running in YOLO/unrestricted mode cannot extract raw secrets into context.\n` +
                `To execute commands with injected secrets safely, use 'hetzer exec -- <command>'.`
            );
        }
    }
    const ancestry = ancestor || checkProcessAncestors();
    if (ancestry.isAgent) {
        throw new Error(
            `Access Denied: 'hetzer creds reveal' blocked by Zero-Plaintext Agent Guard.\n` +
            `Reason: Agent runtime '${ancestry.processName}' detected in process tree ancestry.\n` +
            `Autonomous agents running in YOLO/unrestricted mode cannot extract raw secrets into context.\n` +
            `To execute commands with injected secrets safely, use 'hetzer exec -- <command>'.`
        );
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

export function setCredential({ root, envFile, id, secret }) {
    if (!id || typeof id !== "string") throw new Error("Credential ID is required.");
    if (typeof secret !== "string" || !secret) throw new Error("Secret value is required.");

    const { vault, envFile: targetEnv } = openVault(root, envFile);
    try {
        const known = KNOWN_CREDENTIALS[id];
        const targetId = known?.targetId || id.split("-")[0] || "hetzer";
        const keyName = known?.keyName || id;
        const authType = known?.authType || (id.includes("password") ? "password" : "api-key");
        const label = known?.label || id;
        const allowedActions = ["compose.start", "process.start"];

        vault.upsertTarget({ id: targetId, name: targetId, target_type: "hetzer-module" });
        const existing = vault.find(id);
        if (existing) {
            vault.update(id, { secret, allowedActions });
        } else {
            vault.create({
                id,
                projectId: targetId,
                keyName,
                label,
                authType,
                scope: "env",
                accessRole: "operator",
                allowedActions,
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
            metadata: { envVar },
        });

        return {
            id,
            envVar,
            module: known?.moduleId || targetId,
            description: known?.description || label,
            usage: known?.usage || "",
        };
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
            process.stdout.write("  - Save/update value  : hetzer creds set <id> [value] (prompts if omitted)\n");
            process.stdout.write("================================================================================\n");
        } else if (action === "reveal" || action === "get") {
            const id = args[1];
            if (!id) throw new Error("Usage: hetzer creds reveal <id> [--confirm-ui]");
            assertInteractiveHumanSession();
            if (process.env.HETZER_REQUIRE_OOB_CONFIRM === "1" || args.includes("--confirm-ui")) {
                const confirmed = promptNativeOsConfirmation(id);
                if (!confirmed) {
                    throw new Error(`Access Denied: Out-of-Band (OOB) OS confirmation for '${id}' was rejected or timed out.`);
                }
            }
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
            let secret = args[2];
            if (!id) throw new Error("Usage: hetzer creds set <id> [value]");
            if (!secret) {
                secret = await promptSecret(`Enter secret value for '${id}': `);
            }
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
                process.stdout.write("  Apply       : Run 'node scripts/publish.mjs' or 'npm run publish-pkg' to publish to npm.\n");
            } else {
                const upTarget = result.module && result.module !== "core" ? `hetzer up ${result.module}` : "hetzer up";
                process.stdout.write(`  Apply       : Run '${upTarget}' (or 'hetzer up') to reload services.\n`);
            }
            process.stdout.write("================================================================================\n");
        } else {
            throw new Error(`Unknown creds command: '${action}'. Use 'list', 'reveal', or 'set'.`);
        }
    } catch (error) {
        process.stderr.write(`[hetzer creds error] ${error.message}\n`);
        process.exitCode = error.exitCode || 1;
    }
}
