import "./suppress-warnings.mjs";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { listMcpTools, runMcpToolCommand } from "../mcp/call.mjs";
import { configureMcp } from "../mcp/configure.mjs";
import { diagnoseMcpService } from "../mcp/ping.mjs";
import { KNOWN_CREDENTIALS, assertInteractiveHumanSession, authorizeCredentialReveal, listCredentials, promptSecret, revealCredential, setCredential } from "../vault/creds.mjs";
import { approveCredentialRequest, createCredentialRequest, getCredentialRequest } from "../vault/credential-request.mjs";
import { isolateMasterKey, resolveMasterKey } from "../vault/hetzer-vault.mjs";
import { autoIngestPlaintextEnv, migrateEnvCredentials } from "../vault/migrate-env.mjs";
import { setupCanaryTrap } from "../vault/canary.mjs";
import { readAuditEvents, rotateAuditLedger, verifyAuditLedger } from "../vault/audit.mjs";
import { redactAndVault, scanText, restoreSecrets } from "../vault/sniffer.mjs";
import { getHetzerAsciiBanner, printHetzerBanner } from "./banner.mjs";
import { runDoctor } from "./doctor.mjs";
import { auditAgentContext } from "../skills/audit.mjs";
import { parseEnv } from "./env.mjs";

const cliRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const templatesDir = path.join(cliRoot, "templates");

export function defaultHetzerHome() {
    if (process.env.HETZER_HOME) return path.resolve(process.env.HETZER_HOME);
    return path.join(os.homedir(), ".hetzer");
}

export function isHetzerWorkspace(dir) {
    const envFile = path.join(dir, ".env");
    const exampleFile = path.join(dir, ".env.example");
    const vaultDb = path.join(dir, "data", "hetzer-vault.db");
    if (fs.existsSync(vaultDb)) return true;
    for (const f of [envFile, exampleFile]) {
        if (fs.existsSync(f)) {
            try {
                const content = fs.readFileSync(f, "utf8");
                if (content.includes("HETZER_") || content.includes("hetzer")) return true;
            } catch {
                // ignore
            }
        }
    }
    const composeFile = path.join(dir, "docker-compose.yml");
    if (fs.existsSync(composeFile)) {
        try {
            const content = fs.readFileSync(composeFile, "utf8");
            return content.includes("hetzer") || content.includes("nine-router") || content.includes("NINE_ROUTER");
        } catch {
            return false;
        }
    }
    return false;
}

export function resolveProjectRoot(options = {}) {
    if (options.root) {
        return path.resolve(options.root);
    }
    if (process.env.HETZER_ROOT) {
        return path.resolve(process.env.HETZER_ROOT);
    }
    const cwd = process.cwd();
    if (isHetzerWorkspace(cwd)) {
        return cwd;
    }
    return defaultHetzerHome();
}

export function isGlobalCliInstalled() {
    if (process.env.HETZER_TEST_GLOBAL_CLI !== undefined) {
        return process.env.HETZER_TEST_GLOBAL_CLI === "true";
    }
    if (process.argv[1] && process.argv[1].includes("_npx")) {
        return false;
    }
    const cmd = process.platform === "win32" ? "where.exe" : "which";
    try {
        const result = spawnSync(cmd, ["hetzer"], {
            encoding: "utf8",
            windowsHide: true,
            stdio: "pipe",
        });
        if (result.status !== 0 || !result.stdout) return false;
        const matches = result.stdout.split(/\r?\n/).filter(Boolean);
        return matches.some((p) => !p.includes("_npx"));
    } catch {
        return false;
    }
}

export function levenshteinDistance(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    const row = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
        let prev = i;
        for (let j = 1; j <= b.length; j++) {
            const val = a[i - 1] === b[j - 1] ? row[j - 1] : Math.min(row[j - 1], prev, row[j]) + 1;
            row[j - 1] = prev;
            prev = val;
        }
        row[b.length] = prev;
    }
    return row[b.length];
}

export function suggestCommand(input) {
    const primaryCommands = [
        "help", "doctor", "init", "protect", "skill", "hook",
        "sniffer", "creds", "canary", "audit", "exec", "broker",
        "mcp", "version",
    ];
    const lower = String(input || "").toLowerCase();
    for (const cmd of primaryCommands) {
        if (cmd.startsWith(lower)) {
            return cmd;
        }
    }
    for (const cmd of primaryCommands) {
        if (lower.length >= 3 && lower.startsWith(cmd)) {
            return cmd;
        }
    }
    let bestMatch = null;
    let minDistance = 3;
    for (const cmd of primaryCommands) {
        const dist = levenshteinDistance(lower, cmd);
        if (dist < minDistance) {
            minDistance = dist;
            bestMatch = cmd;
        }
    }
    return bestMatch;
}

export const KNOWN_COMMANDS = new Set([
    "help", "--help", "-h",
    "version", "--version", "-v",
    "doctor",
    "init",
    "protect", "armor", "protec",
    "skill", "skills",
    "hook", "hooks",
    "sniffer", "sniff",
    "creds", "credentials",
    "canary",
    "audit",
    "exec",
    "broker",
    "mcp",
    // Deprecated commands retained for informative redirection
    "up",
    "down",
    "status",
    "logs",
    "modules",
    "install",
    "remove",
    "module",
    "validate",
    "tui",
    "update",
    "upgrade",
    "check-update", "check_update",
    "publish",
]);

function replaceEnvValue(text, name, value) {
    const line = `${name}=${value}`;
    const pattern = new RegExp(`^${name}=.*$`, "m");
    return pattern.test(text) ? text.replace(pattern, line) : `${text.trimEnd()}\n${line}\n`;
}

function copyIfMissing(source, target) {
    if (fs.existsSync(target)) return false;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.cpSync(source, target, { recursive: true, errorOnExist: true });
    return true;
}

function run(file, args, options = {}) {
    const adjustedArgs = file === process.execPath && !args.includes("--no-warnings=ExperimentalWarning")
        ? ["--no-warnings=ExperimentalWarning", ...args]
        : args;
    const result = spawnSync(file, adjustedArgs, {
        cwd: options.cwd,
        env: options.env || process.env,
        stdio: options.capture ? "pipe" : "inherit",
        encoding: options.capture ? "utf8" : undefined,
        windowsHide: true,
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
        const message = options.capture ? String(result.stderr || result.stdout || "").trim() : "";
        throw new Error(message || `${path.basename(file)} exited with status ${result.status}.`);
    }
    return options.capture ? String(result.stdout || "") : "";
}

function projectEnvironment(root) {
    const envFile = path.join(root, ".env");
    if (!fs.existsSync(envFile)) {
        const isHome = root === defaultHetzerHome();
        const locationMsg = isHome ? "Global user home (~/.hetzer)" : `Directory '${root}'`;
        throw new Error(`${locationMsg} is not initialized (.env file not found).\nRun 'hetzer init' first to create initial configuration.`);
    }
    try {
        autoIngestPlaintextEnv({ root, envFile });
    } catch {
        // Continue if auto-ingest encounters non-fatal issue
    }
    const values = parseEnv(fs.readFileSync(envFile, "utf8"));
    return { envFile, values };
}

function handleDeprecatedCommand(command) {
    process.stderr.write(`[!] DEPRECATED: Multi-container stack orchestration in Hetzer ('hetzer ${command}') has been removed. Use Jagdpanzer (https://github.com/agunggnn/jagdpanzer) for full ops stacks.\n`);
    process.exitCode = 1;
}

export function initializeProject(root) {
    const resolvedRoot = path.resolve(root);
    // Refuses when only the retired key alias is configured: generating a key below would leave the existing vault undecryptable.
    const priorEnvFile = path.join(resolvedRoot, ".env");
    resolveMasterKey({ root: resolvedRoot, envValues: fs.existsSync(priorEnvFile) ? parseEnv(fs.readFileSync(priorEnvFile, "utf8")) : {} });
    fs.mkdirSync(resolvedRoot, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(resolvedRoot, 0o700); } catch { /* Windows */ }
    copyIfMissing(path.join(templatesDir, ".env.example"), path.join(resolvedRoot, ".env.example"));

    const dataDir = path.join(resolvedRoot, "data");
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dataDir, 0o700); } catch { /* Windows */ }

    const envFile = path.join(resolvedRoot, ".env");
    copyIfMissing(path.join(resolvedRoot, ".env.example"), envFile);
    let text = fs.readFileSync(envFile, "utf8");
    const values = parseEnv(text);
    if (!values.HETZER_GRIMOIRE_KEY || String(values.HETZER_GRIMOIRE_KEY).startsWith("replace-")) {
        text = replaceEnvValue(text, "HETZER_GRIMOIRE_KEY", crypto.randomBytes(48).toString("base64url"));
    }
    fs.writeFileSync(envFile, text, { encoding: "utf8", mode: 0o600 });
    try { fs.chmodSync(envFile, 0o600); } catch { /* Windows ACLs are managed by the host. */ }

    const current = parseEnv(text);
    migrateEnvCredentials({
        root: resolvedRoot,
        envFile,
        masterKey: process.env.HETZER_GRIMOIRE_KEY || current.HETZER_GRIMOIRE_KEY,
        authorizationRef: "user:hetzer-init",
    });
    try {
        configureMcp(resolvedRoot);
    } catch { /* ignore */ }
    return {
        root: resolvedRoot,
        envFile,
    };
}

function printInitWizard(result) {
    const isGlobal = result.root === defaultHetzerHome();
    const globalCli = isGlobalCliInstalled();
    const prefix = globalCli ? "hetzer" : "npx hetzer";
    process.stdout.write("================================================================================\n");
    process.stdout.write("  HETZER - INITIALIZATION SUCCESSFUL\n");
    process.stdout.write("================================================================================\n");
    process.stdout.write(`[v] Instance Location : ${result.root}${isGlobal ? " (Global User Home)" : " (Local Workspace)"}\n`);
    process.stdout.write(`[v] Configuration File: .env (permissions secured chmod 600)\n`);
    process.stdout.write(`[v] Grimoire Vault    : data/hetzer-vault.db (AES-256-GCM Encrypted)\n`);
    process.stdout.write(`[v] MCP Server        : .mcp.json configured\n`);
    if (isGlobal && !globalCli) {
        process.stdout.write(`[!] Global Access     : 'hetzer' is NOT in your system PATH (running via npx or local script).\n`);
        process.stdout.write(`                        To run direct commands, install globally:\n`);
        process.stdout.write(`                          npm install -g hetzer\n`);
        process.stdout.write(`                        Or prefix commands with npx: 'npx hetzer <command>'\n`);
    }
    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write("  NEXT STEPS:\n");
    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write(`  1. Guard execution   : ${prefix} exec -- <command>\n`);
    process.stdout.write(`  2. Protect workspace : ${prefix} protect\n`);
    process.stdout.write(`  3. Manage secrets    : ${prefix} creds [list|set|reveal]\n`);
    process.stdout.write(`  4. Inspect audit log : ${prefix} audit [tail|verify]\n`);
    process.stdout.write("================================================================================\n");
}

export function help() {
    const banner = getHetzerAsciiBanner({ colored: Boolean(process.stdout.isTTY) });
    return `${banner}

Usage: hetzer [options] <command> [arguments]

Options:
  --root <path>             Specify instance root directory (default: ~/.hetzer)

Commands:
  init [directory]          Initialize a new instance (.env, Grimoire Vault, and MCP configuration)
  doctor [--fix]            Check system compatibility (--fix to auto-repair)
  protect                   Install credential-safety guidance, Git hook, and .env protection
  skill [install|status]    Deploy Universal AI Skills to Hermes, AGY, OpenCode, Cursor, Claude
  hook [install|uninstall|check] Manage Git Pre-Commit Guard to prevent accidental token leaks
  sniffer [scan|redact] <t> Detect or redact credentials supported by the scanner rules
  creds [list|request|approve|status|reveal|set|grant|isolate-key] Manage encrypted secrets in Grimoire Vault (AES-256-GCM)
  canary [setup]            Deploy decoy canary honey-token tripwire to catch prompt injections
  audit [verify [--require-mac]|tail [n]|rotate [--yes] [--reason <text>] [--allow-unkeyed]]
                              Verify the hash-chain (and MACs), inspect the ledger, or archive it and start a new one
  exec [--allow <ids>] [--policy <file>] [--sandbox [image]] [--sandbox-mount <dir>] [--host] [--strict] [--canary] [--timeout <t>] -- <c>
                              Run with mediated credentials; raw injection requires an audited opt-out
  broker --policy <file> -- <command>   Run an HTTP client using a short-lived capability instead of the real credential
  mcp configure|serve|ping  Configure, start bridge, or run MCP diagnostic ping
  mcp tools <service>       List MCP tools with Offline / Hybrid / LLM classification
  mcp call <srv> <tool> [a] Call MCP tool directly from CLI without external AI client
  version                   Display Hetzer version

Deprecated Commands (Delegated to Jagdpanzer):
  up, down, status, logs, modules, install, remove, module, validate, tui
                            Use Jagdpanzer (https://github.com/agunggnn/jagdpanzer) for full ops stacks
`;
}

export async function main(argv = process.argv.slice(2), options = {}) {
    const parsedArgs = [...argv];
    let rootOption = options.root;
    const rootIndex = parsedArgs.indexOf("--root");
    if (rootIndex !== -1 && parsedArgs[rootIndex + 1]) {
        rootOption = parsedArgs[rootIndex + 1];
        parsedArgs.splice(rootIndex, 2);
    }
    const command = parsedArgs[0] || "help";
    const args = parsedArgs.slice(1);
    const root = resolveProjectRoot({ root: rootOption });

    if (!KNOWN_COMMANDS.has(command)) {
        const suggested = suggestCommand(command);
        const suggestionMsg = suggested ? ` Did you mean 'hetzer ${suggested}'?` : "";
        throw new Error(`Unknown command '${command}'.${suggestionMsg} Run 'hetzer help'.`);
    }

    if (["help", "--help", "-h"].includes(command)) {
        process.stdout.write(help());
        return;
    }
    if (["version", "--version", "-v"].includes(command)) {
        const manifest = JSON.parse(fs.readFileSync(path.join(cliRoot, "..", "package.json"), "utf8"));
        process.stdout.write(`hetzer v${manifest.version}\n`);
        return;
    }
    if (["check-update", "check_update", "upgrade"].includes(command)) {
        process.stderr.write("Hetzer CLI upgrades are managed via npm: run 'npm install -g hetzer@latest' to update.\n");
        process.exitCode = 1;
        return;
    }
    if (command === "publish") {
        process.stderr.write("Hetzer releases are published by .github/workflows/release-main.yml when a change merges to main; npmjs versions are staged there and approved by a maintainer with 2FA.\n");
        process.exitCode = 1;
        return;
    }
    if (["up", "down", "status", "logs", "modules", "install", "remove", "module", "validate", "tui", "update"].includes(command)) {
        handleDeprecatedCommand(command);
        return;
    }
    if (command === "doctor") {
        const fix = args.includes("--fix");
        const result = runDoctor({ root, defaultHome: defaultHetzerHome(), fix });
        if (!result.ok) process.exitCode = 1;
        return;
    }
    if (command === "init") {
        const target = args[0]
            ? path.resolve(args[0])
            : (rootOption
                ? path.resolve(rootOption)
                : (isHetzerWorkspace(process.cwd()) ? process.cwd() : defaultHetzerHome()));
        const result = initializeProject(target);
        printInitWizard(result);
        return;
    }

    if (["protect", "armor", "protec"].includes(command)) {
        const workspaceRoot = rootOption ? path.resolve(rootOption) : process.cwd();

        // 1. Install universal skills to all detected and supported AI agents
        run(process.execPath, [
            path.join(cliRoot, "skills", "installer.mjs"),
            "install",
            "all",
        ], { cwd: workspaceRoot });

        // 2. Install git pre-commit hook if .git folder exists
        let gitHookInstalled = false;
        if (fs.existsSync(path.join(workspaceRoot, ".git"))) {
            try {
                run(process.execPath, [
                    path.join(cliRoot, "core", "git-hook.mjs"),
                    "install",
                ], { cwd: workspaceRoot });
                gitHookInstalled = true;
            } catch {
                // non-fatal
            }
        }

        // 3. Scan & auto-ingest .env if present
        let envStatus = "No .env file found";
        const envFile = path.join(workspaceRoot, ".env");
        if (fs.existsSync(envFile)) {
            try {
                const migrated = autoIngestPlaintextEnv({ root: workspaceRoot, envFile });
                envStatus = migrated.length
                    ? `${migrated.length} credential(s) vaulted into AES-256-GCM`
                    : "No credentials migrated; review Vault key and .env values";
            } catch {
                envStatus = "Migration failed; run the migration command for diagnostics";
            }
        }

        process.stdout.write("\n================================================================================\n");
        process.stdout.write("  🛡️ HETZER CREDENTIAL GUARDS CONFIGURED\n");
        process.stdout.write("================================================================================\n");
        process.stdout.write("  [v] Agent Skills       : Installation attempted for supported detected agents\n");
        process.stdout.write(`  [v] Git Pre-Commit     : ${gitHookInstalled ? "Hook installed for supported scanner rules" : "Skipped (no .git directory found)"}\n`);
        process.stdout.write(`  [v] Workspace .env     : ${envStatus}\n`);
        process.stdout.write("  [v] Resource Overhead  : 0 Docker containers, 0 background RAM, 0 npm dependencies\n");
        const contextAudit = auditAgentContext(workspaceRoot);
        process.stdout.write(`  [v] Context Overhead   : ${contextAudit.summary}\n`);
        process.stdout.write("--------------------------------------------------------------------------------\n");
        process.stdout.write("  These controls reduce accidental credential disclosure; review the documented boundaries.\n");
        if (!isGlobalCliInstalled()) {
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write("  ℹ️  CLI PATH NOTICE:\n");
            process.stdout.write("      'hetzer' is not in your system PATH (running via npx or local script).\n");
            process.stdout.write("      * Passive Guards (Active) : Prompt protection & Git hook work immediately.\n");
            process.stdout.write("      * Scoped Execution        : For agents to run 'hetzer exec', install globally:\n");
            process.stdout.write("                                  npm install -g hetzer\n");
            process.stdout.write("                                  (or prefix commands with npx: npx hetzer <cmd>)\n");
        }
        process.stdout.write("================================================================================\n");
        return;
    }

    if (["skill", "skills"].includes(command)) {
        const action = args[0] || "install";
        const target = args[1] || "all";
        const skillRoot = rootOption ? path.resolve(rootOption) : process.cwd();
        run(process.execPath, [
            path.join(cliRoot, "skills", "installer.mjs"),
            action,
            target,
        ], { cwd: skillRoot });
        return;
    }
    if (["hook", "hooks"].includes(command)) {
        const action = args[0] || "check";
        const hookRoot = rootOption ? path.resolve(rootOption) : process.cwd();
        run(process.execPath, [
            path.join(cliRoot, "core", "git-hook.mjs"),
            action,
            ...args.slice(1),
        ], { cwd: hookRoot });
        return;
    }
    if (["sniffer", "sniff"].includes(command)) {
        const sub = args[0] || "scan";
        const input = args.slice(1).join(" ");
        if (!input) {
            throw new Error("Usage: hetzer sniffer <scan|redact> <text>");
        }
        if (sub === "scan") {
            const res = scanText(input);
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - SECRET SNIFFER\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  Detection Status : ${res.hasSecrets ? "[!] SECRETS DETECTED" : "[v] CLEAN (No secrets detected)"}\n`);
            process.stdout.write(`  Execution Time   : ${res.latencyMs} ms\n`);
            if (res.hasSecrets) {
                process.stdout.write("--------------------------------------------------------------------------------\n");
                for (const m of res.matches) {
                    process.stdout.write(`  * ${m.label} (${m.type}) at index ${m.index}\n`);
                }
            }
            process.stdout.write("================================================================================\n");
            return;
        }
    }

    if (command === "audit") {
        const sub = args[0] || "tail";
        if (sub === "verify") {
            const result = verifyAuditLedger({ root, requireMac: args.includes("--require-mac") ? true : undefined });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - AUDIT LEDGER INTEGRITY VERIFICATION\n");
            process.stdout.write("================================================================================\n");
            if (result.ok) {
                process.stdout.write("  Status       : [v] VERIFIED (Cryptographic hash-chain intact)\n");
                process.stdout.write(`  Total Events : ${result.count}\n`);
                process.stdout.write(`  Keyed Entries: ${result.keyedEntries || 0}${result.macVerified ? " (MAC verified with the master key)" : " (MAC not checked)"}\n`);
                if (result.latestHash) {
                    process.stdout.write(`  Latest Hash  : ${result.latestHash}\n`);
                }
            } else {
                process.stdout.write("  Status       : [!] INTEGRITY FAILED (Tampering detected)\n");
                process.stdout.write(`  Error        : ${result.error}\n`);
                if (result.tamperedIndex !== undefined) {
                    process.stdout.write(`  At Entry     : #${result.tamperedIndex}\n`);
                }
                process.exitCode = 1;
            }
            process.stdout.write("================================================================================\n");
            return;
        }
        if (sub === "tail" || sub === "log" || sub === "list") {
            const countArg = args[1] ? Number.parseInt(args[1], 10) : 20;
            const limit = Number.isFinite(countArg) && countArg > 0 ? countArg : 20;
            const events = readAuditEvents({ root, limit });
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  HETZER - AUDIT LEDGER (LAST ${events.length} EVENTS)\n`);
            process.stdout.write("================================================================================\n");
            if (events.length === 0) {
                process.stdout.write("  No audit events recorded yet in this workspace.\n");
            } else {
                process.stdout.write("TIMESTAMP                 EVENT_TYPE            RESULT  TARGET\n");
                process.stdout.write("------------------------  --------------------  ------  ------------------------\n");
                for (const ev of events) {
                    const tsCol = (ev.timestamp || "").padEnd(24);
                    const typeCol = (ev.eventType || "").padEnd(20);
                    const resCol = (ev.result || "").padEnd(6);
                    const targetCol = (ev.target || "").slice(0, 24);
                    process.stdout.write(`${tsCol}  ${typeCol}  ${resCol}  ${targetCol}\n`);
                }
            }
            process.stdout.write("================================================================================\n");
            return;
        }
        if (sub === "rotate") {
            const reasonIndex = args.indexOf("--reason");
            const reason = reasonIndex >= 0 ? String(args[reasonIndex + 1] || "") : "";
            const rule = "================================================================================\n";
            if (!args.includes("--yes")) {
                const current = verifyAuditLedger({ root });
                process.stdout.write(rule);
                process.stdout.write("  HETZER - AUDIT LEDGER ROTATION (PREVIEW, NOTHING CHANGED)\n");
                process.stdout.write(rule);
                process.stdout.write(`  Current ledger: ${current.ok ? "verifies" : `does not verify (${current.error})`}\n`);
                process.stdout.write("  Rotation moves the log, its head anchor and its sentinel to a timestamped archive and\n");
                process.stdout.write("  starts a new ledger whose first entry records the old head. Doing it needs --yes in an\n");
                process.stdout.write("  interactive terminal started by a person.\n");
                process.stdout.write(rule);
                process.exitCode = 1;
                return;
            }
            // A refused ledger is what --strict stops on, so clearing it is not left to an agent session.
            // The check is the same heuristic as the other human-only commands, not a guarantee.
            assertInteractiveHumanSession({ operation: "'hetzer audit rotate --yes'", ...(options.humanSession || {}) });
            const result = rotateAuditLedger({ root, reason, allowUnkeyed: args.includes("--allow-unkeyed") });
            process.stdout.write(rule);
            process.stdout.write("  HETZER - AUDIT LEDGER ROTATION\n");
            process.stdout.write(rule);
            if (!result.rotated) {
                process.stdout.write(`  ${result.message}\n`);
            } else {
                process.stdout.write(`  Archive      : ${result.archive}\n`);
                process.stdout.write(`  Old ledger   : ${result.previous.entries} entries, ${result.previous.verified ? "verified" : `did not verify (${result.previous.error})`}\n`);
                if (result.previous.lastGood) {
                    process.stdout.write(`  Old head hash: ${result.previous.lastGood.hash} (entry #${result.previous.lastGood.index})\n`);
                }
                process.stdout.write(`  New ledger   : ${result.keyed ? "keyed" : "unkeyed"}, entry #1 records the rotation\n`);
                if (result.previous.keyed && !result.keyed) {
                    process.stdout.write("  Warning      : the old ledger was keyed and the new one is not (--allow-unkeyed)\n");
                }
            }
            process.stdout.write(rule);
            return;
        }
        throw new Error(`Unknown audit subcommand: '${sub}'. Use 'verify [--require-mac]', 'tail [count]' or 'rotate'.`);
    }

    const { envFile, values } = projectEnvironment(root);

    if (["creds", "credentials"].includes(command)) {
        const subCommand = args[0] || "list";
        if (subCommand === "list") {
            const list = listCredentials({ root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER CORE - CREDENTIAL VAULT (GRIMOIRE)\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write("ID                            MODULE    STATUS      DESCRIPTION\n");
            process.stdout.write("----------------------------  --------  ----------  ----------------------------\n");
            for (const item of list) {
                const idCol = item.id.padEnd(28);
                const modCol = item.module.padEnd(8);
                const statusCol = (item.configured ? "saved" : "not set").padEnd(10);
                process.stdout.write(`${idCol}  ${modCol}  ${statusCol}  ${item.description}\n`);
            }
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write("Commands:\n");
            process.stdout.write("  - View secret value   : hetzer creds reveal <id>\n");
            process.stdout.write("  - Save/update value   : hetzer creds set <id>\n");
            process.stdout.write("================================================================================\n");
            return;
        }
        if (subCommand === "reveal" || subCommand === "get") {
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
            return;
        }
        if (subCommand === "set") {
            const id = args[1];
            if (!id) throw new Error("Usage: hetzer creds set <id>");
            if (args[2]) throw new Error("Do not pass a secret as a command-line argument. Run 'hetzer creds set <id>' and use the masked prompt.");
            assertInteractiveHumanSession({ operation: "'hetzer creds set'" });
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
            process.stdout.write(`  Apply       : Execute guarded processes with 'hetzer exec --allow ${result.id} -- <cmd>'\n`);
            process.stdout.write("================================================================================\n");
            return;
        }
        if (subCommand === "request") {
            const id = args[1];
            if (!id || args[2]) throw new Error("Usage: hetzer creds request <id>");
            const request = createCredentialRequest({ root, id });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - HUMAN CREDENTIAL APPROVAL REQUEST\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  Request ID  : ${request.requestId}\n`);
            process.stdout.write(`  Credential  : ${request.credentialId}\n`);
            process.stdout.write(`  Expires     : ${new Date(request.expiresAt).toISOString()}\n`);
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write(`  In a separate human terminal, run:\n  hetzer creds approve ${request.requestId}\n`);
            process.stdout.write("  The secret is never stored in this request or returned to the requester.\n");
            process.stdout.write("================================================================================\n");
            return;
        }
        if (subCommand === "status") {
            const requestId = args[1];
            if (!requestId || args[2]) throw new Error("Usage: hetzer creds status <request-id>");
            const request = getCredentialRequest({ root, requestId });
            process.stdout.write(`${request.status}\n`);
            return;
        }
        if (subCommand === "approve") {
            const requestId = args[1];
            if (!requestId || args[2]) throw new Error("Usage: hetzer creds approve <request-id>");
            const result = await approveCredentialRequest({ root, envFile, requestId });
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Credential '${result.id}' approved and saved to Vault.\n`);
            process.stdout.write(`  [v] Request status: ${result.status}\n`);
            process.stdout.write("  The requesting agent receives status only; the secret remains in the vault.\n");
            process.stdout.write("================================================================================\n");
            return;
        }
        if (subCommand === "grant") {
            const id = args[1];
            if (id === "--sign-existing") {
                const { signExistingGrantsCommand } = await import("../vault/creds.mjs");
                await signExistingGrantsCommand({ root, envFile });
                return;
            }
            if (!id) throw new Error("Usage: hetzer creds grant <id> [--origin <url>] [--raw <allow|deny>] [--host <name>] [--action <name>] [--reset] | hetzer creds grant --sign-existing");
            assertInteractiveHumanSession({ operation: "'hetzer creds grant'" });
            const { grantCredentialCommand } = await import("../vault/creds.mjs");
            await grantCredentialCommand({ root, envFile, id, args: args.slice(2) });
            return;
        }
        if (subCommand === "isolate-key" || subCommand === "key-isolate") {
            const res = isolateMasterKey({ root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - GRIMOIRE MASTER KEY ISOLATION\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Master Key moved to : ${res.isolatedFile} (mode 0600)\n`);
            process.stdout.write(`  [v] Workspace Stripped  : ${res.envFile}\n`);
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write("  Result: The workspace .env no longer contains the master key.\n");
            process.stdout.write("  Note: Processes running as the same OS user may still read the isolated key file.\n");
            process.stdout.write("================================================================================\n");
            return;
        }
        throw new Error(`Unknown creds subcommand: '${subCommand}'. Use 'list', 'request', 'approve', 'status', 'reveal', 'set', 'grant', or 'isolate-key'.`);
    }

    if (["sniffer", "sniff"].includes(command)) {
        const sub = args[0] || "scan";
        const input = args.slice(1).join(" ");
        if (!input) {
            throw new Error("Usage: hetzer sniffer <scan|redact> <text>");
        }
        if (sub === "redact") {
            const res = redactAndVault(input, { root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - SECRET SNIFFER (REDACT & AUTO-VAULT)\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  Execution Time   : ${res.latencyMs} ms\n`);
            process.stdout.write(`  Redacted Count   : ${res.redactedCount}\n`);
            process.stdout.write(`  Vaulted Count    : ${res.vaultedCount}\n`);
            if (res.vaultErrors.length) {
                process.stdout.write(`  Vault Warnings   : ${res.vaultErrors.join("; ")}\n`);
            }
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write(`  Safe Redacted Text for AI:\n  ${res.text}\n`);
            process.stdout.write("================================================================================\n");
            return;
        }
        throw new Error(`Unknown sniffer subcommand: '${sub}'. Use 'scan' or 'redact'.`);
    }

    if (command === "canary") {
        const sub = args[0] || "setup";
        if (sub === "setup" || sub === "enable") {
            const trap = setupCanaryTrap({ root, envFile });
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - CANARY HONEY-TOKEN TRAP DEPLOYED\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Honey-Token ID : ${trap.id}\n`);
            process.stdout.write(`  [v] Decoy Binding  : HETZER_CANARY_TOKEN=${trap.ref}\n`);
            process.stdout.write(`  [v] Protection     : Guarded reveal or environment resolution of this ID\n`);
            process.stdout.write(`                       logs an incident and aborts with exit code 43.\n`);
            process.stdout.write("================================================================================\n");
            return;
        }
        throw new Error(`Unknown canary subcommand: '${sub}'. Use 'setup'.`);
    }

    if (command === "mcp") {
        const action = args[0] || "serve";
        if (action === "configure") {
            process.stdout.write(`Registered MCP servers in ${configureMcp(root)}\n`);
            return;
        }
        if (action === "ping") {
            const targetService = args[1];
            const pingResult = await diagnoseMcpService({ root, targetService });
            if (!pingResult.ok) process.exitCode = 1;
            return;
        }
        if (action === "tools") {
            const targetService = args[1];
            if (!targetService) {
                throw new Error("Usage: hetzer mcp tools <service>");
            }
            const result = await listMcpTools({ root, targetService });
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  HETZER CORE - MCP TOOLS LIST (${result.serviceName})\n`);
            process.stdout.write(`  Endpoint: ${result.endpointUrl}\n`);
            process.stdout.write("================================================================================\n");
            if (result.tools.length === 0) {
                process.stdout.write("  No tools exposed by this service.\n");
            } else {
                for (const tool of result.tools) {
                    const tag = tool.classification?.tag || "NATIVE";
                    const note = tool.classification?.note || "";
                    process.stdout.write(`\n* ${tool.name} [${tag}] (${note})\n`);
                    if (tool.description) {
                        process.stdout.write(`  Description : ${tool.description}\n`);
                    }
                    if (tool.inputSchema?.properties && Object.keys(tool.inputSchema.properties).length > 0) {
                        const required = new Set(tool.inputSchema.required || []);
                        const props = Object.entries(tool.inputSchema.properties)
                            .map(([k, v]) => `${k}${required.has(k) ? "*" : ""}: ${v.type || "any"}`)
                            .join(", ");
                        process.stdout.write(`  Arguments   : { ${props} }\n`);
                    }
                    process.stdout.write(`  Invocation  : hetzer mcp call ${targetService} ${tool.name} '{}'\n`);
                }
            }
            process.stdout.write("================================================================================\n");
            return;
        }
        if (action === "call") {
            const targetService = args[1];
            const toolName = args[2];
            const argsJson = args[3] || "{}";
            if (!targetService || !toolName) {
                throw new Error("Usage: hetzer mcp call <service> <tool> [argsJson]");
            }
            const ok = await runMcpToolCommand({
                root,
                targetService,
                toolName,
                argsJson,
            });
            if (!ok) process.exitCode = 1;
            return;
        }
        if (action !== "serve") {
            throw new Error("Usage: hetzer mcp <configure|serve|ping [service]|tools <service>|call <service> <tool> [args]>");
        }
        run(process.execPath, [
            path.join(cliRoot, "vault", "exec.mjs"),
            "--root", root,
            "--env-file", envFile,
            "--",
            process.execPath,
            path.join(cliRoot, "mcp", "server.mjs"),
        ], { cwd: root });
        return;
    }

    if (command === "exec") {
        const marker = args.indexOf("--");
        if (marker === -1 || !args[marker + 1]) {
            throw new Error("Usage: hetzer exec [--policy <file>] [--broker-policy <file>] [--allow NAME,NAME] [--allow-raw-unmediated NAME,NAME] [--strict] [--canary] [--sandbox [image]] [--sandbox-network <net>] [--sandbox-mount <dir>] [--sandbox-ro] [--allow-sensitive-paths] [--host] [--no-sandbox] [--timeout <duration>] -- <command> [args]");
        }
        const execOptions = args.slice(0, marker);
        const hasSandboxOption = execOptions.includes("--sandbox") || execOptions.some((o) => o.startsWith("--sandbox"));
        const hasHostOption = execOptions.includes("--host") || execOptions.includes("--no-sandbox");

        // If HETZER_AUTO_SANDBOX is enabled and host mode is not explicitly requested, default to sandbox
        const autoSandboxEnabled = process.env.HETZER_AUTO_SANDBOX === "1" || values.HETZER_AUTO_SANDBOX === "1";
        const effectiveExecOptions = [...execOptions];
        if (autoSandboxEnabled && !hasSandboxOption && !hasHostOption) {
            effectiveExecOptions.push("--sandbox");
        }

        const { executeProcess, parseArguments } = await import("../vault/exec.mjs");
        const parsedExecOptions = parseArguments([
            "--root", root,
            "--env-file", envFile,
            ...effectiveExecOptions,
            "--",
            ...args.slice(marker + 1),
        ]);
        const result = await executeProcess(parsedExecOptions);
        process.exitCode = result.status;
        return;
    }

    if (command === "broker") {
        if (args[0] === "approve") {
            const policyFile = args[1];
            if (!policyFile) {
                throw new Error("Usage: hetzer broker approve <policy-file>");
            }
            const { approveBrokerPolicyCommand } = await import("../vault/creds.mjs");
            await approveBrokerPolicyCommand({ root, envFile, policyFile });
            return;
        }
        const marker = args.indexOf("--");
        if (marker === -1 || !args[marker + 1]) {
            throw new Error("Usage: hetzer broker --policy <file> -- <command> [args]");
        }
        const brokerOptions = args.slice(0, marker);
        const policyIndex = brokerOptions.indexOf("--policy");
        if (policyIndex === -1 || !brokerOptions[policyIndex + 1]) {
            throw new Error("Usage: hetzer broker --policy <file> -- <command> [args]");
        }
        run(process.execPath, [
            path.join(cliRoot, "vault", "http-broker.mjs"),
            "--root", root,
            "--env-file", envFile,
            ...brokerOptions,
            "--",
            ...args.slice(marker + 1),
        ], { cwd: root });
        return;
    }

    const suggested = suggestCommand(command);
    const suggestionMsg = suggested ? ` Did you mean 'hetzer ${suggested}'?` : "";
    throw new Error(`Unknown command '${command}'.${suggestionMsg} Run 'hetzer help'.`);
}
