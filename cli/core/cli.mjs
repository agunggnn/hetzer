import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { listMcpTools, runMcpToolCommand } from "../mcp/call.mjs";
import { configureMcp } from "../mcp/configure.mjs";
import { diagnoseMcpService } from "../mcp/ping.mjs";
import { createModuleRecipe, createModuleRecipeFromSource } from "../modules/create.mjs";
import { runInstallWizard } from "../modules/install-wizard.mjs";
import { loadModuleRegistry } from "../modules/registry.mjs";
import { resolveModuleProfiles } from "../modules/resolve.mjs";
import { setModuleEnabled } from "../modules/toggle.mjs";
import { formatValidationReport, validateAllModules, validateModuleRecipe } from "../modules/validate.mjs";
import { KNOWN_CREDENTIALS, authorizeCredentialReveal, listCredentials, promptSecret, revealCredential, setCredential } from "../vault/creds.mjs";
import { isolateMasterKey, resolveMasterKey } from "../vault/hetzer-vault.mjs";
import { autoIngestPlaintextEnv, migrateEnvCredentials } from "../vault/migrate-env.mjs";
import { setupCanaryTrap } from "../vault/canary.mjs";
import { redactAndVault, scanText, restoreSecrets } from "../vault/sniffer.mjs";
import { getHetzerAsciiBanner, printHetzerBanner } from "./banner.mjs";
import { runDoctor } from "./doctor.mjs";
import { parseEnv } from "./env.mjs";
import {
    migrateBundledImagePins,
    moduleIdsForProfiles,
    resolveLifecycleTarget,
    updateComposeCommands,
} from "./update.mjs";
import { verifyModuleDeployment } from "./verifier.mjs";

const cliRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const builtinFile = path.join(cliRoot, "modules", "builtin.json");
const templatesDir = path.join(cliRoot, "templates");

export function defaultHetzerHome() {
    if (process.env.HETZER_HOME) return path.resolve(process.env.HETZER_HOME);
    return path.join(os.homedir(), ".hetzer");
}

export function isHetzerWorkspace(dir) {
    const composeFile = path.join(dir, "docker-compose.yml");
    const envFile = path.join(dir, ".env");
    const exampleFile = path.join(dir, ".env.example");
    if (fs.existsSync(composeFile)) {
        try {
            const content = fs.readFileSync(composeFile, "utf8");
            const isHetzer = content.includes("hetzer") || content.includes("nine-router") || content.includes("NINE_ROUTER");
            if (isHetzer && (fs.existsSync(envFile) || fs.existsSync(exampleFile))) {
                return true;
            }
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

function randomHex(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function run(file, args, options = {}) {
    const result = spawnSync(file, args, {
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

function registryFor(root, values) {
    return loadModuleRegistry({
        builtinFile,
        root,
        disabledModules: process.env.HETZER_DISABLED_MODULES || values.HETZER_DISABLED_MODULES,
        enabledModules: process.env.HETZER_ENABLED_MODULES || values.HETZER_ENABLED_MODULES,
    });
}

function compose(root, envFile, args) {
    run(process.execPath, [
        path.join(cliRoot, "vault", "compose-runner.mjs"),
        "--root", root,
        "--env-file", envFile,
        "--",
        ...args,
    ], { cwd: root });
}

function profileArguments(root, values, target) {
    const registry = registryFor(root, values);
    const resolvedTarget = resolveLifecycleTarget(registry, target);
    const profiles = resolveModuleProfiles({ registry, target: resolvedTarget });
    return {
        registry,
        profiles,
        arguments: profiles.flatMap((profile) => ["--profile", profile]),
    };
}

export function initializeProject(root) {
    const resolvedRoot = path.resolve(root);
    fs.mkdirSync(resolvedRoot, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(resolvedRoot, 0o700); } catch { /* Windows */ }
    copyIfMissing(path.join(templatesDir, "docker-compose.yml"), path.join(resolvedRoot, "docker-compose.yml"));
    copyIfMissing(path.join(templatesDir, ".env.example"), path.join(resolvedRoot, ".env.example"));
    const modulesTemplateDir = path.join(templatesDir, "modules");
    if (fs.existsSync(modulesTemplateDir)) {
        const entries = fs.readdirSync(modulesTemplateDir, { withFileTypes: true });
        for (const entry of entries) {
            if (entry.isDirectory()) {
                copyIfMissing(path.join(modulesTemplateDir, entry.name), path.join(resolvedRoot, "modules", entry.name));
            }
        }
    }

    const dataDir = path.join(resolvedRoot, "data");
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    try { fs.chmodSync(dataDir, 0o700); } catch { /* Windows */ }

    const envFile = path.join(resolvedRoot, ".env");
    copyIfMissing(path.join(resolvedRoot, ".env.example"), envFile);
    let text = fs.readFileSync(envFile, "utf8");
    const values = parseEnv(text);
    const generated = {
        NINE_ROUTER_JWT_SECRET: randomHex(),
        NINE_ROUTER_INITIAL_PASSWORD: randomHex(16),
        NINE_ROUTER_API_KEY_SECRET: randomHex(),
        NINE_ROUTER_MACHINE_ID_SALT: randomHex(),
        HETZER_GRIMOIRE_KEY: crypto.randomBytes(48).toString("base64url"),
    };
    for (const [name, value] of Object.entries(generated)) {
        if (!values[name] || String(values[name]).startsWith("replace-")) text = replaceEnvValue(text, name, value);
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
        initialPasswordRef: "secretRef:nine-router-initial-password",
    };
}

function printInitWizard(result) {
    const isGlobal = result.root === defaultHetzerHome();
    process.stdout.write("================================================================================\n");
    process.stdout.write("  HETZER - INITIALIZATION SUCCESSFUL\n");
    process.stdout.write("================================================================================\n");
    process.stdout.write(`[v] Instance Location : ${result.root}${isGlobal ? " (Global User Home)" : " (Local Workspace)"}\n`);
    process.stdout.write(`[v] Configuration File: .env (permissions secured chmod 600)\n`);
    process.stdout.write(`[v] Grimoire Vault    : data/hetzer-vault.db (AES-256-GCM Encrypted)\n`);
    process.stdout.write(`[v] MCP Server        : .mcp.json configured\n`);
    if (isGlobal) {
        process.stdout.write(`[v] Global Access     : You can run 'hetzer' from any directory!\n`);
    }
    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write("  9ROUTER INITIAL LOGIN & CREDENTIAL INFORMATION:\n");
    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write("  Web UI URL       : http://127.0.0.1:20140\n");
    process.stdout.write("  Login Form       : 9Router requires the password stored in Grimoire Vault\n");
    process.stdout.write(`  Password Ref     : ${result.initialPasswordRef}\n`);
    process.stdout.write("  Human retrieval  : hetzer creds reveal nine-router-initial-password\n\n");
    process.stdout.write("  IMPORTANT INITIALIZATION NOTE:\n");
    process.stdout.write("  9Router only reads the Initial Password when its database is first created.\n");
    process.stdout.write("  If 9Router was previously initialized, run:\n");
    process.stdout.write("    hetzer down -v && hetzer up\n");
    process.stdout.write("  to reset existing volumes so the new password takes effect.\n\n");
    process.stdout.write("  SECURITY CONTRACT (ZERO-PLAINTEXT):\n");
    process.stdout.write("  This password is encrypted in Grimoire Vault (data/hetzer-vault.db).\n");
    process.stdout.write("  The .env file only stores an opaque reference:\n");
    process.stdout.write("    NINE_ROUTER_INITIAL_PASSWORD=secretRef:nine-router-initial-password\n");
    process.stdout.write("  protecting your secrets from accidental git exposure.\n\n");
    process.stdout.write("  CREDENTIAL MANAGEMENT:\n");
    process.stdout.write("  - Reveal password anytime   : hetzer creds reveal nine-router-initial-password\n");
    process.stdout.write("  - Update password in vault  : hetzer creds set nine-router-initial-password\n");
    process.stdout.write("  - Inspect all credentials   : hetzer creds list\n");
    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write("  NEXT STEPS:\n");
    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write("  1. Start services      : hetzer up\n");
    process.stdout.write("  2. Retrieve password   : hetzer creds reveal nine-router-initial-password\n");
    process.stdout.write("  3. Open Web UI         : http://127.0.0.1:20140\n");
    process.stdout.write("  4. Open live dashboard : hetzer tui\n");
    process.stdout.write("  5. View extra modules  : hetzer modules\n");
    process.stdout.write("================================================================================\n");
}

function printModuleGuide(moduleId, action) {
    if (action === "install") {
        process.stdout.write(`Module '${moduleId}' successfully enabled.\n`);
        if (moduleId === "cognee") {
            process.stdout.write("\n================================================================================\n");
            process.stdout.write("  MODULE CONFIGURATION GUIDE: cognee\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write("The 'cognee' module provides persistent graph & vector memory via Model Context Protocol (MCP).\n\n");
            process.stdout.write("REQUIRED CREDENTIALS:\n");
            process.stdout.write("  This module requires an LLM API key (OpenAI, Anthropic, OpenRouter, etc.).\n\n");
            process.stdout.write("HOW TO CONFIGURE CREDENTIALS:\n");
            process.stdout.write("  Run the following command to store the API key in the encrypted Vault:\n");
            process.stdout.write("    hetzer creds set cognee-llm-api-key\n\n");
            process.stdout.write("HOW TO START & CONNECT:\n");
            process.stdout.write("  1. Start service   : hetzer up cognee\n");
            process.stdout.write("  2. Setup MCP       : hetzer mcp configure\n");
            process.stdout.write("  3. Use MCP         : In Claude Desktop / Cursor / Cline, the following tools activate:\n");
            process.stdout.write("                       - remember, recall, improve, forget_memory\n");
            process.stdout.write("================================================================================\n");
        } else if (moduleId === "9router") {
            process.stdout.write("\n================================================================================\n");
            process.stdout.write("  MODULE GUIDE: 9router\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write("The '9router' module is a local AI Gateway for smart model routing and fallbacks.\n\n");
            process.stdout.write("HOW TO ACCESS & LOGIN:\n");
            process.stdout.write("  1. Start service    : hetzer up 9router\n");
            process.stdout.write("  2. Open browser     : http://127.0.0.1:20140\n");
            process.stdout.write("  3. Check password   : hetzer creds reveal nine-router-initial-password\n");
            process.stdout.write("================================================================================\n");
        } else {
            process.stdout.write(`Run 'hetzer up ${moduleId}' to start this module.\n`);
        }
    } else {
        process.stdout.write(`Module '${moduleId}' successfully disabled.\n`);
        process.stdout.write(`[i] Run 'hetzer up' to apply Compose profile changes.\n`);
    }
}

export function printModuleHelp(moduleId, root, values) {
    const registry = registryFor(root, values);
    const module = registry.modules.find((m) => m.id === moduleId);
    if (!module) {
        process.stdout.write(`Module '${moduleId}' not found.\n`);
        process.stdout.write("Run 'hetzer modules' to view available modules.\n");
        return;
    }

    const isEnabled = module.enabled;
    const isCompose = module.lifecycle === "compose";
    const service = module.services[0] || {};
    const composeService = service.composeService || moduleId;

    process.stdout.write("================================================================================\n");
    process.stdout.write(`  NATIVE MODULE GUIDE: ${module.label || moduleId} (${module.id})\n`);
    process.stdout.write("================================================================================\n");
    process.stdout.write(`  Status      : ${isEnabled ? "Enabled" : "Disabled"}\n`);
    process.stdout.write(`  Lifecycle   : ${module.lifecycle}${isCompose ? " (Docker Compose Container)" : " (Host Process)"}\n`);
    if (module.sourceUrl) process.stdout.write(`  Source Repo : ${module.sourceUrl}\n`);
    if (service.role) process.stdout.write(`  Role        : ${service.role}\n`);
    if (service.lore) process.stdout.write(`  Description : ${service.lore}\n`);
    if (service.portEnv && values[service.portEnv]) {
        process.stdout.write(`  Web UI/Port : http://127.0.0.1:${values[service.portEnv]}\n`);
    } else if (service.fallbackPort) {
        process.stdout.write(`  Web UI/Port : http://127.0.0.1:${service.fallbackPort}\n`);
    }
    if (service.mcpServer) {
        process.stdout.write(`  MCP Server  : ${service.mcpServer.name} (${service.mcpServer.transport} at ${service.mcpServer.path})\n`);
        process.stdout.write(`  Tools Check : hetzer mcp tools ${service.mcpServer.name}\n`);
        process.stdout.write(`  Ping Test   : hetzer mcp ping ${service.mcpServer.name}\n`);
    }

    process.stdout.write("--------------------------------------------------------------------------------\n");
    process.stdout.write("  AVAILABLE NATIVE COMMANDS:\n");
    process.stdout.write("--------------------------------------------------------------------------------\n");

    if (isCompose) {
        process.stdout.write("1. DOCKER CONTAINER MANAGEMENT:\n");
        process.stdout.write(`   - Start container           : hetzer up ${module.id}\n`);
        process.stdout.write(`   - Update image to new digest: hetzer update ${module.id}\n`);
        process.stdout.write(`   - Stream live logs          : hetzer logs ${composeService}\n`);
        process.stdout.write(`   - Inspect container status  : hetzer status\n\n`);
    }

    const creds = Object.entries(KNOWN_CREDENTIALS)
        .filter(([_, def]) => def.moduleId === module.id)
        .map(([id, def]) => ({ id, ...def }));

    if (creds.length > 0) {
        process.stdout.write("2. CREDENTIALS & SECRETS (GRIMOIRE VAULT):\n");
        for (const cred of creds) {
            process.stdout.write(`   - Reveal secret '${cred.id}':\n`);
            process.stdout.write(`       hetzer creds reveal ${cred.id}\n`);
            process.stdout.write(`   - Configure secret '${cred.id}':\n`);
            process.stdout.write(`       hetzer creds set ${cred.id}\n`);
        }
        process.stdout.write("\n");
    }

    process.stdout.write("3. MODULE ACTIVATION & STATUS:\n");
    process.stdout.write(`   - Enable module             : hetzer install ${module.id}\n`);
    process.stdout.write(`   - Disable module            : hetzer remove ${module.id}\n`);

    if (module.runtime?.actions?.length) {
        process.stdout.write("\n4. HOST-PROCESS ACTIONS:\n");
        for (const act of module.runtime.actions) {
            process.stdout.write(`   - hetzer module ${module.id} ${act} [args]\n`);
        }
    }

    if (module.id === "9router") {
        process.stdout.write("\n4. WEB UI ACCESS & LOGIN NOTES:\n");
        process.stdout.write("   - Web UI URL                : http://127.0.0.1:20140\n");
        process.stdout.write("   - Login Form                : Enter Initial Password (no username required)\n");
        process.stdout.write("   - Reset Volume (Password)   : hetzer down -v && hetzer up 9router\n");
    }

    if (service.mcpServer) {
        process.stdout.write(`\n4. MCP TOOL INTEGRATION (${service.mcpServer.name}):\n`);
        process.stdout.write(`   - List tools & nature       : hetzer mcp tools ${service.mcpServer.name}\n`);
        process.stdout.write(`   - Call tool directly in CLI : hetzer mcp call ${service.mcpServer.name} <tool> [args]\n`);
        process.stdout.write(`   - Register to AI clients    : hetzer mcp configure\n`);
    }

    process.stdout.write("================================================================================\n");
}

function help() {
    const banner = getHetzerAsciiBanner({ colored: Boolean(process.stdout.isTTY) });
    return `${banner}

Usage: hetzer [options] <command> [arguments]

Options:
  --root <path>             Specify instance root directory (default: ~/.hetzer)

Commands:
  init [directory]          Initialize a new instance (default: ~/.hetzer or current workspace)
  doctor [--fix]            Check system & Docker compatibility (--fix to auto-repair)
  up [module|all] [--wait]  Start core, 9router, or active module containers (--wait polls health)
  update [target|all]       Pull and update module/service image digests
  down [-v]                 Stop services (use -v to purge persistent data volumes)
  status                    View container states and image digests
  logs [service]            Stream service logs
  modules [module]          List available modules or print detailed module guide
  install <module>          Enable module (e.g. 9router, cognee)
  remove <module>           Disable module without deleting persistent data
  module <id> [action|help] Print native command guide or run host module action
  module create <id> [--source <repo>] Scaffold new module recipe (AI-assisted via 9Router)
  validate [module]         Validate module integrity, security, and compose recipe
  creds [list|reveal|set]   Manage encrypted secrets in Grimoire Vault (AES-256-GCM)
  canary [setup]            Deploy decoy canary honey-token tripwire to catch prompt injections
  exec [--allow <ids>] [--strict] -- <c> Run command with scoped secret injection & real-time stream sanitization
  sniffer [scan|redact] <t> Detect or redact credentials supported by the scanner rules
  protect                   Install credential-safety guidance, Git hook, and .env protection
  skill [install|status]    Deploy Universal AI Skills to Hermes, AGY, OpenCode, Cursor, Claude
  hook [install|uninstall|check] Manage Git Pre-Commit Guard to prevent accidental token leaks
  mcp configure|serve|ping  Configure, start bridge, or run MCP diagnostic ping
  mcp tools <service>       List MCP tools with Offline / Hybrid / LLM classification
  mcp call <srv> <tool> [a] Call MCP tool directly from CLI without external AI client
  publish                   Build, verify test suite, and publish package to npm
  tui                       Launch interactive terminal operations dashboard
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

    if (["help", "--help", "-h"].includes(command)) {
        process.stdout.write(help());
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

    if (["protect", "armor"].includes(command)) {
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
        process.stdout.write("--------------------------------------------------------------------------------\n");
        process.stdout.write("  These controls reduce accidental credential disclosure; review the documented boundaries.\n");
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

    const { envFile, values } = projectEnvironment(root);
    if (["install", "remove"].includes(command)) {
        if (!args[0]) throw new Error(`Usage: hetzer ${command} <module>`);
        const moduleId = args[0];
        if (command === "install") {
            const templateModuleDir = path.join(templatesDir, "modules", moduleId);
            const targetModuleDir = path.join(root, "modules", moduleId);
            if (!fs.existsSync(targetModuleDir) && fs.existsSync(templateModuleDir)) {
                copyIfMissing(templateModuleDir, targetModuleDir);
            }
            const nonInteractive = args.includes("--yes") || args.includes("--default");
            await runInstallWizard({ root, envFile, moduleId, nonInteractive });
        }
        setModuleEnabled({
            root,
            envFile,
            moduleId,
            enabled: command === "install",
            builtinFile,
        });
        configureMcp(root);
        printModuleGuide(moduleId, command);
        return;
    }
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
                process.stdout.write("  Apply       : Run 'npm run publish-pkg' or 'node scripts/publish.mjs' to publish to npm.\n");
            } else {
                const upTarget = result.module && result.module !== "core" ? `hetzer up ${result.module}` : "hetzer up";
                process.stdout.write(`  Apply       : Run '${upTarget}' (or 'hetzer up') to reload containers.\n`);
            }
            process.stdout.write("================================================================================\n");
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
        throw new Error(`Unknown creds subcommand: '${subCommand}'. Use 'list', 'reveal', 'set', or 'isolate-key'.`);
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
    if (command === "modules") {
        if (args[0] && !args[0].startsWith("-")) {
            printModuleHelp(args[0], root, values);
            return;
        }
        run(process.execPath, [path.join(cliRoot, "modules", "list.mjs"), "--root", root, ...args], { cwd: root });
        return;
    }
    if (command === "up") {
        printHetzerBanner();
        const hasVerify = args.includes("--verify") || args.includes("--wait");
        const filteredArgs = args.filter((a) => a !== "--verify" && a !== "--wait");
        const target = filteredArgs[0] === "all" ? "*" : (filteredArgs[0] || "*");
        const selection = profileArguments(root, values, target);
        compose(root, envFile, [...selection.arguments, "pull", "--policy", "always", "--ignore-buildable"]);
        compose(root, envFile, [...selection.arguments, "up", "-d"]);
        if (hasVerify || (target !== "*" && target !== "all")) {
            const serviceId = target === "cognee" ? "cognee-mcp" : (target === "9router" ? "nine-router" : target);
            const composeFile = path.join(root, "modules", target, `docker-compose.${target}.yml`);
            const endpointUrl = target === "cognee"
                ? `http://127.0.0.1:${values.COGNEE_MCP_PORT || 8001}/health`
                : (target === "9router" ? `http://127.0.0.1:${values.NINE_ROUTER_PORT || 20140}/api/health` : null);
            const timeoutMs = target === "cognee" ? 75000 : 35000;
            await verifyModuleDeployment({
                root,
                moduleId: target,
                serviceId,
                composeFile,
                endpointUrl,
                timeoutMs,
            });
        }
        return;
    }
    if (command === "update") {
        const requestedTarget = args[0] || "all";
        const selection = profileArguments(root, values, requestedTarget);
        const currentEnv = fs.readFileSync(envFile, "utf8");
        const migration = migrateBundledImagePins({
            envText: currentEnv,
            moduleIds: moduleIdsForProfiles(selection.registry, selection.profiles),
        });
        if (migration.text !== currentEnv) {
            fs.writeFileSync(envFile, migration.text, { encoding: "utf8", mode: 0o600 });
        }
        for (const change of migration.changes) {
            process.stdout.write(`Pinned ${change.serviceId} ${change.version} in ${path.basename(envFile)}.\n`);
        }
        for (const custom of migration.custom) {
            process.stdout.write(`Keeping custom ${custom.variable}; only known Hetzer release pins are migrated.\n`);
        }
        for (const composeArgs of updateComposeCommands(selection.arguments)) {
            compose(root, envFile, composeArgs);
        }
        process.stdout.write(`Updated '${requestedTarget}' from its configured image digests.\n`);
        return;
    }
    if (command === "down") {
        compose(root, envFile, [...profileArguments(root, values, "*").arguments, "down", ...args]);
        return;
    }
    if (command === "status") {
        compose(root, envFile, [...profileArguments(root, values, "*").arguments, "ps", "--all"]);
        return;
    }
    if (command === "logs") {
        const registry = registryFor(root, values);
        const mappedArgs = [];
        for (const arg of args) {
            if (arg.startsWith("-")) {
                mappedArgs.push(arg);
                continue;
            }
            let foundModule = null;
            let foundService = null;
            for (const mod of registry.modules) {
                if (mod.id === arg) {
                    foundModule = mod;
                    foundService = mod.services[0];
                    break;
                }
                const s = mod.services.find((cand) => cand.id === arg || cand.composeService === arg);
                if (s) {
                    foundModule = mod;
                    foundService = s;
                    break;
                }
            }
            if (foundModule) {
                if (!foundModule.enabled) {
                    process.stderr.write(`[!] Module '${foundModule.id}' is not yet enabled.\n    Run 'hetzer install ${foundModule.id} && hetzer up ${foundModule.id}' first.\n`);
                    return;
                }
                mappedArgs.push(foundService?.composeService || arg);
            } else {
                mappedArgs.push(arg);
            }
        }
        compose(root, envFile, [...profileArguments(root, values, "*").arguments, "logs", "-f", ...mappedArgs]);
        return;
    }
    if (command === "validate") {
        const targetModule = args[0];
        if (targetModule) {
            const result = validateModuleRecipe({ root, moduleId: targetModule });
            process.stdout.write(formatValidationReport(result));
            if (!result.valid) process.exitCode = 1;
        } else {
            const results = validateAllModules({ root });
            if (!results.length) {
                process.stdout.write("No module recipes found in 'modules/' directory.\n");
                return;
            }
            let hasError = false;
            for (const r of results) {
                process.stdout.write(formatValidationReport(r));
                if (!r.valid) hasError = true;
            }
            if (hasError) process.exitCode = 1;
        }
        return;
    }
    if (command === "module") {
        const moduleId = args[0];
        const action = args[1];
        if (moduleId === "create") {
            const targetId = action;
            if (!targetId || targetId.startsWith("-")) {
                throw new Error("Usage: hetzer module create <id> [--source <repo/url>] [--label <label>] [--port <port>] [--mcp] [--web-ui]");
            }
            let label = "";
            let port = 0;
            let mcp = false;
            let webUi = false;
            let source = "";
            for (let i = 2; i < args.length; i++) {
                if (args[i] === "--label" && args[i + 1]) {
                    label = args[++i];
                } else if (args[i] === "--port" && args[i + 1]) {
                    port = parseInt(args[++i], 10) || 0;
                } else if (args[i] === "--mcp") {
                    mcp = true;
                } else if (args[i] === "--web-ui") {
                    webUi = true;
                } else if (args[i] === "--source" && args[i + 1]) {
                    source = args[++i];
                }
            }

            let created;
            if (source) {
                process.stdout.write(`[i] Analyzing module source via 9Router AI Engine: ${source}...\n`);
                created = await createModuleRecipeFromSource({
                    root,
                    moduleId: targetId,
                    source,
                    label,
                    port: port || undefined,
                    mcp: mcp || undefined,
                    webUi: webUi || undefined,
                });
            } else {
                created = createModuleRecipe({
                    root,
                    moduleId: targetId,
                    label,
                    port: port || 8080,
                    mcp,
                    webUi,
                });
            }

            process.stdout.write("================================================================================\n");
            process.stdout.write(`  HETZER - MODULE GENERATOR: ${created.moduleId}\n`);
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Directory created   : modules/${created.moduleId}/\n`);
            process.stdout.write(`  [v] Manifest created    : modules/${created.moduleId}/module.json\n`);
            process.stdout.write(`  [v] Compose created     : modules/${created.moduleId}/docker-compose.${created.moduleId}.yml\n`);
            process.stdout.write(`  [v] Documentation       : modules/${created.moduleId}/README.md\n`);
            if (created.sourceUrl) {
                process.stdout.write(`  [v] Upstream Source     : ${created.sourceUrl}\n`);
            }
            process.stdout.write("--------------------------------------------------------------------------------\n");
            process.stdout.write("  Next steps:\n");
            process.stdout.write(`    1. Validate recipe    : hetzer validate ${created.moduleId}\n`);
            process.stdout.write(`    2. Enable module      : hetzer install ${created.moduleId}\n`);
            process.stdout.write(`    3. Start container    : hetzer up ${created.moduleId}\n`);
            process.stdout.write("================================================================================\n");
            return;
        }
        if (moduleId === "validate") {
            const targetModule = action;
            if (targetModule) {
                const result = validateModuleRecipe({ root, moduleId: targetModule });
                process.stdout.write(formatValidationReport(result));
                if (!result.valid) process.exitCode = 1;
            } else {
                const results = validateAllModules({ root });
                if (!results.length) {
                    process.stdout.write("No module recipes found in 'modules/' directory.\n");
                    return;
                }
                let hasError = false;
                for (const r of results) {
                    process.stdout.write(formatValidationReport(r));
                    if (!r.valid) hasError = true;
                }
                if (hasError) process.exitCode = 1;
            }
            return;
        }
        if (action === "validate") {
            const result = validateModuleRecipe({ root, moduleId });
            process.stdout.write(formatValidationReport(result));
            if (!result.valid) process.exitCode = 1;
            return;
        }
        if (!moduleId || ["help", "--help", "-h"].includes(moduleId)) {
            process.stdout.write("Usage: hetzer module <id> [action|help|validate]\n");
            process.stdout.write("       hetzer module create <id> [options]\n\n");
            process.stdout.write("Native module guides:\n");
            process.stdout.write("  hetzer module 9router help\n");
            process.stdout.write("  hetzer module cognee help\n");
            process.stdout.write("  hetzer module validate [id]     (Validate module recipes & security standards)\n");
            process.stdout.write("  hetzer module create <id>       (Generate boilerplate recipe for a new module)\n\n");
            process.stdout.write("Run 'hetzer modules' to list all available modules.\n");
            return;
        }
        if (!action || ["help", "--help", "-h"].includes(action)) {
            printModuleHelp(moduleId, root, values);
            return;
        }
        run(process.execPath, [path.join(cliRoot, "modules", "runtime.mjs"), ...args], {
            cwd: root,
            env: { ...process.env, HETZER_ROOT: root, HETZER_ENV_FILE: envFile },
        });
        return;
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
                throw new Error("Usage: hetzer mcp tools <service>\nExample: hetzer mcp tools cognee");
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
                throw new Error("Usage: hetzer mcp call <service> <tool> [argsJson]\nExample: hetzer mcp call cognee search '{\"query\": \"notes\"}'");
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
    if (command === "publish") {
        const publishScript = path.join(cliRoot, "..", "scripts", "publish.mjs");
        run(process.execPath, [publishScript], { cwd: root });
        return;
    }
    if (command === "exec") {
        const marker = args.indexOf("--");
        if (marker === -1 || !args[marker + 1]) {
            throw new Error("Usage: hetzer exec [--allow NAME,NAME] [--strict] -- <command> [args]");
        }
        const execOptions = args.slice(0, marker);
        const passArgs = [
            path.join(cliRoot, "vault", "exec.mjs"),
            "--root", root,
            "--env-file", envFile,
            ...execOptions,
            "--",
            ...args.slice(marker + 1),
        ];
        run(process.execPath, passArgs, { cwd: root });
        return;
    }
    if (command === "tui") {
        run(process.execPath, [path.join(cliRoot, "modules", "tui.mjs"), "--root", root], { cwd: root });
        return;
    }
    throw new Error(`Unknown command '${command}'. Run 'hetzer help'.`);
}
