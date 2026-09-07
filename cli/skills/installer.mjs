#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
    AGENT_SYSTEM_RULE,
    ANTIGRAVITY_SKILL_CONTENT,
    CLAUDE_RULE_CONTENT,
    CLINE_RULE_CONTENT,
    CURSOR_MDC_CONTENT,
    ENTRY_POINTER_BLOCK,
    HETZER_SKILL_CONTENT,
    POINTER_END,
    POINTER_START,
} from "./rules.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const cliRoot = path.resolve(here, "..");
const hetzerBin = path.join(cliRoot, "bin", "hetzer.js");

export function getInstallHome() {
    return path.resolve(process.env.HETZER_INSTALL_HOME || os.homedir());
}

export const SUPPORTED_AGENTS = [
    { id: "antigravity", label: "Antigravity (AGY)", skillDir: ".agents/skills/hetzer", entryFile: "AGENTS.md" },
    { id: "hermes", label: "Hermes Agent", skillDir: ".hermes/skills/hetzer", entryFile: "AGENTS.md", globalOnly: true },
    { id: "opencode", label: "OpenCode", skillDir: ".opencode/skills/hetzer", entryFile: "AGENTS.md" },
    { id: "commandcode", label: "CommandCode", skillDir: ".commandcode/skills/hetzer", entryFile: "AGENTS.md" },
    { id: "cursor", label: "Cursor IDE", skillDir: ".cursor/skills/hetzer", entryFile: "AGENTS.md" },
    { id: "claude", label: "Claude Desktop / Code", skillDir: ".claude/skills/hetzer", entryFile: "CLAUDE.md" },
    { id: "cline", label: "Cline / Roo Code", skillDir: null, entryFile: ".clinerules" },
    { id: "codex", label: "Codex", skillDir: ".codex/skills/hetzer", entryFile: "AGENTS.md" },
    { id: "gemini", label: "Gemini CLI", skillDir: ".gemini/skills/hetzer", entryFile: "GEMINI.md" },
];

export function writePointerBlock(filePath, block = ENTRY_POINTER_BLOCK) {
    const existing = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : "";
    const lines = existing.split(/\r?\n/);
    const start = lines.findIndex((l) => l.trim() === POINTER_START);
    const end = lines.findIndex((l) => l.trim() === POINTER_END);
    const replacing = start !== -1 && end !== -1 && start < end;
    const head = replacing ? lines.slice(0, start) : lines;
    const tail = replacing ? lines.slice(end + 1) : [];

    const body = [...head, "", block, "", ...tail]
        .join("\n")
        .replace(/\n{3,}/g, "\n\n")
        .replace(/^\n+/, "")
        .trimEnd();

    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, body + "\n", "utf8");
    return filePath;
}

export function getClaudeDesktopConfigPath() {
    const installHome = getInstallHome();
    if (process.platform === "win32") {
        const appData = process.env.HETZER_INSTALL_HOME
            ? path.join(installHome, "AppData", "Roaming")
            : (process.env.APPDATA || "");
        return path.join(appData, "Claude", "claude_desktop_config.json");
    }
    if (process.platform === "darwin") {
        return path.join(installHome, "Library", "Application Support", "Claude", "claude_desktop_config.json");
    }
    return path.join(installHome, ".config", "Claude", "claude_desktop_config.json");
}

export function getClineSettingsPaths() {
    const results = [];
    const installHome = getInstallHome();
    const baseDir = process.platform === "win32"
        ? path.join(
            process.env.HETZER_INSTALL_HOME ? path.join(installHome, "AppData", "Roaming") : (process.env.APPDATA || ""),
            "Code", "User", "globalStorage"
        )
        : (process.platform === "darwin"
            ? path.join(installHome, "Library", "Application Support", "Code", "User", "globalStorage")
            : path.join(installHome, ".config", "Code", "User", "globalStorage"));

    const plugins = ["saoudrizwan.claude-dev", "rooveterinaryinc.roo-cline"];
    for (const plugin of plugins) {
        const file = path.join(baseDir, plugin, "settings", "cline_mcp_settings.json");
        results.push({ plugin, path: file });
    }
    return results;
}

export function detectPlatforms(root = process.cwd()) {
    const home = getInstallHome();
    const platforms = [];

    // Cursor
    const hasCursor = fs.existsSync(path.join(root, ".cursor")) || fs.existsSync(path.join(root, ".cursorrules"));
    platforms.push({ id: "cursor", name: "Cursor IDE", detected: Boolean(hasCursor || process.env.CURSOR_AGENT) });

    // Claude Desktop & Code
    const claudeConfig = getClaudeDesktopConfigPath();
    const hasClaude = fs.existsSync(path.dirname(claudeConfig)) || fs.existsSync(path.join(root, ".claude")) || fs.existsSync(path.join(root, "CLAUDE.md"));
    platforms.push({ id: "claude", name: "Claude Desktop / Code", detected: Boolean(hasClaude), configPath: claudeConfig });

    // Cline / Roo Code
    const clineSettings = getClineSettingsPaths();
    const hasCline = clineSettings.some((s) => fs.existsSync(path.dirname(s.path))) || fs.existsSync(path.join(root, ".clinerules"));
    platforms.push({ id: "cline", name: "Cline / Roo Code", detected: Boolean(hasCline) });

    // Antigravity (AGY)
    const hasAgy = fs.existsSync(path.join(root, ".agents")) || fs.existsSync(path.join(home, ".gemini", "config")) || fs.existsSync(path.join(home, ".gemini", "antigravity-cli"));
    platforms.push({ id: "antigravity", name: "Antigravity (AGY)", detected: Boolean(hasAgy) });

    // Hermes Agent
    const hasHermes = fs.existsSync(path.join(home, ".hermes"));
    platforms.push({ id: "hermes", name: "Hermes Agent", detected: Boolean(hasHermes) });

    // OpenCode
    const hasOpenCode = fs.existsSync(path.join(root, ".opencode")) || fs.existsSync(path.join(home, ".config", "opencode"));
    platforms.push({ id: "opencode", name: "OpenCode", detected: Boolean(hasOpenCode) });

    // CommandCode
    const hasCommandCode = fs.existsSync(path.join(root, ".commandcode")) || fs.existsSync(path.join(home, ".commandcode"));
    platforms.push({ id: "commandcode", name: "CommandCode", detected: Boolean(hasCommandCode) });

    // Codex
    const hasCodex = fs.existsSync(path.join(root, ".codex"));
    platforms.push({ id: "codex", name: "Codex", detected: Boolean(hasCodex) });

    // Gemini CLI
    const hasGemini = fs.existsSync(path.join(root, ".gemini")) || fs.existsSync(path.join(home, ".gemini"));
    platforms.push({ id: "gemini", name: "Gemini CLI", detected: Boolean(hasGemini) });

    return platforms;
}

export function installToAntigravity(root = process.cwd()) {
    const created = [];
    const home = getInstallHome();

    // 1. Workspace skill (.agents/skills/hetzer/SKILL.md)
    const wsSkillDir = path.join(root, ".agents", "skills", "hetzer");
    fs.mkdirSync(wsSkillDir, { recursive: true });
    const wsSkill = path.join(wsSkillDir, "SKILL.md");
    fs.writeFileSync(wsSkill, ANTIGRAVITY_SKILL_CONTENT, "utf8");
    created.push(wsSkill);

    // 2. Global skill (~/.gemini/config/skills/hetzer/SKILL.md)
    const globalSkillDir = path.join(home, ".gemini", "config", "skills", "hetzer");
    fs.mkdirSync(globalSkillDir, { recursive: true });
    const globalSkill = path.join(globalSkillDir, "SKILL.md");
    fs.writeFileSync(globalSkill, ANTIGRAVITY_SKILL_CONTENT, "utf8");
    created.push(globalSkill);

    // 3. Workspace AGENTS.md entry pointer
    const agentsMd = path.join(root, "AGENTS.md");
    writePointerBlock(agentsMd);
    created.push(agentsMd);

    return created;
}

export function installToHermes() {
    const created = [];
    const home = getInstallHome();

    // Hermes reads skills exclusively from ~/.hermes/skills/
    const skillDir = path.join(home, ".hermes", "skills", "hetzer");
    fs.mkdirSync(skillDir, { recursive: true });
    const skillFile = path.join(skillDir, "SKILL.md");
    fs.writeFileSync(skillFile, HETZER_SKILL_CONTENT, "utf8");
    created.push(skillFile);

    // Optional MCP configuration in ~/.hermes/config.yaml if file exists
    const hermesConfig = path.join(home, ".hermes", "config.yaml");
    if (fs.existsSync(hermesConfig)) {
        try {
            let content = fs.readFileSync(hermesConfig, "utf8");
            if (!content.includes("hetzer")) {
                const snippet = `\nmcp_servers:\n  hetzer:\n    command: "node"\n    args: ["${hetzerBin.replace(/\\/g, "/")}", "mcp", "serve"]\n`;
                fs.appendFileSync(hermesConfig, snippet, "utf8");
                created.push(hermesConfig);
            }
        } catch { /* ignore */ }
    }

    return created;
}

export function installToOpenCode(root = process.cwd()) {
    const created = [];
    const wsSkillDir = path.join(root, ".opencode", "skills", "hetzer");
    fs.mkdirSync(wsSkillDir, { recursive: true });
    const wsSkill = path.join(wsSkillDir, "SKILL.md");
    fs.writeFileSync(wsSkill, HETZER_SKILL_CONTENT, "utf8");
    created.push(wsSkill);

    const agentsMd = path.join(root, "AGENTS.md");
    writePointerBlock(agentsMd);
    created.push(agentsMd);
    return created;
}

export function installToCommandCode(root = process.cwd()) {
    const created = [];
    const wsSkillDir = path.join(root, ".commandcode", "skills", "hetzer");
    fs.mkdirSync(wsSkillDir, { recursive: true });
    const wsSkill = path.join(wsSkillDir, "SKILL.md");
    fs.writeFileSync(wsSkill, HETZER_SKILL_CONTENT, "utf8");
    created.push(wsSkill);

    const agentsMd = path.join(root, "AGENTS.md");
    writePointerBlock(agentsMd);
    created.push(agentsMd);
    return created;
}

export function installToCursor(root = process.cwd()) {
    const created = [];

    // 1. Modern .cursor/rules/hetzer.mdc
    const rulesDir = path.join(root, ".cursor", "rules");
    fs.mkdirSync(rulesDir, { recursive: true });
    const mdcPath = path.join(rulesDir, "hetzer.mdc");
    fs.writeFileSync(mdcPath, CURSOR_MDC_CONTENT, "utf8");
    created.push(mdcPath);

    // 2. Cursor skills folder
    const skillDir = path.join(root, ".cursor", "skills", "hetzer");
    fs.mkdirSync(skillDir, { recursive: true });
    const skillFile = path.join(skillDir, "SKILL.md");
    fs.writeFileSync(skillFile, HETZER_SKILL_CONTENT, "utf8");
    created.push(skillFile);

    // 3. Legacy .cursorrules
    const cursorRulesPath = path.join(root, ".cursorrules");
    if (!fs.existsSync(cursorRulesPath)) {
        fs.writeFileSync(cursorRulesPath, AGENT_SYSTEM_RULE, "utf8");
    } else {
        const existingRules = fs.readFileSync(cursorRulesPath, "utf8");
        if (/^# Hetzer(?: Vault)?:/m.test(existingRules)) {
            fs.writeFileSync(cursorRulesPath, AGENT_SYSTEM_RULE, "utf8");
        } else {
            writePointerBlock(cursorRulesPath);
        }
    }
    created.push(cursorRulesPath);

    // 4. AGENTS.md entry pointer
    const agentsMd = path.join(root, "AGENTS.md");
    writePointerBlock(agentsMd);
    created.push(agentsMd);

    return created;
}

export function installToClaudeDesktop(root = process.cwd()) {
    const created = [];
    const configFile = getClaudeDesktopConfigPath();
    fs.mkdirSync(path.dirname(configFile), { recursive: true });

    let config = { mcpServers: {} };
    if (fs.existsSync(configFile)) {
        try {
            config = JSON.parse(fs.readFileSync(configFile, "utf8"));
            if (!config.mcpServers) config.mcpServers = {};
        } catch {
            config = { mcpServers: {} };
        }
    }

    config.mcpServers["hetzer-vault"] = {
        command: "node",
        args: [hetzerBin, "mcp", "serve"],
    };

    fs.writeFileSync(configFile, JSON.stringify(config, null, 2), "utf8");
    created.push(configFile);

    // Skill directory for Claude Code CLI (.claude/skills/hetzer/SKILL.md)
    const claudeSkillDir = path.join(root, ".claude", "skills", "hetzer");
    fs.mkdirSync(claudeSkillDir, { recursive: true });
    const claudeSkill = path.join(claudeSkillDir, "SKILL.md");
    fs.writeFileSync(claudeSkill, HETZER_SKILL_CONTENT, "utf8");
    created.push(claudeSkill);

    // CLAUDE.md in workspace root with pointer block
    const claudeMd = path.join(root, "CLAUDE.md");
    writePointerBlock(claudeMd);
    created.push(claudeMd);

    return created;
}

export function installToCline(root = process.cwd()) {
    const created = [];

    // 1. Workspace .clinerules
    const clineRules = path.join(root, ".clinerules");
    fs.writeFileSync(clineRules, CLINE_RULE_CONTENT, "utf8");
    created.push(clineRules);

    // 2. MCP Settings injection
    for (const { path: settingsPath } of getClineSettingsPaths()) {
        if (fs.existsSync(path.dirname(settingsPath))) {
            let settings = { mcpServers: {} };
            if (fs.existsSync(settingsPath)) {
                try {
                    settings = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
                    if (!settings.mcpServers) settings.mcpServers = {};
                } catch {
                    settings = { mcpServers: {} };
                }
            }
            settings.mcpServers["hetzer-vault"] = {
                command: "node",
                args: [hetzerBin, "mcp", "serve"],
                disabled: false,
                autoApprove: ["hetzer_vault_list", "hetzer_vault_has", "hetzer_sniffer_scan"],
            };
            fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2), "utf8");
            created.push(settingsPath);
        }
    }

    return created;
}

export function installToCodex(root = process.cwd()) {
    const created = [];
    const skillDir = path.join(root, ".codex", "skills", "hetzer");
    fs.mkdirSync(skillDir, { recursive: true });
    const skillFile = path.join(skillDir, "SKILL.md");
    fs.writeFileSync(skillFile, HETZER_SKILL_CONTENT, "utf8");
    created.push(skillFile);

    const agentsMd = path.join(root, "AGENTS.md");
    writePointerBlock(agentsMd);
    created.push(agentsMd);
    return created;
}

export function installToGeminiCli(root = process.cwd()) {
    const created = [];
    const skillDir = path.join(root, ".gemini", "skills", "hetzer");
    fs.mkdirSync(skillDir, { recursive: true });
    const skillFile = path.join(skillDir, "SKILL.md");
    fs.writeFileSync(skillFile, HETZER_SKILL_CONTENT, "utf8");
    created.push(skillFile);

    const geminiMd = path.join(root, "GEMINI.md");
    writePointerBlock(geminiMd);
    created.push(geminiMd);
    return created;
}

export function installSkill({ root = process.cwd(), target = "all" } = {}) {
    const installed = [];
    const normalized = String(target).toLowerCase();

    if (["all", "cursor"].includes(normalized)) {
        installed.push(...installToCursor(root));
    }
    if (["all", "claude"].includes(normalized)) {
        installed.push(...installToClaudeDesktop(root));
    }
    if (["all", "cline", "roo"].includes(normalized)) {
        installed.push(...installToCline(root));
    }
    if (["all", "antigravity", "gemini-agy", "agy"].includes(normalized)) {
        installed.push(...installToAntigravity(root));
    }
    if (["all", "hermes"].includes(normalized)) {
        installed.push(...installToHermes());
    }
    if (["all", "opencode"].includes(normalized)) {
        installed.push(...installToOpenCode(root));
    }
    if (["all", "commandcode"].includes(normalized)) {
        installed.push(...installToCommandCode(root));
    }
    if (["all", "codex"].includes(normalized)) {
        installed.push(...installToCodex(root));
    }
    if (["all", "gemini"].includes(normalized)) {
        installed.push(...installToGeminiCli(root));
    }

    return Array.from(new Set(installed));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const args = process.argv.slice(2);
    const action = args[0] || "install";
    const target = args[1] || "all";
    const root = process.cwd();

    if (action === "status" || action === "list") {
        const detected = detectPlatforms(root);
        process.stdout.write("================================================================================\n");
        process.stdout.write("  HETZER - AI AGENT SKILL INTEGRATION STATUS\n");
        process.stdout.write("================================================================================\n");
        for (const p of detected) {
            const status = p.detected ? "[v] Detected" : "[ ] Not detected";
            process.stdout.write(`  ${p.name.padEnd(26)} : ${status}\n`);
        }
        process.stdout.write("================================================================================\n");
        process.stdout.write("Run 'hetzer skill install' to configure across all detected agents.\n");
        process.exit(0);
    }

    if (action === "install") {
        process.stdout.write("================================================================================\n");
        process.stdout.write("  HETZER - UNIVERSAL AI AGENT SKILL INSTALLER\n");
        process.stdout.write("================================================================================\n");
        const results = installSkill({ root, target });
        for (const file of results) {
            const rel = path.relative(root, file);
            process.stdout.write(`  [v] Configured: ${rel.startsWith("..") ? file : rel}\n`);
        }
        process.stdout.write("--------------------------------------------------------------------------------\n");
        process.stdout.write("  [v] Complete! Credential-safety guidance and supported MCP settings were installed for\n");
        process.stdout.write("      Hermes, AGY, OpenCode, CommandCode, Cursor, Claude, Cline, Codex, and Gemini.\n");
        process.stdout.write("================================================================================\n");
        process.exit(0);
    }

    process.stderr.write(`Unknown action: '${action}'. Use 'install' or 'status'.\n`);
    process.exit(1);
}
