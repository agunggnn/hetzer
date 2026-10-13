import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
    help,
    KNOWN_COMMANDS,
    main,
    suggestCommand,
} from "./cli.mjs";

const cliRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = path.resolve(cliRoot, "..");

test("CONTRACT: help() commands and KNOWN_COMMANDS maintain strict bidirectional sync", () => {
    const helpText = help();
    assert.ok(helpText.includes("Usage: hetzer [options] <command> [arguments]"));

    const commandsSection = helpText.split("Commands:\n")[1];
    assert.ok(commandsSection, "Help must contain a 'Commands:' section");

    const helpLines = commandsSection
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("Run with") && !l.startsWith("==") && !l.startsWith("Deprecated"));

    const helpCommands = new Set();
    for (const line of helpLines) {
        const match = line.match(/^([a-z0-9_-]+)/);
        if (match) {
            helpCommands.add(match[1]);
        }
    }

    // Every command in help() must be registered in KNOWN_COMMANDS
    for (const cmd of helpCommands) {
        assert.ok(
            KNOWN_COMMANDS.has(cmd),
            `Command '${cmd}' documented in help() must exist in KNOWN_COMMANDS`
        );
    }

    // Primary commands that must appear in help()
    const requiredPrimaryCommands = [
        "init", "doctor", "protect", "skill", "hook", "sniffer",
        "creds", "canary", "audit", "exec", "broker", "mcp",
        "version",
    ];
    for (const req of requiredPrimaryCommands) {
        assert.ok(
            helpCommands.has(req),
            `Primary command '${req}' must be documented in help()`
        );
    }
});

test("CONTRACT: suggestCommand() primaryCommands strictly align with KNOWN_COMMANDS", () => {
    const testCases = [
        ["hepl", "help"],
        ["versoin", "version"],
        ["audt", "audit"],
        ["canry", "canary"],
        ["sniff", "sniffer"],
        ["docktor", "doctor"],
        ["skil", "skill"],
        ["hoko", "hook"],
        ["cred", "creds"],
    ];

    for (const [typo, expected] of testCases) {
        const suggested = suggestCommand(typo);
        assert.equal(suggested, expected, `Typo '${typo}' should suggest '${expected}', got '${suggested}'`);
    }

    // Completely unrelated input should return null
    assert.equal(suggestCommand("xyzzy_nonsense_token_999"), null);
});

test("CONTRACT: README.md CLI cheat sheet table covers all active and deprecated commands", () => {
    const readmePath = path.join(repoRoot, "README.md");
    const readmeContent = fs.readFileSync(readmePath, "utf8");

    // Extract table rows under CLI Command Cheat Sheet
    const cheatSheetIndex = readmeContent.indexOf("## 🛠️ CLI Command Cheat Sheet");
    assert.ok(cheatSheetIndex !== -1, "README.md must contain CLI Command Cheat Sheet section");
    const nextSectionIndex = readmeContent.indexOf("## ❓ Frequently Asked Questions", cheatSheetIndex);
    const cheatSheetSection = readmeContent.slice(cheatSheetIndex, nextSectionIndex !== -1 ? nextSectionIndex : undefined);

    const readmeCommands = new Set();
    const commandRows = cheatSheetSection.match(/`hetzer\s+([a-z0-9_-]+)/g) || [];
    for (const row of commandRows) {
        const cmd = row.replace(/`hetzer\s+/, "").trim();
        readmeCommands.add(cmd);
    }

    const coreCommands = [
        "doctor", "init", "protect", "skill", "hook", "sniffer",
        "creds", "canary", "audit", "exec", "broker", "mcp",
        "version",
    ];

    for (const cmd of coreCommands) {
        assert.ok(
            readmeCommands.has(cmd),
            `Core command '${cmd}' must be present in README.md cheat sheet table`
        );
    }

    // Verify deprecated commands in README.md are clearly marked as deprecated
    const tableLines = cheatSheetSection.split("\n").filter((line) => line.startsWith("| `hetzer "));
    const deprecatedCommands = ["up", "down", "status", "logs", "modules", "install", "remove", "module", "validate", "tui"];
    for (const dep of deprecatedCommands) {
        const row = tableLines.find((l) => l.startsWith(`| \`hetzer ${dep} `) || l.startsWith(`| \`hetzer ${dep}\``));
        assert.ok(row, `Deprecated command '${dep}' must be in cheat sheet table`);
        assert.ok(row.toLowerCase().includes("deprecated"), `Deprecated command '${dep}' in README.md must explicitly contain 'deprecated'`);
    }
});

test("CONTRACT: Documentation installation methods safeguard against legacy unscoped npm package", () => {
    const installDocPath = path.join(repoRoot, "docs", "installation.md");
    const installContent = fs.readFileSync(installDocPath, "utf8");

    assert.match(installContent, /npm install -g @agunggnn\/hetzer/);
    assert.match(installContent, /git\+https:\/\/github\.com\/agunggnn\/hetzer\.git/);
    assert.match(installContent, /hetzer upgrade/);
    assert.match(installContent, /hetzer check-update/);
    assert.match(installContent, /hetzer version --check/);
});

test("CONTRACT: Multi-file version consistency is mathematically uniform", () => {
    const pkgPath = path.join(repoRoot, "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    const expectedVersion = pkg.version;
    assert.ok(expectedVersion, "package.json must declare version");

    // 1. package-lock.json
    const lockPath = path.join(repoRoot, "package-lock.json");
    if (fs.existsSync(lockPath)) {
        const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
        assert.equal(lock.version, expectedVersion, "package-lock.json version mismatch");
        assert.equal(lock.packages[""].version, expectedVersion, "package-lock.json packages[''].version mismatch");
    }

    // 2. cli/mcp/protocol.mjs
    const protocolPath = path.join(cliRoot, "mcp", "protocol.mjs");
    const protocolContent = fs.readFileSync(protocolPath, "utf8");
    const versionPattern = /version:\s*"([^"]+)"/g;
    let match = versionPattern.exec(protocolContent);
    assert.ok(match, "cli/mcp/protocol.mjs must contain at least one version field");
    while (match !== null) {
        assert.equal(match[1], expectedVersion, `cli/mcp/protocol.mjs version '${match[1]}' does not match package.json '${expectedVersion}'`);
        match = versionPattern.exec(protocolContent);
    }

    // 3. cli/mcp/ping.mjs
    const pingPath = path.join(cliRoot, "mcp", "ping.mjs");
    const pingContent = fs.readFileSync(pingPath, "utf8");
    assert.ok(
        pingContent.includes(`version: "${expectedVersion}"`),
        `cli/mcp/ping.mjs version does not match package.json '${expectedVersion}'`
    );

    // 4. cli/mcp/call.mjs
    const callPath = path.join(cliRoot, "mcp", "call.mjs");
    const callContent = fs.readFileSync(callPath, "utf8");
    assert.ok(
        callContent.includes(`version: "${expectedVersion}"`),
        `cli/mcp/call.mjs version does not match package.json '${expectedVersion}'`
    );

    // 5. AGENTS.md
    const agentsPath = path.join(repoRoot, "AGENTS.md");
    const agentsContent = fs.readFileSync(agentsPath, "utf8");
    assert.ok(
        agentsContent.includes(`> **Version**: v${expectedVersion}`),
        `AGENTS.md version does not match package.json '${expectedVersion}'`
    );
});

test("CONTRACT: Unknown command produces helpful suggestion and rejects cleanly", async () => {
    await assert.rejects(
        () => main(["docotr"]),
        (err) => {
            assert.match(err.message, /Unknown command 'docotr'/);
            assert.match(err.message, /Did you mean 'hetzer doctor'\?/);
            assert.match(err.message, /Run 'hetzer help'/);
            return true;
        }
    );
});
