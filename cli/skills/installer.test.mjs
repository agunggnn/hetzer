import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    detectPlatforms,
    installSkill,
    installToAntigravity,
    installToCline,
    installToCursor,
    installToHermes,
    installToOpenCode,
    writePointerBlock,
} from "./installer.mjs";

test("detectPlatforms reports available agents and returns structured list", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-skill-detect-"));
    try {
        const list = detectPlatforms(tempDir);
        assert.ok(Array.isArray(list));
        assert.ok(list.length >= 7);
        const ids = list.map((p) => p.id);
        assert.ok(ids.includes("cursor"));
        assert.ok(ids.includes("claude"));
        assert.ok(ids.includes("cline"));
        assert.ok(ids.includes("hermes"));
        assert.ok(ids.includes("antigravity"));
        assert.ok(ids.includes("opencode"));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("writePointerBlock is cleanly idempotent and replaces existing block without duplication", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-pointer-"));
    try {
        const file = path.join(tempDir, "AGENTS.md");
        fs.writeFileSync(file, "# Project Agents\n\nInitial rules here.\n", "utf8");

        writePointerBlock(file);
        const firstPass = fs.readFileSync(file, "utf8");
        assert.ok(firstPass.includes("<!-- hetzer:start -->"));
        assert.ok(firstPass.includes("<!-- hetzer:end -->"));
        assert.ok(firstPass.includes("Initial rules here."));

        // Second pass should replace cleanly, not duplicate
        writePointerBlock(file);
        const secondPass = fs.readFileSync(file, "utf8");
        const matchCount = (secondPass.match(/<!-- hetzer:start -->/g) || []).length;
        assert.equal(matchCount, 1, "Pointer block must exist exactly once");
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("installToCursor writes rules and AGENTS.md entry pointer", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-skill-cursor-"));
    try {
        const created = installToCursor(tempDir);
        assert.ok(created.length >= 2);

        const mdcFile = path.join(tempDir, ".cursor", "rules", "hetzer.mdc");
        assert.ok(fs.existsSync(mdcFile), ".cursor/rules/hetzer.mdc must exist");
        const mdcContent = fs.readFileSync(mdcFile, "utf8");
        assert.ok(mdcContent.includes("Zero-Plaintext"));
        assert.ok(mdcContent.includes("secretRef:"));

        const agentsMd = path.join(tempDir, "AGENTS.md");
        assert.ok(fs.existsSync(agentsMd), "AGENTS.md must exist");
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("installToCline writes .clinerules in workspace", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-skill-cline-"));
    const originalInstallHome = process.env.HETZER_INSTALL_HOME;
    try {
        process.env.HETZER_INSTALL_HOME = path.join(tempDir, "home");
        const created = installToCline(tempDir);
        assert.ok(created.length >= 1);

        const clineFile = path.join(tempDir, ".clinerules");
        assert.ok(fs.existsSync(clineFile), ".clinerules must exist");
        const content = fs.readFileSync(clineFile, "utf8");
        assert.ok(content.includes("Zero-Plaintext"));
        assert.ok(content.includes("secretRef:"));
    } finally {
        if (originalInstallHome === undefined) delete process.env.HETZER_INSTALL_HOME;
        else process.env.HETZER_INSTALL_HOME = originalInstallHome;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("installToOpenCode writes .opencode/skills and AGENTS.md", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-skill-opencode-"));
    try {
        const created = installToOpenCode(tempDir);
        assert.ok(created.length >= 2);
        assert.ok(fs.existsSync(path.join(tempDir, ".opencode", "skills", "hetzer", "SKILL.md")));
        assert.ok(fs.existsSync(path.join(tempDir, "AGENTS.md")));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("installToAntigravity writes workspace .agents/skills and AGENTS.md", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-skill-agy-"));
    const originalInstallHome = process.env.HETZER_INSTALL_HOME;
    try {
        process.env.HETZER_INSTALL_HOME = path.join(tempDir, "home");
        const created = installToAntigravity(tempDir);
        assert.ok(created.length >= 2);
        assert.ok(fs.existsSync(path.join(tempDir, ".agents", "skills", "hetzer", "SKILL.md")));
        assert.ok(fs.existsSync(path.join(tempDir, "AGENTS.md")));
    } finally {
        if (originalInstallHome === undefined) delete process.env.HETZER_INSTALL_HOME;
        else process.env.HETZER_INSTALL_HOME = originalInstallHome;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("installSkill dispatches target correctly", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-skill-dispatch-"));
    try {
        const created = installSkill({ root: tempDir, target: "cursor" });
        assert.ok(created.length >= 2);
        assert.ok(fs.existsSync(path.join(tempDir, ".cursor", "rules", "hetzer.mdc")));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
