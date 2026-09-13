import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    auditAgentContext,
    estimateTokenCount,
    FULL_RULE_TOKEN_BUDGET,
    POINTER_TOKEN_BUDGET,
    SKILL_TOKEN_BUDGET,
} from "./audit.mjs";
import { ENTRY_POINTER_BLOCK, POINTER_END, POINTER_START } from "./rules.mjs";

test("estimateTokenCount returns expected values for empty and valid inputs", () => {
    assert.equal(estimateTokenCount(""), 0);
    assert.equal(estimateTokenCount(null), 0);
    assert.equal(estimateTokenCount(undefined), 0);
    assert.equal(estimateTokenCount("   "), 0);

    const singleWord = estimateTokenCount("hello");
    assert.ok(singleWord >= 1 && singleWord <= 2);

    const pointerTokens = estimateTokenCount(ENTRY_POINTER_BLOCK);
    // Standard ENTRY_POINTER_BLOCK is ~140-170 tokens
    assert.ok(pointerTokens >= 100 && pointerTokens <= 200, `Unexpected pointer token count: ${pointerTokens}`);
});

test("auditAgentContext handles unconfigured workspace gracefully", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-empty-"));
    try {
        const res = auditAgentContext(tmpDir);
        assert.equal(res.configured, false);
        assert.equal(res.ok, true);
        assert.equal(res.pointerTokens, 0);
        assert.equal(res.files.length, 0);
        assert.equal(res.summary, "Not configured");
        assert.equal(res.issues.length, 0);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test("auditAgentContext audits valid pointer files within budget", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-valid-"));
    try {
        const agentsFile = path.join(tmpDir, "AGENTS.md");
        fs.writeFileSync(agentsFile, `# Project Agent Rules\n\n${ENTRY_POINTER_BLOCK}\n\n## Next steps`, "utf8");

        const skillDir = path.join(tmpDir, ".agents", "skills", "hetzer");
        fs.mkdirSync(skillDir, { recursive: true });
        const skillFile = path.join(skillDir, "SKILL.md");
        fs.writeFileSync(
            skillFile,
            `---\nname: hetzer\ndescription: Use only for credentials\n---\n# Guide\nSome instructions.`,
            "utf8"
        );

        const res = auditAgentContext(tmpDir);
        assert.equal(res.configured, true);
        assert.equal(res.ok, true);
        assert.ok(res.pointerTokens > 0);
        assert.ok(res.pointerTokens <= POINTER_TOKEN_BUDGET);
        assert.equal(res.cacheFriendly, true);
        assert.equal(res.issues.length, 0);
        assert.match(res.summary, /100% prompt-cache friendly/);

        const auditedAgents = res.files.find((f) => f.path === "AGENTS.md");
        assert.ok(auditedAgents);
        assert.equal(auditedAgents.withinBudget, true);
        assert.equal(auditedAgents.cacheFriendly, true);

        const auditedSkill = res.files.find((f) => f.path.includes("SKILL.md"));
        assert.ok(auditedSkill);
        assert.equal(auditedSkill.onDemand, true);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test("auditAgentContext detects oversized pointer blocks exceeding budget", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-oversized-"));
    try {
        const agentsFile = path.join(tmpDir, "AGENTS.md");
        const giantText = "Word ".repeat(500);
        const oversizedPointer = `${POINTER_START}\n${giantText}\n${POINTER_END}`;
        fs.writeFileSync(agentsFile, oversizedPointer, "utf8");

        const res = auditAgentContext(tmpDir, { pointerBudget: 100 });
        assert.equal(res.configured, true);
        assert.equal(res.ok, false);
        assert.ok(res.issues.some((i) => i.type === "OVERSIZED_POINTER"));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test("auditAgentContext detects dynamic cache-breaking tokens", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-cachebreak-"));
    try {
        const agentsFile = path.join(tmpDir, "AGENTS.md");
        const dynamicPointer = `${POINTER_START}\nTimestamp: 2026-09-13T09:00:00Z\nSession: uuid-12345\n${POINTER_END}`;
        fs.writeFileSync(agentsFile, dynamicPointer, "utf8");

        const res = auditAgentContext(tmpDir);
        assert.equal(res.configured, true);
        assert.equal(res.ok, false);
        assert.equal(res.cacheFriendly, false);
        assert.ok(res.issues.some((i) => i.type === "DYNAMIC_CACHE_BREAK"));
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});
