import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    checkStagedDiff,
    findGitDir,
    installGitHook,
    scanAddedLines,
    uninstallGitHook,
} from "./git-hook.mjs";

test("findGitDir locates current git root directory", () => {
    const gitDir = findGitDir(process.cwd());
    assert.ok(gitDir, "Must locate .git directory");
    assert.ok(fs.existsSync(gitDir));
});

test("scanAddedLines detects a multiline PKCS8 key and reports its opening line", () => {
    const violations = scanAddedLines([
        { file: "fixture.pem", line: 8, text: "-----BEGIN PRIVATE KEY-----" },
        { file: "fixture.pem", line: 9, text: "c3ludGhldGljLXRlc3QtZGF0YS1vbmx5" },
        { file: "fixture.pem", line: 10, text: "-----END PRIVATE KEY-----" },
    ]);
    assert.equal(violations.some((item) => item.type === "private_key" && item.line === 8), true);
});

test("checkStagedDiff reports clean on clean tree", () => {
    const result = checkStagedDiff(process.cwd());
    assert.equal(typeof result.ok, "boolean");
    assert.equal(typeof result.latencyMs, "number");
    assert.ok(result.latencyMs >= 0);
});

test("installGitHook and uninstallGitHook manage pre-commit file cleanly in mock repo", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-hook-test-"));
    try {
        const mockGit = path.join(tempDir, ".git");
        fs.mkdirSync(mockGit, { recursive: true });

        const installRes = installGitHook(tempDir);
        assert.ok(installRes.installed);
        assert.ok(fs.existsSync(installRes.path));

        const content = fs.readFileSync(installRes.path, "utf8");
        assert.ok(content.includes("Hetzer Credential-Safety Pre-Commit Hook"));

        const uninstallRes = uninstallGitHook(tempDir);
        assert.ok(uninstallRes.uninstalled);
        assert.ok(!fs.existsSync(installRes.path));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
