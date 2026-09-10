import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    checkCommitMessage,
    checkCommitMessageFile,
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

test("checkCommitMessage permits clean commit messages and ignores comment lines", () => {
    const cleanMsg = "feat(auth): add local credential validation\n\n# Please enter the commit message for your changes.";
    const result = checkCommitMessage(cleanMsg);
    assert.equal(result.ok, true);
    assert.equal(result.violations.length, 0);
    assert.ok(result.latencyMs >= 0);
});

test("checkCommitMessage detects leaked token in commit message text", () => {
    const fakeNpm = ["npm_", "b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8"].join("");
    const msg = `fix(core): hotfix deploy\n\nAccidentally pasted token ${fakeNpm} here`;
    const result = checkCommitMessage(msg);
    assert.equal(result.ok, false);
    assert.equal(result.violations.length, 1);
    assert.equal(result.violations[0].line, 3);
    assert.equal(result.violations[0].type, "npm_token");
});

test("checkCommitMessageFile reads from disk and detects violations", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-msg-test-"));
    try {
        const msgFile = path.join(tempDir, "COMMIT_EDITMSG");
        const fakeAnthropic = ["sk-ant-", "api03-synthetic-sample-token-12345"].join("");
        fs.writeFileSync(msgFile, `docs: update notes\n\nToken: ${fakeAnthropic}\n# Git comment\n`);

        const result = checkCommitMessageFile(msgFile);
        assert.equal(result.ok, false);
        assert.equal(result.violations.length, 1);
        assert.equal(result.violations[0].line, 3);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("installGitHook and uninstallGitHook manage pre-commit and commit-msg files cleanly in mock repo", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-hook-test-"));
    try {
        const mockGit = path.join(tempDir, ".git");
        fs.mkdirSync(mockGit, { recursive: true });

        const installRes = installGitHook(tempDir);
        assert.ok(installRes.installed);
        assert.ok(fs.existsSync(installRes.preCommitPath));
        assert.ok(fs.existsSync(installRes.commitMsgPath));

        const preCommitContent = fs.readFileSync(installRes.preCommitPath, "utf8");
        assert.ok(preCommitContent.includes("Hetzer Credential-Safety Pre-Commit Hook"));

        const commitMsgContent = fs.readFileSync(installRes.commitMsgPath, "utf8");
        assert.ok(commitMsgContent.includes("Hetzer Credential-Safety Commit-Msg Hook"));

        const uninstallRes = uninstallGitHook(tempDir);
        assert.ok(uninstallRes.uninstalled);
        assert.ok(!fs.existsSync(installRes.preCommitPath));
        assert.ok(!fs.existsSync(installRes.commitMsgPath));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
