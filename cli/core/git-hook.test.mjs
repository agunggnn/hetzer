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

test("findGitDir supports git worktree with .git file pointing to gitdir", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-worktree-test-"));
    const mainGitDir = path.join(tempDir, "main-repo", ".git", "worktrees", "wt-branch");
    fs.mkdirSync(mainGitDir, { recursive: true });
    const worktreeDir = path.join(tempDir, "wt-checkout");
    fs.mkdirSync(worktreeDir, { recursive: true });
    fs.writeFileSync(path.join(worktreeDir, ".git"), `gitdir: ${mainGitDir}\n`);

    try {
        const found = findGitDir(worktreeDir);
        assert.equal(found, mainGitDir);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
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

test("checkCommitMessage detects leaked token in lines starting with # (issue references, markdown headers)", () => {
    const fakeNpm = ["npm_", "b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8"].join("");
    const issueMsg = `#104: resolve deployment using ${fakeNpm}\n\n# Please enter the commit message for your changes.`;
    const issueRes = checkCommitMessage(issueMsg);
    assert.equal(issueRes.ok, false);
    assert.equal(issueRes.violations.length, 1);
    assert.equal(issueRes.violations[0].line, 1);
    assert.equal(issueRes.violations[0].type, "npm_token");

    const fakeAnthropic = ["sk-ant-", "api03-synthetic-sample-token-12345"].join("");
    const headerMsg = `# Security Patch with ${fakeAnthropic}\n\nDetailed release description.\n# On branch main`;
    const headerRes = checkCommitMessage(headerMsg);
    assert.equal(headerRes.ok, false);
    assert.equal(headerRes.violations.length, 1);
    assert.equal(headerRes.violations[0].line, 1);

    // Scissors cut line truncates diff output below it
    const scissorsMsg = [
        "feat: clean commit message",
        "",
        "# ------------------------ >8 ------------------------",
        `# diff --git a/test.txt b/test.txt\n# + ${fakeNpm}`,
    ].join("\n");
    const scissorsRes = checkCommitMessage(scissorsMsg);
    assert.equal(scissorsRes.ok, true);
    assert.equal(scissorsRes.violations.length, 0);
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

test("installGitHook and uninstallGitHook manage hooks in common directory when called inside a worktree", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-wt-hook-test-"));
    try {
        const mainGitDir = path.join(tempDir, "main-repo", ".git");
        const wtGitDir = path.join(mainGitDir, "worktrees", "wt-branch");
        fs.mkdirSync(wtGitDir, { recursive: true });
        fs.writeFileSync(path.join(wtGitDir, "commondir"), "../..\n");

        const worktreeDir = path.join(tempDir, "wt-checkout");
        fs.mkdirSync(worktreeDir, { recursive: true });
        fs.writeFileSync(path.join(worktreeDir, ".git"), `gitdir: ${wtGitDir}\n`);

        const installRes = installGitHook(worktreeDir);
        assert.ok(installRes.installed);
        const expectedPreCommit = path.join(mainGitDir, "hooks", "pre-commit");
        const expectedCommitMsg = path.join(mainGitDir, "hooks", "commit-msg");
        assert.equal(installRes.preCommitPath, expectedPreCommit);
        assert.equal(installRes.commitMsgPath, expectedCommitMsg);
        assert.ok(fs.existsSync(expectedPreCommit));
        assert.ok(fs.existsSync(expectedCommitMsg));
        assert.ok(!fs.existsSync(path.join(wtGitDir, "hooks")));

        const uninstallRes = uninstallGitHook(worktreeDir);
        assert.ok(uninstallRes.uninstalled);
        assert.ok(!fs.existsSync(expectedPreCommit));
        assert.ok(!fs.existsSync(expectedCommitMsg));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
