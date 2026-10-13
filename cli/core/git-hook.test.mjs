import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
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
    stripLockfileIntegrity,
    uninstallGitHook,
} from "./git-hook.mjs";

// Deterministic SRI value shaped like the integrity hashes npm writes to lockfiles.
const SRI = `sha512-${crypto.createHash("sha512").update("hetzer-lockfile-fixture").digest("base64")}`;
// Assembled at runtime so no credential-shaped literal appears in this file.
const SYNTHETIC_TOKEN = ["gh", "p_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"].join("");

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

test("checkCommitMessage detects leaked tokens even when appended to Git status template comment lines", () => {
    const fakeNpm = ["npm_", "b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8"].join("");

    const case1 = checkCommitMessage(`# On branch main ${fakeNpm}`);
    assert.equal(case1.ok, false);
    assert.equal(case1.violations.length, 1);
    assert.equal(case1.violations[0].type, "npm_token");

    const case2 = checkCommitMessage(`# Please enter the commit message ${fakeNpm}`);
    assert.equal(case2.ok, false);
    assert.equal(case2.violations.length, 1);
    assert.equal(case2.violations[0].type, "npm_token");

    const case3 = checkCommitMessage(`# Lines starting with ${fakeNpm}`);
    assert.equal(case3.ok, false);
    assert.equal(case3.violations.length, 1);
    assert.equal(case3.violations[0].type, "npm_token");

    const case4 = checkCommitMessage(`# Changes to be committed ${fakeNpm}`);
    assert.equal(case4.ok, false);
    assert.equal(case4.violations.length, 1);
    assert.equal(case4.violations[0].type, "npm_token");
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

test("stripLockfileIntegrity removes integrity values from known lockfiles only", () => {
    assert.equal(
        stripLockfileIntegrity("package-lock.json", `      "integrity": "${SRI}",`),
        '      "integrity": "",',
    );
    assert.equal(
        stripLockfileIntegrity("sub/dir/yarn.lock", `  integrity ${SRI}`),
        "  integrity ",
    );
    assert.equal(
        stripLockfileIntegrity("pnpm-lock.yaml", `    resolution: {integrity: ${SRI}}`),
        "    resolution: {integrity: }",
    );
    // Other files keep the value so a real secret named "integrity" is still scanned.
    const untouched = `"integrity": "${SRI}"`;
    assert.equal(stripLockfileIntegrity("config/settings.json", untouched), untouched);
    // Lines in a lockfile that are not integrity fields are returned unchanged.
    const resolved = `"resolved": "https://registry.example.test/pkg/-/pkg-1.0.0.tgz"`;
    assert.equal(stripLockfileIntegrity("package-lock.json", resolved), resolved);
});

test("scanAddedLines ignores lockfile integrity hashes but still flags other secrets in lockfiles", () => {
    const integrityOnly = scanAddedLines([
        { file: "package-lock.json", line: 10, text: `      "integrity": "${SRI}",` },
    ]);
    assert.equal(integrityOnly.length, 0);

    const outsideLockfile = scanAddedLines([
        { file: "config/settings.json", line: 3, text: `  "integrity": "${SRI}",` },
    ]);
    assert.ok(outsideLockfile.length > 0, "same value outside a lockfile must still be reported");

    const leakedInLockfile = scanAddedLines([
        { file: "package-lock.json", line: 11, text: `      "resolved": "https://registry.example.test/pkg.tgz?token=${SYNTHETIC_TOKEN}",` },
    ]);
    assert.ok(leakedInLockfile.length > 0, "a credential in a lockfile must still be reported");
});

test("checkStagedDiff permits a staged lockfile with integrity hashes", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-lockfile-diff-"));
    try {
        const git = (...args) => spawnSync("git", args, { cwd: tempDir, encoding: "utf8", windowsHide: true });
        assert.equal(git("init", "-q").status, 0);
        const lock = {
            name: "fixture",
            lockfileVersion: 3,
            packages: { "node_modules/example": { version: "1.0.0", integrity: SRI } },
        };
        fs.writeFileSync(path.join(tempDir, "package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
        assert.equal(git("add", "package-lock.json").status, 0);
        const result = checkStagedDiff(tempDir);
        assert.equal(result.ok, true, JSON.stringify(result.violations));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
