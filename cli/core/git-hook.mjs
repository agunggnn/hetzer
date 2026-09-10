import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";

import { scanText } from "../vault/sniffer.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const gitHookScriptPath = fileURLToPath(import.meta.url);

export function findGitDir(startDir = process.cwd()) {
    let current = path.resolve(startDir);
    while (current) {
        const gitPath = path.join(current, ".git");
        if (fs.existsSync(gitPath)) {
            const stat = fs.statSync(gitPath);
            return stat.isDirectory() ? gitPath : null;
        }
        const parent = path.dirname(current);
        if (parent === current) break;
        current = parent;
    }
    return null;
}

export function scanAddedLines(addedLines) {
    const violations = [];
    const byFile = new Map();
    for (const item of addedLines) {
        if (!byFile.has(item.file)) byFile.set(item.file, []);
        byFile.get(item.file).push(item);
    }

    for (const [file, lines] of byFile) {
        let text = "";
        const offsets = [];
        for (const line of lines) {
            offsets.push({ offset: text.length, line: line.line });
            text += `${line.text}\n`;
        }
        const scan = scanText(text);
        for (const match of scan.matches) {
            let line = 0;
            for (let index = offsets.length - 1; index >= 0; index -= 1) {
                if (offsets[index].offset <= match.index) {
                    line = offsets[index].line;
                    break;
                }
            }
            violations.push({ file, line, type: match.type, label: match.label });
        }
    }
    return violations;
}

export function checkStagedDiff(root = process.cwd()) {
    const start = performance.now();
    const violations = [];
    const addedLines = [];

    // 1. Check if sensitive files (.env) are accidentally staged
    const stagedFilesResult = spawnSync("git", ["diff", "--cached", "--name-only", "--diff-filter=ACM"], {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
    });

    if (stagedFilesResult.status !== 0) {
        violations.push({ file: "", line: 0, type: "GIT_SCAN_ERROR", label: "Unable to list staged files" });
    }

    if (stagedFilesResult.status === 0) {
        const fileNames = stagedFilesResult.stdout.split(/\r?\n/).map((f) => f.trim()).filter(Boolean);
        for (const file of fileNames) {
            const base = path.basename(file);
            if (base === ".env" || (base.startsWith(".env.") && !base.endsWith(".example") && !base.endsWith(".sample"))) {
                violations.push({
                    file,
                    line: 0,
                    type: "RAW_ENV_FILE",
                    label: `Plaintext environment file '${file}' cannot be committed`,
                });
            }
        }
    }

    // 2. Scan added lines in git staged diff
    const diffResult = spawnSync("git", ["diff", "--cached", "-U0", "--no-color"], {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
    });

    if (diffResult.status !== 0) {
        violations.push({ file: "", line: 0, type: "GIT_SCAN_ERROR", label: "Unable to read the staged diff" });
    }

    if (diffResult.status === 0 && diffResult.stdout) {
        let currentFile = "";
        let currentLine = 0;
        const lines = diffResult.stdout.split(/\r?\n/);

function isTestOrFixtureFile(filePath) {
    const norm = filePath.replace(/\\/g, "/");
    return norm.includes(".test.") || norm.includes("/test/") || norm.includes("/tests/") || norm.includes("/fixtures/") || norm.includes("verify-evidence");
}

        for (const line of lines) {
            if (line.startsWith("+++ b/")) {
                currentFile = line.slice(6);
                continue;
            }
            if (line.startsWith("@@ ")) {
                const match = line.match(/\+([0-9]+)/);
                if (match) currentLine = parseInt(match[1], 10);
                continue;
            }
            if (line.startsWith("+") && !line.startsWith("+++")) {
                const addedText = line.slice(1);
                if (addedText && !isTestOrFixtureFile(currentFile)) {
                    addedLines.push({ file: currentFile, line: currentLine, text: addedText });
                }
                currentLine++;
            }
        }
    }

    violations.push(...scanAddedLines(addedLines));

    const duration = Math.round((performance.now() - start) * 100) / 100;
    return {
        ok: violations.length === 0,
        violations,
        latencyMs: duration,
    };
}

export function checkCommitMessage(text) {
    const start = performance.now();
    const violations = [];

    if (typeof text !== "string" || !text.trim()) {
        return {
            ok: true,
            violations,
            latencyMs: Number((performance.now() - start).toFixed(4)),
        };
    }

    const lines = text.split(/\r?\n/);
    const activeLines = [];
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (!line.trimStart().startsWith("#")) {
            activeLines.push({ line: index + 1, text: line });
        }
    }

    if (activeLines.length > 0) {
        let combined = "";
        const offsets = [];
        for (const item of activeLines) {
            offsets.push({ offset: combined.length, line: item.line });
            combined += `${item.text}\n`;
        }
        const scan = scanText(combined);
        for (const match of scan.matches) {
            let line = activeLines[0].line;
            for (let index = offsets.length - 1; index >= 0; index -= 1) {
                if (offsets[index].offset <= match.index) {
                    line = offsets[index].line;
                    break;
                }
            }
            violations.push({
                file: "COMMIT_EDITMSG",
                line,
                type: match.type,
                label: match.label,
            });
        }
    }

    return {
        ok: violations.length === 0,
        violations,
        latencyMs: Number((performance.now() - start).toFixed(4)),
    };
}

export function checkCommitMessageFile(filePath) {
    if (!filePath || !fs.existsSync(filePath)) {
        return {
            ok: true,
            violations: [],
            latencyMs: 0,
        };
    }
    const text = fs.readFileSync(filePath, "utf8");
    return checkCommitMessage(text);
}

export function installGitHook(root = process.cwd()) {
    const gitDir = findGitDir(root);
    if (!gitDir) {
        throw new Error(`.git directory not found in '${root}'. Ensure you are inside a Git repository.`);
    }

    const hooksDir = path.join(gitDir, "hooks");
    fs.mkdirSync(hooksDir, { recursive: true });

    const preCommitFile = path.join(hooksDir, "pre-commit");
    const commitMsgFile = path.join(hooksDir, "commit-msg");
    const scriptPathNorm = gitHookScriptPath.replace(/\\/g, "/");

    const preCommitContent = `#!/bin/sh
# Hetzer Credential-Safety Pre-Commit Hook
# Scans staged additions for leaked secrets, API keys, and tokens.

if command -v node >/dev/null 2>&1; then
    node "${scriptPathNorm}" check
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        exit 1
    fi
else
    echo "[!] Node.js not detected in PATH. Skipping Hetzer pre-commit check."
fi
exit 0
`;

    const commitMsgContent = `#!/bin/sh
# Hetzer Credential-Safety Commit-Msg Hook
# Scans commit messages for leaked secrets, API keys, and tokens.

if command -v node >/dev/null 2>&1; then
    node "${scriptPathNorm}" check-msg "$1"
    EXIT_CODE=$?
    if [ $EXIT_CODE -ne 0 ]; then
        exit 1
    fi
else
    echo "[!] Node.js not detected in PATH. Skipping Hetzer commit-msg check."
fi
exit 0
`;

    fs.writeFileSync(preCommitFile, preCommitContent, { encoding: "utf8", mode: 0o755 });
    fs.writeFileSync(commitMsgFile, commitMsgContent, { encoding: "utf8", mode: 0o755 });
    try { fs.chmodSync(preCommitFile, 0o755); } catch { /* Windows */ }
    try { fs.chmodSync(commitMsgFile, 0o755); } catch { /* Windows */ }

    return {
        installed: true,
        path: preCommitFile,
        preCommitPath: preCommitFile,
        commitMsgPath: commitMsgFile,
    };
}

export function uninstallGitHook(root = process.cwd()) {
    const gitDir = findGitDir(root);
    if (!gitDir) return { uninstalled: false };

    let uninstalled = false;
    const hooksDir = path.join(gitDir, "hooks");
    const preCommitFile = path.join(hooksDir, "pre-commit");
    const commitMsgFile = path.join(hooksDir, "commit-msg");

    if (fs.existsSync(preCommitFile)) {
        const content = fs.readFileSync(preCommitFile, "utf8");
        if (
            content.includes("Hetzer Credential-Safety Pre-Commit Hook")
            || content.includes("Hetzer Zero-Plaintext Pre-Commit Hook")
        ) {
            fs.unlinkSync(preCommitFile);
            uninstalled = true;
        }
    }

    if (fs.existsSync(commitMsgFile)) {
        const content = fs.readFileSync(commitMsgFile, "utf8");
        if (content.includes("Hetzer Credential-Safety Commit-Msg Hook")) {
            fs.unlinkSync(commitMsgFile);
            uninstalled = true;
        }
    }

    return { uninstalled, path: preCommitFile };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const action = process.argv[2] || "check";
    const root = process.cwd();

    if (action === "install") {
        try {
            const res = installGitHook(root);
            process.stdout.write("================================================================================\n");
            process.stdout.write("  HETZER - GIT HOOKS INSTALLER (PRE-COMMIT & COMMIT-MSG)\n");
            process.stdout.write("================================================================================\n");
            process.stdout.write(`  [v] Pre-commit hook installed at : ${res.preCommitPath}\n`);
            process.stdout.write(`  [v] Commit-msg hook installed at : ${res.commitMsgPath}\n`);
            process.stdout.write("  [v] Git commits now run the Hetzer Secret Sniffer hooks.\n");
            process.stdout.write("      Supported token patterns, staged .env files, and commit messages are blocked on leak.\n");
            process.stdout.write("================================================================================\n");
            process.exit(0);
        } catch (err) {
            process.stderr.write(`[x] Failed to install git hooks: ${err.message}\n`);
            process.exit(1);
        }
    }

    if (action === "uninstall") {
        const res = uninstallGitHook(root);
        if (res.uninstalled) {
            process.stdout.write(`[v] Hetzer git hooks successfully uninstalled from: ${res.path}\n`);
        } else {
            process.stdout.write("[i] No Hetzer git hooks installed.\n");
        }
        process.exit(0);
    }

    if (action === "check-msg") {
        const msgFile = process.argv[3];
        if (!msgFile) {
            process.stderr.write("[x] Error: Commit message file path required for check-msg\n");
            process.exit(1);
        }
        const result = checkCommitMessageFile(msgFile);
        if (!result.ok) {
            process.stderr.write("\n================================================================================\n");
            process.stderr.write("  🛑 HETZER ARMOR: GIT COMMIT REJECTED (SECRET IN COMMIT MESSAGE!)\n");
            process.stderr.write("================================================================================\n");
            process.stderr.write(`  Scan Latency : ${result.latencyMs} ms\n`);
            process.stderr.write(`  Violations   : Detected ${result.violations.length} raw credential(s) in commit message:\n\n`);
            for (const v of result.violations) {
                process.stderr.write(`  * Line ${v.line} -> [${v.type}] ${v.label}\n`);
            }
            process.stderr.write("\n  HOW TO FIX:\n");
            process.stderr.write("  1. Remove the raw token/credential from your commit message.\n");
            process.stderr.write("  2. If referencing a credential, use: secretRef:<id>\n");
            process.stderr.write("================================================================================\n\n");
            process.exit(1);
        }
        process.stdout.write(`[v] Hetzer Sniffer: Commit message clean (${result.latencyMs} ms). Commit permitted.\n`);
        process.exit(0);
    }

    if (action === "check") {
        const result = checkStagedDiff(root);
        if (!result.ok) {
            process.stderr.write("\n================================================================================\n");
            process.stderr.write("  🛑 HETZER ARMOR: GIT COMMIT BLOCKED (TOKEN LEAK DETECTED!)\n");
            process.stderr.write("================================================================================\n");
            process.stderr.write(`  Scan Latency : ${result.latencyMs} ms\n`);
            process.stderr.write(`  Violations   : Detected ${result.violations.length} raw credential(s) in staged changes:\n\n`);
            for (const v of result.violations) {
                if (v.line > 0) {
                    process.stderr.write(`  * ${v.file}:${v.line} -> [${v.type}] ${v.label}\n`);
                } else {
                    process.stderr.write(`  * ${v.file} -> [${v.type}] ${v.label}\n`);
                }
            }
            process.stderr.write("\n  HOW TO FIX:\n");
            process.stderr.write("  1. Save value to Vault: hetzer creds set <id>\n");
            process.stderr.write("  2. Replace token in your code with: secretRef:<id>\n");
            process.stderr.write("  3. If .env was staged by mistake, run: git rm --cached .env\n");
            process.stderr.write("================================================================================\n\n");
            process.exit(1);
        }
        process.stdout.write(`[v] Hetzer Sniffer: Staged changes clean (${result.latencyMs} ms). Commit permitted.\n`);
        process.exit(0);
    }
}
