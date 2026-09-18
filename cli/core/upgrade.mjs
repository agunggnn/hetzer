import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { checkForUpdates, formatUpdateBanner } from "./version-check.mjs";

export async function runCliUpgrade(args = [], {
    cliRoot,
    manifest,
    spawnFn = spawnSync,
    fetchFn = globalThis.fetch,
    stdout = process.stdout,
    stderr = process.stderr,
} = {}) {
    const isYes = args.includes("--yes") || args.includes("-y");
    const isCheck = args.includes("--check") || args.includes("-c");
    const repoDir = path.resolve(cliRoot, "..");
    const isGitRepo = fs.existsSync(path.join(repoDir, ".git"));

    stdout.write("================================================================================\n");
    stdout.write("  HETZER - CLI UPGRADE MANAGER\n");
    stdout.write("================================================================================\n");
    stdout.write(`  Current Version : v${manifest.version}\n`);
    stdout.write("  Checking for updates...\n");

    const update = await checkForUpdates({
        currentVersion: manifest.version,
        force: true,
        fetchFn,
    });

    if (update.networkFailed && !update.latestVersion) {
        stderr.write("  [!] Error: Unable to reach GitHub Releases or update registry.\n");
        stderr.write("      Please check your network connection.\n");
        stdout.write("================================================================================\n");
        return { ok: false, error: "network_failed" };
    }

    if (!update.updateAvailable) {
        stdout.write(`  Status          : [v] Hetzer is up to date (v${manifest.version}).\n`);
        stdout.write("================================================================================\n");
        return { ok: true, updated: false, currentVersion: manifest.version };
    }

    stdout.write(`  Latest Version  : v${update.latestVersion}\n`);
    stdout.write(`  Release Notes   : ${update.url}\n`);
    stdout.write("--------------------------------------------------------------------------------\n");

    if (isCheck) {
        stdout.write(`  An update is available! Run 'hetzer upgrade' to install v${update.latestVersion}.\n`);
        stdout.write("================================================================================\n");
        return { ok: true, updated: false, updateAvailable: true, latestVersion: update.latestVersion };
    }

    if (isGitRepo) {
        stdout.write("  Installation Type : Local Git Repository\n");

        // Verify active branch is main or master to prevent merging into feature branches
        const branchRes = spawnFn("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
            cwd: repoDir,
            encoding: "utf8",
            windowsHide: true,
        });
        const activeBranch = String(branchRes?.stdout || "").trim();
        if (activeBranch && activeBranch !== "main" && activeBranch !== "master") {
            stderr.write(`  [!] Active git branch is '${activeBranch}'.\n`);
            stderr.write("      Automated upgrade can only be run on the 'main' branch to prevent unintended merges.\n");
            stderr.write("      Please commit your work, switch to 'main', and rerun 'hetzer upgrade'.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "git_branch_mismatch", activeBranch };
        }

        // Verify working tree is clean
        const statusRes = spawnFn("git", ["status", "--porcelain"], {
            cwd: repoDir,
            encoding: "utf8",
            windowsHide: true,
        });
        if (String(statusRes?.stdout || "").trim()) {
            stderr.write("  [!] Git working directory has uncommitted changes.\n");
            stderr.write("      Please commit or stash your changes before upgrading.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "git_dirty_working_tree" };
        }

        stdout.write("  Action            : Pulling latest changes from git origin...\n");
        const pullRes = spawnFn("git", ["pull", "origin", "main"], {
            cwd: repoDir,
            stdio: "inherit",
            windowsHide: true,
        });
        if (pullRes.status !== 0) {
            stderr.write("  [!] 'git pull' failed. Please resolve conflicts or run 'git pull' manually.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "git_pull_failed" };
        }

        stdout.write("  Action            : Installing dependencies & updating global symlink...\n");
        const installRes = spawnFn("npm", ["install"], { cwd: repoDir, stdio: "inherit", windowsHide: true });
        if (installRes.status !== 0) {
            stderr.write("  [!] 'npm install' failed during upgrade.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "npm_install_failed" };
        }

        const linkRes = spawnFn("npm", ["link"], { cwd: repoDir, stdio: "inherit", windowsHide: true });
        if (linkRes.status !== 0) {
            stderr.write("  [!] 'npm link' failed during upgrade.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "npm_link_failed" };
        }

        stdout.write("--------------------------------------------------------------------------------\n");
        stdout.write(`  [v] Successfully upgraded Hetzer to v${update.latestVersion}!\n`);
        stdout.write("================================================================================\n");
        return { ok: true, updated: true, latestVersion: update.latestVersion };
    }

    // Global npm package installation with release integrity verification
    stdout.write("  Installation Type : Global NPM Package\n");
    stdout.write(`  Action            : Downloading and verifying release v${update.latestVersion}...\n`);
    const releaseTarballUrl = `https://github.com/agunggnn/hetzer/releases/download/v${update.latestVersion}/hetzer-${update.latestVersion}.tgz`;
    const checksumUrl = `https://github.com/agunggnn/hetzer/releases/download/v${update.latestVersion}/SHASUMS256.txt`;

    let tarballPath = null;
    try {
        const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-upgrade-"));
        tarballPath = path.join(tempDir, `hetzer-${update.latestVersion}.tgz`);

        const tarballRes = await fetchFn(releaseTarballUrl);
        if (!tarballRes.ok) {
            stderr.write(`  [!] Failed to download release tarball (HTTP ${tarballRes.status}).\n`);
            stdout.write("================================================================================\n");
            return { ok: false, error: "release_download_failed" };
        }
        const tarballBuffer = Buffer.from(await tarballRes.arrayBuffer());
        const actualSha256 = crypto.createHash("sha256").update(tarballBuffer).digest("hex");

        let checksumRes;
        try {
            checksumRes = await fetchFn(checksumUrl);
        } catch (err) {
            stderr.write(`  [!] Failed to reach release checksum URL: ${err.message}\n`);
            stdout.write("================================================================================\n");
            return { ok: false, error: "checksum_download_failed" };
        }

        if (!checksumRes || !checksumRes.ok) {
            stderr.write(`  [!] Release checksum asset unavailable (HTTP ${checksumRes?.status || "error"}).\n`);
            stderr.write("      Installation aborted because release integrity could not be verified.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "checksum_unavailable" };
        }

        const checksumText = await checksumRes.text();
        const expectedLine = checksumText.split("\n").find((line) => line.includes(`hetzer-${update.latestVersion}.tgz`));
        if (!expectedLine) {
            stderr.write(`  [!] Release checksum file missing entry for hetzer-${update.latestVersion}.tgz.\n`);
            stderr.write("      Installation aborted due to unverified package integrity.\n");
            stdout.write("================================================================================\n");
            return { ok: false, error: "checksum_entry_missing" };
        }

        const expectedSha = expectedLine.trim().split(/\s+/)[0].toLowerCase();
        if (!/^[0-9a-f]{64}$/.test(expectedSha) || actualSha256 !== expectedSha) {
            stderr.write("  [!] CRITICAL INTEGRITY ERROR: Release checksum mismatch!\n");
            stderr.write(`      Expected : ${expectedSha}\n`);
            stderr.write(`      Actual   : ${actualSha256}\n`);
            stdout.write("================================================================================\n");
            return { ok: false, error: "integrity_check_failed" };
        }
        stdout.write("  [v] Release integrity verified via SHA-256.\n");

        fs.writeFileSync(tarballPath, tarballBuffer);

        stdout.write(`  Action            : Installing v${update.latestVersion} via npm...\n`);
        const installRes = spawnFn("npm", ["install", "-g", tarballPath], {
            stdio: "inherit",
            windowsHide: true,
        });

        if (installRes.status !== 0) {
            stderr.write("  [!] 'npm install -g' failed. Run manually:\n");
            stderr.write(`      npm install -g @agunggnn/hetzer@${update.latestVersion} --registry=https://npm.pkg.github.com\n`);
            stdout.write("================================================================================\n");
            return { ok: false, error: "npm_install_failed" };
        }

        stdout.write("--------------------------------------------------------------------------------\n");
        stdout.write(`  [v] Successfully upgraded Hetzer to v${update.latestVersion}!\n`);
        stdout.write("================================================================================\n");
        return { ok: true, updated: true, latestVersion: update.latestVersion };
    } finally {
        if (tarballPath) {
            try {
                fs.rmSync(path.dirname(tarballPath), { recursive: true, force: true });
            } catch {
                // Ignore cleanup error
            }
        }
    }
}
