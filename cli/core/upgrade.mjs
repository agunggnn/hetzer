import { spawnSync } from "node:child_process";
import fs from "node:fs";
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
        spawnFn("npm", ["install"], { cwd: repoDir, stdio: "inherit", windowsHide: true });
        spawnFn("npm", ["link"], { cwd: repoDir, stdio: "inherit", windowsHide: true });

        stdout.write("--------------------------------------------------------------------------------\n");
        stdout.write(`  [v] Successfully upgraded Hetzer to v${update.latestVersion}!\n`);
        stdout.write("================================================================================\n");
        return { ok: true, updated: true, latestVersion: update.latestVersion };
    }

    // Global npm package installation via GitHub Release tarball or git URL
    const releaseTarball = `https://github.com/agunggnn/hetzer/releases/download/v${update.latestVersion}/hetzer-${update.latestVersion}.tgz`;
    stdout.write("  Installation Type : Global NPM Package\n");
    stdout.write(`  Action            : Installing v${update.latestVersion} via npm...\n`);

    const installRes = spawnFn("npm", ["install", "-g", releaseTarball], {
        stdio: "inherit",
        windowsHide: true,
    });

    if (installRes.status !== 0) {
        stdout.write("  Falling back to GitHub repository URL...\n");
        const fallbackRes = spawnFn("npm", ["install", "-g", "git+https://github.com/agunggnn/hetzer.git"], {
            stdio: "inherit",
            windowsHide: true,
        });
        if (fallbackRes.status !== 0) {
            stderr.write("  [!] Upgrade failed. Run manually:\n");
            stderr.write(`      npm install -g ${releaseTarball}\n`);
            stdout.write("================================================================================\n");
            return { ok: false, error: "npm_install_failed" };
        }
    }

    stdout.write("--------------------------------------------------------------------------------\n");
    stdout.write(`  [v] Successfully upgraded Hetzer to v${update.latestVersion}!\n`);
    stdout.write("================================================================================\n");
    return { ok: true, updated: true, latestVersion: update.latestVersion };
}
