import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const STAGING_PREFIX = "hetzer-package-";

export function listPackageFiles(root, { run = spawnSync } = {}) {
    const result = run("npm", ["pack", "--dry-run", "--json"], {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
        shell: process.platform === "win32",
    });
    if (result.status !== 0) {
        throw new Error(`npm pack file discovery failed: ${result.stderr || result.stdout || "unknown error"}`);
    }

    const report = JSON.parse(result.stdout);
    const files = report?.[0]?.files?.map((entry) => entry.path);
    if (!Array.isArray(files) || !files.includes("package.json")) {
        throw new Error("npm pack did not return a valid package file list.");
    }
    return files;
}

export function listTrackedFiles(root, { run = spawnSync } = {}) {
    const result = run("git", ["-c", `safe.directory=${path.resolve(root).replaceAll("\\", "/")}`, "ls-files", "-z"], {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
    });
    if (result.status !== 0) {
        throw new Error(`git tracked-file discovery failed: ${result.stderr || result.stdout || "unknown error"}`);
    }
    return new Set(result.stdout.split("\0").filter(Boolean).map((file) => file.replaceAll("\\", "/")));
}

export function assertTrackedTreeClean(root, { run = spawnSync } = {}) {
    const resolvedRoot = path.resolve(root);
    const result = run("git", [
        "-c",
        `safe.directory=${resolvedRoot.replaceAll("\\", "/")}`,
        "status",
        "--porcelain=v1",
        "--untracked-files=no",
    ], {
        cwd: resolvedRoot,
        encoding: "utf8",
        windowsHide: true,
    });
    if (result.status !== 0) {
        throw new Error(`git release-state check failed: ${result.stderr || result.stdout || "unknown error"}`);
    }
    const trackedChanges = result.stdout.split(/\r?\n/).filter((line) => line && !line.startsWith("??"));
    if (trackedChanges.length > 0) {
        throw new Error("Refusing to build or publish from a tree with tracked changes. Commit the release state first.");
    }
}

export function stagePackage({
    root,
    packageName,
    registry,
    files,
    tempRoot = os.tmpdir(),
    run = spawnSync,
} = {}) {
    if (!root || !packageName || !registry) throw new Error("root, packageName, and registry are required.");
    const registryUrl = new URL(registry);
    if (registryUrl.protocol !== "https:") throw new Error("Package registry must use HTTPS.");

    const resolvedRoot = path.resolve(root);
    const rootPrefix = `${resolvedRoot}${path.sep}`;
    const discoveredFiles = files || listPackageFiles(resolvedRoot, { run });
    const trackedFiles = files ? null : listTrackedFiles(resolvedRoot, { run });
    const packageFiles = trackedFiles
        ? discoveredFiles.filter((file) => trackedFiles.has(file.replaceAll("\\", "/")))
        : discoveredFiles;
    if (!packageFiles.includes("package.json")) {
        throw new Error("Tracked package files must include package.json.");
    }
    const stagingRoot = fs.mkdtempSync(path.join(tempRoot, STAGING_PREFIX));

    try {
        for (const relativeFile of packageFiles) {
            const source = path.resolve(resolvedRoot, relativeFile);
            if (!source.startsWith(rootPrefix) || !fs.statSync(source).isFile()) {
                throw new Error(`Refusing unsafe package path: ${relativeFile}`);
            }
            const target = path.join(stagingRoot, relativeFile);
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.copyFileSync(source, target);
            try { fs.chmodSync(target, fs.statSync(source).mode); } catch { /* Best effort on Windows. */ }
        }

        const manifestPath = path.join(stagingRoot, "package.json");
        const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
        manifest.name = packageName;
        manifest.publishConfig = { access: "public", registry: registryUrl.href };
        fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
        return stagingRoot;
    } catch (error) {
        removeStagedPackage(stagingRoot, { tempRoot });
        throw error;
    }
}

export function removeStagedPackage(stagingRoot, { tempRoot = os.tmpdir() } = {}) {
    const resolvedTemp = path.resolve(tempRoot);
    const resolvedStage = path.resolve(stagingRoot);
    if (path.dirname(resolvedStage) !== resolvedTemp || !path.basename(resolvedStage).startsWith(STAGING_PREFIX)) {
        throw new Error(`Refusing to remove unexpected staging path: ${resolvedStage}`);
    }
    fs.rmSync(resolvedStage, { recursive: true, force: true });
}
