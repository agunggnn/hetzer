#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { assertTrackedTreeClean, removeStagedPackage, stagePackage } from "./package-stage.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifactRoot = path.join(root, "artifacts");

function pack(cwd) {
    const result = spawnSync("npm", ["pack", "--json", "--pack-destination", artifactRoot], {
        cwd,
        encoding: "utf8",
        windowsHide: true,
        shell: process.platform === "win32",
    });
    if (result.status !== 0) throw new Error(result.stderr || result.stdout || "npm pack failed");
    const report = JSON.parse(result.stdout);
    const artifact = report?.[0];
    if (!artifact?.filename || !artifact?.integrity) throw new Error("npm pack returned an invalid artifact report.");
    return artifact;
}

fs.mkdirSync(artifactRoot, { recursive: true });
assertTrackedTreeClean(root);
const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const scopedStage = stagePackage({
    root,
    packageName: manifest.name,
    registry: manifest.publishConfig.registry,
});
const publicStage = stagePackage({
    root,
    packageName: "hetzer",
    registry: "https://registry.npmjs.org/",
});

try {
    const scoped = pack(scopedStage);
    const publicNpm = pack(publicStage);
    const scopedSha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(artifactRoot, scoped.filename))).digest("hex");
    const publicSha256 = crypto.createHash("sha256").update(fs.readFileSync(path.join(artifactRoot, publicNpm.filename))).digest("hex");
    const checksums = [
        "# SHA-256 Checksums",
        `${scopedSha256}  ${scoped.filename}`,
        `${publicSha256}  ${publicNpm.filename}`,
        "",
        "# Subresource Integrity (SRI)",
        `${scoped.integrity}  ${scoped.filename}`,
        `${publicNpm.integrity}  ${publicNpm.filename}`,
    ].join("\n") + "\n";
    fs.writeFileSync(path.join(artifactRoot, "checksums.txt"), checksums);
    process.stdout.write(`Built ${scoped.filename} (sha256: ${scopedSha256})\n`);
    process.stdout.write(`Built ${publicNpm.filename} (sha256: ${publicSha256})\n`);
    process.stdout.write(`Generated ${path.join(artifactRoot, "checksums.txt")}\n`);
} finally {
    removeStagedPackage(scopedStage);
    removeStagedPackage(publicStage);
}
