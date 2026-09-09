#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const sourceRoots = ["cli/core", "cli/modules", "cli/mcp", "cli/vault", "cli/skills", "scripts"];

function filesUnder(dir) {
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        if (entry.name === "node_modules") return [];
        const target = path.join(dir, entry.name);
        return entry.isDirectory() ? filesUnder(target) : [target];
    });
}

const sources = sourceRoots
    .flatMap((dir) => filesUnder(path.join(root, dir)))
    .filter((file) => /\.(?:js|mjs)$/.test(file));

for (const file of sources) {
    const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit", windowsHide: true });
    if (result.status !== 0) process.exit(result.status || 1);
}

const forbidden = [
    ["agunggnn", "/Shadow"].join(""),
    ["UN", "LICENSED"].join(""),
    ["MY", "_MEMORY_"].join(""),
    ["THREADS", "_API_"].join(""),
    ["POSTIZ", "_"].join(""),
    ["PROJECT", "_FORGE_"].join(""),
    ["GUARD", "_API_"].join(""),
    ["hetzer", "-pet"].join(""),
];
const publicFiles = filesUnder(root).filter((file) =>
    !file.includes(`${path.sep}.git${path.sep}`)
    && !file.includes(`${path.sep}node_modules${path.sep}`)
    && /\.(?:cjs|js|json|md|mjs|txt|ya?ml)$/.test(file)
);
const credentialPatterns = [
    /\bAKIA[0-9A-Z]{16}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
    /\bsk-[A-Za-z0-9_-]{20,}\b/,
    /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
];
for (const file of publicFiles) {
    const text = fs.readFileSync(file, "utf8");
    const marker = forbidden.find((value) => text.includes(value));
    if (marker) {
        process.stderr.write(`Forbidden public marker '${marker}' in ${path.relative(root, file)}\n`);
        process.exit(1);
    }
    if (credentialPatterns.some((pattern) => pattern.test(text))) {
        process.stderr.write(`Credential-like value in ${path.relative(root, file)}\n`);
        process.exit(1);
    }
}

process.stdout.write(`Hetzer static check passed: ${sources.length} source files and public credential-pattern scan.\n`);
