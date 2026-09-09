#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const releasePattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;

export function buildReleaseMetadata({ version, commit, taggedCommit = null }) {
    if (!releasePattern.test(String(version))) {
        throw new Error(`Package version is not a supported release version: ${version}`);
    }
    if (!/^[0-9a-f]{40}$/i.test(String(commit))) {
        throw new Error("RELEASE_COMMIT must be a full Git commit SHA.");
    }
    if (taggedCommit !== null && taggedCommit !== commit) {
        throw new Error(`Refusing to move v${version}; it already points to ${taggedCommit}.`);
    }

    return {
        version,
        tag: `v${version}`,
        tagExists: taggedCommit !== null,
    };
}

function resolveTagCommit(tag) {
    const gitPrefix = ["-c", `safe.directory=${root.replaceAll("\\", "/")}`];
    const options = {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
    };
    const exists = spawnSync("git", [...gitPrefix, "show-ref", "--verify", "--quiet", `refs/tags/${tag}`], options);
    if (exists.status === 1) return null;
    if (exists.status !== 0) {
        throw new Error(exists.stderr || exists.stdout || `Unable to inspect ${tag}.`);
    }

    const resolved = spawnSync("git", [...gitPrefix, "rev-list", "-n", "1", `refs/tags/${tag}`], options);
    const commit = resolved.stdout.trim();
    if (resolved.status !== 0 || !/^[0-9a-f]{40}$/i.test(commit)) {
        throw new Error(resolved.stderr || resolved.stdout || `Unable to resolve ${tag}.`);
    }
    return commit;
}

function resolveHeadCommit() {
    const gitPrefix = ["-c", `safe.directory=${root.replaceAll("\\", "/")}`];
    const options = {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
    };
    const resolved = spawnSync("git", [...gitPrefix, "rev-parse", "HEAD"], options);
    const commit = resolved.stdout.trim();
    if (resolved.status !== 0 || !/^[0-9a-f]{40}$/i.test(commit)) {
        return "";
    }
    return commit;
}

function main() {
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const commit = process.env.RELEASE_COMMIT || resolveHeadCommit();
    const tag = `v${manifest.version}`;
    const metadata = buildReleaseMetadata({
        version: manifest.version,
        commit,
        taggedCommit: resolveTagCommit(tag),
    });

    if (process.env.GITHUB_OUTPUT) {
        fs.appendFileSync(process.env.GITHUB_OUTPUT, [
            `version=${metadata.version}`,
            `tag=${metadata.tag}`,
            `tag_exists=${metadata.tagExists}`,
            "",
        ].join("\n"));
    } else {
        process.stdout.write(`Release metadata validated: ${JSON.stringify(metadata)}\n`);
    }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
