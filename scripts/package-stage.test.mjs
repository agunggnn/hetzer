import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { assertTrackedTreeClean, removeStagedPackage, stagePackage } from "./package-stage.mjs";

test("stagePackage creates a registry-specific manifest from an explicit safe file list", () => {
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-stage-fixture-"));
    fs.mkdirSync(path.join(fixtureRoot, "cli"), { recursive: true });
    fs.writeFileSync(path.join(fixtureRoot, "package.json"), JSON.stringify({ name: "@agunggnn/hetzer", version: "0.4.7" }));
    fs.writeFileSync(path.join(fixtureRoot, "cli", "entry.js"), "#!/usr/bin/env node\n");

    let staged;
    try {
        staged = stagePackage({
            root: fixtureRoot,
            packageName: "hetzer",
            registry: "https://registry.npmjs.org/",
            files: ["package.json", "cli/entry.js"],
        });
        const manifest = JSON.parse(fs.readFileSync(path.join(staged, "package.json"), "utf8"));
        assert.equal(manifest.name, "hetzer");
        assert.equal(manifest.version, "0.4.7");
        assert.equal(manifest.publishConfig.registry, "https://registry.npmjs.org/");
        assert.equal(fs.readFileSync(path.join(staged, "cli", "entry.js"), "utf8"), "#!/usr/bin/env node\n");
    } finally {
        if (staged) removeStagedPackage(staged);
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
});

test("stagePackage rejects paths outside the source package", () => {
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-stage-fixture-"));
    fs.writeFileSync(path.join(fixtureRoot, "package.json"), JSON.stringify({ name: "hetzer", version: "0.4.7" }));
    try {
        assert.throws(() => stagePackage({
            root: fixtureRoot,
            packageName: "hetzer",
            registry: "https://registry.npmjs.org/",
            files: ["package.json", "../outside.txt"],
        }), /Refusing unsafe package path/);
    } finally {
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
});

test("stagePackage excludes untracked files discovered by npm pack", () => {
    const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-stage-fixture-"));
    fs.writeFileSync(path.join(fixtureRoot, "package.json"), JSON.stringify({ name: "hetzer", version: "0.4.7" }));
    fs.writeFileSync(path.join(fixtureRoot, "tracked.txt"), "tracked\n");
    fs.writeFileSync(path.join(fixtureRoot, "untracked.txt"), "untracked\n");

    const run = (command) => {
        if (command === "npm") {
            return {
                status: 0,
                stdout: JSON.stringify([{
                    files: ["package.json", "tracked.txt", "untracked.txt"].map((file) => ({ path: file })),
                }]),
                stderr: "",
            };
        }
        if (command === "git") {
            return { status: 0, stdout: "package.json\0tracked.txt\0", stderr: "" };
        }
        throw new Error(`Unexpected command: ${command}`);
    };

    let staged;
    try {
        staged = stagePackage({
            root: fixtureRoot,
            packageName: "hetzer",
            registry: "https://registry.npmjs.org/",
            run,
        });
        assert.equal(fs.existsSync(path.join(staged, "tracked.txt")), true);
        assert.equal(fs.existsSync(path.join(staged, "untracked.txt")), false);
    } finally {
        if (staged) removeStagedPackage(staged);
        fs.rmSync(fixtureRoot, { recursive: true, force: true });
    }
});

test("assertTrackedTreeClean permits untracked files but rejects tracked changes", () => {
    const cleanRun = () => ({ status: 0, stdout: "?? local-note.md\n", stderr: "" });
    assert.doesNotThrow(() => assertTrackedTreeClean(".", { run: cleanRun }));

    const dirtyRun = () => ({ status: 0, stdout: " M package.json\n", stderr: "" });
    assert.throws(
        () => assertTrackedTreeClean(".", { run: dirtyRun }),
        /Refusing to build or publish from a tree with tracked changes/,
    );
});
