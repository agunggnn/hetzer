import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { setModuleEnabled } from "./toggle.mjs";

function setupTempModule(root, moduleId) {
    const moduleDir = path.join(root, "modules", moduleId);
    fs.mkdirSync(moduleDir, { recursive: true });
    fs.writeFileSync(path.join(moduleDir, "module.json"), JSON.stringify({
        id: moduleId,
        label: moduleId,
        version: "1",
        profile: moduleId,
        lifecycle: "compose",
        surface: "headless",
        defaultEnabled: false,
        requires: ["core"],
        composeFiles: ["docker-compose.yml"],
        services: []
    }, null, 2));
}

test("setModuleEnabled adds to HETZER_ENABLED_MODULES", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-toggle-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=\nHETZER_DISABLED_MODULES=\n");
    setupTempModule(root, "sample-mod");
    setModuleEnabled({ root, envFile, moduleId: "sample-mod", enabled: true, builtinFile: path.resolve("cli/modules/builtin.json") });
    const updated = fs.readFileSync(envFile, "utf8");
    assert.ok(updated.includes("HETZER_ENABLED_MODULES=sample-mod"));
    fs.rmSync(root, { recursive: true, force: true });
});

test("setModuleEnabled removes from HETZER_ENABLED_MODULES", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-toggle-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=sample-mod\nHETZER_DISABLED_MODULES=\n");
    setupTempModule(root, "sample-mod");
    setModuleEnabled({ root, envFile, moduleId: "sample-mod", enabled: false, builtinFile: path.resolve("cli/modules/builtin.json") });
    const updated = fs.readFileSync(envFile, "utf8");
    assert.ok(updated.includes("HETZER_DISABLED_MODULES=sample-mod"));
    assert.ok(!updated.includes("HETZER_ENABLED_MODULES=sample-mod"));
    fs.rmSync(root, { recursive: true, force: true });
});

test("setModuleEnabled throws on unknown module", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-toggle-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=\nHETZER_DISABLED_MODULES=\n");
    setupTempModule(root, "sample-mod");
    assert.throws(() => setModuleEnabled({ root, envFile, moduleId: "nonexistent", enabled: true, builtinFile: path.resolve("cli/modules/builtin.json") }), /not installed/);
    fs.rmSync(root, { recursive: true, force: true });
});

test("setModuleEnabled throws when trying to disable core", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-toggle-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=\nHETZER_DISABLED_MODULES=\n");
    assert.throws(() => setModuleEnabled({ root, envFile, moduleId: "core", enabled: false, builtinFile: path.resolve("cli/modules/builtin.json") }), /cannot be removed/);
    fs.rmSync(root, { recursive: true, force: true });
});

test("setModuleEnabled allows disabling and enabling 9router module", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-toggle-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=\nHETZER_DISABLED_MODULES=\n");
    // Disable 9router
    setModuleEnabled({ root, envFile, moduleId: "9router", enabled: false, builtinFile: path.resolve("cli/modules/builtin.json") });
    let updated = fs.readFileSync(envFile, "utf8");
    assert.ok(updated.includes("HETZER_DISABLED_MODULES=9router"));
    // Re-enable 9router
    setModuleEnabled({ root, envFile, moduleId: "9router", enabled: true, builtinFile: path.resolve("cli/modules/builtin.json") });
    updated = fs.readFileSync(envFile, "utf8");
    assert.ok(updated.includes("HETZER_ENABLED_MODULES=9router"));
    assert.ok(!updated.includes("HETZER_DISABLED_MODULES=9router"));
    fs.rmSync(root, { recursive: true, force: true });
});

test("setModuleEnabled sets chmod 600 on .env (Unix)", { skip: process.platform === "win32" }, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-toggle-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=\nHETZER_DISABLED_MODULES=\n");
    setupTempModule(root, "sample-mod");
    fs.chmodSync(envFile, 0o644); // start with loose perms
    setModuleEnabled({ root, envFile, moduleId: "sample-mod", enabled: true, builtinFile: path.resolve("cli/modules/builtin.json") });
    const stats = fs.statSync(envFile);
    assert.equal(stats.mode & 0o777, 0o600);
    fs.rmSync(root, { recursive: true, force: true });
});