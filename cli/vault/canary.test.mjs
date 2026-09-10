import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { generateCanaryToken, isCanaryCredential, isCanaryToken, setupCanaryTrap, triggerCanaryAlert } from "./canary.mjs";
import { revealCredential } from "./creds.mjs";
import { resolveSecretEnvironment } from "./secret-env.mjs";

test("isCanaryCredential accurately detects decoy credential identifiers", () => {
    assert.equal(isCanaryCredential("canary-token"), true);
    assert.equal(isCanaryCredential("canary-aws-key"), true);
    assert.equal(isCanaryCredential("decoy-password"), true);
    assert.equal(isCanaryCredential("npm-token"), false);
    assert.equal(isCanaryCredential("github-token"), false);
    assert.equal(isCanaryCredential("cognee-llm-api-key"), false);
});

test("setupCanaryTrap stores decoy honey-token and updates .env safely", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-canary-test-"));
    const dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(root, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    const trap = setupCanaryTrap({ root, envFile });
    assert.equal(trap.id, "canary-token");
    assert.match(trap.decoyToken, /^canary_trap_[0-9a-f]{32}$/);

    const envContent = fs.readFileSync(envFile, "utf8");
    assert.match(envContent, /CANARY_TOKEN=secretRef:canary-token/);

    fs.rmSync(root, { recursive: true, force: true });
});

test("revealCredential trips immediately when a canary honey-token is requested", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-canary-reveal-"));
    const dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(root, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    setupCanaryTrap({ root, envFile });

    assert.throws(() => {
        revealCredential({ root, envFile, id: "canary-token" });
    }, (err) => {
        assert.equal(err.code, "ERR_CANARY_TRIPWIRE_TRIGGERED");
        assert.equal(err.exitCode, 43);
        assert.match(err.message, /forbidden/);
        return true;
    });

    const incidentsLog = path.join(root, "data", "hetzer-incidents.log");
    assert.ok(fs.existsSync(incidentsLog));
    const logContent = fs.readFileSync(incidentsLog, "utf8");
    assert.match(logContent, /Canary 'canary-token' triggered/);

    fs.rmSync(root, { recursive: true, force: true });
});

test("resolveSecretEnvironment trips tripwire when canary binding is resolved", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-canary-resolve-"));
    const dataDir = path.join(root, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(root, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\nHETZER_CANARY_TOKEN=secretRef:canary-token\n`);

    setupCanaryTrap({ root, envFile });

    assert.throws(() => {
        resolveSecretEnvironment({
            root,
            envFile,
            baseEnv: { HETZER_GRIMOIRE_KEY: masterKey },
            allowNames: ["canary-token"],
        });
    }, (err) => {
        assert.equal(err.code, "ERR_CANARY_TRIPWIRE_TRIGGERED");
        return true;
    });

    fs.rmSync(root, { recursive: true, force: true });
});

test("isCanaryToken and generateCanaryToken properly identify synthetic decoy honeytokens", () => {
    const token = generateCanaryToken();
    assert.match(token, /^canary_trap_[0-9a-f]{32}$/);
    assert.equal(isCanaryToken(token), true);
    assert.equal(isCanaryToken(`Bearer ${token}`), true);
    assert.equal(isCanaryToken("canary_trap_abcdef0123456789abcdef0123456789"), true);
    assert.equal(isCanaryToken("regular-secret-value"), false);
    assert.equal(isCanaryToken(""), false);
    assert.equal(isCanaryToken(null), false);
});

test("resolveSecretEnvironment automatically injects HETZER_CANARY_TOKEN when canary is enabled", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-canary-env-"));
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    const resolved = resolveSecretEnvironment({
        root,
        envFile,
        baseEnv: { PATH: process.env.PATH },
        canary: true,
    });

    assert.ok(resolved.HETZER_CANARY_TOKEN);
    assert.match(resolved.HETZER_CANARY_TOKEN, /^canary_trap_[0-9a-f]{32}$/);
    assert.equal(isCanaryToken(resolved.HETZER_CANARY_TOKEN), true);

    fs.rmSync(root, { recursive: true, force: true });
});

