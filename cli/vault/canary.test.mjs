import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    generateCanaryToken,
    isCanaryCredential,
    isCanaryToken,
    listExternalCanaries,
    plantExternalCanary,
    removeExternalCanary,
    setupCanaryTrap,
    triggerCanaryAlert,
} from "./canary.mjs";
import { revealCredential } from "./creds.mjs";
import { resolveSecretEnvironment } from "./secret-env.mjs";
import { readAuditEvents } from "./audit.mjs";

test("isCanaryCredential accurately detects decoy credential identifiers", () => {
    assert.equal(isCanaryCredential("canary-token"), true);
    assert.equal(isCanaryCredential("canary-aws-key"), true);
    assert.equal(isCanaryCredential("decoy-password"), true);
    assert.equal(isCanaryCredential("npm-token"), false);
    assert.equal(isCanaryCredential("github-token"), false);
    assert.equal(isCanaryCredential("nine-router-jwt-secret"), false);
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

    // Setup records the decoy credential in the same ledger; the trip itself is exactly one event.
    const auditEvents = readAuditEvents({ root }).filter((entry) => entry.eventType === "CANARY_TRIGGER");
    assert.equal(auditEvents.length, 1);
    assert.equal(auditEvents[0].target, "canary-token");
    assert.equal(auditEvents[0].result, "TRIGGERED");
    assert.match(auditEvents[0].details.threatVector, /Unauthorized Credential Scraping/);
    assert.ok(readAuditEvents({ root }).some((entry) => entry.eventType === "VAULT_SET_CREDENTIAL" && entry.target === "canary-token"));

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


test("external canary: plants a decoy in an untracked bait file, keeps it out of Git and stores only fingerprints", () => {
    const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-ext-canary-")));
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-ext-canary-home-"));
    const git = (...args) => spawnSync("git", ["-C", root, ...args], { encoding: "utf8" });
    const keyId = ["AKIA", "DECOYTEST", "0000000"].join("");
    const secretValue = ["decoy", "secret", "value", "0123456789"].join("-");
    try {
        const haveGit = git("init", "-q").status === 0;
        fs.writeFileSync(path.join(root, ".env"), "API_KEY=secretRef:api-key\n");
        const bait = path.join(root, ".env.backup");
        const planted = plantExternalCanary({
            root, homeDir, file: bait, id: "decoy-aws", label: "canarytokens AWS key",
            entries: [{ name: "AWS_ACCESS_KEY_ID", value: keyId }, { name: "AWS_SECRET_ACCESS_KEY", value: secretValue }],
        });
        assert.equal(fs.readFileSync(bait, "utf8"), `AWS_ACCESS_KEY_ID=${keyId}\nAWS_SECRET_ACCESS_KEY=${secretValue}\n`);
        const registryText = fs.readFileSync(planted.registryFile, "utf8");
        assert.equal(registryText.includes(keyId) || registryText.includes(secretValue), false, "the registry holds no decoy value");
        assert.equal(path.relative(homeDir, planted.registryFile).startsWith(".."), false, "the registry lives under the home directory");
        if (haveGit) {
            assert.match(fs.readFileSync(path.join(root, ".git", "info", "exclude"), "utf8"), /^\/\.env\.backup$/m);
            assert.equal(git("status", "--porcelain", "--", ".env.backup").stdout.trim(), "", "the bait file is invisible to git status");
        }
        assert.deepEqual(listExternalCanaries({ root, homeDir }).map(({ id, present }) => ({ id, present })), [{ id: "decoy-aws", present: true }]);

        const code = (fn) => { try { fn(); return "none"; } catch (error) { return error.code; } };
        const one = [{ name: "X_TOKEN", value: "decoy-x" }];
        assert.equal(code(() => plantExternalCanary({ root, homeDir, file: path.join(root, ".env"), entries: one })), "ERR_CANARY_FILE_UNSAFE");
        assert.equal(code(() => plantExternalCanary({ root, homeDir, file: path.join(root, "data", "x"), entries: one })), "ERR_CANARY_FILE_UNSAFE");
        assert.equal(code(() => plantExternalCanary({ root, homeDir, file: bait, entries: [{ name: "AWS_ACCESS_KEY_ID", value: "other" }] })), "ERR_CANARY_NAME_EXISTS");
        assert.equal(code(() => plantExternalCanary({ root, homeDir, file: bait, entries: [{ name: "BAD NAME", value: "x" }] })), "ERR_CANARY_NAME_INVALID");
        assert.equal(code(() => plantExternalCanary({ root, homeDir, file: bait, entries: [{ name: "Y", value: "a\nb" }] })), "ERR_CANARY_VALUE_INVALID");
        if (haveGit) {
            const tracked = path.join(root, "tracked.env");
            fs.writeFileSync(tracked, "A=1\n");
            git("add", "tracked.env");
            assert.equal(code(() => plantExternalCanary({ root, homeDir, file: tracked, entries: one })), "ERR_CANARY_FILE_TRACKED");
        }

        fs.appendFileSync(bait, "KEEP_ME=1\n");
        fs.writeFileSync(bait, fs.readFileSync(bait, "utf8").replace(secretValue, "edited"));
        assert.equal(listExternalCanaries({ root, homeDir })[0].present, false, "a changed decoy is reported");
        const removed = removeExternalCanary({ root, homeDir, id: "decoy-aws" });
        assert.equal(removed.removedLines, 1, "only lines that still match a fingerprint are removed");
        assert.equal(fs.readFileSync(bait, "utf8"), "AWS_SECRET_ACCESS_KEY=edited\nKEEP_ME=1\n");
        assert.deepEqual(listExternalCanaries({ root, homeDir }), []);
        assert.equal(code(() => removeExternalCanary({ root, homeDir, id: "decoy-aws" })), "ERR_CANARY_NOT_FOUND");
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(homeDir, { recursive: true, force: true });
    }
});
