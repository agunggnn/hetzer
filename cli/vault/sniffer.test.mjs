import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { scanText, redactAndVault, restoreSecrets, shannonEntropy } from "./sniffer.mjs";
import { Grimoire } from "./hetzer-vault.mjs";

test("sniffer scanText executes in sub-millisecond on clean text", () => {
    const text = "Please analyze the following Postgres database structure and generate an SQL query.";
    const result = scanText(text);
    assert.equal(result.hasSecrets, false);
    assert.equal(result.matches.length, 0);
    assert.ok(result.latencyMs < 5.0, `Expected latency < 5ms, got ${result.latencyMs}ms`);
});

test("sniffer scanText accurately detects candidate tokens", () => {
    const fakeNpm = ["npm_", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"].join("");
    const input = `Deploy package with token ${fakeNpm} to npmjs.`;
    const result = scanText(input);

    assert.equal(result.hasSecrets, true);
    assert.equal(result.matches.length, 1);
    assert.equal(result.matches[0].type, "npm_token");
    assert.equal(result.matches[0].value, fakeNpm);
    assert.ok(result.latencyMs < 5.0, `Expected latency < 5ms, got ${result.latencyMs}ms`);
});

test("sniffer detects PKCS8 private keys, credentialed database URLs, and high-entropy candidates", () => {
    const privateKey = [
        "-----BEGIN PRIVATE KEY-----",
        "c3ludGhldGljLXRlc3QtZGF0YS1vbmx5",
        "-----END PRIVATE KEY-----",
    ].join("\n");
    assert.equal(scanText(privateKey).matches.some((item) => item.type === "private_key"), true);
    assert.equal(
        scanText("postgresql://audit-user:synthetic-password@localhost/audit").matches.some((item) => item.type === "database_url"),
        true
    );
    const candidate = "A7fK2mQ9xR4vN8pL3sT6yW1cD5hJ0uBz";
    assert.ok(shannonEntropy(candidate) >= 4.3);
    assert.equal(scanText(candidate).matches.some((item) => item.type === "high_entropy"), true);
});

test("sniffer redactAndVault replaces raw credentials with secretRef and auto-vaults", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sniffer-test-"));
    const dataDir = path.join(tempDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(tempDir, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    try {
        const fakeNpm = ["npm_", "x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m6n7o8"].join("");
        const prompt = `Send publish request with token ${fakeNpm} now.`;

        const res = redactAndVault(prompt, { root: tempDir, envFile, masterKey, autoVault: true });

        assert.equal(res.redactedCount, 1);
        assert.equal(res.vaultedCount, 1);
        assert.deepEqual(res.vaultErrors, []);
        assert.ok(res.text.includes("secretRef:npm-token"));
        assert.ok(!res.text.includes(fakeNpm));
        assert.equal(Number.isFinite(res.latencyMs), true);

        // Exercise scan/redact on an already initialized database.
        const warmRes = redactAndVault("Clean text without secrets.");
        assert.equal(Number.isFinite(warmRes.latencyMs), true);

        // Verify Vault storage
        const vault = new Grimoire({ dbPath: path.join(dataDir, "hetzer-vault.db"), masterKey });
        const entry = vault.find("npm-token");
        assert.ok(entry, "Credential npm-token must be stored in Vault");
        const revealed = vault.reveal("npm-token");
        assert.equal(revealed, fakeNpm);
        vault.close();

        // Verify out-of-band restore
        const restored = restoreSecrets(res.text, { root: tempDir, envFile, masterKey });
        assert.equal(restored, prompt);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("auto-vaulting a new candidate does not overwrite an existing provider credential", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sniffer-collision-"));
    const dataDir = path.join(tempDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(tempDir, ".env");
    const masterKey = "22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    const first = ["npm_", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"].join("");
    const second = ["npm_", "z9y8x7w6v5u4t3s2r1q0p9o8n7m6l5k4j3i2"].join("");
    try {
        const initial = redactAndVault(first, { root: tempDir, envFile, masterKey });
        const next = redactAndVault(second, { root: tempDir, envFile, masterKey });
        assert.equal(initial.detected[0].id, "npm-token");
        assert.notEqual(next.detected[0].id, "npm-token");
        assert.equal(next.vaultedCount, 1);

        const vault = new Grimoire({ dbPath: path.join(dataDir, "hetzer-vault.db"), masterKey });
        assert.equal(vault.reveal("npm-token"), first);
        assert.equal(vault.reveal(next.detected[0].id), second);
        vault.close();
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
