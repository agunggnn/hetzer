import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Writable } from "node:stream";
import test from "node:test";

import { createHetzer, HetzerSdkError, SDK_ERROR_CODES } from "./index.mjs";
import { Grimoire } from "../cli/vault/hetzer-vault.mjs";

test("public SDK export creates a lazy metadata client", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-export-"));
    const vaultPath = path.join(root, "data", "hetzer-vault.db");
    const client = createHetzer({ root, vaultPath });

    assert.equal(client.kind, "hetzer-sdk");
    assert.equal(client.apiVersion, "experimental-1");
    assert.equal(fs.existsSync(vaultPath), false);
    assert.equal(typeof client.credentials.list, "function");
    assert.equal(typeof client.credentials.metadata, "function");
    assert.equal("resolveRaw" in client, false);
    assert.equal("reveal" in client, false);

    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("public SDK returns safe credential metadata without notes or plaintext", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-metadata-"));
    const vaultPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "synthetic-sdk-master-key-long-enough";
    const secret = "synthetic-sdk-credential-value";
    const vault = new Grimoire({ dbPath: vaultPath, masterKey });
    vault.create({
        id: "sample-api-key",
        projectId: "sample-app",
        keyName: "api-key",
        label: "Sample API key",
        authType: "bearer",
        notes: secret,
        secret,
    });
    vault.close();

    const client = createHetzer({ root, vaultPath });
    const metadata = client.credentials.metadata("sample-api-key");
    const serialized = JSON.stringify(metadata);

    assert.equal(metadata.id, "sample-api-key");
    assert.equal(metadata.projectId, "sample-app");
    assert.equal(metadata.hasSecret, true);
    assert.equal("notes" in metadata, false);
    assert.equal(serialized.includes(secret), false);
    assert.deepEqual(client.credentials.list(), [metadata]);

    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("public SDK rejects invalid configuration and credential ids", () => {
    assert.throws(
        () => createHetzer({ root: path.join(os.tmpdir(), "hetzer-sdk-does-not-exist") }),
        (error) => error instanceof HetzerSdkError && error.code === SDK_ERROR_CODES.INVALID_CONFIG,
    );

    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-validation-"));
    const client = createHetzer({ root, vaultPath: ":memory:" });
    assert.throws(
        () => client.credentials.metadata("Invalid_ID"),
        (error) => error instanceof HetzerSdkError && error.code === SDK_ERROR_CODES.INVALID_CREDENTIAL_ID,
    );
    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("public SDK validates references against target, action, and expiry without decrypting", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-validate-"));
    const vaultPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "synthetic-sdk-validation-master-key";
    const vault = new Grimoire({ dbPath: vaultPath, masterKey });
    vault.create({
        id: "deploy-token",
        projectId: "sample-app",
        keyName: "token",
        allowedActions: ["deploy", "health.check"],
        secret: "synthetic-deploy-secret",
    });
    vault.create({
        id: "expired-token",
        projectId: "sample-app",
        keyName: "expired-token",
        expiresAt: "2020-01-01T00:00:00.000Z",
        secret: "synthetic-expired-secret",
    });
    vault.close();

    const client = createHetzer({ root, vaultPath, actor: "sdk-test" });
    const result = client.credentials.validate("secretRef:deploy-token", {
        targetId: "sample-app",
        action: "deploy",
    });

    assert.equal(result.valid, true);
    assert.equal(result.reference, "secretRef:deploy-token");
    assert.equal(result.action, "deploy");
    assert.equal(result.metadata.hasSecret, true);
    assert.equal(JSON.stringify(result).includes("synthetic-deploy-secret"), false);

    assert.throws(
        () => client.credentials.validate("deploy-token", { targetId: "other-app", action: "deploy" }),
        (error) => error.code === SDK_ERROR_CODES.TARGET_MISMATCH,
    );
    assert.throws(
        () => client.credentials.validate("deploy-token", { targetId: "sample-app", action: "read" }),
        (error) => error.code === SDK_ERROR_CODES.NOT_ALLOWED,
    );
    assert.throws(
        () => client.credentials.validate("expired-token", { targetId: "sample-app" }),
        (error) => error.code === SDK_ERROR_CODES.EXPIRED,
    );
    assert.throws(
        () => client.credentials.validate("secretRef:missing-token"),
        (error) => error.code === SDK_ERROR_CODES.NOT_FOUND,
    );

    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("public SDK validation triggers the existing canary boundary", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-canary-"));
    const client = createHetzer({ root, vaultPath: ":memory:" });

    assert.throws(
        () => client.credentials.validate("secretRef:canary-token"),
        (error) => error.code === "ERR_CANARY_TRIPWIRE_TRIGGERED" && error.exitCode === 43,
    );

    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("public SDK runs a command with strict execution and sanitized streams", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-exec-"));
    const stdout = [];
    const stderr = [];
    const output = (target) => new Writable({
        write(chunk, _encoding, callback) {
            target.push(String(chunk));
            callback();
        },
    });
    const client = createHetzer({ root, vaultPath: ":memory:" });

    const result = await client.execution.run({
        command: process.execPath,
        args: ["-e", "process.stdout.write('sdk-execution-ok')"],
        allow: [],
        stdout: output(stdout),
        stderr: output(stderr),
    });

    assert.deepEqual(result, { status: 0 });
    assert.equal(stdout.join(""), "sdk-execution-ok");
    assert.equal(stderr.join(""), "");
    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("public SDK rejects reflection commands and exposes only a sanitized execution error", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-exec-error-"));
    const client = createHetzer({ root, vaultPath: ":memory:" });

    await assert.rejects(
        () => client.execution.run({
            command: process.execPath,
            args: ["-e", "console.log(process.env)"],
        }),
        (error) => {
            assert.equal(error.code, "ERR_REFLECTION_BLOCKED");
            assert.equal(error.message, "Hetzer execution failed (ERR_REFLECTION_BLOCKED).");
            assert.equal(error.cause, undefined);
            return true;
        },
    );

    client.close();
    fs.rmSync(root, { recursive: true, force: true });
});
