import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as sdk from "./index.mjs";
import { createHetzer, SDK_API_VERSION, SDK_ERROR_CODES } from "./index.mjs";
import { setCredential } from "../cli/vault/creds.mjs";
import { Grimoire } from "../cli/vault/hetzer-vault.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FORBIDDEN_MEMBER = /resolve|reveal|decrypt|lease/i;

function tree(value, prefix = "") {
    const names = [];
    for (const key of Object.keys(value).sort()) {
        names.push(`${prefix}${key}`);
        if (value[key] && typeof value[key] === "object") names.push(...tree(value[key], `${prefix}${key}.`));
    }
    return names;
}

test("the SDK contract lists exactly the documented members", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-contract-"));
    const client = createHetzer({ root, vaultPath: ":memory:" });
    try {
        assert.equal(SDK_API_VERSION, 1);
        assert.equal(client.apiVersion, SDK_API_VERSION);
        assert.deepEqual(tree(client), [
            "apiVersion", "close", "credentials", "credentials.list", "credentials.metadata", "credentials.validate",
            "execution", "execution.run", "kind",
        ]);
        assert.deepEqual(Object.keys(sdk).sort(), [
            "HetzerSdkError", "SDK_API_VERSION", "SDK_ERROR_CODES", "createHetzer", "formatSecretRef", "isSecretRef", "parseSecretRef",
        ]);
        assert.deepEqual(Object.values(SDK_ERROR_CODES).sort(), [
            "ERR_CREDENTIAL_EXPIRED", "ERR_CREDENTIAL_ID_INVALID", "ERR_CREDENTIAL_NOT_ALLOWED", "ERR_CREDENTIAL_NOT_FOUND",
            "ERR_CREDENTIAL_REFERENCE_INVALID", "ERR_CREDENTIAL_TARGET_MISMATCH", "ERR_SDK_INVALID_CONFIG",
        ]);
        assert.ok(Object.isFrozen(client) && Object.isFrozen(client.credentials) && Object.isFrozen(client.execution));
    } finally {
        client.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("the SDK exposes no resolve, reveal, decrypt or lease member and the package exports only the SDK entry", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-contract-"));
    const client = createHetzer({ root, vaultPath: ":memory:" });
    try {
        for (const name of [...tree(client), ...Object.keys(sdk)]) {
            assert.equal(FORBIDDEN_MEMBER.test(name), false, `${name} must not be part of the public SDK`);
        }
        const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
        assert.deepEqual(Object.keys(pkg.exports).sort(), ["./package.json", "./sdk"]);
    } finally {
        client.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("credential values do not appear in any SDK result or error", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-contract-"));
    const masterKey = "synthetic-sdk-contract-master-key-0123456789";
    const secret = ["synthetic", "contract", "credential", "value", "0001"].join("-");
    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    vault.create({
        id: "contract-key", projectId: "sample-app", keyName: "contract-key", notes: secret, secret,
        allowedActions: ["deploy"],
    });
    vault.close();
    const client = createHetzer({ root, vaultPath: path.join(root, "data", "hetzer-vault.db") });
    const seen = [];
    const capture = (value) => seen.push(JSON.stringify(value, Object.getOwnPropertyNames(Object(value))), String(value?.stack || ""), String(value?.message || ""));
    try {
        capture(client.credentials.list());
        capture(client.credentials.metadata("contract-key"));
        capture(client.credentials.validate("secretRef:contract-key", { targetId: "sample-app", action: "deploy" }));
        for (const attempt of [
            () => client.credentials.validate("secretRef:contract-key", { targetId: "other-app" }),
            () => client.credentials.validate("secretRef:contract-key", { action: "read" }),
            () => client.credentials.validate("secretRef:missing-key"),
            () => client.credentials.metadata("contract_key"),
        ]) {
            try { attempt(); assert.fail("expected an error"); } catch (error) { assert.ok(error instanceof sdk.HetzerSdkError); capture(error); }
        }
        capture(Object.keys(client));
        for (const text of seen) assert.equal(text.includes(secret), false);
    } finally {
        client.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("SDK execution checks the vault grant before a raw credential reaches a child", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-contract-"));
    const envFile = path.join(root, ".env");
    const masterKey = "1122334455667788990011223344556677889900aabbccddeeff001122334455";
    const secret = ["synthetic", "grant", "denied", "value", "0002"].join("-");
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);
    setCredential({ root, envFile, id: "npm-token", secret, rawInjection: "deny" });
    const marker = path.join(root, "ran.txt");
    const client = createHetzer({ root });
    try {
        await assert.rejects(
            () => client.execution.run({
                command: process.execPath,
                args: ["-e", `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "ran")`],
                allow: ["npm-token"],
                allowRawUnmediated: ["npm-token"],
            }),
            (error) => {
                assert.equal(error.code, "ERR_RAW_UNMEDIATED_DENIED_BY_GRANT");
                assert.equal(error.message, "Hetzer execution failed (ERR_RAW_UNMEDIATED_DENIED_BY_GRANT).");
                assert.equal(`${error.stack}${error.message}`.includes(secret), false);
                return true;
            },
        );
        assert.equal(fs.existsSync(marker), false, "the child must not start");
    } finally {
        client.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("the SDK accepts one credential id grammar: lowercase kebab-case", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sdk-contract-"));
    const client = createHetzer({ root, vaultPath: ":memory:" });
    try {
        for (const id of ["a_b", "a.b", "A-b", "-a", "a-", "a--b", ""]) {
            assert.throws(() => client.credentials.metadata(id), (error) => error.code === SDK_ERROR_CODES.INVALID_CREDENTIAL_ID, id);
            assert.throws(() => client.credentials.validate(id), (error) => error.code === SDK_ERROR_CODES.INVALID_REFERENCE, id);
            if (id) assert.throws(() => client.credentials.validate(`secretRef:${id}`), (error) => error.code === SDK_ERROR_CODES.INVALID_REFERENCE, id);
        }
        assert.throws(() => client.credentials.validate("secretRef:a-b", { targetId: "a.b" }), (error) => error.code === SDK_ERROR_CODES.INVALID_CONFIG);
        assert.throws(() => client.credentials.validate("a-b", { targetId: "a_b" }), (error) => error.code === SDK_ERROR_CODES.INVALID_CONFIG);
    } finally {
        client.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});
