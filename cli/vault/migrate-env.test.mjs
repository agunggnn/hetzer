import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { Grimoire } from "./hetzer-vault.mjs";
import { autoIngestPlaintextEnv, migrateEnvCredentials } from "./migrate-env.mjs";

test("Cognee provider keys move from plaintext to scoped Vault references", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-cognee-key-"));
    const envFile = path.join(root, ".env");
    const masterKey = "test-migration-master-key-that-is-long-enough";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\nCOGNEE_LLM_API_KEY=provider-secret\n`);

    const migrated = migrateEnvCredentials({ root, envFile, masterKey, authorizationRef: "user:test-approval" });
    assert.deepEqual(migrated, ["COGNEE_LLM_API_KEY"]);
    assert.match(fs.readFileSync(envFile, "utf8"), /COGNEE_LLM_API_KEY=secretRef:cognee-llm-api-key/);
    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    assert.equal(vault.resolveRef("secretRef:cognee-llm-api-key", {
        targetId: "cognee",
        action: "compose.start",
    }), "provider-secret");
    vault.close();
    fs.rmSync(root, { recursive: true, force: true });
});

test("automatic env ingestion refuses to overwrite an existing credential", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-auto-ingest-conflict-"));
    const envFile = path.join(root, ".env");
    const masterKey = "test-auto-ingest-master-key-that-is-long-enough";
    const originalValue = ["original", "synthetic", "value"].join("-");
    const incomingValue = ["incoming", "synthetic", "value"].join("-");
    fs.mkdirSync(path.join(root, "data"), { recursive: true });
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\nNINE_ROUTER_INITIAL_PASSWORD=${incomingValue}\n`);

    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    vault.upsertTarget({ id: "nine-router", name: "nine-router", target_type: "hetzer-module" });
    vault.create({
        id: "nine-router-initial-password",
        projectId: "nine-router",
        keyName: "initial_password",
        authType: "password",
        secret: originalValue,
        allowedActions: ["process.start"],
    });
    vault.close();

    assert.throws(
        () => autoIngestPlaintextEnv({ root, envFile, masterKey }),
        /refused to overwrite existing credential/
    );
    const reopened = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    assert.equal(reopened.reveal("nine-router-initial-password"), originalValue);
    reopened.close();
    assert.equal(fs.readFileSync(envFile, "utf8").includes(incomingValue), true);
    fs.rmSync(root, { recursive: true, force: true });
});
