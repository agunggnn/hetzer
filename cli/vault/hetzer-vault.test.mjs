import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";

import { Grimoire } from "./hetzer-vault.mjs";
import { grantCredentialCommand, setCredential } from "./creds.mjs";

test("Grimoire initializes schema with Gate G0 columns and approved policies table", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-init-"));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    const vault = new Grimoire({ dbPath, masterKey });
    try {
        const columns = vault.db.prepare("PRAGMA table_info(vault_credentials)").all().map((c) => c.name);
        assert.ok(columns.includes("allowed_origins"), "column allowed_origins must exist");
        assert.ok(columns.includes("raw_injection"), "column raw_injection must exist");
        assert.ok(columns.includes("bind_hosts"), "column bind_hosts must exist");

        const policyColumns = vault.db.prepare("PRAGMA table_info(vault_approved_policies)").all().map((c) => c.name);
        assert.ok(policyColumns.includes("policy_hash"), "table vault_approved_policies must exist");
        assert.ok(policyColumns.includes("target_origin"));
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("Grimoire automatically migrates older database schemas lacking Gate G0 columns", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-mig-"));
    fs.mkdirSync(path.join(root, "data"), { recursive: true });
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    // Simulate an older v0.5.12 database without Gate G0 columns
    const rawDb = new DatabaseSync(dbPath);
    rawDb.exec(`
        CREATE TABLE vault_targets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE vault_credentials (
            id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            key_name TEXT NOT NULL,
            label TEXT DEFAULT '',
            realm TEXT DEFAULT 'frontier',
            authType TEXT DEFAULT 'api-key',
            auth_type TEXT DEFAULT 'api-key',
            transport_scope TEXT DEFAULT 'header',
            access_role TEXT DEFAULT 'operator',
            header_name TEXT DEFAULT '',
            username TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            allowed_actions TEXT DEFAULT '[]',
            encrypted_value TEXT NOT NULL,
            crypto_version TEXT DEFAULT 'hetzer-vault-v1',
            source TEXT DEFAULT 'manual',
            expires_at TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_used_at TEXT DEFAULT '',
            is_valid INTEGER DEFAULT 1
        );
        CREATE TABLE vault_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE vault_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target_id TEXT,
            credential_id TEXT,
            reason TEXT,
            outcome TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL
        );
        CREATE TABLE vault_audit_findings (
            id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            vulnerability_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT DEFAULT '',
            exploitation_vector TEXT,
            is_resolved INTEGER DEFAULT 0,
            discovered_at TEXT NOT NULL,
            resolved_at TEXT
        );
    `);
    rawDb.close();

    // Now open via Grimoire - should run migration without throwing
    const vault = new Grimoire({ dbPath, masterKey });
    try {
        const columns = vault.db.prepare("PRAGMA table_info(vault_credentials)").all().map((c) => c.name);
        assert.ok(columns.includes("allowed_origins"), "migrated column allowed_origins");
        assert.ok(columns.includes("raw_injection"), "migrated column raw_injection");
        assert.ok(columns.includes("bind_hosts"), "migrated column bind_hosts");

        const policyColumns = vault.db.prepare("PRAGMA table_info(vault_approved_policies)").all().map((c) => c.name);
        assert.ok(policyColumns.includes("policy_hash"), "migrated table vault_approved_policies");
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("Grimoire enforces mandatory action check on resolve()", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-resolve-"));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    const vault = new Grimoire({ dbPath, masterKey });
    try {
        vault.upsertTarget({ id: "test-target", name: "test-target" });
        vault.create({
            id: "scoped-key",
            projectId: "test-target",
            secret: "secret-value-12345",
            allowedActions: ["process.start"],
            allowedOrigins: ["https://example.com"],
            rawInjection: "deny",
        });

        // 1. Missing action fails closed (returns null)
        assert.equal(vault.resolve("scoped-key"), null);
        assert.equal(vault.resolve("scoped-key", { targetId: "test-target" }), null);

        // 2. Un-granted action fails closed
        assert.equal(vault.resolve("scoped-key", { targetId: "test-target", action: "broker.proxy" }), null);

        // 3. Granted action succeeds
        assert.equal(vault.resolve("scoped-key", { targetId: "test-target", action: "process.start" }), "secret-value-12345");
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("Grimoire approveBrokerPolicy records approval and grants origin and broker.proxy action", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-approve-"));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    const vault = new Grimoire({ dbPath, masterKey });
    try {
        vault.upsertTarget({ id: "broker-target", name: "broker-target" });
        vault.create({
            id: "api-cred",
            projectId: "broker-target",
            secret: "api-secret-key-abc",
            allowedActions: ["mcp.tools/call"],
            allowedOrigins: ["https://api.trusted.com"],
        });

        const initialEntry = vault.find("api-cred");
        assert.deepEqual(initialEntry.allowedOrigins, ["https://api.trusted.com"]);
        assert.deepEqual(initialEntry.allowedActions, ["mcp.tools/call"]);
        assert.equal(vault.isBrokerPolicyApproved("api-cred", "abc123hash"), false);

        // Operator approves policy
        const approved = vault.approveBrokerPolicy({
            credentialId: "api-cred",
            policyHash: "abc123hash",
            targetOrigin: "https://api.partner.com",
            policyPath: "policies/partner.json",
            approvedBy: "operator-alice",
        });

        assert.equal(approved.credentialId, "api-cred");
        assert.equal(approved.policyHash, "abc123hash");
        assert.equal(approved.targetOrigin, "https://api.partner.com");

        assert.equal(vault.isBrokerPolicyApproved("api-cred", "abc123hash"), true);
        const record = vault.getApprovedBrokerPolicy("api-cred", "abc123hash");
        assert.equal(record.target_origin, "https://api.partner.com");
        assert.equal(record.approved_by, "operator-alice");

        // Credential entry has updated grants
        const updatedEntry = vault.find("api-cred");
        assert.ok(updatedEntry.allowedOrigins.includes("https://api.trusted.com"));
        assert.ok(updatedEntry.allowedOrigins.includes("https://api.partner.com"));
        assert.ok(updatedEntry.allowedActions.includes("broker.proxy"));
        assert.ok(updatedEntry.allowedActions.includes("mcp.tools/call"));
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("setCredential supports allowedOrigins, rawInjection, and bindHosts operator configuration", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-set-"));
    const envFile = path.join(root, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    setCredential({
        root,
        envFile,
        id: "deploy-token",
        secret: "deploy-secret-token-xyz",
        allowedOrigins: ["https://api.deploy.net"],
        rawInjection: "allow",
        bindHosts: ["deploy.internal"],
        allowedActions: ["process.start"],
    });

    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    try {
        const entry = vault.find("deploy-token");
        assert.deepEqual(entry.allowedOrigins, ["https://api.deploy.net"]);
        assert.equal(entry.rawInjection, "allow");
        assert.deepEqual(entry.bindHosts, ["deploy.internal"]);
        assert.deepEqual(entry.allowedActions, ["process.start"]);
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("Grimoire rejects tampered grant columns via HMAC signature verification (Probes P2 & P3b)", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-hmac-"));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    const vault = new Grimoire({ dbPath, masterKey });
    try {
        vault.upsertTarget({ id: "secure-app", name: "secure-app" });
        vault.create({
            id: "api-token",
            projectId: "secure-app",
            secret: "top-secret-payload",
            allowedActions: ["broker.proxy"],
            allowedOrigins: ["https://trusted.corp.test"],
            rawInjection: "deny",
        });

        // Legitimate entry is valid
        const initial = vault.find("api-token");
        assert.equal(initial.grantValid, true);
        assert.deepEqual(initial.allowedOrigins, ["https://trusted.corp.test"]);
        assert.equal(initial.rawInjection, "deny");
        assert.equal(vault.resolve("api-token", { targetId: "secure-app", action: "broker.proxy" }), "top-secret-payload");

        // 1. Probe P2: Attacker directly updates allowed_origins in SQLite without master key
        vault.db.prepare("UPDATE vault_credentials SET allowed_origins = '[\"https://attacker.evil.test\"]' WHERE id = 'api-token'").run();

        const tamperedOrigins = vault.find("api-token");
        assert.equal(tamperedOrigins.grantValid, false, "tampered grant signature must fail verification");
        assert.deepEqual(tamperedOrigins.allowedOrigins, [], "tampered origins must fail-closed to empty array");
        assert.deepEqual(tamperedOrigins.allowedActions, [], "tampered actions must fail-closed to empty array");
        assert.equal(vault.resolve("api-token", { targetId: "secure-app", action: "broker.proxy" }), null, "resolve() must return null for tampered row");

        // Restore legitimate signature via Grimoire update
        vault.update("api-token", {
            allowedOrigins: ["https://trusted.corp.test"],
            allowedActions: ["broker.proxy"],
            rawInjection: "deny",
        });
        assert.equal(vault.find("api-token").grantValid, true);

        // 2. Probe P3b: Attacker directly updates raw_injection = 'allow' in SQLite
        vault.db.prepare("UPDATE vault_credentials SET raw_injection = 'allow' WHERE id = 'api-token'").run();

        const tamperedRaw = vault.find("api-token");
        assert.equal(tamperedRaw.grantValid, false, "tampered raw_injection must fail signature verification");
        assert.equal(tamperedRaw.rawInjection, "deny", "tampered raw_injection must fail-closed to 'deny'");
        assert.equal(vault.resolve("api-token", { targetId: "secure-app", action: "broker.proxy" }), null);
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("grantCredentialCommand enforces human TTY session and updates grants with valid HMAC", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-g0-grant-cmd-"));
    const envFile = path.join(root, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    try {
        vault.upsertTarget({ id: "service", name: "service" });
        vault.create({
            id: "my-key",
            projectId: "service",
            secret: "s3cr3t-v4lu3",
            allowedActions: ["broker.proxy"],
            allowedOrigins: ["https://api.initial.test"],
            rawInjection: "deny",
        });
    } finally {
        vault.close();
    }

    // 1. Non-interactive session throws access denied
    await assert.rejects(
        () => grantCredentialCommand({
            root,
            envFile,
            id: "my-key",
            origin: "https://api.granted.test",
            input: { isTTY: false },
        }),
        /requires a direct human interactive TTY terminal/i,
    );

    // 2. Interactive session updates grants with valid HMAC signature
    const updated = await grantCredentialCommand({
        root,
        envFile,
        id: "my-key",
        origin: "https://api.granted.test",
        raw: "allow",
        action: "process.start",
        input: { isTTY: true },
        env: {},
        ancestor: { isAgent: false },
    });

    assert.equal(updated.id, "my-key");
    assert.ok(updated.allowedOrigins.includes("https://api.granted.test"));
    assert.equal(updated.rawInjection, "allow");
    assert.ok(updated.allowedActions.includes("process.start"));

    // Verify stored row in database has valid grant signature
    const vault2 = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    try {
        const stored = vault2.find("my-key");
        assert.equal(stored.grantValid, true);
        assert.ok(stored.allowedOrigins.includes("https://api.granted.test"));
        assert.equal(stored.rawInjection, "allow");
        assert.ok(stored.allowedActions.includes("process.start"));
        assert.equal(vault2.resolve("my-key", { targetId: "service", action: "process.start" }), "s3cr3t-v4lu3");
    } finally {
        vault2.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});
