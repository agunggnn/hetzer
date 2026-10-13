import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";

import { readAuditEvents, verifyAuditLedger } from "./audit.mjs";
import { Grimoire, VAULT_FORMAT_VERSION } from "./hetzer-vault.mjs";
import { grantCredentialCommand, setCredential, signExistingGrantsCommand } from "./creds.mjs";

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

const FAIL_CLOSED_KEY = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

function seedVault(prefix) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const vault = new Grimoire({ dbPath, masterKey: FAIL_CLOSED_KEY });
    vault.upsertTarget({ id: "svc", name: "svc" });
    vault.create({
        id: "api-token",
        projectId: "svc",
        secret: "synthetic-secret-value",
        allowedActions: ["broker.proxy"],
        allowedOrigins: ["https://trusted.corp.test"],
    });
    return { root, dbPath, vault };
}

test("clearing the grant signature does not make forged grants trusted, and reopening never re-signs them", () => {
    const { root, dbPath, vault } = seedVault("hetzer-vault-sig-null-");
    try {
        // A writer without the master key forges the grant and removes the signature.
        vault.db.prepare("UPDATE vault_credentials SET allowed_origins = ?, grant_sig = NULL WHERE id = 'api-token'")
            .run(JSON.stringify(["https://attacker.evil.test"]));
        vault.close();

        const reopened = new Grimoire({ dbPath, masterKey: FAIL_CLOSED_KEY });
        try {
            const entry = reopened.find("api-token");
            assert.equal(entry.grantValid, false);
            assert.deepEqual(entry.allowedOrigins, []);
            assert.equal(reopened.resolve("api-token", { targetId: "svc", action: "broker.proxy" }), null);
            const stored = reopened.db.prepare("SELECT grant_sig FROM vault_credentials WHERE id = 'api-token'").get();
            assert.equal(stored.grant_sig, null, "opening the vault must not sign unsigned grants");
        } finally {
            reopened.close();
        }
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("signLegacyGrants signs only unsigned rows and leaves mismatched signatures alone", () => {
    const { root, vault } = seedVault("hetzer-vault-sig-legacy-");
    try {
        vault.create({ id: "legacy-token", projectId: "svc", secret: "synthetic-secret-two", allowedActions: ["process.start"] });
        vault.db.prepare("UPDATE vault_credentials SET grant_sig = NULL WHERE id = 'legacy-token'").run();
        vault.db.prepare("UPDATE vault_credentials SET raw_injection = 'allow' WHERE id = 'api-token'").run();

        assert.deepEqual(vault.listUnsignedGrants().map((grant) => grant.id), ["legacy-token"]);
        assert.equal(vault.find("legacy-token").grantValid, false);

        const signed = vault.signLegacyGrants(["legacy-token", "api-token"]);
        assert.deepEqual(signed, ["legacy-token"]);
        assert.equal(vault.find("legacy-token").grantValid, true);
        assert.equal(vault.resolve("legacy-token", { targetId: "svc", action: "process.start" }), "synthetic-secret-two");
        assert.equal(vault.find("api-token").grantValid, false, "a mismatched signature must not be repaired by signLegacyGrants");
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("broker policy approvals are signed: forged and altered approval rows are ignored", () => {
    const { root, vault } = seedVault("hetzer-vault-approval-sig-");
    try {
        const hash = "ab".repeat(32);
        vault.approveBrokerPolicy({ credentialId: "api-token", policyHash: hash, targetOrigin: "https://trusted.corp.test" });
        assert.equal(vault.isBrokerPolicyApproved("api-token", hash), true);
        assert.equal(vault.listApprovedPolicies("api-token")[0].signatureValid, true);

        // Altering the approved origin invalidates the approval.
        vault.db.prepare("UPDATE vault_approved_policies SET target_origin = 'https://attacker.evil.test' WHERE policy_hash = ?").run(hash);
        assert.equal(vault.isBrokerPolicyApproved("api-token", hash), false);
        assert.equal(vault.listApprovedPolicies("api-token")[0].signatureValid, false);

        // A row inserted without the master key has no valid signature.
        const forgedHash = "cd".repeat(32);
        vault.db.prepare(`
            INSERT INTO vault_approved_policies (id, credential_id, policy_hash, target_origin, policy_path, approved_at, approved_by)
            VALUES ('forged-1', 'api-token', ?, 'https://attacker.evil.test', NULL, ?, 'operator')
        `).run(forgedHash, new Date().toISOString());
        assert.equal(vault.isBrokerPolicyApproved("api-token", forgedHash), false);
        assert.equal(vault.getApprovedBrokerPolicy("api-token", forgedHash), null);
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("rewriting an unrelated field does not re-sign grants that were modified outside Hetzer", () => {
    const { root, vault } = seedVault("hetzer-vault-no-launder-");
    try {
        vault.db.prepare("UPDATE vault_credentials SET allowed_origins = ? WHERE id = 'api-token'")
            .run(JSON.stringify(["https://attacker.evil.test"]));
        vault.update("api-token", { label: "renamed" });

        const entry = vault.find("api-token");
        assert.equal(entry.label, "renamed");
        assert.deepEqual(entry.allowedOrigins, [], "tampered origins must not be carried into the rewritten row");
        assert.deepEqual(entry.allowedActions, []);
        assert.equal(entry.rawInjection, "deny");
    } finally {
        vault.close();
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("signExistingGrantsCommand requires a human session, a typed confirmation, and skips tampered rows", async () => {
    const { root, dbPath, vault } = seedVault("hetzer-vault-sign-cmd-");
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${FAIL_CLOSED_KEY}\n`);
    try {
        vault.create({ id: "legacy-token", projectId: "svc", secret: "synthetic-secret-two", allowedActions: ["process.start"] });
        vault.db.prepare("UPDATE vault_credentials SET grant_sig = NULL WHERE id = 'legacy-token'").run();
        vault.db.prepare("UPDATE vault_credentials SET raw_injection = 'allow' WHERE id = 'api-token'").run();
        vault.close();

        const lines = [];
        const output = { write: (text) => { lines.push(String(text)); return true; } };

        await assert.rejects(
            signExistingGrantsCommand({ root, envFile, input: { isTTY: false }, output }),
            /requires a direct human interactive TTY/i,
        );

        const declined = await signExistingGrantsCommand({
            root, envFile, output, input: { isTTY: true }, env: {}, ancestor: { isAgent: false }, confirm: async () => "no",
        });
        assert.deepEqual(declined.signed, []);
        assert.equal(declined.cancelled, true);

        const approved = await signExistingGrantsCommand({
            root, envFile, output, input: { isTTY: true }, env: {}, ancestor: { isAgent: false }, confirm: async () => "yes",
        });
        assert.deepEqual(approved.signed, ["legacy-token"]);
        assert.deepEqual(approved.tampered, ["api-token"]);
        assert.match(lines.join(""), /creds grant <id> --reset/);

        const after = new Grimoire({ dbPath, masterKey: FAIL_CLOSED_KEY });
        try {
            assert.equal(after.find("legacy-token").grantValid, true);
            assert.equal(after.find("api-token").grantValid, false);
        } finally {
            after.close();
        }
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("vault audit events are mirrored into the keyed file ledger and SQLite keeps its copy", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-ledger-"));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    const previous = process.env.HETZER_AUDIT_LOG_PATH;
    delete process.env.HETZER_AUDIT_LOG_PATH;

    const vault = new Grimoire({ dbPath, masterKey });
    try {
        vault.recordAudit({ actor: "tester", action: "vault.set-credential", credential_id: "demo-token", outcome: "allowed", reason: "synthetic", metadata: { note: "n" } });
        vault.recordAudit({ actor: "tester", action: "broker.policy.approve", credential_id: "demo-token", outcome: "allowed" });

        const logFile = path.join(root, ".hetzer", "audit.log");
        assert.equal(vault.auditLogFile, logFile);
        const events = readAuditEvents({ logFile });
        assert.deepEqual(events.map((event) => event.eventType), ["VAULT_SET_CREDENTIAL", "VAULT_BROKER_POLICY_APPROVE"]);
        assert.equal(events[0].target, "demo-token");
        assert.equal(events[0].result, "ALLOWED");
        assert.equal(events[0].actor.user, "tester");
        assert.ok(events.every((event) => typeof event.mac === "string"));

        const check = verifyAuditLedger({ logFile, macKey: masterKey });
        assert.equal(check.ok, true);
        assert.equal(check.macVerified, true);
        assert.equal(vault.listAudit().length, 2);
    } finally {
        vault.close();
        if (previous !== undefined) process.env.HETZER_AUDIT_LOG_PATH = previous;
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("vault audit events stay in SQLite only for in-memory vaults and non-workspace layouts", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-ledger-off-"));
    const previous = process.env.HETZER_AUDIT_LOG_PATH;
    delete process.env.HETZER_AUDIT_LOG_PATH;
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    const elsewhere = new Grimoire({ dbPath: path.join(root, "vault.db"), masterKey });
    const memory = new Grimoire({ dbPath: ":memory:", masterKey });
    try {
        assert.equal(elsewhere.auditLogFile, null);
        assert.equal(memory.auditLogFile, null);
        elsewhere.recordAudit({ actor: "tester", action: "vault.x", outcome: "allowed" });
        assert.equal(fs.existsSync(path.join(root, ".hetzer")), false);
        assert.equal(elsewhere.listAudit().length, 1);
    } finally {
        elsewhere.close();
        memory.close();
        if (previous !== undefined) process.env.HETZER_AUDIT_LOG_PATH = previous;
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("a new vault is stamped with the format version and a vault without a stamp is version 1", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-format-"));
    const dbPath = path.join(root, "data", "hetzer-vault.db");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    const secret = ["synthetic", "format", "value", "0001"].join("-");
    try {
        let vault = new Grimoire({ dbPath, masterKey });
        assert.equal(vault.formatVersion, VAULT_FORMAT_VERSION);
        assert.equal(vault._meta("format_version"), String(VAULT_FORMAT_VERSION));
        vault.create({ id: "format-key", projectId: "sample-app", keyName: "format-key", secret });
        // A vault from a build that did not stamp a version: no marker row.
        vault.db.prepare("DELETE FROM vault_meta WHERE key = 'format_version'").run();
        vault.close();

        vault = new Grimoire({ dbPath, masterKey });
        assert.equal(vault._meta("format_version"), "1", "an unstamped vault is stamped as version 1");
        assert.equal(vault.matchesSecret("format-key", secret), true, "its credentials still decrypt");
        vault.close();
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("a vault written by a newer format is refused before any schema change or stamp", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-format-newer-"));
    const dbPath = path.join(root, "hetzer-vault.db");
    try {
        // An old-shaped vault stamped with a future format: none of the current tables or columns exist.
        const raw = new DatabaseSync(dbPath);
        raw.exec(`
            CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
            INSERT INTO vault_meta VALUES ('format_version', '${VAULT_FORMAT_VERSION + 1}', '2026-01-01T00:00:00.000Z');
            CREATE TABLE vault_credentials (id TEXT PRIMARY KEY, encrypted_value TEXT NOT NULL);
        `);
        raw.close();
        const before = fs.readFileSync(dbPath);
        const filesBefore = fs.readdirSync(root).sort();

        assert.throws(() => new Grimoire({ dbPath, masterKey: "synthetic-format-master-key-long-enough" }), (error) => {
            assert.equal(error.code, "ERR_VAULT_FORMAT_UNSUPPORTED");
            assert.match(error.message, /nothing was changed/);
            return true;
        });
        assert.ok(fs.readFileSync(dbPath).equals(before), "the vault file is byte-identical");
        assert.deepEqual(fs.readdirSync(root).sort(), filesBefore, "no journal or side file was left behind");

        const check = new DatabaseSync(dbPath);
        const tables = check.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name);
        const columns = check.prepare("PRAGMA table_info(vault_credentials)").all().map((column) => column.name);
        check.close();
        assert.deepEqual(tables, ["vault_credentials", "vault_meta"], "no table was created");
        assert.deepEqual(columns, ["id", "encrypted_value"], "no column was added");
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("a malformed format marker is refused", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-format-bad-"));
    const dbPath = path.join(root, "hetzer-vault.db");
    try {
        for (const marker of ["abc", "0", "-1", "1.5", ""]) {
            const raw = new DatabaseSync(dbPath);
            raw.exec(`
                CREATE TABLE IF NOT EXISTS vault_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
                DELETE FROM vault_meta;
                INSERT INTO vault_meta VALUES ('format_version', '${marker}', '2026-01-01T00:00:00.000Z');
            `);
            raw.close();
            assert.throws(() => new Grimoire({ dbPath }), (error) => error.code === "ERR_VAULT_FORMAT_UNSUPPORTED", `marker '${marker}'`);
        }
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});
