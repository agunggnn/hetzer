import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";

import { initializeProject } from "../core/cli.mjs";
import { rotateAuditLedger, verifyAuditLedger } from "./audit.mjs";
import {
    Grimoire,
    RETIRED_MASTER_KEY_ALIAS,
    VAULT_FORMAT_VERSION,
    getIsolatedKeyPath,
    grantIntegrityError,
    resolveMasterKey,
} from "./hetzer-vault.mjs";

const KEY = "5a".repeat(32);
const OTHER_KEY = "6b".repeat(32);
const SECRET = ["synthetic", "migration", "value"].join("-");
const MIGRATION_EVENT = "VAULT_MIGRATE_SCHEMA_V2";
const PENDING_MARKER = "pending-audit:migrate-schema-v2";

function withWorkspace(fn) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-vault-v2-"));
    const paths = { root, dbPath: path.join(root, "data", "hetzer-vault.db"), logFile: path.join(root, ".hetzer", "audit.log") };
    const done = () => fs.rmSync(root, { recursive: true, force: true });
    let result;
    try {
        result = fn(paths);
    } catch (error) {
        done();
        throw error;
    }
    if (result && typeof result.then === "function") return result.finally(done);
    done();
    return result;
}

function open({ dbPath, logFile }, masterKey = KEY, extra = {}) {
    return new Grimoire({ dbPath, masterKey, auditLogFile: logFile, ...extra });
}

/** A vault as a build before format 2 left it: one credential, the three legacy tables with rows, marker at 1 or absent. */
function seedFormat1(paths, { stamp = "1", legacyTables = true } = {}) {
    const vault = open(paths);
    vault.create({ id: "api-token", projectId: "svc", secret: SECRET, allowedActions: ["broker.proxy"], allowedOrigins: ["https://trusted.corp.test"] });
    vault.recordAudit({ actor: "seed", action: "vault.set-credential", credentialId: "api-token", outcome: "allowed" });
    vault.close();

    const raw = new DatabaseSync(paths.dbPath);
    try {
        if (legacyTables) {
            raw.exec(`
                CREATE TABLE vault_targets (id TEXT PRIMARY KEY, name TEXT NOT NULL, host_address TEXT, port INTEGER);
                INSERT INTO vault_targets VALUES ('svc', 'svc', '10.0.0.5', 8443), ('other', 'other', NULL, NULL);
                CREATE TABLE vault_audit_findings (id TEXT PRIMARY KEY, target_id TEXT NOT NULL, description TEXT);
                INSERT INTO vault_audit_findings VALUES ('f1', 'svc', 'synthetic finding');
                CREATE TABLE vault_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            `);
        }
        if (stamp === null) raw.exec("DELETE FROM vault_meta WHERE key = 'format_version'");
        else raw.prepare("UPDATE vault_meta SET value = ? WHERE key = 'format_version'").run(stamp);
    } finally {
        raw.close();
    }
}

function inspect(dbPath) {
    const raw = new DatabaseSync(dbPath);
    try {
        return {
            tables: raw.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'vault_%' ORDER BY name").all().map((row) => row.name),
            format: raw.prepare("SELECT value FROM vault_meta WHERE key = 'format_version'").get()?.value,
            owed: raw.prepare("SELECT value FROM vault_meta WHERE key = ?").get(PENDING_MARKER)?.value,
            migrationRows: raw.prepare("SELECT metadata FROM vault_audit_events WHERE action = 'vault.migrate-schema-v2'").all().map((row) => JSON.parse(row.metadata)),
        };
    } finally {
        raw.close();
    }
}

function ledgerEntries(logFile, eventType = MIGRATION_EVENT) {
    if (!fs.existsSync(logFile)) return [];
    return fs.readFileSync(logFile, "utf8").split(/\r?\n/).filter(Boolean)
        .map((line) => { try { return JSON.parse(line); } catch { return null; } })
        .filter((entry) => entry && entry.eventType === eventType);
}

const LEGACY_TABLES = ["vault_audit_findings", "vault_metadata", "vault_targets"];

test("a format 1 vault is migrated once: tables dropped, credential and grant intact, one keyed ledger record", () => {
    withWorkspace((paths) => {
        seedFormat1(paths);
        assert.deepEqual(inspect(paths.dbPath).tables.filter((name) => LEGACY_TABLES.includes(name)), LEGACY_TABLES);

        let vault = open(paths);
        assert.equal(vault.matchesSecret("api-token", SECRET), true, "the credential still decrypts");
        assert.equal(grantIntegrityError(vault.find("api-token")), null, "its grant signature still verifies");
        assert.equal(vault.status().migrationAuditPending, false);
        assert.equal(vault.formatVersion, 2);
        vault.close();

        const state = inspect(paths.dbPath);
        assert.deepEqual(state.tables.filter((name) => LEGACY_TABLES.includes(name)), [], "the legacy tables are gone");
        assert.equal(state.format, "2");
        assert.equal(state.owed, undefined, "nothing is owed once the ledger has the record");
        assert.equal(state.migrationRows.length, 1);
        assert.deepEqual(state.migrationRows[0].droppedTables, { vault_targets: 2, vault_audit_findings: 1, vault_metadata: 0 });

        const entries = ledgerEntries(paths.logFile);
        assert.equal(entries.length, 1);
        assert.match(entries[0].mac, /^[0-9a-f]{64}$/);
        assert.deepEqual(entries[0].details.metadata.droppedTables, { vault_targets: 2, vault_audit_findings: 1, vault_metadata: 0 });
        assert.equal(entries[0].details.metadata.fromFormat, 1);
        assert.equal(verifyAuditLedger({ logFile: paths.logFile, macKey: KEY, requireMac: true }).ok, true);

        // Opening the migrated vault again changes nothing.
        vault = open(paths);
        vault.close();
        assert.equal(inspect(paths.dbPath).migrationRows.length, 1);
        assert.equal(ledgerEntries(paths.logFile).length, 1);
    });
});

test("a vault with no format marker takes the same migration", () => {
    withWorkspace((paths) => {
        seedFormat1(paths, { stamp: null });
        const vault = open(paths);
        assert.equal(vault.matchesSecret("api-token", SECRET), true);
        vault.close();
        const state = inspect(paths.dbPath);
        assert.equal(state.format, String(VAULT_FORMAT_VERSION));
        assert.deepEqual(state.tables.filter((name) => LEGACY_TABLES.includes(name)), []);
        assert.equal(ledgerEntries(paths.logFile).length, 1);
    });
});

test("a migration interrupted after the drops completes on the next open", () => {
    withWorkspace((paths) => {
        seedFormat1(paths, { legacyTables: false });
        const vault = open(paths);
        assert.equal(vault.matchesSecret("api-token", SECRET), true);
        vault.close();
        const state = inspect(paths.dbPath);
        assert.equal(state.format, "2");
        assert.deepEqual(state.migrationRows[0].droppedTables, {});
        assert.equal(ledgerEntries(paths.logFile).length, 1);
    });
});

test("a failure inside the migration leaves the format 1 vault as it was", () => {
    withWorkspace((paths) => {
        seedFormat1(paths);
        class FailingVault extends Grimoire {
            _insertAuditRow(event) {
                if (event.action === "vault.migrate-schema-v2") throw new Error("synthetic failure inside the migration");
                return super._insertAuditRow(event);
            }
        }
        assert.throws(() => new FailingVault({ dbPath: paths.dbPath, masterKey: KEY, auditLogFile: paths.logFile }), /synthetic failure/);
        const state = inspect(paths.dbPath);
        assert.equal(state.format, "1");
        assert.deepEqual(state.tables.filter((name) => LEGACY_TABLES.includes(name)), LEGACY_TABLES, "the drops were rolled back");
        assert.equal(state.owed, undefined);
        assert.equal(ledgerEntries(paths.logFile).length, 0);

        const vault = open(paths);
        assert.equal(vault.matchesSecret("api-token", SECRET), true, "a later open migrates normally");
        vault.close();
        assert.equal(inspect(paths.dbPath).format, "2");
    });
});

test("a ledger that refuses the migration record is owed it until it accepts", () => {
    withWorkspace((paths) => {
        seedFormat1(paths);
        fs.appendFileSync(paths.logFile, "{partial-garbage\n");

        let vault = open(paths);
        assert.equal(vault.matchesSecret("api-token", SECRET), true, "the vault still opens and works");
        assert.equal(vault.status().migrationAuditPending, true);
        vault.close();
        let state = inspect(paths.dbPath);
        assert.equal(state.format, "2");
        assert.equal(state.migrationRows.length, 1, "SQLite has its row");
        assert.equal(ledgerEntries(paths.logFile).length, 0, "the damaged ledger did not take the record");
        const owed = JSON.parse(state.owed);

        // Still refused on the next open: still owed, and no second SQLite row.
        vault = open(paths);
        assert.equal(vault.status().migrationAuditPending, true);
        vault.close();
        assert.equal(inspect(paths.dbPath).migrationRows.length, 1);

        rotateAuditLedger({ logFile: paths.logFile, macKey: KEY, reason: "test: damaged tail" });
        vault = open(paths);
        assert.equal(vault.status().migrationAuditPending, false);
        vault.close();
        state = inspect(paths.dbPath);
        assert.equal(state.owed, undefined);
        const entries = ledgerEntries(paths.logFile);
        assert.equal(entries.length, 1);
        assert.equal(entries[0].details.metadata.migratedAt, owed.metadata.migratedAt, "the record carries when the migration ran, not when it was written");
        assert.equal(verifyAuditLedger({ logFile: paths.logFile, macKey: KEY }).ok, true);
    });
});

test("a vault opened locked migrates but leaves the ledger record to a process that has the key", () => {
    withWorkspace((paths) => {
        seedFormat1(paths);
        const before = fs.readFileSync(paths.logFile, "utf8");

        let vault = open(paths, "");
        assert.equal(vault.unlocked, false);
        assert.equal(vault.status().migrationAuditPending, true);
        vault.close();
        assert.equal(inspect(paths.dbPath).format, "2");
        assert.equal(fs.readFileSync(paths.logFile, "utf8"), before, "the keyed ledger was not touched without the key");

        vault = open(paths);
        assert.equal(vault.status().migrationAuditPending, false);
        vault.close();
        const entries = ledgerEntries(paths.logFile);
        assert.equal(entries.length, 1);
        assert.match(entries[0].mac, /^[0-9a-f]{64}$/);
        assert.equal(verifyAuditLedger({ logFile: paths.logFile, macKey: KEY, requireMac: true }).ok, true);
    });

    // With no ledger yet, a locked open does not start one unkeyed.
    withWorkspace((paths) => {
        seedFormat1(paths);
        fs.rmSync(path.dirname(paths.logFile), { recursive: true, force: true });
        const vault = open(paths, "");
        vault.close();
        assert.equal(fs.existsSync(paths.logFile), false);
        assert.ok(inspect(paths.dbPath).owed);
    });
});

test("a vault with no file ledger keeps the SQLite row and owes nothing", () => {
    withWorkspace((paths) => {
        seedFormat1(paths);
        const vault = new Grimoire({ dbPath: paths.dbPath, masterKey: KEY, auditLogFile: false });
        assert.equal(vault.status().migrationAuditPending, false);
        vault.close();
        const state = inspect(paths.dbPath);
        assert.equal(state.migrationRows.length, 1);
        assert.equal(state.owed, undefined);
    });
});

test("processes opening the same format 1 vault at once migrate it once", async () => {
    await withWorkspace(async (paths) => {
        seedFormat1(paths);
        const child = path.join(paths.root, "open.mjs");
        fs.writeFileSync(child, [
            `import { Grimoire } from ${JSON.stringify(pathToFileURL(path.join(import.meta.dirname, "hetzer-vault.mjs")).href)};`,
            "const [dbPath, masterKey, auditLogFile] = process.argv.slice(2);",
            "const vault = new Grimoire({ dbPath, masterKey, auditLogFile });",
            "vault.close();",
        ].join("\n"));
        const results = await Promise.all(Array.from({ length: 4 }, () => new Promise((resolve) => {
            const proc = spawn(process.execPath, [child, paths.dbPath, KEY, paths.logFile], { stdio: ["ignore", "ignore", "pipe"] });
            let stderr = "";
            proc.stderr.on("data", (chunk) => { stderr += chunk; });
            proc.on("close", (code) => resolve(code === 0 ? "ok" : stderr.split(/\r?\n/).filter((line) => line && !/ExperimentalWarning|trace-warnings/.test(line)).slice(0, 2).join(" | ")));
        })));
        assert.deepEqual(results, ["ok", "ok", "ok", "ok"]);

        const state = inspect(paths.dbPath);
        assert.equal(state.format, "2");
        assert.equal(state.migrationRows.length, 1, "the transaction lets one process migrate");
        assert.deepEqual(state.migrationRows[0].droppedTables, { vault_targets: 2, vault_audit_findings: 1, vault_metadata: 0 });
        assert.equal(state.owed, undefined);
        // At least once: openers that overlap the writer can each write the record.
        assert.ok(ledgerEntries(paths.logFile).length >= 1);
        assert.equal(verifyAuditLedger({ logFile: paths.logFile, macKey: KEY }).ok, true);
    });
});

async function warningsDuring(fn) {
    const seen = [];
    const listener = (warning) => { if (warning.code === "HETZER_LEGACY_VAULT_NOT_IMPORTED") seen.push(warning); };
    process.on("warning", listener);
    try {
        fn();
        await new Promise((resolve) => setImmediate(resolve));
    } finally {
        process.off("warning", listener);
    }
    return seen;
}

test("a legacy JSON vault that was never imported is reported, once, with the ids it holds", async () => {
    await withWorkspace(async (paths) => {
        const legacyFile = path.join(paths.root, "data", "vault.json");
        fs.mkdirSync(path.dirname(legacyFile), { recursive: true });
        fs.writeFileSync(legacyFile, JSON.stringify({ entries: [{ id: "old-token" }, { id: "api-token" }, { id: "Not A Valid Id\u001b[31m" }, {}] }));

        let state;
        const first = await warningsDuring(() => {
            const vault = open(paths, KEY, { legacyFile });
            vault.create({ id: "api-token", projectId: "svc", secret: SECRET });
            state = { status: vault.status(), legacyImport: vault.legacyImport };
            vault.close();
        });
        assert.equal(state.status.legacyImportPending, true);
        assert.deepEqual(state.legacyImport.ids, ["old-token", "api-token"], "only well-formed ids that the vault lacks");
        assert.equal(first.length, 1);
        assert.match(first[0].message, /old-token/);
        assert.match(first[0].message, /hetzer creds set/);
        assert.equal(first[0].message.includes("\u001b"), false, "nothing from the file reaches the terminal unchecked");

        const second = await warningsDuring(() => {
            const vault = open(paths, KEY, { legacyFile });
            assert.deepEqual(vault.legacyImport.ids, ["old-token"], "an id now in the vault is no longer reported");
            vault.close();
        });
        assert.equal(second.length, 0, "one warning per file and process");
    });
});

test("a legacy JSON vault is not reported when it was imported earlier, holds nothing new, or cannot be read", async () => {
    await withWorkspace(async (paths) => {
        const legacyFile = path.join(paths.root, "data", "vault.json");
        fs.mkdirSync(path.dirname(legacyFile), { recursive: true });

        fs.writeFileSync(legacyFile, "{not json");
        let vault = open(paths, KEY, { legacyFile });
        assert.equal(vault.status().legacyImportPending, false);
        vault.create({ id: "api-token", projectId: "svc", secret: SECRET });
        vault.close();

        fs.writeFileSync(legacyFile, JSON.stringify({ entries: [{ id: "api-token" }] }));
        vault = open(paths, KEY, { legacyFile });
        assert.equal(vault.status().legacyImportPending, false);
        vault.close();

        // The marker an earlier build wrote after importing this file.
        fs.writeFileSync(legacyFile, JSON.stringify({ entries: [{ id: "never-kept" }] }));
        const { createHash } = await import("node:crypto");
        vault = open(paths, KEY);
        vault._setMeta(`legacy-json:${createHash("sha256").update(path.resolve(legacyFile)).digest("hex")}`, "{}");
        vault.close();
        const seen = await warningsDuring(() => {
            vault = open(paths, KEY, { legacyFile });
            assert.equal(vault.status().legacyImportPending, false);
            vault.close();
        });
        assert.equal(seen.length, 0);

        vault = open(paths, KEY, { legacyFile: path.join(paths.root, "data", "absent.json") });
        assert.equal(vault.status().legacyImportPending, false);
        vault.close();
    });
});

test("the retired key alias is refused with a rename instruction when it is the only key configured", () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-alias-home-"));
    const emptyHome = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-alias-empty-"));
    try {
        const retired = (error) => error.code === "ERR_MASTER_KEY_ALIAS_RETIRED"
            && error.message.includes("HETZER_GRIMOIRE_KEY")
            && /Do not run 'hetzer init'/.test(error.message)
            && !error.message.includes(KEY);
        const call = (baseEnv, envValues, homeDir = emptyHome) => resolveMasterKey({ root: emptyHome, envValues, baseEnv, homeDir });

        assert.throws(() => call({ [RETIRED_MASTER_KEY_ALIAS]: KEY }, {}), (error) => retired(error) && /the environment/.test(error.message));
        assert.throws(() => call({}, { [RETIRED_MASTER_KEY_ALIAS]: KEY }), (error) => retired(error) && /workspace \.env/.test(error.message));

        // The current name wins wherever it is set, as before.
        assert.equal(call({ [RETIRED_MASTER_KEY_ALIAS]: KEY, HETZER_GRIMOIRE_KEY: OTHER_KEY }, {}), OTHER_KEY);
        assert.equal(call({ [RETIRED_MASTER_KEY_ALIAS]: KEY }, { HETZER_GRIMOIRE_KEY: OTHER_KEY }), OTHER_KEY);

        // The alias used to outrank the isolated key file: the same key is fine, another key is not used in silence.
        fs.mkdirSync(path.dirname(getIsolatedKeyPath(home)), { recursive: true });
        fs.writeFileSync(getIsolatedKeyPath(home), `${KEY}\n`);
        assert.equal(call({ [RETIRED_MASTER_KEY_ALIAS]: KEY.toUpperCase() }, {}, home), KEY);
        assert.throws(() => call({ [RETIRED_MASTER_KEY_ALIAS]: OTHER_KEY }, {}, home), retired);
        assert.equal(call({}, {}, home), KEY);

        // Unchanged: nothing configured resolves to no key, and a secretRef value is not a key.
        assert.equal(call({}, {}), "");
        assert.equal(call({ [RETIRED_MASTER_KEY_ALIAS]: "secretRef:some-id" }, {}), "");
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(emptyHome, { recursive: true, force: true });
    }
});

test("hetzer init does not generate a second key over a workspace that only has the retired alias", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-alias-init-"));
    const saved = { home: process.env.HETZER_INSTALL_HOME, key: process.env.HETZER_GRIMOIRE_KEY, alias: process.env[RETIRED_MASTER_KEY_ALIAS] };
    try {
        delete process.env.HETZER_GRIMOIRE_KEY;
        delete process.env[RETIRED_MASTER_KEY_ALIAS];
        process.env.HETZER_INSTALL_HOME = path.join(root, "home");
        const envFile = path.join(root, ".env");
        const text = `${RETIRED_MASTER_KEY_ALIAS}=${KEY}\n`;
        fs.writeFileSync(envFile, text);
        assert.throws(() => initializeProject(root), (error) => error.code === "ERR_MASTER_KEY_ALIAS_RETIRED");
        assert.equal(fs.readFileSync(envFile, "utf8"), text, "the workspace .env is untouched");
        assert.equal(fs.existsSync(path.join(root, "data")), false, "nothing was created");
    } finally {
        for (const [name, value] of [["HETZER_INSTALL_HOME", saved.home], ["HETZER_GRIMOIRE_KEY", saved.key], [RETIRED_MASTER_KEY_ALIAS, saved.alias]]) {
            if (value === undefined) delete process.env[name];
            else process.env[name] = value;
        }
        fs.rmSync(root, { recursive: true, force: true });
    }
});
