// Canonical Hetzer credential vault.
// Grimoire is the product surface; this SQLite store is the only persistence
// backend used by CLI services and MCP callers.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const MAX_ENTRIES = 500;
const MAX_SECRET_LENGTH = 8192;
const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ALLOWED_ACTION_PATTERN = /^[a-z0-9]+(?:[.:_-][a-z0-9]+)*$/;

export const SCOPES = new Set(["header", "query", "env", "basic"]);
export const REALMS = new Set(["core", "data", "memory", "social", "command", "frontier"]);
export const ACCESS_ROLES = new Set(["reader", "operator", "admin"]);
export const SECRET_REF_PATTERN = /^secretRef:([a-z0-9]+(?:[._-][a-z0-9]+)*)$/;

function sha256(text) {
    return crypto.createHash("sha256").update(String(text)).digest("hex");
}

export function deriveKey(masterKey) {
    const raw = crypto.hkdfSync("sha256", String(masterKey), "hetzer-grimoire-v1", "grimoire-master-key", 32);
    return Buffer.from(raw).toString("hex");
}

export function normalizeMasterKey(raw) {
    const text = String(raw || "").trim();
    if (/^[0-9a-f]{64}$/i.test(text)) return text.toLowerCase();
    if (text.length >= 32) return sha256(text);
    return "";
}

export function generateMasterKey() {
    return crypto.randomBytes(48).toString("base64url");
}

export function parseSecretRef(reference) {
    const match = SECRET_REF_PATTERN.exec(String(reference || "").trim());
    if (!match) throw new Error("secretRef must use the form secretRef:<credential-id>.");
    return match[1];
}

export function resolveVaultPath(root) {
    const override = String(process.env.HETZER_VAULT_PATH || "").trim();
    if (!override) return "";
    if (override === ":memory:") return ":memory:";
    return path.isAbsolute(override) ? override : path.join(root || process.cwd(), override);
}

export function getIsolatedKeyPath() {
    try {
        const home = os.homedir();
        return path.join(home, ".hetzer", "grimoire.key");
    } catch {
        return "";
    }
}

export function resolveMasterKey({ root = process.cwd(), envValues = {}, baseEnv = process.env } = {}) {
    // 1. Explicit runtime environment variable (highest priority)
    const envKey = baseEnv.HETZER_GRIMOIRE_KEY || baseEnv.SHADOW_GRIMOIRE_KEY;
    if (envKey && !String(envKey).startsWith("secretRef:")) {
        return String(envKey).trim();
    }

    // 2. User-level Home Isolated Store (~/.hetzer/grimoire.key)
    // Isolated outside project workspace so workspace agents cannot read it!
    const isolatedFile = getIsolatedKeyPath();
    if (isolatedFile && fs.existsSync(isolatedFile)) {
        try {
            const val = fs.readFileSync(isolatedFile, "utf8").trim();
            if (val && !val.startsWith("secretRef:")) {
                return val;
            }
        } catch {
            // Continue to fallback
        }
    }

    // 3. Local .env file (Legacy workspace fallback)
    const fileKey = envValues.HETZER_GRIMOIRE_KEY || envValues.SHADOW_GRIMOIRE_KEY;
    if (fileKey && !String(fileKey).startsWith("secretRef:")) {
        return String(fileKey).trim();
    }

    return "";
}

export function isolateMasterKey({ root = process.cwd(), envFile } = {}) {
    const targetEnv = envFile || path.join(root, ".env");
    let currentKey = "";
    let envContent = "";
    if (fs.existsSync(targetEnv)) {
        envContent = fs.readFileSync(targetEnv, "utf8");
        const match = envContent.match(/^HETZER_GRIMOIRE_KEY=(.+)$/m) || envContent.match(/^SHADOW_GRIMOIRE_KEY=(.+)$/m);
        if (match) {
            currentKey = match[1].trim();
        }
    }
    if (!currentKey && process.env.HETZER_GRIMOIRE_KEY) {
        currentKey = process.env.HETZER_GRIMOIRE_KEY.trim();
    }
    if (!currentKey) {
        throw new Error("No HETZER_GRIMOIRE_KEY found to isolate. Run 'hetzer init' first.");
    }

    const isolatedFile = getIsolatedKeyPath();
    if (!isolatedFile) {
        throw new Error("Unable to determine user home directory for key isolation.");
    }

    fs.mkdirSync(path.dirname(isolatedFile), { recursive: true });
    fs.writeFileSync(isolatedFile, currentKey + "\n", { encoding: "utf8", mode: 0o600 });
    try { fs.chmodSync(isolatedFile, 0o600); } catch { /* Windows */ }

    // Strip HETZER_GRIMOIRE_KEY from .env
    if (fs.existsSync(targetEnv)) {
        const cleanedEnv = envContent
            .split(/\r?\n/)
            .filter((line) => !line.startsWith("HETZER_GRIMOIRE_KEY=") && !line.startsWith("SHADOW_GRIMOIRE_KEY="))
            .join("\n");
        fs.writeFileSync(targetEnv, cleanedEnv, { encoding: "utf8", mode: 0o600 });
        try { fs.chmodSync(targetEnv, 0o600); } catch { /* Windows */ }
    }

    return {
        isolatedFile,
        envFile: targetEnv,
    };
}

function keyBuffer(masterKey) {
    return Buffer.from(deriveKey(masterKey), "hex");
}

function encryptSecret(masterKey, plaintext, aad) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", keyBuffer(masterKey), iv);
    cipher.setAAD(Buffer.from(aad));
    const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
    return `${iv.toString("base64")}.${encrypted.toString("base64")}.${cipher.getAuthTag().toString("base64")}`;
}

function decryptSecret(masterKey, payload, aad) {
    try {
        const [iv, ciphertext, authTag] = String(payload || "").split(".");
        if (!iv || !ciphertext || !authTag) return null;
        const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuffer(masterKey), Buffer.from(iv, "base64"));
        decipher.setAAD(Buffer.from(aad));
        decipher.setAuthTag(Buffer.from(authTag, "base64"));
        return Buffer.concat([
            decipher.update(Buffer.from(ciphertext, "base64")),
            decipher.final(),
        ]).toString("utf8");
    } catch {
        return null;
    }
}

function credentialAad(id, createdAt) {
    return `hetzer-vault:v1:${id}:${createdAt}`;
}

export function grimoireAad(id, createdAt) {
    return `grimoire:v1:${id}:${createdAt}`;
}

function safeJsonArray(value, validate = () => true) {
    const source = Array.isArray(value) ? value : [];
    return [...new Set(source.map((item) => String(item || "").trim()).filter((item) => item && validate(item)))];
}

function parseJsonArray(value) {
    try {
        const parsed = JSON.parse(value || "[]");
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function slug(value) {
    return String(value || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");
}

function ensureParent(file) {
    if (file === ":memory:") return;
    fs.mkdirSync(path.dirname(file), { recursive: true });
}

export class Grimoire {
    constructor({ dbPath, file, legacyFile, masterKey }) {
        const envPath = resolveVaultPath(process.cwd());
        const resolvedDb = dbPath || file || envPath || path.join(process.cwd(), "data", "hetzer-vault.db");
        this.dbPath = resolvedDb;
        this.legacyFile = legacyFile || (String(file || "").endsWith(".json") ? file : "");
        this.masterKey = normalizeMasterKey(masterKey);
        ensureParent(this.dbPath);
        this.db = new DatabaseSync(this.dbPath);
        this._initSchema();
        this.migration = this._migrateLegacy();
        if (this.dbPath !== ":memory:") {
            try { fs.chmodSync(this.dbPath, 0o600); } catch { /* best effort on Windows */ }
        }
    }

    get file() {
        return this.dbPath;
    }

    get unlocked() {
        return Boolean(this.masterKey);
    }

    _initSchema() {
        // Retry once on SQLITE_BUSY during parallel test open — WAL + busy_timeout mitigates this.
        const execWithRetry = (sql) => {
            let lastErr;
            for (let attempt = 0; attempt < 3; attempt += 1) {
                try {
                    this.db.exec(sql);
                    return;
                } catch (err) {
                    lastErr = err;
                    const msg = String(err?.message || "");
                    if (!msg.includes("database is locked") && !msg.includes("busy")) throw err;
                    // Tiny backoff before retry; busy_timeout handles most cases.
                    const start = Date.now();
                    while (Date.now() - start < 20) { /* spin */ }
                }
            }
            throw lastErr;
        };
        execWithRetry(`
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            PRAGMA busy_timeout = 5000;`);
        // Remaining DDL uses standard exec (already has busy_timeout guard)
        this.db.exec(`

            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target_type TEXT NOT NULL DEFAULT 'service',
                host_address TEXT,
                port INTEGER,
                source_code_path TEXT,
                status TEXT NOT NULL DEFAULT 'discovered',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vault_credentials (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                key_name TEXT NOT NULL,
                label TEXT NOT NULL,
                realm TEXT NOT NULL,
                auth_type TEXT NOT NULL,
                transport_scope TEXT NOT NULL,
                access_role TEXT NOT NULL,
                header_name TEXT,
                username TEXT,
                notes TEXT,
                allowed_actions TEXT NOT NULL DEFAULT '[]',
                encrypted_value TEXT NOT NULL,
                crypto_version TEXT NOT NULL DEFAULT 'hetzer-vault-v1',
                source TEXT NOT NULL DEFAULT 'explicit',
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                is_valid INTEGER NOT NULL DEFAULT 1,
                UNIQUE(target_id, key_name)
            );

            CREATE TABLE IF NOT EXISTS vault_audit_events (
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

            CREATE TABLE IF NOT EXISTS vault_audit_findings (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                exploitation_vector TEXT,
                is_resolved INTEGER NOT NULL DEFAULT 0,
                discovered_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_vault_credentials_target
                ON vault_credentials(target_id, is_valid);
            CREATE INDEX IF NOT EXISTS idx_vault_audit_created
                ON vault_audit_events(created_at);
        `);
    }

    _meta(key) {
        return this.db.prepare("SELECT value FROM vault_meta WHERE key = ?").get(key)?.value || "";
    }

    _setMeta(key, value) {
        const now = new Date().toISOString();
        this.db.prepare(`
            INSERT INTO vault_meta (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        `).run(key, String(value), now);
    }

    _migrateLegacy() {
        if (!this.legacyFile || !fs.existsSync(this.legacyFile)) return { pending: false, imported: 0 };
        const marker = `legacy-json:${sha256(path.resolve(this.legacyFile))}`;
        if (this._meta(marker)) return { pending: false, imported: 0 };
        if (!this.unlocked) return { pending: true, imported: 0 };

        let parsed;
        try {
            parsed = JSON.parse(fs.readFileSync(this.legacyFile, "utf8"));
        } catch {
            return { pending: true, imported: 0 };
        }
        if (!Array.isArray(parsed?.entries)) return { pending: true, imported: 0 };

        let imported = 0;
        for (const entry of parsed.entries) {
            if (!entry?.id || this.find(entry.id)) continue;
            const plaintext = decryptSecret(
                this.masterKey,
                entry.secret,
                grimoireAad(entry.id, entry.createdAt),
            );
            if (plaintext === null) continue;
            this.create({
                id: entry.id,
                projectId: entry.projectId,
                keyName: entry.keyName || entry.id,
                label: entry.label,
                realm: entry.realm,
                authType: entry.authType,
                scope: entry.scope,
                accessRole: entry.accessRole || "operator",
                headerName: entry.headerName,
                username: entry.username,
                notes: entry.notes,
                allowedActions: entry.allowedActions || [],
                secret: plaintext,
                source: "legacy-json-import",
                createdAt: entry.createdAt,
                lastUsedAt: entry.lastUsedAt,
            });
            imported += 1;
        }
        this._setMeta(marker, JSON.stringify({ imported, importedAt: new Date().toISOString() }));
        this.recordAudit({
            actor: "hetzer-migration",
            action: "vault.import-legacy-json",
            reason: "One-time migration from Grimoire JSON to the canonical SQLite vault.",
            outcome: "allowed",
            metadata: { imported, source: path.basename(this.legacyFile) },
        });
        return { pending: false, imported };
    }

    _rowToPublic(row) {
        if (!row) return null;
        const now = Date.now();
        return {
            id: row.id,
            projectId: row.target_id,
            keyName: row.key_name,
            label: row.label,
            realm: row.realm,
            authType: row.auth_type,
            scope: row.transport_scope,
            accessRole: row.access_role,
            allowedActions: parseJsonArray(row.allowed_actions),
            headerName: row.header_name || "",
            notes: row.notes || "",
            createdAt: row.created_at,
            updatedAt: row.updated_at,
            lastUsedAt: row.last_used_at || "",
            expiresAt: row.expires_at || "",
            source: row.source,
            hasSecret: true,
            ageDays: Math.max(0, Math.floor((now - Date.parse(row.updated_at)) / 86400000)),
        };
    }

    list() {
        return this.db.prepare(`
            SELECT * FROM vault_credentials WHERE is_valid = 1 ORDER BY created_at ASC
        `).all().map((row) => this._rowToPublic(row));
    }

    find(id) {
        const row = this.db.prepare("SELECT * FROM vault_credentials WHERE id = ? AND is_valid = 1").get(id);
        return this._rowToPublic(row);
    }

    create(input) {
        const id = slug(input.id);
        if (!ID_PATTERN.test(id) || id !== String(input.id || "").trim().toLowerCase()) {
            throw new Error("id must be lowercase kebab-case (letters, numbers, hyphens).");
        }
        if (this.find(id)) throw new Error(`Key '${id}' already exists in Grimoire Vault.`);
        return this._writeEntry(id, input, null);
    }

    update(id, input) {
        const row = this.db.prepare("SELECT * FROM vault_credentials WHERE id = ? AND is_valid = 1").get(id);
        if (!row) throw new Error(`Key '${id}' not found.`);
        return this._writeEntry(id, input, row);
    }

    _writeEntry(id, input, existing) {
        if (!this.unlocked) {
            throw new Error("Grimoire is locked: HETZER_GRIMOIRE_KEY (master key) is not set.");
        }
        const secret = typeof input.secret === "string" ? input.secret : "";
        if (!existing && !secret) throw new Error("secret is required for new key.");
        if (secret.length > MAX_SECRET_LENGTH) {
            throw new Error(`secret is too long (maximum ${MAX_SECRET_LENGTH} characters).`);
        }
        if (!existing) {
            const total = this.db.prepare("SELECT COUNT(*) AS count FROM vault_credentials WHERE is_valid = 1").get().count;
            if (Number(total) >= MAX_ENTRIES) throw new Error(`Grimoire Vault is full (maximum ${MAX_ENTRIES} entries).`);
        }

        const projectId = String(input.projectId || existing?.target_id || "").trim().toLowerCase();
        if (!ID_PATTERN.test(projectId)) {
            throw new Error("projectId must be lowercase kebab-case (e.g. sample-project, my-lab).");
        }
        const now = new Date().toISOString();
        const createdAt = existing?.created_at || input.createdAt || now;
        const value = secret || (existing
            ? decryptSecret(this.masterKey, existing.encrypted_value, credentialAad(id, existing.created_at))
            : "");
        if (value === null) throw new Error("Existing key could not be decrypted with active master key.");

        const scope = SCOPES.has(input.scope) ? input.scope : (existing?.transport_scope || "header");
        const accessRole = ACCESS_ROLES.has(input.accessRole)
            ? input.accessRole
            : (existing?.access_role || "operator");
        const allowedActions = safeJsonArray(
            input.allowedActions === undefined ? parseJsonArray(existing?.allowed_actions) : input.allowedActions,
            (item) => ALLOWED_ACTION_PATTERN.test(item),
        );
        const encrypted = encryptSecret(this.masterKey, value, credentialAad(id, createdAt));
        const keyName = String(input.keyName || existing?.key_name || id).trim().slice(0, 160);
        const authType = ["api-key", "bearer", "basic", "password", "cookie"].includes(input.authType)
            ? input.authType
            : (existing?.auth_type || "api-key");
        const realm = REALMS.has(input.realm) ? input.realm : (existing?.realm || "frontier");

        this.db.prepare(`
            INSERT INTO vault_credentials (
                id, target_id, key_name, label, realm, auth_type, transport_scope, access_role,
                header_name, username, notes, allowed_actions, encrypted_value, crypto_version,
                source, expires_at, created_at, updated_at, last_used_at, is_valid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'hetzer-vault-v1', ?, ?, ?, ?, ?, 1)
            ON CONFLICT(id) DO UPDATE SET
                target_id = excluded.target_id,
                key_name = excluded.key_name,
                label = excluded.label,
                realm = excluded.realm,
                auth_type = excluded.auth_type,
                transport_scope = excluded.transport_scope,
                access_role = excluded.access_role,
                header_name = excluded.header_name,
                username = excluded.username,
                notes = excluded.notes,
                allowed_actions = excluded.allowed_actions,
                encrypted_value = excluded.encrypted_value,
                crypto_version = excluded.crypto_version,
                source = excluded.source,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at,
                last_used_at = excluded.last_used_at,
                is_valid = 1
        `).run(
            id,
            projectId,
            keyName,
            String(input.label || existing?.label || id).trim().slice(0, 120) || id,
            realm,
            authType,
            scope,
            accessRole,
            scope === "header" ? String(input.headerName || existing?.header_name || "Authorization").trim().slice(0, 60) : "",
            authType === "basic" ? String(input.username || existing?.username || "").trim().slice(0, 120) : "",
            String(input.notes ?? existing?.notes ?? "").trim().slice(0, 500),
            JSON.stringify(allowedActions),
            encrypted,
            String(input.source || existing?.source || "explicit").slice(0, 80),
            input.expiresAt || existing?.expires_at || null,
            createdAt,
            now,
            input.lastUsedAt || existing?.last_used_at || null,
        );
        return this.find(id);
    }

    reveal(id, aad) {
        const row = this.db.prepare("SELECT * FROM vault_credentials WHERE id = ? AND is_valid = 1").get(id);
        if (!row) return null;
        const boundAad = aad || credentialAad(id, row.created_at);
        return decryptSecret(this.masterKey, row.encrypted_value, boundAad);
    }

    resolve(id, { targetId = "", action = "" } = {}) {
        const entry = this.find(id);
        if (!entry) return null;
        if (targetId && entry.projectId !== targetId) return null;
        if (entry.allowedActions.length && (!action || !entry.allowedActions.includes(action))) return null;
        if (entry.expiresAt && Date.parse(entry.expiresAt) <= Date.now()) return null;
        const value = this.reveal(id);
        if (value !== null) this.touch(id);
        return value;
    }

    resolveRef(reference, context = {}) {
        return this.resolve(parseSecretRef(reference), context);
    }

    remove(id) {
        if (!this.find(id)) throw new Error(`Key '${id}' not found.`);
        this.db.prepare("UPDATE vault_credentials SET is_valid = 0, updated_at = ? WHERE id = ?")
            .run(new Date().toISOString(), id);
    }

    touch(id) {
        this.db.prepare("UPDATE vault_credentials SET last_used_at = ? WHERE id = ? AND is_valid = 1")
            .run(new Date().toISOString(), id);
    }

    portalHeaders(reference, context = {}) {
        const id = String(reference || "").startsWith("secretRef:")
            ? parseSecretRef(reference)
            : String(reference || "");
        const row = this.db.prepare("SELECT * FROM vault_credentials WHERE id = ? AND is_valid = 1").get(id);
        const secret = this.resolve(id, context);
        if (!row || secret === null) return null;
        if (row.auth_type === "bearer") {
            return { [row.header_name || "Authorization"]: `Bearer ${secret}` };
        }
        if (row.auth_type === "basic") {
            return { Authorization: `Basic ${Buffer.from(`${row.username || ""}:${secret}`).toString("base64")}` };
        }
        if (row.auth_type === "cookie") return { Cookie: secret };
        return { [row.header_name || "X-Api-Key"]: secret };
    }

    upsertTarget(target) {
        const id = slug(target.id || target.name);
        if (!id) throw new Error("target id is required.");
        const now = new Date().toISOString();
        this.db.prepare(`
            INSERT INTO vault_targets (
                id, name, target_type, host_address, port, source_code_path, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                target_type = excluded.target_type,
                host_address = excluded.host_address,
                port = excluded.port,
                source_code_path = excluded.source_code_path,
                status = excluded.status,
                updated_at = excluded.updated_at
        `).run(
            id,
            String(target.name || id).slice(0, 160),
            String(target.target_type || target.targetType || "service").slice(0, 60),
            target.host_address || target.hostAddress || null,
            target.port || null,
            target.source_code_path || target.sourceCodePath || null,
            String(target.status || "discovered").slice(0, 40),
            now,
            now,
        );
        return id;
    }

    storeCredential(targetId, keyName, rawSecret, options = {}) {
        const target = slug(targetId);
        const key = String(keyName || "").trim();
        const existing = this.db.prepare(`
            SELECT id FROM vault_credentials WHERE target_id = ? AND key_name = ? AND is_valid = 1
        `).get(target, key);
        const id = existing?.id || slug(`${target}-${key}`);
        const input = {
            id,
            projectId: target,
            keyName: key,
            label: options.label || key,
            authType: options.credentialType === "jwt" ? "bearer" : (options.authType || "api-key"),
            scope: options.transportScope || "env",
            accessRole: options.accessRole || options.scope || "operator",
            allowedActions: options.allowedActions || [],
            expiresAt: options.expiresAt,
            source: options.source || "explicit",
            secret: String(rawSecret),
        };
        if (existing) this.update(id, input);
        else this.create(input);
        return id;
    }

    getCredential(targetId, keyName, context = {}) {
        const row = this.db.prepare(`
            SELECT * FROM vault_credentials
            WHERE target_id = ? AND key_name = ? AND is_valid = 1
        `).get(slug(targetId), String(keyName || "").trim());
        if (!row) return null;
        const value = this.resolve(row.id, { targetId: slug(targetId), ...context });
        if (value === null) return null;
        return {
            id: row.id,
            targetId: row.target_id,
            keyName: row.key_name,
            credentialType: row.auth_type,
            value,
            scope: row.access_role,
            transportScope: row.transport_scope,
            allowedActions: parseJsonArray(row.allowed_actions),
            expiresAt: row.expires_at,
        };
    }

    listTargets() {
        const targets = this.db.prepare("SELECT * FROM vault_targets ORDER BY name ASC").all();
        const credentials = this.db.prepare(`
            SELECT key_name, auth_type, access_role, transport_scope, expires_at, updated_at, is_valid
            FROM vault_credentials WHERE target_id = ?
        `);
        return targets.map((target) => ({ ...target, credentials: credentials.all(target.id) }));
    }

    recordAudit(event) {
        const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
        this.db.prepare(`
            INSERT INTO vault_audit_events (
                actor, action, target_id, credential_id, reason, outcome, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            String(event.actor || "unknown").slice(0, 120),
            String(event.action || "unknown").slice(0, 120),
            event.targetId || null,
            event.credentialId || null,
            String(event.reason || "").slice(0, 500) || null,
            String(event.outcome || "unknown").slice(0, 40),
            JSON.stringify(metadata).slice(0, 4000),
            new Date().toISOString(),
        );
    }

    listAudit(options = {}) {
        const limit = options.limit || 100;
        return this.db.prepare(`
            SELECT id, actor, action, target_id, credential_id, reason, outcome, metadata, created_at
            FROM vault_audit_events
            ORDER BY id DESC
            LIMIT ?
        `).all(limit);
    }

    recordAuditFinding(targetId, finding) {
        const id = crypto.randomUUID();
        this.db.prepare(`
            INSERT INTO vault_audit_findings (
                id, target_id, vulnerability_type, severity, description,
                exploitation_vector, is_resolved, discovered_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        `).run(
            id,
            slug(targetId),
            finding.vulnerabilityType || "hardcoded_secret",
            finding.severity || "high",
            String(finding.description || "").slice(0, 1000),
            finding.exploitationVector || null,
            new Date().toISOString(),
        );
        return id;
    }

    status() {
        const total = this.db.prepare("SELECT COUNT(*) AS count FROM vault_credentials WHERE is_valid = 1").get().count;
        return {
            unlocked: this.unlocked,
            totalKeys: Number(total),
            file: path.basename(this.dbPath),
            storage: "sqlite",
            legacyImportPending: Boolean(this.migration?.pending),
        };
    }

    close() {
        this.db.close();
    }
}
