// Canonical Hetzer credential vault.
// Grimoire is the product surface; this SQLite store is the only persistence
// backend used by CLI services and MCP callers.

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { parseEnv } from "../core/env.mjs";
import { recordAuditEvent } from "./audit.mjs";
import { assertInteractiveHumanSession } from "./human-guard.mjs";

export function secureFilePermissions(filePath, { run = spawnSync } = {}) {
    if (!filePath || filePath === ":memory:") return;
    try {
        fs.chmodSync(filePath, 0o600);
    } catch { /* Windows or unsupported filesystem */ }
    if (process.platform === "win32") {
        try {
            const username = process.env.USERNAME || process.env.USER;
            if (username && fs.existsSync(filePath)) {
                run("icacls", [filePath, "/inheritance:r", "/grant:r", `${username}:(R,W)`], {
                    windowsHide: true,
                    stdio: "ignore",
                    timeout: 3000,
                });
            }
        } catch { /* best effort on Windows */ }
    }
}

const MAX_ENTRIES = 500;
const MAX_SECRET_LENGTH = 8192;
const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const ALLOWED_ACTION_PATTERN = /^[a-z0-9]+(?:[.:_/-][a-z0-9]+)*$/;

export const SCOPES = new Set(["header", "query", "env", "basic"]);
export const REALMS = new Set(["core", "data", "memory", "social", "command", "frontier"]);
export const ACCESS_ROLES = new Set(["reader", "operator", "admin"]);
/**
 * Where vault events are mirrored into the audit ledger: an explicit option, HETZER_AUDIT_LOG_PATH,
 * or the workspace default when the database sits in <root>/data. Other layouts and in-memory
 * vaults record to SQLite only.
 */
export function resolveVaultAuditLogFile({ auditLogFile, dbPath } = {}) {
    if (auditLogFile === false) return null;
    if (auditLogFile) return path.resolve(auditLogFile);
    if (process.env.HETZER_AUDIT_LOG_PATH) return path.resolve(process.env.HETZER_AUDIT_LOG_PATH);
    if (!dbPath || dbPath === ":memory:") return null;
    const dataDir = path.dirname(path.resolve(dbPath));
    if (path.basename(dataDir) !== "data") return null;
    return path.join(path.dirname(dataDir), ".hetzer", "audit.log");
}

export const SECRET_REF_PATTERN = /^secretRef:([a-z0-9]+(?:-[a-z0-9]+)*)$/;

/**
 * Fresh global matcher for secretRef tokens embedded in longer text. A reference only matches when
 * the whole token is a valid credential id: "secretRef:github.pat" or "secretRef:npm_token" are left
 * untouched instead of resolving the shorter prefix ("github", "npm"). A sentence-ending period or
 * comma still ends the token; a trailing hyphen, underscore or dotted suffix does not.
 */
export function createSecretRefScanner() {
    return /secretRef:([a-z0-9]+(?:-[a-z0-9]+)*)(?![A-Za-z0-9_-]|\.[A-Za-z0-9])/g;
}

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

export function isSecretRef(reference) {
    return typeof reference === "string" && SECRET_REF_PATTERN.test(reference.trim());
}

export function formatSecretRef(id) {
    const trimmed = String(id || "").trim();
    if (!trimmed || !ID_PATTERN.test(trimmed)) {
        throw new Error(`Invalid credential ID '${id}' for secretRef formatting (must be lowercase kebab-case).`);
    }
    return `secretRef:${trimmed}`;
}

export function parseSecretRef(reference) {
    const match = SECRET_REF_PATTERN.exec(String(reference || "").trim());
    if (!match) throw new Error("secretRef must use the form secretRef:<credential-id>.");
    return match[1];
}

export function resolveVaultPath(root, configuredPath = undefined) {
    const override = String(
        configuredPath === undefined ? process.env.HETZER_VAULT_PATH || "" : configuredPath,
    ).trim();
    if (!override) return "";
    if (override === ":memory:") return ":memory:";
    return path.isAbsolute(override) ? override : path.join(root || process.cwd(), override);
}

export function getIsolatedKeyPath(homeDir) {
    try {
        const home = homeDir || os.homedir();
        return path.join(home, ".hetzer", "grimoire.key");
    } catch {
        return "";
    }
}

export function resolveMasterKey({ root = process.cwd(), envValues = {}, baseEnv = process.env, homeDir } = {}) {
    // 1. Explicit runtime environment variable (highest priority)
    const envKey = baseEnv.HETZER_GRIMOIRE_KEY || baseEnv.SHADOW_GRIMOIRE_KEY;
    if (envKey && !String(envKey).startsWith("secretRef:")) {
        return String(envKey).trim();
    }

    // 2. Local .env file (explicit workspace configuration)
    const fileKey = envValues.HETZER_GRIMOIRE_KEY || envValues.SHADOW_GRIMOIRE_KEY;
    if (fileKey && !String(fileKey).startsWith("secretRef:")) {
        return String(fileKey).trim();
    }

    // 3. User-level Home Isolated Store (~/.hetzer/grimoire.key) fallback.
    // Isolated outside project workspace so workspace agents cannot read it!
    const effectiveHome = homeDir || baseEnv.HETZER_INSTALL_HOME || (baseEnv === process.env ? os.homedir() : "");
    const isolatedFile = effectiveHome ? getIsolatedKeyPath(effectiveHome) : "";
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

    return "";
}

export function isolateMasterKey({ root = process.cwd(), envFile } = {}) {
    const targetEnv = envFile || path.join(root, ".env");
    let currentKey = "";
    let envContent = "";
    if (fs.existsSync(targetEnv)) {
        envContent = fs.readFileSync(targetEnv, "utf8");
        const values = parseEnv(envContent);
        currentKey = values.HETZER_GRIMOIRE_KEY || values.SHADOW_GRIMOIRE_KEY || "";
    }
    if (!currentKey) {
        currentKey = process.env.HETZER_GRIMOIRE_KEY || process.env.SHADOW_GRIMOIRE_KEY || "";
    }
    currentKey = String(currentKey).trim();
    if (!currentKey) {
        throw new Error("No HETZER_GRIMOIRE_KEY found to isolate. Run 'hetzer init' first.");
    }

    const isolatedFile = getIsolatedKeyPath();
    if (!isolatedFile) {
        throw new Error("Unable to determine user home directory for key isolation.");
    }

    fs.mkdirSync(path.dirname(isolatedFile), { recursive: true });
    fs.writeFileSync(isolatedFile, currentKey + "\n", { encoding: "utf8", mode: 0o600 });
    secureFilePermissions(isolatedFile);

    // Strip HETZER_GRIMOIRE_KEY from .env
    if (fs.existsSync(targetEnv)) {
        const cleanedEnv = envContent
            .split(/\r?\n/)
            .filter((line) => !line.startsWith("HETZER_GRIMOIRE_KEY=") && !line.startsWith("SHADOW_GRIMOIRE_KEY="))
            .join("\n");
        fs.writeFileSync(targetEnv, cleanedEnv, { encoding: "utf8", mode: 0o600 });
        secureFilePermissions(targetEnv);
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

export function computeGrantSignature(masterKey, id, { allowedActions, allowedOrigins, rawInjection, bindHosts } = {}) {
    if (!masterKey) return "";
    const subkey = crypto.createHmac("sha256", keyBuffer(masterKey))
        .update("hetzer:grant-integrity:v1")
        .digest();
    const payload = JSON.stringify({
        id: String(id || "").trim().toLowerCase(),
        actions: [...(allowedActions || [])].sort(),
        origins: [...(allowedOrigins || [])].sort(),
        raw: rawInjection || "deny",
        hosts: [...(bindHosts || [])].sort(),
    });
    return crypto.createHmac("sha256", subkey).update(payload).digest("hex");
}

export function verifyGrantSignature(masterKey, row) {
    if (!masterKey || !row || !row.grant_sig) return false;
    const expected = computeGrantSignature(masterKey, row.id, {
        allowedActions: parseJsonArray(row.allowed_actions),
        allowedOrigins: parseJsonArray(row.allowed_origins),
        rawInjection: row.raw_injection || "deny",
        bindHosts: parseJsonArray(row.bind_hosts),
    });
    try {
        const a = Buffer.from(String(row.grant_sig), "hex");
        const b = Buffer.from(expected, "hex");
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

export function computeAuditMac(masterKey, entryHash) {
    // Writers hold the key in different forms (raw text from the environment, normalized inside the vault).
    // normalizeMasterKey is idempotent, so every form maps to the same MAC key.
    const normalizedKey = normalizeMasterKey(masterKey);
    if (!normalizedKey) return "";
    const subkey = crypto.createHmac("sha256", keyBuffer(normalizedKey))
        .update("hetzer:audit-integrity:v1")
        .digest();
    return crypto.createHmac("sha256", subkey).update(String(entryHash)).digest("hex");
}

export function computeApprovalSignature(masterKey, { credentialId, policyHash, targetOrigin } = {}) {
    if (!masterKey) return "";
    const subkey = crypto.createHmac("sha256", keyBuffer(masterKey))
        .update("hetzer:policy-approval:v1")
        .digest();
    const payload = JSON.stringify({
        credential: String(credentialId || "").trim().toLowerCase(),
        hash: String(policyHash || "").trim().toLowerCase(),
        origin: String(targetOrigin || ""),
    });
    return crypto.createHmac("sha256", subkey).update(payload).digest("hex");
}

export function verifyApprovalSignature(masterKey, row) {
    if (!masterKey || !row || !row.sig) return false;
    const expected = computeApprovalSignature(masterKey, {
        credentialId: row.credential_id,
        policyHash: row.policy_hash,
        targetOrigin: row.target_origin,
    });
    try {
        const a = Buffer.from(String(row.sig), "hex");
        const b = Buffer.from(expected, "hex");
        return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
    } catch {
        return false;
    }
}

/**
 * Returns an Error with a stable code when a credential's grants are not honored because their
 * signature is missing or does not verify, or null when the grants can be trusted.
 */
export function grantIntegrityError(entry) {
    if (!entry || entry.grantValid !== false) return null;
    const error = new Error(
        `Grants for credential '${entry.id}' are not trusted: the grant signature is missing or does not match.\n`
        + "A missing signature means the credential predates grant signing; an operator can review and sign it with:\n"
        + "  hetzer creds grant --sign-existing\n"
        + "A mismatched signature means the vault was modified outside Hetzer; reset it with:\n"
        + `  hetzer creds grant ${entry.id} --reset`,
    );
    error.code = "ERR_GRANT_SIGNATURE_INVALID";
    return error;
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
    constructor({ dbPath, file, legacyFile, masterKey, root, auditLogFile }) {
        const rootDir = root || process.cwd();
        const envPath = resolveVaultPath(rootDir);
        const resolvedDb = dbPath || file || envPath || path.join(rootDir, "data", "hetzer-vault.db");
        this.dbPath = resolvedDb;
        this.legacyFile = legacyFile || (String(file || "").endsWith(".json") ? file : "");
        this.masterKey = normalizeMasterKey(masterKey);
        this.auditLogFile = resolveVaultAuditLogFile({ auditLogFile, dbPath: resolvedDb });
        ensureParent(this.dbPath);
        this.db = new DatabaseSync(this.dbPath);
        this._initSchema();
        this.migration = this._migrateLegacy();
        if (this.dbPath !== ":memory:") {
            secureFilePermissions(this.dbPath);
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
                allowed_origins TEXT NOT NULL DEFAULT '[]',
                raw_injection TEXT NOT NULL DEFAULT 'deny',
                bind_hosts TEXT NOT NULL DEFAULT '[]',
                encrypted_value TEXT NOT NULL,
                crypto_version TEXT NOT NULL DEFAULT 'hetzer-vault-v1',
                source TEXT NOT NULL DEFAULT 'explicit',
                expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                grant_sig TEXT,
                is_valid INTEGER NOT NULL DEFAULT 1,
                UNIQUE(target_id, key_name)
            );

            CREATE TABLE IF NOT EXISTS vault_approved_policies (
                id TEXT PRIMARY KEY,
                credential_id TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                target_origin TEXT NOT NULL,
                policy_path TEXT,
                approved_at TEXT NOT NULL,
                approved_by TEXT NOT NULL DEFAULT 'operator',
                sig TEXT,
                UNIQUE(credential_id, policy_hash)
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
            CREATE INDEX IF NOT EXISTS idx_vault_approved_policies_hash
                ON vault_approved_policies(policy_hash);
            CREATE INDEX IF NOT EXISTS idx_vault_audit_created
                ON vault_audit_events(created_at);
        `);

        // Migration check for existing tables lacking new Gate G0 grant columns
        try {
            const cols = new Set(this.db.prepare("PRAGMA table_info(vault_credentials)").all().map((c) => c.name));
            if (!cols.has("allowed_origins")) {
                this.db.exec("ALTER TABLE vault_credentials ADD COLUMN allowed_origins TEXT NOT NULL DEFAULT '[]';");
                // Baseline migration for legacy credentials with empty actions
                this.db.exec(`
                    UPDATE vault_credentials
                    SET allowed_actions = '["process.start","mcp.tools/call"]'
                    WHERE is_valid = 1 AND (allowed_actions = '[]' OR allowed_actions IS NULL);
                `);
            }
            if (!cols.has("raw_injection")) {
                this.db.exec("ALTER TABLE vault_credentials ADD COLUMN raw_injection TEXT NOT NULL DEFAULT 'deny';");
            }
            if (!cols.has("bind_hosts")) {
                this.db.exec("ALTER TABLE vault_credentials ADD COLUMN bind_hosts TEXT NOT NULL DEFAULT '[]';");
            }
            if (!cols.has("grant_sig")) {
                this.db.exec("ALTER TABLE vault_credentials ADD COLUMN grant_sig TEXT;");
            }
            const approvalCols = new Set(this.db.prepare("PRAGMA table_info(vault_approved_policies)").all().map((c) => c.name));
            if (!approvalCols.has("sig")) {
                this.db.exec("ALTER TABLE vault_approved_policies ADD COLUMN sig TEXT;");
            }
        } catch { /* best effort migration */ }
    }

    /**
     * Credentials whose grants have no signature (created before grant signing existed).
     * Their grants are not honored until an operator reviews and signs them. Signing is never
     * automatic: a missing signature is exactly what a writer without the master key can produce,
     * so treating "unsigned" as "trusted" would make the signature meaningless.
     */
    listUnsignedGrants() {
        return this.db.prepare("SELECT * FROM vault_credentials WHERE grant_sig IS NULL AND is_valid = 1 ORDER BY created_at ASC")
            .all()
            .map((row) => ({
                id: row.id,
                allowedActions: parseJsonArray(row.allowed_actions),
                allowedOrigins: parseJsonArray(row.allowed_origins),
                rawInjection: row.raw_injection || "deny",
                bindHosts: parseJsonArray(row.bind_hosts),
            }));
    }

    /** Sign the current stored grants of the given unsigned credentials. Rows that already carry a signature are never touched. */
    signLegacyGrants(ids) {
        if (!this.unlocked) throw new Error("Grimoire is locked: HETZER_GRIMOIRE_KEY (master key) is not set.");
        const wanted = new Set((ids || []).map((id) => String(id)));
        const signed = [];
        for (const row of this.db.prepare("SELECT * FROM vault_credentials WHERE grant_sig IS NULL AND is_valid = 1").all()) {
            if (!wanted.has(row.id)) continue;
            const sig = computeGrantSignature(this.masterKey, row.id, {
                allowedActions: parseJsonArray(row.allowed_actions),
                allowedOrigins: parseJsonArray(row.allowed_origins),
                rawInjection: row.raw_injection || "deny",
                bindHosts: parseJsonArray(row.bind_hosts),
            });
            this.db.prepare("UPDATE vault_credentials SET grant_sig = ? WHERE id = ? AND grant_sig IS NULL").run(sig, row.id);
            signed.push(row.id);
        }
        return signed;
    }

    /** Grants of a stored row that may be carried into a rewritten row: only values whose signature verifies. */
    _trustedGrantsOf(row) {
        if (!row || !this.unlocked || !verifyGrantSignature(this.masterKey, row)) {
            return { allowedActions: [], allowedOrigins: [], rawInjection: "deny", bindHosts: [] };
        }
        return {
            allowedActions: parseJsonArray(row.allowed_actions),
            allowedOrigins: parseJsonArray(row.allowed_origins),
            rawInjection: row.raw_injection || "deny",
            bindHosts: parseJsonArray(row.bind_hosts),
        };
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
        const hasKey = Boolean(this.masterKey);
        const isGrantValid = hasKey ? verifyGrantSignature(this.masterKey, row) : null;
        const grantsHonored = hasKey ? isGrantValid : true;
        return {
            id: row.id,
            projectId: row.target_id,
            keyName: row.key_name,
            label: row.label,
            realm: row.realm,
            authType: row.auth_type,
            scope: row.transport_scope,
            accessRole: row.access_role,
            allowedActions: grantsHonored ? parseJsonArray(row.allowed_actions) : [],
            allowedOrigins: grantsHonored ? parseJsonArray(row.allowed_origins) : [],
            rawInjection: grantsHonored ? (row.raw_injection || "deny") : "deny",
            bindHosts: grantsHonored ? parseJsonArray(row.bind_hosts) : [],
            grantValid: isGrantValid,
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
        // Carry existing grants forward only when their signature verifies. Otherwise a rewrite of an
        // unrelated field would re-sign values that were modified outside Hetzer.
        const trusted = this._trustedGrantsOf(existing);
        const allowedActions = safeJsonArray(
            input.allowedActions === undefined ? trusted.allowedActions : input.allowedActions,
            (item) => ALLOWED_ACTION_PATTERN.test(item),
        );
        const allowedOrigins = safeJsonArray(
            input.allowedOrigins === undefined ? trusted.allowedOrigins : input.allowedOrigins,
            (item) => {
                try {
                    const u = new URL(item);
                    return u.protocol === "https:" || u.protocol === "http:";
                } catch {
                    return false;
                }
            },
        );
        const rawInjection = ["allow", "deny"].includes(input.rawInjection)
            ? input.rawInjection
            : trusted.rawInjection;
        const bindHosts = safeJsonArray(
            input.bindHosts === undefined ? trusted.bindHosts : input.bindHosts,
            (item) => typeof item === "string" && Boolean(item.trim()),
        );
        const encrypted = encryptSecret(this.masterKey, value, credentialAad(id, createdAt));
        const keyName = String(input.keyName || existing?.key_name || id).trim().slice(0, 160);
        const authType = ["api-key", "bearer", "basic", "password", "cookie"].includes(input.authType)
            ? input.authType
            : (existing?.auth_type || "api-key");
        const realm = REALMS.has(input.realm) ? input.realm : (existing?.realm || "frontier");

        const grantSig = computeGrantSignature(this.masterKey, id, {
            allowedActions,
            allowedOrigins,
            rawInjection,
            bindHosts,
        });

        this.db.prepare(`
            INSERT INTO vault_credentials (
                id, target_id, key_name, label, realm, auth_type, transport_scope, access_role,
                header_name, username, notes, allowed_actions, allowed_origins, raw_injection, bind_hosts,
                encrypted_value, crypto_version, source, expires_at, created_at, updated_at, last_used_at, grant_sig, is_valid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'hetzer-vault-v1', ?, ?, ?, ?, ?, ?, 1)
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
                allowed_origins = excluded.allowed_origins,
                raw_injection = excluded.raw_injection,
                bind_hosts = excluded.bind_hosts,
                encrypted_value = excluded.encrypted_value,
                crypto_version = excluded.crypto_version,
                source = excluded.source,
                expires_at = excluded.expires_at,
                updated_at = excluded.updated_at,
                last_used_at = excluded.last_used_at,
                grant_sig = excluded.grant_sig,
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
            JSON.stringify(allowedOrigins),
            rawInjection,
            JSON.stringify(bindHosts),
            encrypted,
            String(input.source || existing?.source || "explicit").slice(0, 80),
            input.expiresAt || existing?.expires_at || null,
            createdAt,
            now,
            input.lastUsedAt || existing?.last_used_at || null,
            grantSig,
        );
        return this.find(id);
    }

    #decryptRaw(id, aad) {
        const row = this.db.prepare("SELECT * FROM vault_credentials WHERE id = ? AND is_valid = 1").get(id);
        if (!row) return null;
        const boundAad = aad || credentialAad(id, row.created_at);
        return decryptSecret(this.masterKey, row.encrypted_value, boundAad);
    }

    reveal(id, aad) {
        try {
            assertInteractiveHumanSession({ operation: `'Grimoire.reveal:${String(id)}'` });
        } catch (error) {
            try {
                this.recordAudit({
                    actor: "vault-guard",
                    action: "vault.reveal-blocked",
                    credential_id: String(id),
                    reason: error.message,
                    outcome: "blocked",
                    metadata: { isAgentic: true },
                });
            } catch { /* best effort */ }
            throw error;
        }
        return this.#decryptRaw(id, aad);
    }

    resolve(id, { targetId = "", action = "" } = {}) {
        const entry = this.find(id);
        if (!entry) return null;
        if (!entry.grantValid) return null;
        // Every non-human resolution must be bound to the target that owns the
        // credential. An omitted target must not turn the action allowlist into
        // a global plaintext lookup for same-user callers.
        if (!targetId || entry.projectId !== targetId) return null;
        if (!action || !entry.allowedActions.includes(action)) return null;
        if (entry.expiresAt && Date.parse(entry.expiresAt) <= Date.now()) return null;
        const value = this.#decryptRaw(id);
        if (value !== null) this.touch(id);
        return value;
    }

    matchesSecret(id, expected, aad) {
        const value = this.#decryptRaw(id, aad);
        return value !== null && value === String(expected);
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
        const secret = this.resolve(id, {
            targetId: row?.target_id,
            action: context.action || "mcp.tools/call",
            ...context,
        });
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
        this._mirrorAuditToLedger(event);
        const metadata = event.metadata && typeof event.metadata === "object" ? event.metadata : {};
        this.db.prepare(`
            INSERT INTO vault_audit_events (
                actor, action, target_id, credential_id, reason, outcome, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            String(event.actor || "unknown").slice(0, 120),
            String(event.action || "unknown").slice(0, 120),
            event.targetId || event.target_id || null,
            event.credentialId || event.credential_id || null,
            String(event.reason || "").slice(0, 500) || null,
            String(event.outcome || "unknown").slice(0, 40),
            JSON.stringify(metadata).slice(0, 4000),
            new Date().toISOString(),
        );
    }

    /**
     * Vault events also go to the hash-chained file ledger (the single audit stream). The SQLite
     * table is kept as a mirror for existing readers. A ledger failure never blocks a vault
     * operation; the last failure is kept on `auditLedgerError` for callers that need to know.
     */
    _mirrorAuditToLedger(event) {
        if (!this.auditLogFile) return;
        try {
            const action = String(event.action || "unknown");
            recordAuditEvent({
                eventType: `VAULT_${action.replace(/^vault[.-_]/i, "").replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_+|_+$/g, "")}`,
                target: String(event.credentialId || event.credential_id || event.targetId || event.target_id || ""),
                result: String(event.outcome || "unknown"),
                actor: { user: String(event.actor || "unknown").slice(0, 120) },
                details: {
                    reason: String(event.reason || "").slice(0, 500) || undefined,
                    metadata: event.metadata && typeof event.metadata === "object" ? event.metadata : undefined,
                },
                logFile: this.auditLogFile,
                macKey: this.masterKey || false,
            });
            this.auditLedgerError = null;
        } catch (error) {
            this.auditLedgerError = error;
        }
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

    approveBrokerPolicy({ credentialId, policyHash, targetOrigin, policyPath = null, approvedBy = "operator" }) {
        const entry = this.find(credentialId);
        if (!entry) throw new Error(`Credential '${credentialId}' not found.`);
        const id = crypto.randomUUID();
        const now = new Date().toISOString();
        const normalizedHash = String(policyHash || "").trim().toLowerCase();
        if (!this.unlocked) throw new Error("Grimoire is locked: HETZER_GRIMOIRE_KEY (master key) is not set.");
        const sig = computeApprovalSignature(this.masterKey, { credentialId, policyHash: normalizedHash, targetOrigin });
        this.db.prepare(`
            INSERT INTO vault_approved_policies (id, credential_id, policy_hash, target_origin, policy_path, approved_at, approved_by, sig)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(credential_id, policy_hash) DO UPDATE SET
                target_origin = excluded.target_origin,
                policy_path = excluded.policy_path,
                approved_at = excluded.approved_at,
                approved_by = excluded.approved_by,
                sig = excluded.sig
        `).run(id, credentialId, normalizedHash, targetOrigin, policyPath, now, approvedBy, sig);

        // Ensure credential grants the target origin and broker.proxy action
        const origins = new Set(entry.allowedOrigins);
        origins.add(targetOrigin);
        const actions = new Set(entry.allowedActions);
        actions.add("broker.proxy");
        this.update(credentialId, {
            allowedOrigins: [...origins],
            allowedActions: [...actions],
        });

        this.recordAudit({
            actor: approvedBy,
            action: "broker.policy.approve",
            credential_id: credentialId,
            reason: `Approved broker policy with target origin ${targetOrigin}`,
            outcome: "allowed",
            metadata: { policyHash: normalizedHash, targetOrigin, policyPath },
        });
        return { id, credentialId, policyHash: normalizedHash, targetOrigin, approvedAt: now };
    }

    isBrokerPolicyApproved(credentialId, policyHash) {
        return this.getApprovedBrokerPolicy(credentialId, policyHash) !== null;
    }

    /** Returns the approval record only when its signature verifies; forged or unsigned rows are ignored. */
    getApprovedBrokerPolicy(credentialId, policyHash) {
        const normalizedHash = String(policyHash || "").trim().toLowerCase();
        const row = this.db.prepare(`
            SELECT * FROM vault_approved_policies
            WHERE credential_id = ? AND policy_hash = ?
        `).get(credentialId, normalizedHash);
        if (!row || !this.unlocked || !verifyApprovalSignature(this.masterKey, row)) return null;
        return row;
    }

    listApprovedPolicies(credentialId) {
        const rows = credentialId
            ? this.db.prepare("SELECT * FROM vault_approved_policies WHERE credential_id = ? ORDER BY approved_at DESC").all(credentialId)
            : this.db.prepare("SELECT * FROM vault_approved_policies ORDER BY approved_at DESC").all();
        return rows.map((row) => ({ ...row, signatureValid: this.unlocked ? verifyApprovalSignature(this.masterKey, row) : null }));
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
        if (!this._closed) {
            this._closed = true;
            try {
                this.db?.close();
            } catch {
                // Fail soft if already closed
            }
        }
    }
}
