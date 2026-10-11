import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { recordAuditEvent, verifyAuditLedger } from "./audit.mjs";
import { vaultAuditEventType } from "./hetzer-vault.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const schemaDoc = fs.readFileSync(path.join(repoRoot, "docs", "audit-event-schema.md"), "utf8");
const GENESIS = "0".repeat(64);
const KEY = "synthetic-schema-key-0123456789abcdef0123456789";

// The verifier below is written from the formulas in docs/audit-event-schema.md and imports nothing from
// the module under test, so a gap in the document shows up as a mismatch.
function s(value) {
    if (value === null || value === undefined) return "";
    return typeof value === "string" ? value : JSON.stringify(value);
}

function docHash(entry) {
    const body = entry.v === undefined
        ? `${entry.prevHash}|${entry.index}|${entry.timestamp}|${entry.eventType}|${entry.target}|${entry.result}|${s(entry.details)}`
        : `v${entry.v}|${entry.prevHash}|${entry.index}|${entry.timestamp}|${entry.eventType}|${entry.target}|${entry.result}|${s(entry.actor)}|${s(entry.details)}`;
    return crypto.createHash("sha256").update(body, "utf8").digest("hex");
}

function docMac(keyText, hash) {
    const text = String(keyText).trim();
    const normalized = /^[0-9a-f]{64}$/i.test(text) ? text.toLowerCase() : crypto.createHash("sha256").update(text).digest("hex");
    const k = Buffer.from(crypto.hkdfSync("sha256", normalized, "hetzer-grimoire-v1", "grimoire-master-key", 32));
    const subkey = crypto.createHmac("sha256", k).update("hetzer:audit-integrity:v1").digest();
    return crypto.createHmac("sha256", subkey).update(hash).digest("hex");
}

function docVerify(lines, keyText) {
    let prev = GENESIS;
    let version = 1;
    lines.forEach((line, position) => {
        const entry = JSON.parse(line);
        assert.equal(entry.index, position + 1);
        assert.equal(entry.prevHash, prev);
        const v = entry.v === undefined ? 1 : entry.v;
        assert.ok(Number.isInteger(v) && v >= version);
        version = v;
        assert.equal(entry.hash, docHash(entry));
        if (entry.mac !== undefined) {
            assert.ok(v >= 2);
            if (keyText) assert.equal(entry.mac, docMac(keyText, entry.hash));
        }
        prev = entry.hash;
    });
    return prev;
}

function tempLog() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-schema-"));
    return { dir, logFile: path.join(dir, "audit.log") };
}

test("the document's formulas verify ledgers from the real writer, keyed and unkeyed", () => {
    const { dir, logFile } = tempLog();
    try {
        for (const [macKey, name] of [[KEY, "keyed"], [false, "unkeyed"]]) {
            const file = `${logFile}.${name}`;
            recordAuditEvent({ eventType: "exec", target: "node", result: "allow", details: { command: "node", strict: true }, logFile: file, macKey });
            recordAuditEvent({ eventType: "SANDBOX_EXEC", target: "node", actor: { user: "alice", extra: 1 }, logFile: file, macKey });
            recordAuditEvent({ eventType: "NO_DETAILS", target: "", details: undefined, logFile: file, macKey });
            const lines = fs.readFileSync(file, "utf8").trim().split(/\r?\n/);
            const last = docVerify(lines, macKey || "");
            assert.equal(JSON.parse(lines.at(-1)).hash, last);
            assert.equal(JSON.parse(lines[0]).v, 2);
            assert.equal(JSON.parse(lines[0]).eventType, "EXEC", "event types are upper-cased");
            assert.equal(lines.every((line) => ("mac" in JSON.parse(line)) === Boolean(macKey)), true);
            assert.equal(JSON.parse(fs.readFileSync(`${file}.head`, "utf8")).lastHash, last);
            assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(`${file}.state`, "utf8"))).sort(), ["initializedAt", "version"]);
        }
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test("a version 1 ledger built from the document's formula is accepted by the real verifier", () => {
    const { dir, logFile } = tempLog();
    try {
        let prevHash = GENESIS;
        const entries = [1, 2, 3].map((index) => {
            const entry = { index, timestamp: `2026-01-0${index}T00:00:00.000Z`, eventType: "OLD", target: "t", result: "ALLOW", actor: { user: "u" }, details: { index }, prevHash, hash: "" };
            entry.hash = docHash(entry);
            prevHash = entry.hash;
            return entry;
        });
        fs.writeFileSync(logFile, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`);
        fs.writeFileSync(`${logFile}.head`, JSON.stringify({ lastIndex: 3, lastHash: prevHash, updatedAt: entries[2].timestamp }));
        fs.writeFileSync(`${logFile}.state`, JSON.stringify({ version: 1, initializedAt: entries[0].timestamp }));
        const check = verifyAuditLedger({ logFile, macKey: false });
        assert.equal(check.ok, true, check.error);
        assert.equal(check.count, 3);

        // A writer extends it with version 2 entries that the document's formula also accepts.
        recordAuditEvent({ eventType: "NEW", logFile, macKey: false });
        docVerify(fs.readFileSync(logFile, "utf8").trim().split(/\r?\n/), "");
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

function sourceFiles(dir) {
    const files = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) files.push(...sourceFiles(full));
        else if (entry.name.endsWith(".mjs") && !entry.name.endsWith(".test.mjs")) files.push(full);
    }
    return files;
}

function documentedEventTypes() {
    const section = (schemaDoc.split("## Event catalog")[1] || "").split("### Vault events")[0];
    return new Set([...section.matchAll(/^\| `([A-Z][A-Z0-9_]+)` \|/gm)].map((match) => match[1]));
}

test("every event type in the code is in the catalog and every catalog entry is in the code", () => {
    const emitted = new Set();
    const viaVault = new Map();
    for (const file of sourceFiles(path.join(repoRoot, "cli"))) {
        const text = fs.readFileSync(file, "utf8");
        for (const match of text.matchAll(/eventType:\s*"([A-Z][A-Z0-9_]+)"/g)) emitted.add(match[1]);
        for (const match of text.matchAll(/\.recordAudit\(\{[^}]*?action:\s*"([^"]+)"/gs)) viaVault.set(vaultAuditEventType(match[1]), match[1]);
    }
    for (const match of fs.readFileSync(path.join(repoRoot, "cli", "vault", "hetzer-vault.mjs"), "utf8").matchAll(/this\.recordAudit\(\{[^}]*?action:\s*"([^"]+)"/gs)) {
        viaVault.set(vaultAuditEventType(match[1]), match[1]);
    }
    assert.ok(emitted.size >= 15, "the scan must find the literal event types");
    assert.ok(viaVault.size >= 10, "the scan must find the vault actions");

    const documented = documentedEventTypes();
    for (const type of emitted) assert.ok(documented.has(type), `${type} is emitted by the code but missing from docs/audit-event-schema.md`);
    for (const [type, action] of viaVault) {
        assert.ok(schemaDoc.includes(`| \`${type}\` | \`${action}\` |`), `${type} (action ${action}) is missing from the vault events table`);
    }
    for (const type of documented) assert.ok(emitted.has(type), `${type} is documented but no code emits it`);
    const documentedVault = [...schemaDoc.matchAll(/^\| `(VAULT_[A-Z0-9_]+)` \| `([^`]+)` \|$/gm)];
    assert.equal(documentedVault.length, viaVault.size, "the vault events table lists exactly the actions the code records");
    for (const [, type, action] of documentedVault) assert.equal(vaultAuditEventType(action), type);
});
