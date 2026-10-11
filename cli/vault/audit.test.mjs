import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { computeAuditMac } from "./hetzer-vault.mjs";
import {
    computeAuditEntryHash,
    GENESIS_HASH,
    getAuditLogPath,
    readAuditEvents,
    recordAuditEvent,
    verifyAuditLedger,
} from "./audit.mjs";

test("audit ledger writes chained events and verifies valid chain", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-test-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        const e1 = recordAuditEvent({
            eventType: "CRED_REQUEST",
            target: "github-token",
            result: "ALLOW",
            details: { requestId: "req-1" },
            logFile,
        });

        assert.equal(e1.index, 1);
        assert.equal(e1.prevHash, GENESIS_HASH);
        assert.ok(e1.hash);

        const e2 = recordAuditEvent({
            eventType: "CRED_APPROVE",
            target: "github-token",
            result: "ALLOW",
            details: { requestId: "req-1" },
            logFile,
        });

        assert.equal(e2.index, 2);
        assert.equal(e2.prevHash, e1.hash);
        assert.ok(e2.hash);

        const verification = verifyAuditLedger({ logFile });
        assert.equal(verification.ok, true);
        assert.equal(verification.count, 2);
        assert.equal(verification.latestHash, e2.hash);

        const events = readAuditEvents({ logFile });
        assert.equal(events.length, 2);
        assert.equal(events[0].eventType, "CRED_REQUEST");
        assert.equal(events[1].eventType, "CRED_APPROVE");
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit ledger detects altered entry content (tampering)", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-tamper-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        recordAuditEvent({ eventType: "CRED_APPROVE", target: "npm-token", result: "ALLOW", logFile });
        recordAuditEvent({ eventType: "CANARY_TRIGGER", target: "canary-token", result: "TRIGGERED", logFile });

        // Tamper with first line
        const content = fs.readFileSync(logFile, "utf8").split("\n");
        const entry1 = JSON.parse(content[0]);
        entry1.target = "hacked-token"; // Alter payload
        content[0] = JSON.stringify(entry1);
        fs.writeFileSync(logFile, content.join("\n"));

        const check = verifyAuditLedger({ logFile });
        assert.equal(check.ok, false);
        assert.equal(check.tamperedIndex, 1);
        assert.match(check.error, /Integrity check failed/i);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit ledger detects deleted or skipped lines", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-deletion-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        recordAuditEvent({ eventType: "E1", target: "t1", logFile });
        recordAuditEvent({ eventType: "E2", target: "t2", logFile });
        recordAuditEvent({ eventType: "E3", target: "t3", logFile });

        // Delete line 2
        const content = fs.readFileSync(logFile, "utf8").trim().split("\n");
        content.splice(1, 1); // remove index 2
        fs.writeFileSync(logFile, content.join("\n") + "\n");

        const check = verifyAuditLedger({ logFile });
        assert.equal(check.ok, false);
        assert.match(check.error, /Sequence break|Hash chain broken/i);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit ledger detects deletion of newest entries (tail truncation)", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-tail-trunc-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        recordAuditEvent({ eventType: "E1", target: "t1", logFile });
        recordAuditEvent({ eventType: "E2", target: "t2", logFile });
        const e3 = recordAuditEvent({ eventType: "E3", target: "t3", logFile });

        // Verify clean state
        const initialCheck = verifyAuditLedger({ logFile });
        assert.equal(initialCheck.ok, true);
        assert.equal(initialCheck.count, 3);
        assert.equal(initialCheck.latestHash, e3.hash);

        // Delete the newest entry (tail entry 3)
        const content = fs.readFileSync(logFile, "utf8").trim().split("\n");
        content.pop(); // remove index 3
        fs.writeFileSync(logFile, content.join("\n") + "\n");

        // Verification must fail!
        const check = verifyAuditLedger({ logFile });
        assert.equal(check.ok, false);
        assert.match(check.error, /Audit ledger truncated|checkpoint anchor/i);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit ledger detects complete deletion of audit.log when checkpoint anchor exists", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-delete-log-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        recordAuditEvent({ eventType: "E1", target: "t1", logFile });
        recordAuditEvent({ eventType: "E2", target: "t2", logFile });

        // Verify valid initial state
        const initialCheck = verifyAuditLedger({ logFile });
        assert.equal(initialCheck.ok, true);
        assert.equal(initialCheck.count, 2);

        // Delete audit.log entirely, leaving audit.log.head intact
        fs.unlinkSync(logFile);

        // Verification must fail (not report clean state)!
        const check = verifyAuditLedger({ logFile });
        assert.equal(check.ok, false);
        assert.equal(check.tamperedIndex, 1);
        assert.match(check.error, /Audit ledger missing or empty, but checkpoint anchor records 2 entries/i);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit ledger detects deletion of log and checkpoint when initialization sentinel remains", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-delete-pair-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        recordAuditEvent({ eventType: "E1", target: "t1", logFile });
        fs.unlinkSync(logFile);
        fs.unlinkSync(`${logFile}.head`);

        const check = verifyAuditLedger({ logFile });
        assert.equal(check.ok, false);
        assert.match(check.error, /initialization sentinel remains/i);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit ledger fails closed when checkpoint anchor is malformed", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-bad-head-"));
    const logFile = path.join(tempDir, "audit.log");

    try {
        recordAuditEvent({ eventType: "E1", target: "t1", logFile });
        fs.writeFileSync(`${logFile}.head`, "{broken");

        const check = verifyAuditLedger({ logFile });
        assert.equal(check.ok, false);
        assert.match(check.error, /checkpoint anchor is missing or malformed/i);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

const KEY = "synthetic-audit-key-0123456789abcdef0123456789";
const OTHER_KEY = "synthetic-other-key-0123456789abcdef012345678";

function readEntries(logFile) {
    return fs.readFileSync(logFile, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line));
}

function writeEntries(logFile, entries) {
    fs.writeFileSync(logFile, `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`);
}

function writeLedger(logFile, count, macKey) {
    for (let i = 0; i < count; i += 1) {
        recordAuditEvent({
            eventType: "PROBE",
            target: `t${i}`,
            result: i === 2 ? "DENY" : "ALLOW",
            actor: { user: "alice", pid: 7, isTTY: true },
            logFile,
            macKey,
        });
    }
}

/** Rewrites the whole chain consistently, the way an attacker without the chain's key would. */
function rewriteChain(logFile, mutate, macKey) {
    let prevHash = GENESIS_HASH;
    const rewritten = readEntries(logFile).map((entry) => {
        mutate(entry);
        entry.prevHash = prevHash;
        entry.hash = computeAuditEntryHash(entry);
        if (macKey) entry.mac = computeAuditMac(macKey, entry.hash);
        else delete entry.mac;
        prevHash = entry.hash;
        return entry;
    });
    writeEntries(logFile, rewritten);
    const last = rewritten.at(-1);
    fs.writeFileSync(`${logFile}.head`, JSON.stringify({ lastIndex: last.index, lastHash: last.hash, updatedAt: last.timestamp }));
}

function withTempLedger(fn) {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-keyed-"));
    try {
        return fn(path.join(tempDir, "audit.log"), tempDir);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
}

test("audit entries are version 2, cover the actor, and edits to the actor are detected", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 3, false);
        assert.equal(readEntries(logFile)[0].v, 2);
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, true);

        const entries = readEntries(logFile);
        entries[0].actor.user = "mallory";
        writeEntries(logFile, entries);
        const check = verifyAuditLedger({ logFile, macKey: false });
        assert.equal(check.ok, false);
        assert.match(check.error, /entry hash mismatch/);
    });
});

test("legacy version 1 ledgers still verify and can be extended with version 2 entries", () => {
    withTempLedger((logFile) => {
        let prevHash = GENESIS_HASH;
        const legacy = [];
        for (let index = 1; index <= 3; index += 1) {
            const entry = { index, timestamp: new Date().toISOString(), eventType: "OLD", target: "t", result: "ALLOW", actor: { user: "u" }, details: {}, prevHash, hash: "" };
            entry.hash = computeAuditEntryHash(entry);
            prevHash = entry.hash;
            legacy.push(entry);
        }
        writeEntries(logFile, legacy);
        fs.writeFileSync(`${logFile}.head`, JSON.stringify({ lastIndex: 3, lastHash: prevHash }));

        assert.equal(verifyAuditLedger({ logFile, macKey: KEY }).ok, true);
        recordAuditEvent({ eventType: "NEW", logFile, macKey: KEY });
        const check = verifyAuditLedger({ logFile, macKey: KEY });
        assert.equal(check.ok, true);
        assert.equal(check.count, 4);
        assert.equal(check.keyedEntries, 1);
    });
});

test("keyed ledgers verify with the right key and reject a different key", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 4, KEY);
        const ok = verifyAuditLedger({ logFile, macKey: KEY });
        assert.equal(ok.ok, true);
        assert.equal(ok.macVerified, true);
        assert.equal(ok.keyedEntries, 4);

        const wrong = verifyAuditLedger({ logFile, macKey: OTHER_KEY });
        assert.equal(wrong.ok, false);
        assert.match(wrong.error, /Keyed MAC check failed/);
    });
});

test("editing a keyed entry, truncating the tail or rewriting the tail without the key is detected", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 5, KEY);
        const entries = readEntries(logFile);
        entries[2].result = "ALLOW";
        writeEntries(logFile, entries);
        assert.match(verifyAuditLedger({ logFile, macKey: KEY }).error, /entry hash mismatch/);
    });

    withTempLedger((logFile) => {
        writeLedger(logFile, 5, KEY);
        writeEntries(logFile, readEntries(logFile).slice(0, 3));
        assert.match(verifyAuditLedger({ logFile, macKey: KEY }).error, /truncated/);
    });

    withTempLedger((logFile) => {
        writeLedger(logFile, 5, KEY);
        let position = 0;
        let prevHash = GENESIS_HASH;
        const rewritten = readEntries(logFile).map((entry) => {
            position += 1;
            if (position >= 3) entry.result = "ALLOW";
            entry.prevHash = prevHash;
            entry.hash = computeAuditEntryHash(entry);
            if (position < 3) entry.mac = computeAuditMac(KEY, entry.hash);
            else delete entry.mac;
            prevHash = entry.hash;
            return entry;
        });
        writeEntries(logFile, rewritten);
        fs.writeFileSync(`${logFile}.head`, JSON.stringify({ lastIndex: 5, lastHash: prevHash }));

        // The downgrade is visible from the file alone, with or without the key.
        for (const macKey of [KEY, false]) {
            const check = verifyAuditLedger({ logFile, macKey });
            assert.equal(check.ok, false);
            assert.match(check.error, /MAC downgrade/);
        }
    });
});

test("a full unkeyed rewrite passes by default and is rejected when a keyed ledger is required", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 5, KEY);
        rewriteChain(logFile, (entry) => { if (entry.result === "DENY") entry.result = "ALLOW"; }, null);

        // Documented limit: without an anchor outside the file, a consistent unkeyed rewrite is not detectable by default.
        assert.equal(verifyAuditLedger({ logFile, macKey: KEY, requireMac: false }).ok, true);
        const strict = verifyAuditLedger({ logFile, macKey: KEY, requireMac: true });
        assert.equal(strict.ok, false);
        assert.match(strict.error, /no MAC/);
        assert.equal(verifyAuditLedger({ logFile, macKey: false, requireMac: true }).ok, false);
    });
});

test("a writer without the key, or with another key, cannot extend a keyed ledger", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 2, KEY);
        assert.throws(() => recordAuditEvent({ eventType: "X", logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_KEY_REQUIRED");
        assert.throws(() => recordAuditEvent({ eventType: "X", logFile, macKey: OTHER_KEY }), (error) => error.code === "ERR_AUDIT_KEY_MISMATCH");
        assert.equal(readEntries(logFile).length, 2);
        recordAuditEvent({ eventType: "X", logFile, macKey: KEY });
        assert.equal(verifyAuditLedger({ logFile, macKey: KEY }).count, 3);
    });
});

test("a version 1 entry after version 2 entries is rejected as a downgrade", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 3, false);
        rewriteChain(logFile, (entry) => { if (entry.index === 3) delete entry.v; }, null);
        const check = verifyAuditLedger({ logFile, macKey: false });
        assert.equal(check.ok, false);
        assert.match(check.error, /downgrade/);
    });
});

test("writing after a damaged tail line fails instead of restarting the chain", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 3, false);
        fs.appendFileSync(logFile, "{partial-garbage\n");
        assert.throws(() => recordAuditEvent({ eventType: "AFTER", logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_LEDGER_CORRUPT");
        assert.equal(fs.readFileSync(logFile, "utf8").trim().split(/\r?\n/).length, 4);
    });
});

test("appending after a very large entry reads the correct previous hash", () => {
    withTempLedger((logFile) => {
        recordAuditEvent({ eventType: "BIG", logFile, macKey: false, details: { blob: "x".repeat(200000) } });
        recordAuditEvent({ eventType: "NEXT", logFile, macKey: false });
        const check = verifyAuditLedger({ logFile, macKey: false });
        assert.equal(check.ok, true);
        assert.equal(check.count, 2);
    });
});

test("concurrent writer processes keep one valid chain and lose no events", () => {
    withTempLedger((logFile, tempDir) => {
        const auditModule = pathToFileURL(path.join(import.meta.dirname, "audit.mjs")).href;
        const writer = path.join(tempDir, "writer.mjs");
        fs.writeFileSync(writer, [
            `import { recordAuditEvent } from ${JSON.stringify(auditModule)};`,
            "const [file, tag] = process.argv.slice(2);",
            "for (let i = 0; i < 15; i += 1) recordAuditEvent({ eventType: \"CONCURRENT\", target: `${tag}-${i}`, logFile: file, macKey: false });",
        ].join("\n"));
        const workers = 5;
        // One driver process starts every writer at once and waits for all of them.
        const driver = spawnSync(process.execPath, ["-e", `
            const { spawn } = require("node:child_process");
            const runs = Array.from({ length: ${workers} }, (_, k) => new Promise((resolve) => {
                const child = spawn(process.execPath, [${JSON.stringify(writer)}, ${JSON.stringify(logFile)}, "w" + k], { stdio: "ignore" });
                child.on("close", resolve);
            }));
            Promise.all(runs).then((codes) => process.exit(codes.every((code) => code === 0) ? 0 : 1));
        `], { encoding: "utf8" });
        assert.equal(driver.status, 0);
        const check = verifyAuditLedger({ logFile, macKey: false });
        assert.equal(check.ok, true, check.error);
        assert.equal(check.count, workers * 15);
    });
});

test("the MAC key is the same whether it is given as raw text or in its normalized form", () => {
    withTempLedger((logFile) => {
        const raw = "a-raw-master-key-that-is-longer-than-32-characters";
        const normalized = crypto.createHash("sha256").update(raw).digest("hex");
        assert.equal(computeAuditMac(raw, "abc"), computeAuditMac(normalized, "abc"));

        recordAuditEvent({ eventType: "A", logFile, macKey: normalized });
        recordAuditEvent({ eventType: "B", logFile, macKey: raw });
        for (const macKey of [raw, normalized]) {
            const check = verifyAuditLedger({ logFile, macKey });
            assert.equal(check.ok, true);
            assert.equal(check.macVerified, true);
        }
    });
});

test("a writer refuses to extend a ledger whose entries were removed behind its checkpoint anchor", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 4, false);
        writeEntries(logFile, readEntries(logFile).slice(0, 2));
        assert.throws(() => recordAuditEvent({ eventType: "AFTER", logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_LEDGER_TRUNCATED");
        assert.equal(JSON.parse(fs.readFileSync(logFile + ".head", "utf8")).lastIndex, 4, "the anchor must not be overwritten");
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, false);
    });

    withTempLedger((logFile) => {
        writeLedger(logFile, 3, false);
        fs.renameSync(logFile, `${logFile}.moved`);
        assert.throws(() => recordAuditEvent({ eventType: "AFTER", logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_LEDGER_TRUNCATED");

        // Moving the log, the anchor and the sentinel together is the documented way to start a new ledger.
        for (const suffix of [".head", ".state"]) fs.renameSync(logFile + suffix, `${logFile}${suffix}.moved`);
        recordAuditEvent({ eventType: "FRESH", logFile, macKey: false });
        const check = verifyAuditLedger({ logFile, macKey: false });
        assert.equal(check.ok, true);
        assert.equal(check.count, 1);
    });
});
