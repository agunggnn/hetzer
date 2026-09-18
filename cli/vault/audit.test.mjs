import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

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
