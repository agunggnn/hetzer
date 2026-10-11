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
    rotateAuditLedger,
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

function archiveFiles(logFile) {
    const dir = path.dirname(logFile);
    return fs.readdirSync(dir)
        .filter((name) => name.startsWith("audit.log.") && !name.endsWith(".head") && !name.endsWith(".state") && !name.endsWith(".lock") && !name.endsWith(".moved"))
        .map((name) => path.join(dir, name));
}

function snapshotBytes(logFile) {
    return Object.fromEntries(["", ".head", ".state"].filter((suffix) => fs.existsSync(logFile + suffix)).map((suffix) => [suffix, fs.readFileSync(logFile + suffix)]));
}

test("rotate recovers each refusal state and records the old ledger in the new one", () => {
    const states = [
        {
            name: "damaged tail",
            prepare: (logFile) => { writeLedger(logFile, 3, false); fs.appendFileSync(logFile, "{partial-garbage\n"); },
            code: "ERR_AUDIT_LEDGER_CORRUPT", macKey: false, options: {},
        },
        {
            name: "different key",
            prepare: (logFile) => writeLedger(logFile, 3, KEY),
            code: "ERR_AUDIT_KEY_MISMATCH", macKey: OTHER_KEY, options: {},
        },
        {
            name: "missing key",
            prepare: (logFile) => writeLedger(logFile, 3, KEY),
            code: "ERR_AUDIT_KEY_REQUIRED", macKey: false, options: { allowUnkeyed: true }, verified: true,
        },
        {
            name: "entries removed behind the anchor",
            prepare: (logFile) => { writeLedger(logFile, 4, false); writeEntries(logFile, readEntries(logFile).slice(0, 2)); },
            code: "ERR_AUDIT_LEDGER_TRUNCATED", macKey: false, options: {},
        },
    ];
    for (const state of states) {
        withTempLedger((logFile) => {
            state.prepare(logFile);
            assert.throws(() => recordAuditEvent({ eventType: "BLOCKED", logFile, macKey: state.macKey }), (error) => error.code === state.code, state.name);
            const original = snapshotBytes(logFile);

            const result = rotateAuditLedger({ logFile, macKey: state.macKey, reason: `recover ${state.name}`, ...state.options });
            assert.equal(result.rotated, true, state.name);
            const expectVerified = state.verified === true;
            assert.equal(result.previous.verified, expectVerified, `${state.name}: the old ledger's verification outcome is recorded`);
            assert.equal(result.previous.macChecked, false, `${state.name}: no MAC could be checked here`);

            // The archive is the old files, byte for byte.
            const archived = archiveFiles(logFile);
            assert.equal(archived.length, 1, state.name);
            for (const [suffix, bytes] of Object.entries(original)) {
                assert.ok(fs.readFileSync(archived[0] + suffix).equals(bytes), `${state.name}: ${suffix || "log"} archived unchanged`);
            }

            // The new ledger starts at genesis with the rotation entry and accepts writers again.
            const entries = readEntries(logFile);
            assert.equal(entries.length, 1);
            assert.equal(entries[0].index, 1);
            assert.equal(entries[0].prevHash, GENESIS_HASH);
            assert.equal(entries[0].eventType, "AUDIT_LEDGER_ROTATED");
            assert.equal(entries[0].details.reason, `recover ${state.name}`);
            assert.equal(entries[0].details.previousVerified, expectVerified);
            assert.equal(entries[0].details.previousMacChecked, false);
            assert.equal(entries[0].details.archive, path.basename(archived[0]));
            assert.equal(entries[0].details.archiveSha256, crypto.createHash("sha256").update(original[""]).digest("hex"));
            assert.ok(!JSON.stringify(entries[0]).includes(path.dirname(logFile)), "no absolute path in the entry");
            recordAuditEvent({ eventType: "AFTER", logFile, macKey: state.macKey });
            const check = verifyAuditLedger({ logFile, macKey: state.macKey });
            assert.equal(check.ok, true, `${state.name}: ${check.error}`);
            assert.equal(check.count, 2);
        });
    }
});

test("rotating a healthy keyed ledger carries the old head forward and keeps the archive verifiable", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 3, KEY);
        const oldHead = readEntries(logFile).at(-1);
        const result = rotateAuditLedger({ logFile, macKey: KEY, now: new Date("2026-10-11T10:15:30.123Z") });
        assert.equal(result.previous.verified, true);
        assert.equal(path.basename(result.archive), "audit.log.20261011T101530Z");
        assert.deepEqual(result.previous.lastGood, { index: 3, hash: oldHead.hash });

        const [first] = readEntries(logFile);
        assert.deepEqual(first.details.previousLastGood, { index: 3, hash: oldHead.hash });
        assert.deepEqual(first.details.previousAnchor, { lastIndex: 3, lastHash: oldHead.hash });
        assert.equal(first.details.previousKeyed, true);
        assert.equal(first.details.keyed, true);
        assert.ok(first.mac, "the new ledger is keyed");

        assert.equal(verifyAuditLedger({ logFile, macKey: KEY }).ok, true);
        const archived = verifyAuditLedger({ logFile: result.archive, macKey: KEY });
        assert.equal(archived.ok, true, archived.error);
        assert.equal(archived.count, 3);
    });
});

test("rotate refuses to turn a keyed ledger into an unkeyed one unless asked to", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 2, KEY);
        const before = snapshotBytes(logFile);
        assert.throws(() => rotateAuditLedger({ logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_ROTATE_UNKEYED");
        assert.deepEqual(snapshotBytes(logFile), before, "nothing was moved");
        assert.equal(archiveFiles(logFile).length, 0);

        const result = rotateAuditLedger({ logFile, macKey: false, allowUnkeyed: true });
        assert.equal(result.keyed, false);
        assert.equal(result.previous.keyed, true);
        assert.equal(readEntries(logFile)[0].details.previousKeyed, true);
        assert.equal(readEntries(logFile)[0].details.keyed, false);
    });
});

test("rotate handles a partly moved ledger, nothing to rotate, and two rotations in the same instant", () => {
    withTempLedger((logFile) => {
        assert.deepEqual(rotateAuditLedger({ logFile, macKey: false }), { rotated: false, message: "There is no audit ledger to rotate." });
        assert.equal(fs.existsSync(logFile), false, "nothing is created when there is nothing to rotate");
    });

    withTempLedger((logFile) => {
        writeLedger(logFile, 3, false);
        fs.renameSync(`${logFile}.state`, `${logFile}.state.moved`);
        const result = rotateAuditLedger({ logFile, macKey: false });
        assert.equal(result.rotated, true);
        assert.equal(result.archivedFiles.length, 2);
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, true);
    });

    withTempLedger((logFile) => {
        const now = new Date("2026-10-11T10:15:30.000Z");
        writeLedger(logFile, 1, false);
        const first = rotateAuditLedger({ logFile, macKey: false, now });
        const second = rotateAuditLedger({ logFile, macKey: false, now });
        assert.notEqual(first.archive, second.archive);
        assert.equal(archiveFiles(logFile).length, 2);
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, true);
    });
});

test("events from concurrent writers land in exactly one of the archive and the new ledger across a rotation", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-rotate-"));
    try {
        const logFile = path.join(tempDir, "audit.log");
        const auditModule = pathToFileURL(path.join(import.meta.dirname, "audit.mjs")).href;
        const writer = path.join(tempDir, "writer.mjs");
        fs.writeFileSync(writer, [
            `import { recordAuditEvent } from ${JSON.stringify(auditModule)};`,
            "const [file, tag] = process.argv.slice(2);",
            // The lock wait is bounded (5 s). Under CPU starvation a writer can time out; this test is about
            // conservation across a rotation, so a writer retries the same event, as a caller that must not lose it would.
            "function record(target) {",
            "    for (let attempt = 0; ; attempt += 1) {",
            "        try { return recordAuditEvent({ eventType: \"CONCURRENT\", target, logFile: file, macKey: false }); }",
            "        catch (error) { if (!/Timeout acquiring audit log lock/.test(error.message) || attempt >= 20) throw error; }",
            "    }",
            "}",
            // Real callers have work between events; a loop with no gap keeps re-taking the lock and starves every waiter.
            "for (let i = 0; i < 100; i += 1) { record(`${tag}-${i}`); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 3); }",
        ].join("\n"));
        const { spawn } = await import("node:child_process");
        const workers = 4;
        const done = Array.from({ length: workers }, (_, k) => new Promise((resolve) => {
            const child = spawn(process.execPath, [writer, logFile, `w${k}`], { stdio: ["ignore", "ignore", "pipe"] });
            let stderr = "";
            child.stderr.on("data", (chunk) => { stderr += chunk; });
            child.on("close", (code) => resolve(code === 0 ? 0 : `${code}: ${stderr.trim().split(/\r?\n/).slice(0, 3).join(" | ")}`));
        }));
        const deadline = Date.now() + 20000;
        while (Date.now() < deadline && !(fs.existsSync(logFile) && fs.readFileSync(logFile, "utf8").split("\n").length > 25)) {
            await new Promise((resolve) => setTimeout(resolve, 5));
        }
        // The lock is not fair and its wait is bounded; an operator whose rotation times out runs it again.
        let result;
        for (let attempt = 0; !result; attempt += 1) {
            try { result = rotateAuditLedger({ logFile, macKey: false, reason: "rotate under load" }); }
            catch (error) { if (!/Timeout acquiring audit log lock/.test(error.message) || attempt >= 5) throw error; }
        }
        assert.equal(result.rotated, true);
        assert.deepEqual(await Promise.all(done), Array(workers).fill(0));

        const archived = readEntries(result.archive);
        const current = readEntries(logFile);
        assert.ok(archived.length > 0 && current.length > 1, "writers were running on both sides of the rotation");
        assert.equal(current[0].eventType, "AUDIT_LEDGER_ROTATED");
        assert.equal(current[0].details.previousEntries, archived.length, "the rotation entry saw the whole old ledger");
        const targets = [...archived, ...current.slice(1)].map((entry) => entry.target);
        assert.equal(targets.length, workers * 100, "no event lost");
        assert.equal(new Set(targets).size, workers * 100, "no event recorded twice");
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, true);
        assert.equal(verifyAuditLedger({ logFile: result.archive, macKey: false }).ok, true);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("rotate still sees a keyed ledger as keyed after its leading lines were removed or damaged", () => {
    for (const damage of [
        (logFile) => writeEntries(logFile, readEntries(logFile).slice(1)),
        (logFile) => fs.writeFileSync(logFile, `{broken\n${fs.readFileSync(logFile, "utf8").split("\n").slice(1).join("\n")}`),
    ]) {
        withTempLedger((logFile) => {
            writeLedger(logFile, 4, KEY);
            damage(logFile);
            const before = snapshotBytes(logFile);
            assert.throws(() => rotateAuditLedger({ logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_ROTATE_UNKEYED");
            assert.deepEqual(snapshotBytes(logFile), before, "nothing was moved");
            assert.equal(archiveFiles(logFile).length, 0);
        });
    }
});

test("a failure after the files were moved puts the old ledger back", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 3, false);
        const before = snapshotBytes(logFile);
        const failing = { toString() { throw new Error("synthetic failure"); } };
        assert.throws(() => rotateAuditLedger({ logFile, macKey: false, reason: failing }), /synthetic failure/);
        assert.deepEqual(snapshotBytes(logFile), before, "the old log, anchor and sentinel are back unchanged");
        assert.equal(archiveFiles(logFile).length, 0);
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, true);
    });
});

test("refusal messages point to a person-run recovery and do not carry the --yes flag", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 2, false);
        fs.appendFileSync(logFile, "{partial-garbage\n");
        assert.throws(
            () => recordAuditEvent({ eventType: "AFTER", logFile, macKey: false }),
            (error) => /hetzer audit rotate/.test(error.message) && /interactive terminal/.test(error.message) && !error.message.includes("--yes"),
        );
    });
});

function writeLock(logFile, pid, ageMs) {
    const lockPath = `${logFile}.lock`;
    fs.writeFileSync(lockPath, `${pid}\n${Date.now() - ageMs}\nsynthetic\n`);
    const when = new Date(Date.now() - ageMs);
    fs.utimesSync(lockPath, when, when);
    return lockPath;
}

test("a lock held by a live process is never taken over, however old, and a lock from a dead one is", () => {
    withTempLedger((logFile) => {
        const lockPath = writeLock(logFile, process.pid, 60000);
        assert.throws(() => recordAuditEvent({ eventType: "WAITS", logFile, macKey: false, lockTimeoutMs: 400 }), /Timeout acquiring audit log lock/);
        assert.equal(fs.existsSync(lockPath), true, "the live holder's lock is untouched");
        assert.equal(fs.existsSync(logFile), false, "nothing was written without the lock");

        const finished = spawnSync(process.execPath, ["-e", ""]);
        fs.rmSync(lockPath);
        writeLock(logFile, finished.pid, 60000);
        recordAuditEvent({ eventType: "TAKES_OVER", logFile, macKey: false, lockTimeoutMs: 2000 });
        assert.equal(verifyAuditLedger({ logFile, macKey: false }).ok, true);
        assert.equal(fs.existsSync(`${logFile}.lock`), false, "the lock is released");
    });

    // A fresh lock from a dead process is still waited for: only an old one counts as abandoned.
    withTempLedger((logFile) => {
        const finished = spawnSync(process.execPath, ["-e", ""]);
        writeLock(logFile, finished.pid, 1000);
        assert.throws(() => recordAuditEvent({ eventType: "WAITS", logFile, macKey: false, lockTimeoutMs: 300 }), /Timeout acquiring audit log lock/);
    });
});

test("the lock is released when the guarded work throws", () => {
    withTempLedger((logFile) => {
        writeLedger(logFile, 1, false);
        fs.appendFileSync(logFile, "{partial-garbage\n");
        assert.throws(() => recordAuditEvent({ eventType: "FAILS", logFile, macKey: false }), (error) => error.code === "ERR_AUDIT_LEDGER_CORRUPT");
        assert.equal(fs.existsSync(`${logFile}.lock`), false, "the lock is gone after an error");
    });
});
