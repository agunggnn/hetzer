import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseEnv } from "../core/env.mjs";
import { computeAuditMac, normalizeMasterKey, resolveMasterKey, secureFilePermissions } from "./hetzer-vault.mjs";

export const GENESIS_HASH = "0".repeat(64);

export function getAuditLogPath({ root } = {}) {
    if (process.env.HETZER_AUDIT_LOG_PATH) {
        return path.resolve(process.env.HETZER_AUDIT_LOG_PATH);
    }
    if (root) {
        return path.join(path.resolve(root), ".hetzer", "audit.log");
    }
    try {
        const home = os.homedir();
        if (home) {
            return path.join(home, ".hetzer", "audit.log");
        }
    } catch {
        // Fallback to workspace data directory
    }
    return path.join(process.cwd(), ".hetzer", "audit.log");
}

function canonicalString(value) {
    if (value === undefined || value === null) return "";
    if (typeof value === "string") return value;
    try {
        return JSON.stringify(value);
    } catch {
        return String(value);
    }
}

export const AUDIT_ENTRY_VERSION = 2;

/**
 * Entries without a version field (v1) hash only prevHash, index, timestamp, event, target, result
 * and details. Version 2 also covers the version and the actor, so editing who did something is
 * detected. Old ledgers keep verifying because verification dispatches on the entry's own version.
 */
export function computeAuditEntryHash(entry) {
    const { prevHash, index, timestamp, eventType, target, result, details } = entry;
    const detailsStr = canonicalString(details);
    const payload = entry.v >= 2
        ? `v${entry.v}|${prevHash}|${index}|${timestamp}|${eventType}|${target}|${result}|${canonicalString(entry.actor)}|${detailsStr}`
        : `${prevHash}|${index}|${timestamp}|${eventType}|${target}|${result}|${detailsStr}`;
    return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

function macMatches(masterKey, entry) {
    if (typeof entry.mac !== "string" || !/^[0-9a-f]{64}$/.test(entry.mac)) return false;
    const expected = Buffer.from(computeAuditMac(masterKey, entry.hash), "hex");
    const actual = Buffer.from(entry.mac, "hex");
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

const TAIL_CHUNK_BYTES = 64 * 1024;

/**
 * Recovery text for refusals that need no attacker (an interrupted write, a new vault key). Rotation
 * moves the log, its head anchor and its sentinel together and records why in the new ledger.
 */
function ledgerRecoveryHint() {
    return "Recovery needs a person: run 'hetzer audit rotate' in an interactive terminal to archive this ledger and start a new one.";
}

function readHeadIndex(headPath) {
    try {
        const head = JSON.parse(fs.readFileSync(headPath, "utf8"));
        return Number.isInteger(head?.lastIndex) && head.lastIndex > 0 ? head.lastIndex : 0;
    } catch {
        return 0;
    }
}

function readLastEntry(filePath) {
    if (!fs.existsSync(filePath)) return null;
    const fd = fs.openSync(filePath, "r");
    let text;
    try {
        const size = fs.fstatSync(fd).size;
        let length = Math.min(size, TAIL_CHUNK_BYTES);
        for (;;) {
            const buffer = Buffer.alloc(length);
            fs.readSync(fd, buffer, 0, length, size - length);
            text = buffer.toString("utf8");
            // The last line is complete only if a newline precedes it or the chunk starts at the file start.
            const trimmed = text.replace(/\s+$/, "");
            if (length === size || trimmed.lastIndexOf("\n") > 0) break;
            length = Math.min(size, length * 4);
        }
    } finally {
        fs.closeSync(fd);
    }
    const lines = text.split(/\r?\n/).filter((line) => line.trim());
    if (!lines.length) return null;
    try {
        return JSON.parse(lines[lines.length - 1]);
    } catch {
        const error = new Error(`Audit ledger tail is not valid JSON (an interrupted write or an edit); refusing to extend a damaged chain. Run 'hetzer audit verify' to see where. ${ledgerRecoveryHint()}`);
        error.code = "ERR_AUDIT_LEDGER_CORRUPT";
        throw error;
    }
}

export function getAuditHeadPath(filePath) {
    return `${filePath}.head`;
}

export function getAuditStatePath(filePath) {
    return `${filePath}.state`;
}

function withAuditLock(filePath, fn, timeoutMs = 5000) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const lockPath = `${filePath}.lock`;
    const start = Date.now();
    let lockFd = null;

    while (Date.now() - start < timeoutMs) {
        try {
            lockFd = fs.openSync(lockPath, "wx");
            fs.writeFileSync(lockFd, `${process.pid}\n${Date.now()}\n`);
            break;
        } catch (err) {
            // On Windows, opening a lock file that another process is deleting fails with EPERM or EBUSY.
            if (err.code === "EEXIST" || err.code === "EBUSY" || (process.platform === "win32" && (err.code === "EPERM" || err.code === "EACCES"))) {
                try {
                    const stat = fs.statSync(lockPath);
                    if (Date.now() - stat.mtimeMs > 10000) {
                        try { fs.unlinkSync(lockPath); } catch {}
                        continue;
                    }
                } catch {}
                Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
            } else {
                throw err;
            }
        }
    }

    if (lockFd === null) {
        throw new Error(`Timeout acquiring audit log lock on ${lockPath}`);
    }

    try {
        return fn();
    } finally {
        try { fs.closeSync(lockFd); } catch {}
        try { fs.unlinkSync(lockPath); } catch {}
    }
}

/**
 * The MAC key is the explicit `macKey`, else the master key from the runtime environment, the
 * workspace .env or the isolated key store. No key means unkeyed entries, never an error.
 * Callers that opened the vault with an injected environment pass the same `baseEnv` and `envFile`,
 * so the ledger is keyed with the key the vault used. Pass `macKey: false` to disable key lookup (tests, tools that must not touch the key store).
 */
export function resolveAuditMacKey({ root, macKey, baseEnv = process.env, envFile } = {}) {
    if (macKey === false) return "";
    if (macKey) return normalizeMasterKey(macKey);
    try {
        const envPath = envFile || path.join(path.resolve(root || process.cwd()), ".env");
        const envValues = fs.existsSync(envPath) ? parseEnv(fs.readFileSync(envPath, "utf8")) : {};
        return normalizeMasterKey(resolveMasterKey({ root, envValues, baseEnv }));
    } catch {
        return "";
    }
}

export function recordAuditEvent({
    eventType,
    target = "",
    result = "ALLOW",
    actor = {},
    details = {},
    logFile,
    root,
    macKey,
    baseEnv,
    envFile,
    now = new Date(),
} = {}) {
    if (!eventType) throw new Error("Audit eventType is required.");
    const key = resolveAuditMacKey({ root, macKey, baseEnv, envFile });
    const filePath = logFile || getAuditLogPath({ root });

    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    return withAuditLock(filePath, () => appendEntryUnlocked({ filePath, key, eventType, target, result, actor, details, now }));
}

/** Appends one entry. The caller holds the audit lock. */
function appendEntryUnlocked({ filePath, key, eventType, target, result, actor, details, now }) {
    const statePath = getAuditStatePath(filePath);
    if (!fs.existsSync(statePath)) {
        fs.writeFileSync(statePath, JSON.stringify({ version: 1, initializedAt: new Date().toISOString() }), {
            encoding: "utf8",
            mode: 0o600,
        });
        secureFilePermissions(statePath);
    }

    const lastEntry = readLastEntry(filePath);
    // The head file is written after each append, so it never runs ahead of the log in normal operation.
    // If it does, entries were removed; extending the chain would overwrite the head and hide that.
    const anchoredIndex = readHeadIndex(getAuditHeadPath(filePath));
    if (anchoredIndex > (lastEntry?.index || 0)) {
        const error = new Error(`Audit ledger has ${lastEntry?.index || 0} entries but its checkpoint anchor records ${anchoredIndex}; entries were removed. Run 'hetzer audit verify'. ${ledgerRecoveryHint()}`);
        error.code = "ERR_AUDIT_LEDGER_TRUNCATED";
        throw error;
    }
    if (lastEntry?.mac) {
        // Extending a keyed chain without the key, or with another key, would make it fail verification for good.
        if (!key) {
            const error = new Error(`Audit ledger is keyed but no master key is available to extend it. Set HETZER_GRIMOIRE_KEY for this process. ${ledgerRecoveryHint()}`);
            error.code = "ERR_AUDIT_KEY_REQUIRED";
            throw error;
        }
        if (!macMatches(key, lastEntry)) {
            const error = new Error(`Audit ledger was written with a different master key than this process has (for example after the vault was re-created). ${ledgerRecoveryHint()}`);
            error.code = "ERR_AUDIT_KEY_MISMATCH";
            throw error;
        }
    }
    const prevHash = lastEntry?.hash || GENESIS_HASH;
    const index = (lastEntry?.index || 0) + 1;
    const timestamp = now instanceof Date ? now.toISOString() : new Date(now).toISOString();

    const resolvedActor = {
        pid: actor.pid || process.pid,
        user: actor.user || process.env.USERNAME || process.env.USER || "unknown",
        isTTY: actor.isTTY !== undefined ? Boolean(actor.isTTY) : Boolean(process.stdin?.isTTY),
        processName: actor.processName || path.basename(process.argv[1] || "hetzer"),
        ...actor,
    };

    const entry = {
        v: AUDIT_ENTRY_VERSION,
        index,
        timestamp,
        eventType: String(eventType).toUpperCase(),
        target: String(target),
        result: String(result).toUpperCase(),
        actor: resolvedActor,
        details,
        prevHash,
        hash: "",
    };

    entry.hash = computeAuditEntryHash(entry);
    if (key) entry.mac = computeAuditMac(key, entry.hash);

    const logExisted = fs.existsSync(filePath);
    fs.appendFileSync(filePath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
    if (!logExisted) secureFilePermissions(filePath);

    // Update monotonic head anchor for truncation detection
    const headPath = getAuditHeadPath(filePath);
    const headExisted = fs.existsSync(headPath);
    const headData = {
        lastIndex: entry.index,
        lastHash: entry.hash,
        updatedAt: entry.timestamp,
    };
    fs.writeFileSync(headPath, JSON.stringify(headData, null, 2), { encoding: "utf8", mode: 0o600 });
    if (!headExisted) secureFilePermissions(headPath);

    return entry;
}

export function readAuditEvents({ logFile, root, limit = 50 } = {}) {
    const filePath = logFile || getAuditLogPath({ root });
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, "utf8").trim();
    if (!content) return [];
    const lines = content.split(/\r?\n/).filter(Boolean);
    const entries = [];
    for (const line of lines) {
        try {
            entries.push(JSON.parse(line));
        } catch {
            // Ignore corrupted lines in read
        }
    }
    return entries.slice(-limit);
}

export function verifyAuditLedger({ logFile, root, expectedHeadHash, expectedCount, macKey, requireMac } = {}) {
    const filePath = logFile || getAuditLogPath({ root });
    const key = resolveAuditMacKey({ root, macKey });
    const mustBeKeyed = requireMac ?? process.env.HETZER_AUDIT_REQUIRE_MAC === "1";
    if (mustBeKeyed && !key) {
        return { ok: false, tamperedIndex: 0, error: "A keyed audit check was required but no master key is available." };
    }
    const headPath = getAuditHeadPath(filePath);
    const statePath = getAuditStatePath(filePath);

    if (!fs.existsSync(filePath) && !fs.existsSync(headPath) && !fs.existsSync(statePath)) {
        if (typeof expectedCount === "number" && expectedCount > 0) {
            return {
                ok: false,
                tamperedIndex: 1,
                error: `Audit ledger missing or empty, but expected ${expectedCount} entries.`,
            };
        }
        return {
            ok: true,
            count: 0,
            message: "Audit log does not exist yet (clean state).",
        };
    }

    return withAuditLock(filePath, () => verifyLedgerUnlocked({ filePath, key, mustBeKeyed, expectedHeadHash, expectedCount }));
}

/** Verifies one ledger. The caller holds the audit lock. */
function verifyLedgerUnlocked({ filePath, key, mustBeKeyed, expectedHeadHash, expectedCount }) {
    const headPath = getAuditHeadPath(filePath);
    const statePath = getAuditStatePath(filePath);
    let head = null;
    let headMalformed = false;
    if (fs.existsSync(headPath)) {
        try {
            head = JSON.parse(fs.readFileSync(headPath, "utf8"));
        } catch {
            headMalformed = true;
        }
    }

    const fileExists = fs.existsSync(filePath);
    const content = fileExists ? fs.readFileSync(filePath, "utf8").trim() : "";
    const stateExists = fs.existsSync(statePath);

    if (headMalformed || (fileExists && !head)) {
        return {
            ok: false,
            tamperedIndex: 1,
            error: "Audit ledger checkpoint anchor is missing or malformed.",
        };
    }

    if (!fileExists || !content) {
        if (!fileExists && !head && stateExists) {
            return {
                ok: false,
                tamperedIndex: 1,
                error: "Audit ledger is missing, but its initialization sentinel remains.",
            };
        }
        if (head && typeof head.lastIndex === "number" && head.lastIndex > 0) {
            return {
                ok: false,
                tamperedIndex: 1,
                error: `Audit ledger missing or empty, but checkpoint anchor records ${head.lastIndex} entries.`,
            };
        }
        if (typeof expectedCount === "number" && expectedCount > 0) {
            return {
                ok: false,
                tamperedIndex: 1,
                error: `Audit ledger missing or empty, but expected ${expectedCount} entries.`,
            };
        }
        return {
            ok: true,
            count: 0,
            message: !fileExists ? "Audit log does not exist yet (clean state)." : "Audit log is empty.",
        };
    }

    const lines = content.split(/\r?\n/).filter(Boolean);
    let expectedPrevHash = GENESIS_HASH;
    let expectedIndex = 1;
    let sawVersion = 1;
    let sawMac = false;
    let macCount = 0;

    for (let i = 0; i < lines.length; i++) {
        let entry;
        try {
            entry = JSON.parse(lines[i]);
        } catch {
            return {
                ok: false,
                tamperedIndex: i + 1,
                error: `Corrupted JSON format at line ${i + 1}.`,
            };
        }

        if (entry.index !== expectedIndex) {
            return {
                ok: false,
                tamperedIndex: entry.index,
                error: `Sequence break at line ${i + 1}: expected index ${expectedIndex}, found ${entry.index}.`,
            };
        }

        if (entry.prevHash !== expectedPrevHash) {
            return {
                ok: false,
                tamperedIndex: entry.index,
                error: `Hash chain broken at index ${entry.index}: prevHash does not match previous entry hash.`,
            };
        }

        const entryVersion = entry.v === undefined ? 1 : entry.v;
        if (!Number.isInteger(entryVersion) || entryVersion < sawVersion || entryVersion > AUDIT_ENTRY_VERSION) {
            return {
                ok: false,
                tamperedIndex: entry.index,
                error: `Entry format version at index ${entry.index} is invalid or lower than an earlier entry (downgrade).`,
            };
        }
        sawVersion = entryVersion;

        const calculatedHash = computeAuditEntryHash(entry);
        if (entry.hash !== calculatedHash) {
            return {
                ok: false,
                tamperedIndex: entry.index,
                error: `Integrity check failed at index ${entry.index}: entry hash mismatch (data altered).`,
            };
        }

        if (entry.mac !== undefined) {
            if (entryVersion < 2) {
                return { ok: false, tamperedIndex: entry.index, error: `Entry ${entry.index} carries a MAC but is not a version 2 entry.` };
            }
            sawMac = true;
            macCount += 1;
            if (key && !macMatches(key, entry)) {
                return {
                    ok: false,
                    tamperedIndex: entry.index,
                    error: `Keyed MAC check failed at index ${entry.index}: the entry was not written with the master key available here (a different key, or the entry was altered).`,
                };
            }
        } else if (sawMac) {
            return {
                ok: false,
                tamperedIndex: entry.index,
                error: `Unkeyed entry at index ${entry.index} follows keyed entries (MAC downgrade).`,
            };
        } else if (mustBeKeyed) {
            return { ok: false, tamperedIndex: entry.index, error: `Entry ${entry.index} has no MAC but a keyed ledger was required.` };
        }

        expectedPrevHash = entry.hash;
        expectedIndex += 1;
    }

    // Check against head state anchor or explicit parameters to prevent tail deletion
    const targetExpectedCount = expectedCount !== undefined ? expectedCount : head?.lastIndex;
    if (typeof targetExpectedCount === "number" && lines.length < targetExpectedCount) {
        return {
            ok: false,
            tamperedIndex: lines.length + 1,
            error: `Audit ledger truncated: expected at least ${targetExpectedCount} entries from checkpoint anchor, found ${lines.length}.`,
        };
    }

    const targetExpectedHash = expectedHeadHash || head?.lastHash;
    if (targetExpectedHash && expectedPrevHash !== targetExpectedHash) {
        return {
            ok: false,
            tamperedIndex: lines.length,
            error: `Audit ledger tail hash mismatch: latest entry hash does not match checkpoint anchor.`,
        };
    }

    return {
        ok: true,
        count: lines.length,
        latestHash: expectedPrevHash,
        keyedEntries: macCount,
        macVerified: Boolean(key) && macCount > 0,
        message: `Verified ${lines.length} audit entries. Hash chain valid.${macCount ? (key ? ` ${macCount} keyed entries verified.` : ` ${macCount} keyed entries present; MAC not checked (no master key).`) : ""}`,
    };
}

function sleepMs(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** Renames with a short retry: on Windows a reader that just closed the file can still hold it for a moment. */
function renameWithRetry(from, to, attempts = 20) {
    for (let attempt = 1; ; attempt += 1) {
        try {
            fs.renameSync(from, to);
            return;
        } catch (err) {
            const transient = process.platform === "win32" && ["EPERM", "EBUSY", "EACCES"].includes(err.code);
            if (!transient || attempt >= attempts) throw err;
            sleepMs(50);
        }
    }
}

/** What the old ledger looked like, read without any of the refusals recordAuditEvent applies. */
function snapshotLedger(filePath, key) {
    const verification = verifyLedgerUnlocked({ filePath, key, mustBeKeyed: false });
    let anchor = null;
    try {
        const head = JSON.parse(fs.readFileSync(getAuditHeadPath(filePath), "utf8"));
        if (Number.isInteger(head?.lastIndex)) anchor = { lastIndex: head.lastIndex, lastHash: String(head.lastHash || "") };
    } catch {
        // A missing or malformed anchor is itself part of what is being recorded.
    }
    let lastGood = null;
    let lines = 0;
    let keyedEntries = 0;
    let chainIntact = true;
    if (fs.existsSync(filePath)) {
        for (const line of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
            if (!line.trim()) continue;
            lines += 1;
            let entry;
            try {
                entry = JSON.parse(line);
            } catch {
                chainIntact = false;
                continue;
            }
            // Keyed lines are counted even after the chain breaks (deleted or damaged leading lines
            // must not make a keyed ledger look unkeyed).
            if (entry?.mac !== undefined) keyedEntries += 1;
            if (!chainIntact) continue;
            const expectedIndex = (lastGood?.index || 0) + 1;
            const expectedPrev = lastGood?.hash || GENESIS_HASH;
            if (entry.index !== expectedIndex || entry.prevHash !== expectedPrev || entry.hash !== computeAuditEntryHash(entry)) {
                chainIntact = false;
                continue;
            }
            lastGood = { index: entry.index, hash: entry.hash };
        }
    }
    return { verification, anchor, lastGood, lines, keyedEntries };
}

function archiveStamp(now) {
    return (now instanceof Date ? now : new Date(now)).toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

/**
 * Starts a new ledger and keeps the old one as an archive. Under one lock hold it records what the
 * old ledger looked like (including a failed verification), moves the log, head anchor and
 * sentinel aside, and writes entry #1 of the new ledger, whose details carry the old head forward.
 * The new ledger starts at genesis, so verification is unchanged; the link to the archive lives in
 * the hashed (and, when keyed, MAC'd) details of that first entry. Nothing here prevents someone
 * with write access from deleting the archive together with the rotation entry.
 */
export function rotateAuditLedger({
    logFile,
    root,
    macKey,
    baseEnv,
    envFile,
    reason = "",
    allowUnkeyed = false,
    now = new Date(),
} = {}) {
    const key = resolveAuditMacKey({ root, macKey, baseEnv, envFile });
    const filePath = logFile || getAuditLogPath({ root });
    const parts = [filePath, getAuditHeadPath(filePath), getAuditStatePath(filePath)];

    return withAuditLock(filePath, () => {
        const present = parts.filter((part) => fs.existsSync(part));
        if (!present.length) return { rotated: false, message: "There is no audit ledger to rotate." };

        const before = snapshotLedger(filePath, key);
        if (before.keyedEntries > 0 && !key && !allowUnkeyed) {
            const error = new Error("The audit ledger is keyed but no master key is available here, so the new ledger would start unkeyed (a MAC downgrade). Set the master key for this process, or pass --allow-unkeyed to accept that.");
            error.code = "ERR_AUDIT_ROTATE_UNKEYED";
            throw error;
        }

        const stamp = archiveStamp(now);
        let archiveBase = `${filePath}.${stamp}`;
        for (let n = 2; parts.some((_, i) => fs.existsSync(i === 0 ? archiveBase : `${archiveBase}${parts[i].slice(filePath.length)}`)); n += 1) {
            archiveBase = `${filePath}.${stamp}-${n}`;
        }
        const moved = [];
        try {
            for (const part of present) {
                const target = `${archiveBase}${part.slice(filePath.length)}`;
                renameWithRetry(part, target);
                moved.push([part, target]);
            }
        } catch (err) {
            for (const [original, target] of moved.reverse()) {
                try { fs.renameSync(target, original); } catch {}
            }
            throw err;
        }

        // From here on, a failure puts the old files back so the ledger is never left without a successor.
        const rollback = () => {
            for (const part of parts) {
                try { fs.rmSync(part, { force: true }); } catch {}
            }
            for (const [original, target] of [...moved].reverse()) {
                try { fs.renameSync(target, original); } catch {}
            }
        };
        let entry;
        try {
            const archivedLog = `${archiveBase}`;
            const archiveSha256 = fs.existsSync(archivedLog)
                ? crypto.createHash("sha256").update(fs.readFileSync(archivedLog)).digest("hex")
                : "";
            entry = appendEntryUnlocked({
                filePath,
                key,
                eventType: "AUDIT_LEDGER_ROTATED",
                target: path.basename(archiveBase),
                result: "ALLOW",
                actor: {},
                details: {
                    reason: String(reason || "").slice(0, 200),
                    archive: path.basename(archiveBase),
                    archiveSha256,
                    archivedFiles: moved.map(([, target]) => path.basename(target)),
                    previousEntries: before.lines,
                    previousLastGood: before.lastGood,
                    previousAnchor: before.anchor,
                    previousVerified: before.verification.ok === true,
                    previousMacChecked: before.verification.macVerified === true,
                    previousVerifyError: before.verification.ok ? "" : String(before.verification.error || "").slice(0, 300),
                    previousKeyed: before.keyedEntries > 0,
                    keyed: Boolean(key),
                },
                now,
            });

            const after = verifyLedgerUnlocked({ filePath, key, mustBeKeyed: false });
            if (!after.ok) {
                const error = new Error(`The new audit ledger did not verify after rotation: ${after.error}`);
                error.code = "ERR_AUDIT_ROTATE_FAILED";
                throw error;
            }
        } catch (err) {
            rollback();
            throw err;
        }
        return {
            rotated: true,
            entry,
            archive: archiveBase,
            archivedFiles: moved.map(([, target]) => target),
            previous: {
                verified: before.verification.ok === true,
                macChecked: before.verification.macVerified === true,
                error: before.verification.ok ? "" : before.verification.error,
                entries: before.lines,
                lastGood: before.lastGood,
                anchor: before.anchor,
                keyed: before.keyedEntries > 0,
            },
            keyed: Boolean(key),
        };
    });
}
