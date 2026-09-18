import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { secureFilePermissions } from "./hetzer-vault.mjs";

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

export function computeAuditEntryHash({ prevHash, index, timestamp, eventType, target, result, details }) {
    const detailsStr = canonicalString(details);
    const payload = `${prevHash}|${index}|${timestamp}|${eventType}|${target}|${result}|${detailsStr}`;
    return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

function readLastEntry(filePath) {
    if (!fs.existsSync(filePath)) return null;
    const content = fs.readFileSync(filePath, "utf8").trim();
    if (!content) return null;
    const lines = content.split(/\r?\n/).filter(Boolean);
    if (!lines.length) return null;
    try {
        return JSON.parse(lines[lines.length - 1]);
    } catch {
        return null;
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
            if (err.code === "EEXIST") {
                try {
                    const stat = fs.statSync(lockPath);
                    if (Date.now() - stat.mtimeMs > 10000) {
                        try { fs.unlinkSync(lockPath); } catch {}
                        continue;
                    }
                } catch {}
                const until = Date.now() + 20;
                while (Date.now() < until) {}
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

export function recordAuditEvent({
    eventType,
    target = "",
    result = "ALLOW",
    actor = {},
    details = {},
    logFile,
    root,
    now = new Date(),
} = {}) {
    if (!eventType) throw new Error("Audit eventType is required.");
    const filePath = logFile || getAuditLogPath({ root });

    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    return withAuditLock(filePath, () => {
        const statePath = getAuditStatePath(filePath);
        if (!fs.existsSync(statePath)) {
            fs.writeFileSync(statePath, JSON.stringify({ version: 1, initializedAt: new Date().toISOString() }), {
                encoding: "utf8",
                mode: 0o600,
            });
            secureFilePermissions(statePath);
        }

        const lastEntry = readLastEntry(filePath);
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

        fs.appendFileSync(filePath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
        secureFilePermissions(filePath);

        // Update monotonic head anchor for truncation detection
        const headPath = getAuditHeadPath(filePath);
        const headData = {
            lastIndex: entry.index,
            lastHash: entry.hash,
            updatedAt: entry.timestamp,
        };
        fs.writeFileSync(headPath, JSON.stringify(headData, null, 2), { encoding: "utf8", mode: 0o600 });
        secureFilePermissions(headPath);

        return entry;
    });
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

export function verifyAuditLedger({ logFile, root, expectedHeadHash, expectedCount } = {}) {
    const filePath = logFile || getAuditLogPath({ root });
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

    return withAuditLock(filePath, () => {
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

            const calculatedHash = computeAuditEntryHash(entry);
            if (entry.hash !== calculatedHash) {
                return {
                    ok: false,
                    tamperedIndex: entry.index,
                    error: `Integrity check failed at index ${entry.index}: entry hash mismatch (data altered).`,
                };
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
            message: `Verified ${lines.length} audit entries. Hash chain valid.`,
        };
    });
}
