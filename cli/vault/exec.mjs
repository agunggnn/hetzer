#!/usr/bin/env node

import "../core/suppress-warnings.mjs";
import fs from "node:fs";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { CANARY_TOKEN_PATTERN, isCanaryCredential, isCanaryToken, triggerCanaryAlert } from "./canary.mjs";
import { applyExecPolicy, assertNoShellMetacharacters, loadExecPolicy } from "./exec-policy.mjs";
import { Grimoire, resolveMasterKey, resolveVaultPath } from "./hetzer-vault.mjs";
import { resolveSecretEnvironment } from "./secret-env.mjs";
import { scanText } from "./sniffer.mjs";

const FORMAT_CONTROL = /\p{Cf}/u;
const LEXICAL_CHARACTER = /[A-Za-z0-9+/_=.-]/;
const PRIVATE_KEY_BEGIN = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;
const PRIVATE_KEY_END = /-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/;
const DATABASE_SCHEME = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\//i;
const STRUCTURED_MARKER_TAIL = 128;
const LEXICAL_SCAN_LIMIT = 512;

const FORBIDDEN_REFLECTION = [
    /^\s*(printenv|env|export|set)\b/i,
    /\bprintenv\b/i,
    /\bcat\s+.*\/proc\/(\d+|self)\/environ/i,
    /\bdocker\s+inspect\b/i,
    /process\.env/i,
    /os\.environ/i,
    /\b(?:cmd|cmd\.exe)\s+\/[ck]\s+.*(?:set\b|echo\s+%)/i,
    /\b(?:powershell|pwsh)(?:\.exe)?\s+.*(?:\$env:|Get-ChildItem\s+env:|dir\s+env:|Get-Item\s+env:)/i,
    /\b(?:Get-ChildItem|dir|ls|gci)\s+env:/i,
    /\$env:/i,
];

export function isReflectionCommand(command, commandArgs = []) {
    const full = [command, ...commandArgs].join(" ");
    return FORBIDDEN_REFLECTION.some((pattern) => pattern.test(full));
}

export function sanitizeStreamOutput(text, secretsToRedact = []) {
    let result = text;
    for (const { secret, id } of secretsToRedact) {
        if (secret && typeof secret === "string") {
            result = result.replaceAll(secret, `secretRef:${id}`);
        }
    }
    for (const match of scanText(result).matches) {
        result = result.split(match.value).join(`secretRef:${match.defaultId}`);
    }
    return result;
}

export function collectResolvedSecrets(envFile, env) {
    const secrets = [];
    if (env && typeof env === "object") {
        for (const [name, val] of Object.entries(env)) {
            if (typeof val === "string" && (name === "HETZER_CANARY_TOKEN" || isCanaryToken(val))) {
                if (!secrets.some((s) => s.secret === val)) {
                    secrets.push({
                        id: (name === "HETZER_CANARY_TOKEN" || (!name.toLowerCase().startsWith("canary") && !name.toLowerCase().startsWith("decoy")))
                            ? "canary-token"
                            : name.toLowerCase().replace(/_/g, "-"),
                        secret: val,
                        isCanary: true,
                    });
                }
            }
        }
    }
    if (envFile && fs.existsSync(envFile)) {
        const rawValues = parseEnv(fs.readFileSync(envFile, "utf8"));
        for (const [name, rawValue] of Object.entries(rawValues)) {
            if (!String(rawValue).startsWith("secretRef:")) continue;
            const id = String(rawValue).slice("secretRef:".length);
            const secret = env ? env[name] : undefined;
            if (!secret || typeof secret !== "string" || secret.startsWith("secretRef:")) continue;
            secrets.push({
                id,
                secret,
                isCanary: isCanaryCredential(id) || isCanaryToken(secret),
            });
        }
    }
    return secrets;
}

function createTerminalControlFilter() {
    let escapeMode = "text";

    return {
        write(text) {
            let output = "";
            for (const char of text) {
                const code = char.codePointAt(0);

                if (escapeMode === "csi") {
                    if (code >= 0x40 && code <= 0x7e) escapeMode = "text";
                    continue;
                }
                if (escapeMode === "osc") {
                    if (char === "\u0007") escapeMode = "text";
                    else if (char === "\u001b") escapeMode = "osc-escape";
                    continue;
                }
                if (escapeMode === "osc-escape") {
                    escapeMode = char === "\\" ? "text" : "osc";
                    continue;
                }
                if (escapeMode === "escape") {
                    if (char === "[") escapeMode = "csi";
                    else if (char === "]") escapeMode = "osc";
                    else escapeMode = "text";
                    continue;
                }

                if (char === "\u001b") {
                    escapeMode = "escape";
                    continue;
                }
                if (code === 0x9b) {
                    escapeMode = "csi";
                    continue;
                }
                if (code === 0x9d) {
                    escapeMode = "osc";
                    continue;
                }
                if (
                    char === "\r"
                    || (code >= 0 && code <= 8)
                    || code === 11
                    || code === 12
                    || (code >= 14 && code <= 31)
                    || (code >= 0x7f && code <= 0x9f)
                    || FORMAT_CONTROL.test(char)
                ) {
                    continue;
                }
                output += char;
            }
            return output;
        },
        end() {
            escapeMode = "text";
            return "";
        },
    };
}

function findStructuredStart(text) {
    const privateKey = PRIVATE_KEY_BEGIN.exec(text);
    const database = DATABASE_SCHEME.exec(text);
    if (!privateKey) return database ? { index: database.index, length: database[0].length, mode: "database" } : null;
    if (!database || privateKey.index <= database.index) {
        return { index: privateKey.index, length: privateKey[0].length, mode: "private-key" };
    }
    return { index: database.index, length: database[0].length, mode: "database" };
}

function createStructuredSecretFilter() {
    let pending = "";
    let mode = "text";

    const drain = (final = false) => {
        let output = "";
        while (pending) {
            if (mode === "private-key") {
                const end = PRIVATE_KEY_END.exec(pending);
                if (end) {
                    pending = pending.slice(end.index + end[0].length);
                    mode = "text";
                    continue;
                }
                if (final) pending = "";
                else if (pending.length > STRUCTURED_MARKER_TAIL) pending = pending.slice(-STRUCTURED_MARKER_TAIL);
                return output;
            }

            if (mode === "database") {
                const delimiter = pending.search(/\s/);
                if (delimiter === -1) {
                    pending = "";
                    return output;
                }
                output += pending[delimiter];
                pending = pending.slice(delimiter + 1);
                mode = "text";
                continue;
            }

            const start = findStructuredStart(pending);
            if (start) {
                output += pending.slice(0, start.index);
                output += start.mode === "private-key" ? "secretRef:private-key" : "secretRef:database-url";
                pending = pending.slice(start.index + start.length);
                mode = start.mode;
                continue;
            }

            if (final) {
                output += pending;
                pending = "";
            } else if (pending.length > STRUCTURED_MARKER_TAIL) {
                output += pending.slice(0, -STRUCTURED_MARKER_TAIL);
                pending = pending.slice(-STRUCTURED_MARKER_TAIL);
            }
            return output;
        }
        return output;
    };

    return {
        write(text) {
            pending += text;
            return drain(false);
        },
        end() {
            return drain(true);
        },
    };
}

function createLexicalSecretFilter(secretsToRedact) {
    let pending = "";
    let suppressRemainder = false;

    const sanitizePending = () => {
        const output = sanitizeStreamOutput(pending, secretsToRedact);
        pending = "";
        return output;
    };

    return {
        write(text) {
            let output = "";
            for (const char of text) {
                if (LEXICAL_CHARACTER.test(char)) {
                    if (suppressRemainder) continue;
                    pending += char;
                    if (pending.length >= LEXICAL_SCAN_LIMIT) {
                        const sanitized = sanitizePending();
                        output += sanitized;
                        suppressRemainder = sanitized.includes("secretRef:");
                    }
                    continue;
                }

                if (!suppressRemainder && pending) output += sanitizePending();
                pending = "";
                suppressRemainder = false;
                output += char;
            }
            return output;
        },
        end() {
            if (suppressRemainder) {
                pending = "";
                suppressRemainder = false;
                return "";
            }
            return pending ? sanitizePending() : "";
        },
    };
}

function crossingMatchStart(text, boundary, secretsToRedact) {
    let earliest = boundary;
    for (const { secret } of secretsToRedact) {
        if (!secret || typeof secret !== "string") continue;
        let index = text.indexOf(secret);
        while (index !== -1) {
            if (index < boundary && index + secret.length > boundary) earliest = Math.min(earliest, index);
            index = text.indexOf(secret, index + 1);
        }
    }
    const windowStart = Math.max(0, boundary - 256);
    const windowEnd = Math.min(text.length, boundary + 256);
    const windowText = text.slice(windowStart, windowEnd);
    for (const match of scanText(windowText).matches) {
        const matchIndex = windowStart + match.index;
        if (matchIndex < boundary && matchIndex + match.value.length > boundary) {
            earliest = Math.min(earliest, matchIndex);
        }
    }
    return earliest;
}

export function createStreamSanitizer(secretsToRedact = [], { onCanaryDetected } = {}) {
    const decoder = new StringDecoder("utf8");
    const terminalControls = createTerminalControlFilter();
    const structuredSecrets = createStructuredSecretFilter();
    const redactionSecrets = secretsToRedact.filter((item) => !item.isCanary && !isCanaryCredential(item.id));
    const lexicalSecrets = createLexicalSecretFilter(redactionSecrets);
    const longestSecret = secretsToRedact.reduce((max, item) => Math.max(max, String(item.secret || "").length), 0);
    const retention = Math.max(128, longestSecret * 2);
    let pending = "";
    let rawPending = "";

    const checkForCanaries = (text) => {
        if (!onCanaryDetected || !text) return false;
        for (const item of secretsToRedact) {
            if (item.isCanary && item.secret && typeof item.secret === "string") {
                if (text.includes(item.secret)) {
                    onCanaryDetected({ id: item.id || "canary-token", secret: item.secret });
                    return true;
                }
            }
        }
        if (isCanaryToken(text)) {
            const match = text.match(CANARY_TOKEN_PATTERN);
            onCanaryDetected({ id: "canary-token", secret: match ? match[0] : "" });
            return true;
        }
        return false;
    };

    const preprocess = (text) => {
        const normalized = terminalControls.write(text);
        rawPending += normalized;
        if (checkForCanaries(rawPending)) {
            rawPending = "";
            return null;
        }
        if (rawPending.length > retention) {
            rawPending = rawPending.slice(-retention);
        }
        const structured = structuredSecrets.write(normalized);
        return lexicalSecrets.write(structured);
    };

    const drain = (final = false) => {
        if (final) {
            const output = sanitizeStreamOutput(pending, redactionSecrets);
            pending = "";
            return output;
        }
        if (pending.length <= retention) return "";
        const proposedBoundary = pending.length - retention;
        const boundary = crossingMatchStart(pending, proposedBoundary, redactionSecrets);
        if (boundary <= 0) return "";
        const output = sanitizeStreamOutput(pending.slice(0, boundary), redactionSecrets);
        pending = pending.slice(boundary);
        return output;
    };

    return {
        write(chunk) {
            const decoded = Buffer.isBuffer(chunk) ? decoder.write(chunk) : String(chunk);
            const processed = preprocess(decoded);
            if (processed === null) {
                pending = "";
                return "";
            }
            pending += processed;
            return drain(false);
        },
        end() {
            const decodedEnd = decoder.end();
            if (decodedEnd) {
                const processed = preprocess(decodedEnd);
                if (processed === null) {
                    rawPending = "";
                    pending = "";
                    return "";
                }
                pending += processed;
            }
            const tcEnd = terminalControls.end();
            rawPending += tcEnd;
            if (checkForCanaries(rawPending)) {
                rawPending = "";
                pending = "";
                return "";
            }
            pending += lexicalSecrets.write(structuredSecrets.write(tcEnd));
            pending += lexicalSecrets.write(structuredSecrets.end());
            pending += lexicalSecrets.end();
            return drain(true);
        },
    };
}

export function terminateProcessTree(child, { force = true } = {}) {
    if (!child || !child.pid) return;
    if (process.platform === "win32") {
        try {
            spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true, stdio: "ignore" });
        } catch {}
    }
    try {
        child.kill(force ? "SIGKILL" : "SIGTERM");
    } catch {}
    if (force) {
        try {
            child.kill("SIGTERM");
        } catch {}
    }
}

export function parseDuration(durationStr) {
    if (typeof durationStr === "number" && Number.isFinite(durationStr) && durationStr > 0) {
        return Math.floor(durationStr);
    }
    if (typeof durationStr !== "string" || !durationStr.trim()) {
        throw new Error(`Invalid timeout duration: expected duration string (e.g. '30s', '5m', '10000ms'), received ${JSON.stringify(durationStr)}`);
    }
    const str = durationStr.trim();
    const match = str.match(/^([+-]?\d+(?:\.\d+)?)\s*(ms|s|m|h)?$/i);
    if (!match) {
        throw new Error(`Invalid timeout duration format: '${durationStr}'. Supported units: ms, s, m, h (e.g. '30s', '5m', '10000ms').`);
    }
    const val = parseFloat(match[1]);
    const unit = (match[2] || "ms").toLowerCase();
    let ms;
    switch (unit) {
        case "ms": ms = val; break;
        case "s": ms = val * 1000; break;
        case "m": ms = val * 60 * 1000; break;
        case "h": ms = val * 3600 * 1000; break;
        default: ms = val; break;
    }
    if (!Number.isFinite(ms) || ms <= 0) {
        throw new Error(`Invalid timeout duration value: '${durationStr}'. Duration must be greater than 0.`);
    }
    return Math.floor(ms);
}

export function pipeSanitizedChild(child, secretsToRedact = [], {
    outStream = process.stdout,
    errStream = process.stderr,
    root = process.cwd(),
    timeoutMs,
} = {}) {
    return new Promise((resolve, reject) => {
        let canaryTripped = false;
        let timedOut = false;
        let timeoutTimer = null;
        let killGraceTimer = null;

        const cleanupTimers = () => {
            if (timeoutTimer) clearTimeout(timeoutTimer);
            if (killGraceTimer) clearTimeout(killGraceTimer);
        };

        const handleCanaryTrip = ({ id, secret }) => {
            if (canaryTripped) return;
            canaryTripped = true;
            cleanupTimers();

            terminateProcessTree(child, { force: true });

            try {
                triggerCanaryAlert({
                    id: id || "canary-token",
                    actor: "subprocess.leak",
                    action: "stream.output",
                    root,
                });
            } catch (err) {
                return reject(err);
            }
        };

        if (typeof timeoutMs === "number" && timeoutMs > 0) {
            timeoutTimer = setTimeout(() => {
                timedOut = true;
                errStream.write(`\n[!] Hetzer Timeout Guard: Subprocess exceeded execution budget (${timeoutMs}ms). Initiating termination.\n`);
                terminateProcessTree(child, { force: false });

                killGraceTimer = setTimeout(() => {
                    terminateProcessTree(child, { force: true });
                }, 500);
                killGraceTimer.unref?.();
            }, timeoutMs);
            timeoutTimer.unref?.();
        }

        const stdoutSanitizer = createStreamSanitizer(secretsToRedact, { onCanaryDetected: handleCanaryTrip });
        const stderrSanitizer = createStreamSanitizer(secretsToRedact, { onCanaryDetected: handleCanaryTrip });

        child.stdout.on("data", (chunk) => {
            if (canaryTripped) return;
            const sanitized = stdoutSanitizer.write(chunk);
            if (sanitized && !canaryTripped) outStream.write(sanitized);
        });
        child.stderr.on("data", (chunk) => {
            if (canaryTripped) return;
            const sanitized = stderrSanitizer.write(chunk);
            if (sanitized && !canaryTripped) errStream.write(sanitized);
        });
        child.once("error", (err) => {
            cleanupTimers();
            if (canaryTripped) return;
            reject(err);
        });
        child.once("close", (code, signal) => {
            cleanupTimers();
            if (canaryTripped) return;
            const finalStdout = stdoutSanitizer.end();
            const finalStderr = stderrSanitizer.end();
            if (finalStdout && !canaryTripped) outStream.write(finalStdout);
            if (finalStderr && !canaryTripped) errStream.write(finalStderr);
            if (timedOut) {
                const err = new Error(`Subprocess timed out after ${timeoutMs}ms.`);
                err.code = "ERR_SUBPROCESS_TIMEOUT";
                err.exitCode = 124;
                return reject(err);
            }
            resolve({ status: code ?? (signal ? 1 : 0) });
        });
    });
}

export function resolveCommandForSpawn(command, commandArgs = []) {
    if (process.platform !== "win32") {
        return { cmd: command, args: commandArgs };
    }
    const cmdLower = (command || "").toLowerCase();
    // 1. Resolve npm / npx directly to node <cli.js>
    if (cmdLower === "npm" || cmdLower === "npm.cmd") {
        const npmCliPath = path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
        if (fs.existsSync(npmCliPath)) {
            return { cmd: process.execPath, args: [npmCliPath, ...commandArgs] };
        }
    }
    if (cmdLower === "npx" || cmdLower === "npx.cmd") {
        const npxCliPath = path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npx-cli.js");
        if (fs.existsSync(npxCliPath)) {
            return { cmd: process.execPath, args: [npxCliPath, ...commandArgs] };
        }
    }

    // 2. If command has path separators or ends with .exe, execute directly
    if (cmdLower.endsWith(".exe") || command.includes(path.sep) || command.includes("/")) {
        return { cmd: command, args: commandArgs };
    }

    // 3. Search PATH
    const pathDirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
    for (const dir of pathDirs) {
        const exePath = path.join(dir, `${command}.exe`);
        if (fs.existsSync(exePath)) {
            return { cmd: exePath, args: commandArgs };
        }
    }
    for (const dir of pathDirs) {
        const exactPath = path.join(dir, command);
        if (fs.existsSync(exactPath)) {
            const ext = path.extname(exactPath).toLowerCase();
            if (ext === ".cmd" || ext === ".bat") {
                const comspec = process.env.ComSpec || "cmd.exe";
                return { cmd: comspec, args: ["/d", "/s", "/c", exactPath, ...commandArgs] };
            }
            return { cmd: exactPath, args: commandArgs };
        }
        for (const ext of [".cmd", ".bat"]) {
            const scriptPath = path.join(dir, `${command}${ext}`);
            if (fs.existsSync(scriptPath)) {
                const comspec = process.env.ComSpec || "cmd.exe";
                return { cmd: comspec, args: ["/d", "/s", "/c", scriptPath, ...commandArgs] };
            }
        }
    }
    return { cmd: command, args: commandArgs };
}

export function parseArguments(argv) {
    const marker = argv.indexOf("--");
    if (marker === -1 || !argv[marker + 1]) {
        throw new Error("Usage: exec --root <path> --env-file <path> [--policy <path>] [--policy-hash <sha256>] [--broker-policy <path>] [--allow NAME,NAME] [--allow-raw-unmediated NAME,NAME] [--strict] [--canary] [--timeout <duration>] -- <command> [args]");
    }
    const options = argv.slice(0, marker);
    const value = (name) => {
        const index = options.indexOf(name);
        return index >= 0 ? options[index + 1] : "";
    };
    const values = (name) => options.flatMap((item, index) => item === name && options[index + 1] ? [options[index + 1]] : []);
    const names = (rawValues) => rawValues.flatMap((raw) => raw.split(",")).map((name) => name.trim()).filter(Boolean);
    const rawTimeout = value("--timeout");
    const rawPolicy = value("--policy");
    const rawPolicyHash = value("--policy-hash");
    return {
        root: path.resolve(value("--root") || process.cwd()),
        envFile: path.resolve(value("--env-file")),
        policyFile: rawPolicy ? path.resolve(rawPolicy) : undefined,
        policyHash: rawPolicyHash || undefined,
        brokerPolicyFiles: values("--broker-policy").map((file) => path.resolve(file)),
        allowNames: values("--allow").length ? names(values("--allow")) : undefined,
        allowRawUnmediated: names(values("--allow-raw-unmediated")),
        strict: options.includes("--strict"),
        canary: options.includes("--canary"),
        timeout: rawTimeout || undefined,
        timeoutMs: rawTimeout ? parseDuration(rawTimeout) : undefined,
        command: argv[marker + 1],
        commandArgs: argv.slice(marker + 2),
    };
}

function selectedCredentialBindings(envFile, allowNames = []) {
    const values = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const allow = new Set(allowNames.map((name) => String(name).toLowerCase()));
    return Object.entries(values).flatMap(([envName, value]) => {
        const reference = String(value || "");
        if (!reference.startsWith("secretRef:")) return [];
        const id = reference.slice("secretRef:".length);
        if (!allow.has(envName.toLowerCase()) && !allow.has(id.toLowerCase())) return [];
        return [{ envName, id }];
    });
}

function automaticBrokerPolicyFile(root, credentialId) {
    return path.join(root, ".hetzer", "brokers", `${credentialId}.json`);
}

function brokerEnvSuffix(credentialId) {
    return credentialId.toUpperCase().replace(/[^A-Z0-9_]/g, "_");
}

async function prepareExecutionEnvironment(effectiveOptions, {
    baseEnv,
    brokerFetchFn,
    brokerRandomBytes,
} = {}) {
    const requestedNames = effectiveOptions.allowNames || [];
    const bindings = selectedCredentialBindings(effectiveOptions.envFile, requestedNames);
    const requestedIds = new Set(bindings.map(({ id }) => id));
    const rawAllowed = new Set((effectiveOptions.allowRawUnmediated || []).map((id) => String(id).toLowerCase()));
    for (const id of rawAllowed) {
        if (![...bindings].some((binding) => binding.id.toLowerCase() === id)) {
            throw Object.assign(new Error(`Raw unmediated credential '${id}' must also be selected with --allow.`), {
                code: "ERR_RAW_UNMEDIATED_NOT_SELECTED",
            });
        }
    }

    const { loadBrokerPolicy, openHttpCredentialBroker } = await import("./http-broker.mjs");
    const policyByCredential = new Map();
    for (const policyFile of effectiveOptions.brokerPolicyFiles || []) {
        const policy = loadBrokerPolicy(policyFile);
        if (policyByCredential.has(policy.credentialId)) {
            throw new Error(`Multiple HTTP broker policies were supplied for credential '${policy.credentialId}'.`);
        }
        policyByCredential.set(policy.credentialId, { policy, policyFile });
    }
    for (const id of requestedIds) {
        if (policyByCredential.has(id)) continue;
        const policyFile = automaticBrokerPolicyFile(effectiveOptions.root, id);
        if (fs.existsSync(policyFile)) {
            const policy = loadBrokerPolicy(policyFile);
            if (policy.credentialId !== id) {
                throw new Error(`Automatic broker policy '${policyFile}' must reference secretRef:${id}.`);
            }
            policyByCredential.set(id, { policy, policyFile });
        }
    }
    for (const credentialId of policyByCredential.keys()) {
        if (!requestedIds.has(credentialId)) {
            throw new Error(`Broker policy credential '${credentialId}' must also be selected with --allow.`);
        }
        if (rawAllowed.has(credentialId.toLowerCase())) {
            throw new Error(`Credential '${credentialId}' cannot be both brokered and allowed as raw unmediated.`);
        }
    }

    const rawBindings = [];
    for (const binding of bindings) {
        if (policyByCredential.has(binding.id)) continue;
        if (rawAllowed.has(binding.id.toLowerCase())) {
            rawBindings.push(binding);
            continue;
        }
        const error = new Error(
            `Credential '${binding.id}' has no HTTP broker policy and raw injection is denied by default. `
            + `Configure '${automaticBrokerPolicyFile(effectiveOptions.root, binding.id)}' or explicitly use --allow-raw-unmediated ${binding.id}.`
        );
        error.code = "ERR_RAW_UNMEDIATED_FORBIDDEN";
        throw error;
    }

    const env = resolveSecretEnvironment({
        ...effectiveOptions,
        baseEnv,
        allowNames: rawBindings.map(({ envName }) => envName),
        action: "process.start",
    });
    delete env.HETZER_BROKER_URL;
    delete env.HETZER_BROKER_CAPABILITY;
    for (const name of Object.keys(env)) {
        if (/^HETZER_BROKER_(?:URL|CAPABILITY)_[A-Z0-9_]+$/.test(name)) delete env[name];
    }
    const secretsToRedact = collectResolvedSecrets(effectiveOptions.envFile, env);
    if (rawBindings.length) {
        const envValues = fs.existsSync(effectiveOptions.envFile)
            ? parseEnv(fs.readFileSync(effectiveOptions.envFile, "utf8"))
            : {};
        const masterKey = resolveMasterKey({ root: effectiveOptions.root, envValues, baseEnv });
        if (!masterKey || String(masterKey).startsWith("secretRef:")) {
            throw new Error("Grimoire master key is unavailable.");
        }
        const vault = new Grimoire({
            dbPath: resolveVaultPath(effectiveOptions.root) || path.join(effectiveOptions.root, "data", "hetzer-vault.db"),
            legacyFile: path.join(effectiveOptions.root, "data", "vault.json"),
            masterKey,
        });
        try {
            for (const { envName, id } of rawBindings) {
                const credential = vault.find(id);
                vault.recordAudit({
                    actor: "hetzer-cli",
                    action: "process.raw-unmediated",
                    targetId: credential?.projectId,
                    credentialId: id,
                    reason: "User explicitly allowed raw unmediated credential injection",
                    outcome: "allowed",
                    metadata: { envName, command: path.basename(effectiveOptions.command) },
                });
            }
        } finally {
            vault.close();
        }
    }
    const brokers = [];
    const claimedBrokerEnvNames = new Set();
    try {
        for (const [credentialId, descriptor] of policyByCredential) {
            if (!requestedIds.has(credentialId)) continue;
            for (const envName of [descriptor.policy.baseUrlEnv, descriptor.policy.tokenEnv]) {
                if (claimedBrokerEnvNames.has(envName)) {
                    throw new Error(`HTTP broker environment variable '${envName}' is claimed by multiple policies.`);
                }
                claimedBrokerEnvNames.add(envName);
            }
            const opened = await openHttpCredentialBroker({
                root: effectiveOptions.root,
                envFile: effectiveOptions.envFile,
                policy: descriptor.policy,
                baseEnv,
                fetchFn: brokerFetchFn,
                randomBytes: brokerRandomBytes,
            });
            const brokerUrl = `${opened.broker.url}${opened.policy.basePath === "/" ? "" : opened.policy.basePath}`;
            env[opened.policy.baseUrlEnv] = brokerUrl;
            env[opened.policy.tokenEnv] = opened.broker.capability;
            const suffix = brokerEnvSuffix(credentialId);
            env[`HETZER_BROKER_URL_${suffix}`] = brokerUrl;
            env[`HETZER_BROKER_CAPABILITY_${suffix}`] = opened.broker.capability;
            secretsToRedact.push(
                { id: credentialId, secret: opened.secret },
                { id: `broker-capability-${credentialId}`, secret: opened.broker.capability },
            );
            brokers.push(opened);
        }
        if (brokers.length === 1) {
            const opened = brokers[0];
            env.HETZER_BROKER_URL = `${opened.broker.url}${opened.policy.basePath === "/" ? "" : opened.policy.basePath}`;
            env.HETZER_BROKER_CAPABILITY = opened.broker.capability;
        }
        return { env, secretsToRedact, brokers };
    } catch (error) {
        await Promise.all(brokers.map(async (opened) => {
            await opened.broker.close();
            opened.secret = "";
        }));
        throw error;
    }
}

export async function executeProcess(options, {
    outStream = process.stdout,
    errStream = process.stderr,
    baseEnv = process.env,
    brokerFetchFn = globalThis.fetch,
    brokerRandomBytes,
} = {}) {
    let effectiveOptions = { ...options };
    if (effectiveOptions.policyFile) {
        const loadedPolicy = loadExecPolicy(effectiveOptions.policyFile, effectiveOptions.root, {
            expectedHash: effectiveOptions.policyHash,
        });
        effectiveOptions = applyExecPolicy(loadedPolicy, effectiveOptions);

        try {
            const envValues = fs.existsSync(effectiveOptions.envFile)
                ? parseEnv(fs.readFileSync(effectiveOptions.envFile, "utf8"))
                : {};
            const masterKey = resolveMasterKey({ root: effectiveOptions.root, envValues, baseEnv });
            if (masterKey && !String(masterKey).startsWith("secretRef:")) {
                const vault = new Grimoire({
                    dbPath: resolveVaultPath(effectiveOptions.root) || path.join(effectiveOptions.root, "data", "hetzer-vault.db"),
                    legacyFile: path.join(effectiveOptions.root, "data", "vault.json"),
                    masterKey,
                });
                vault.recordAudit({
                    actor: "hetzer-cli",
                    action: "policy.loaded",
                    targetId: "execution-policy",
                    credentialId: path.basename(loadedPolicy.policyFile),
                    reason: "Execution policy validated and loaded",
                    outcome: "allowed",
                    metadata: { policyHash: loadedPolicy.policyHash, command: path.basename(effectiveOptions.command) },
                });
                vault.close();
            }
        } catch {
            // Fail soft on audit write
        }
    } else if (effectiveOptions.policy) {
        effectiveOptions = applyExecPolicy(effectiveOptions.policy, effectiveOptions);
    }

    assertNoShellMetacharacters(effectiveOptions.command, effectiveOptions.commandArgs);

    if (isReflectionCommand(effectiveOptions.command, effectiveOptions.commandArgs)) {
        const fullCmd = [effectiveOptions.command, ...effectiveOptions.commandArgs].join(" ");
        const err = new Error(
            `Security violation: Command '${fullCmd}' is blocked by the credential-safety policy.\n` +
            "Environment reflection commands (printenv, env, export, inline dumps) are forbidden in 'hetzer exec' to prevent secret leakage into agent context or terminal logs."
        );
        err.code = "ERR_REFLECTION_BLOCKED";
        throw err;
    }
    if (effectiveOptions.strict && effectiveOptions.allowNames === undefined) {
        throw new Error(
            "Security violation: Strict scoping enabled (--strict).\n"
            + "You must explicitly specify which credentials may be resolved via '--allow <id|env-var>'.\n"
            + "No ungranted secrets are accessible in strict mode."
        );
    }

    const { env, secretsToRedact, brokers } = await prepareExecutionEnvironment(
        effectiveOptions,
        { baseEnv, brokerFetchFn, brokerRandomBytes },
    );
    try {
        const { cmd: spawnCmd, args: spawnArgs } = resolveCommandForSpawn(
            effectiveOptions.command,
            effectiveOptions.commandArgs
        );
        const child = spawn(spawnCmd, spawnArgs, {
            stdio: ["inherit", "pipe", "pipe"],
            env,
            windowsHide: true,
            shell: false,
        });
        const timeoutMs = effectiveOptions.timeoutMs ?? (effectiveOptions.timeout ? parseDuration(effectiveOptions.timeout) : undefined);
        return await pipeSanitizedChild(child, secretsToRedact, {
            outStream,
            errStream,
            root: effectiveOptions.root,
            timeoutMs,
        });
    } finally {
        await Promise.all(brokers.map(async (opened) => {
            await opened.broker.close();
            opened.secret = "";
        }));
    }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const options = parseArguments(process.argv.slice(2));
        executeProcess(options)
            .then((result) => {
                process.exitCode = result.status;
            })
            .catch((error) => {
                process.stderr.write(`Hetzer process failed: ${error.message}\n`);
                process.exitCode = error.exitCode || 1;
            });
    } catch (error) {
        process.stderr.write(`Hetzer process failed: ${error.message}\n`);
        process.exitCode = error.exitCode || 1;
    }
}
