#!/usr/bin/env node

import "../core/suppress-warnings.mjs";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
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
    if (!envFile || !fs.existsSync(envFile)) return [];
    const rawValues = parseEnv(fs.readFileSync(envFile, "utf8"));
    const secrets = [];
    for (const [name, rawValue] of Object.entries(rawValues)) {
        if (!String(rawValue).startsWith("secretRef:")) continue;
        const secret = env[name];
        if (!secret || typeof secret !== "string" || secret.startsWith("secretRef:")) continue;
        secrets.push({ id: String(rawValue).slice("secretRef:".length), secret });
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

export function createStreamSanitizer(secretsToRedact = []) {
    const decoder = new StringDecoder("utf8");
    const terminalControls = createTerminalControlFilter();
    const structuredSecrets = createStructuredSecretFilter();
    const lexicalSecrets = createLexicalSecretFilter(secretsToRedact);
    const longestSecret = secretsToRedact.reduce((max, item) => Math.max(max, String(item.secret || "").length), 0);
    const retention = Math.max(128, longestSecret * 2);
    let pending = "";

    const preprocess = (text) => {
        const normalized = terminalControls.write(text);
        const structured = structuredSecrets.write(normalized);
        return lexicalSecrets.write(structured);
    };

    const drain = (final = false) => {
        if (final) {
            const output = sanitizeStreamOutput(pending, secretsToRedact);
            pending = "";
            return output;
        }
        if (pending.length <= retention) return "";
        const proposedBoundary = pending.length - retention;
        const boundary = crossingMatchStart(pending, proposedBoundary, secretsToRedact);
        if (boundary <= 0) return "";
        const output = sanitizeStreamOutput(pending.slice(0, boundary), secretsToRedact);
        pending = pending.slice(boundary);
        return output;
    };

    return {
        write(chunk) {
            const decoded = Buffer.isBuffer(chunk) ? decoder.write(chunk) : String(chunk);
            pending += preprocess(decoded);
            return drain(false);
        },
        end() {
            pending += preprocess(decoder.end());
            pending += lexicalSecrets.write(structuredSecrets.write(terminalControls.end()));
            pending += lexicalSecrets.write(structuredSecrets.end());
            pending += lexicalSecrets.end();
            return drain(true);
        },
    };
}

export function pipeSanitizedChild(child, secretsToRedact = [], {
    outStream = process.stdout,
    errStream = process.stderr,
} = {}) {
    return new Promise((resolve, reject) => {
        const stdoutSanitizer = createStreamSanitizer(secretsToRedact);
        const stderrSanitizer = createStreamSanitizer(secretsToRedact);

        child.stdout.on("data", (chunk) => {
            const sanitized = stdoutSanitizer.write(chunk);
            if (sanitized) outStream.write(sanitized);
        });
        child.stderr.on("data", (chunk) => {
            const sanitized = stderrSanitizer.write(chunk);
            if (sanitized) errStream.write(sanitized);
        });
        child.once("error", reject);
        child.once("close", (code) => {
            const finalStdout = stdoutSanitizer.end();
            const finalStderr = stderrSanitizer.end();
            if (finalStdout) outStream.write(finalStdout);
            if (finalStderr) errStream.write(finalStderr);
            resolve({ status: code ?? 1 });
        });
    });
}

export function parseArguments(argv) {
    const marker = argv.indexOf("--");
    if (marker === -1 || !argv[marker + 1]) {
        throw new Error("Usage: exec --root <path> --env-file <path> [--allow NAME,NAME] [--strict] -- <command> [args]");
    }
    const options = argv.slice(0, marker);
    const value = (name) => {
        const index = options.indexOf(name);
        return index >= 0 ? options[index + 1] : "";
    };
    return {
        root: path.resolve(value("--root") || process.cwd()),
        envFile: path.resolve(value("--env-file")),
        allowNames: value("--allow") ? value("--allow").split(",").map((name) => name.trim()).filter(Boolean) : undefined,
        strict: options.includes("--strict"),
        command: argv[marker + 1],
        commandArgs: argv.slice(marker + 2),
    };
}

export function executeProcess(options, { outStream = process.stdout, errStream = process.stderr } = {}) {
    return new Promise((resolve, reject) => {
        if (isReflectionCommand(options.command, options.commandArgs)) {
            const fullCmd = [options.command, ...options.commandArgs].join(" ");
            const err = new Error(
                `Security violation: Command '${fullCmd}' is blocked by the credential-safety policy.\n` +
                "Environment reflection commands (printenv, env, export, inline dumps) are forbidden in 'hetzer exec' to prevent secret leakage into agent context or terminal logs."
            );
            err.code = "ERR_REFLECTION_BLOCKED";
            return reject(err);
        }

        const env = resolveSecretEnvironment({ ...options, action: "process.start" });

        const secretsToRedact = collectResolvedSecrets(options.envFile, env);

        const targetCmd = (process.platform === "win32" && options.command.includes(" ") && !options.command.startsWith('"'))
            ? `"${options.command}"`
            : options.command;

        const child = spawn(targetCmd, options.commandArgs, {
            stdio: ["inherit", "pipe", "pipe"],
            env,
            windowsHide: true,
            shell: process.platform === "win32",
        });

        pipeSanitizedChild(child, secretsToRedact, { outStream, errStream }).then(resolve, reject);
    });
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
