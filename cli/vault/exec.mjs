#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { resolveSecretEnvironment } from "./secret-env.mjs";
import { MAX_DETECTION_MATCH_LENGTH, scanText } from "./sniffer.mjs";

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
    const longestSecret = secretsToRedact.reduce((max, item) => Math.max(max, String(item.secret || "").length), 0);
    const retention = Math.max(128, longestSecret * 2);
    let pending = "";

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
            pending += Buffer.isBuffer(chunk) ? decoder.write(chunk) : String(chunk);
            return drain(false);
        },
        end() {
            pending += decoder.end();
            return drain(true);
        },
    };
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
                `Security violation: Command '${fullCmd}' is blocked under Zero-Plaintext policy.\n` +
                "Environment reflection commands (printenv, env, export, inline dumps) are forbidden in 'hetzer exec' to prevent secret leakage into agent context or terminal logs."
            );
            err.code = "ERR_REFLECTION_BLOCKED";
            return reject(err);
        }

        const env = resolveSecretEnvironment({ ...options, action: "process.start" });

        // Collect secrets that were injected so we can redact them in real-time from output stream
        const secretsToRedact = [];
        if (fs.existsSync(options.envFile)) {
            const rawValues = parseEnv(fs.readFileSync(options.envFile, "utf8"));
            for (const [key, rawVal] of Object.entries(rawValues)) {
                if (String(rawVal).startsWith("secretRef:")) {
                    const id = rawVal.slice("secretRef:".length);
                    const resolvedSecret = env[key];
                    if (resolvedSecret && typeof resolvedSecret === "string" && !resolvedSecret.startsWith("secretRef:")) {
                        secretsToRedact.push({ id, secret: resolvedSecret });
                    }
                }
            }
        }

        const targetCmd = (process.platform === "win32" && options.command.includes(" ") && !options.command.startsWith('"'))
            ? `"${options.command}"`
            : options.command;

        const child = spawn(targetCmd, options.commandArgs, {
            stdio: ["inherit", "pipe", "pipe"],
            env,
            windowsHide: true,
            shell: process.platform === "win32",
        });

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

        child.on("error", (error) => {
            reject(error);
        });

        child.on("close", (code) => {
            const finalStdout = stdoutSanitizer.end();
            const finalStderr = stderrSanitizer.end();
            if (finalStdout) outStream.write(finalStdout);
            if (finalStderr) errStream.write(finalStderr);
            resolve({ status: code ?? 0 });
        });
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
