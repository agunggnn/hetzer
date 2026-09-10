import fs from "node:fs";
import path from "node:path";
import { parseDuration } from "./exec.mjs";

export function validateExecPolicy(policy) {
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
        throw new Error("Execution policy must be a JSON object.");
    }

    const { version, name, allowedCommands, allowedCredentials, strict, canary, maxTimeout } = policy;

    if (version !== undefined && version !== 1 && version !== "1.0") {
        throw new Error(`Unsupported execution policy version: ${version}. Expected 1 or "1.0".`);
    }

    if (name !== undefined && (typeof name !== "string" || !name.trim())) {
        throw new Error("Execution policy 'name' must be a non-empty string when provided.");
    }

    if (allowedCommands !== undefined) {
        if (!Array.isArray(allowedCommands) || allowedCommands.length === 0) {
            throw new Error("Execution policy 'allowedCommands' must be a non-empty array of command strings when specified.");
        }
        for (const cmd of allowedCommands) {
            if (typeof cmd !== "string" || !cmd.trim()) {
                throw new Error(`Invalid command in allowedCommands: ${JSON.stringify(cmd)}. Expected non-empty string.`);
            }
        }
    }

    if (allowedCredentials !== undefined) {
        if (!Array.isArray(allowedCredentials)) {
            throw new Error("Execution policy 'allowedCredentials' must be an array of credential names when specified.");
        }
        for (const cred of allowedCredentials) {
            if (typeof cred !== "string" || !cred.trim()) {
                throw new Error(`Invalid credential name in allowedCredentials: ${JSON.stringify(cred)}.`);
            }
        }
    }

    if (strict !== undefined && typeof strict !== "boolean") {
        throw new Error("Execution policy 'strict' must be a boolean.");
    }

    if (canary !== undefined && typeof canary !== "boolean") {
        throw new Error("Execution policy 'canary' must be a boolean.");
    }

    let maxTimeoutMs;
    if (maxTimeout !== undefined) {
        maxTimeoutMs = parseDuration(maxTimeout);
    }

    return {
        version: version || 1,
        name: name?.trim() || "default-exec-policy",
        allowedCommands: allowedCommands ? allowedCommands.map((c) => c.trim()) : undefined,
        allowedCredentials: allowedCredentials ? allowedCredentials.map((c) => c.trim()) : undefined,
        strict: Boolean(strict),
        canary: Boolean(canary),
        maxTimeout: maxTimeout || undefined,
        maxTimeoutMs,
    };
}

export function loadExecPolicy(policyFile, root = process.cwd()) {
    if (!policyFile || typeof policyFile !== "string") {
        throw new Error("Policy file path must be provided.");
    }
    const resolvedPath = path.isAbsolute(policyFile) ? policyFile : path.resolve(root, policyFile);
    if (!fs.existsSync(resolvedPath)) {
        throw new Error(`Execution policy file not found: '${resolvedPath}'`);
    }
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
    } catch (err) {
        throw new Error(`Failed to parse execution policy JSON in '${resolvedPath}': ${err.message}`);
    }
    return validateExecPolicy(parsed);
}

export function matchesAllowedCommand(command, commandArgs = [], allowedCommands = []) {
    if (!allowedCommands || allowedCommands.length === 0) return true;
    const fullCommand = [command, ...commandArgs].join(" ").trim();
    const commandBase = path.basename(command).toLowerCase();

    return allowedCommands.some((pattern) => {
        const p = pattern.trim();
        if (fullCommand === p || fullCommand.startsWith(p + " ")) return true;
        if (!p.includes(" ")) {
            if (command === p || commandBase === p.toLowerCase() || commandBase === `${p.toLowerCase()}.exe`) {
                return true;
            }
        }
        return false;
    });
}

export function applyExecPolicy(policy, options) {
    if (!policy) return options;

    const validated = validateExecPolicy(policy);
    const result = { ...options };

    if (validated.allowedCommands && validated.allowedCommands.length > 0) {
        if (!matchesAllowedCommand(result.command, result.commandArgs, validated.allowedCommands)) {
            const invoked = [result.command, ...(result.commandArgs || [])].join(" ");
            const err = new Error(
                `Policy violation [${validated.name}]: Command '${invoked}' is not permitted by allowedCommands.\n` +
                `Permitted command patterns: ${JSON.stringify(validated.allowedCommands)}`
            );
            err.code = "ERR_POLICY_COMMAND_FORBIDDEN";
            err.exitCode = 1;
            throw err;
        }
    }

    if (validated.allowedCredentials !== undefined) {
        if (result.allowNames && result.allowNames.length > 0) {
            const forbidden = result.allowNames.filter((name) => !validated.allowedCredentials.includes(name));
            if (forbidden.length > 0) {
                const err = new Error(
                    `Policy violation [${validated.name}]: Requested credential(s) ${JSON.stringify(forbidden)} are not permitted.\n` +
                    `Policy permits only: ${JSON.stringify(validated.allowedCredentials)}`
                );
                err.code = "ERR_POLICY_CREDENTIAL_FORBIDDEN";
                err.exitCode = 1;
                throw err;
            }
        } else {
            result.allowNames = [...validated.allowedCredentials];
        }
    }

    if (validated.strict) {
        result.strict = true;
    }

    if (validated.canary) {
        result.canary = true;
    }

    if (validated.maxTimeoutMs) {
        if (result.timeoutMs) {
            if (result.timeoutMs > validated.maxTimeoutMs) {
                const err = new Error(
                    `Policy violation [${validated.name}]: Requested timeout (${result.timeoutMs}ms) exceeds policy maximum (${validated.maxTimeoutMs}ms).`
                );
                err.code = "ERR_POLICY_TIMEOUT_EXCEEDED";
                err.exitCode = 1;
                throw err;
            }
        } else {
            result.timeout = validated.maxTimeout;
            result.timeoutMs = validated.maxTimeoutMs;
        }
    }

    return result;
}
