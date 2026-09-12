import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { parseDuration } from "./exec.mjs";

export const SHELL_METACHAR_PATTERN = /[&|;<>`$\n\r%^\0]/;

export function containsShellMetacharacters(str) {
    if (typeof str !== "string") return false;
    return SHELL_METACHAR_PATTERN.test(str);
}

export function assertNoShellMetacharacters(command, commandArgs = []) {
    const invoked = [command, ...(commandArgs || [])];
    for (const token of invoked) {
        if (typeof token === "string" && containsShellMetacharacters(token)) {
            const err = new Error(
                `Security violation: Command argument contains forbidden shell metacharacters: ${JSON.stringify(token)}.\n` +
                "Command chaining (&, &&, |, ||, ;), redirection (<, >), subshells, and shell variable expansions ($, %, `) are forbidden."
            );
            err.code = "ERR_SHELL_METACHARACTERS_FORBIDDEN";
            err.exitCode = 1;
            throw err;
        }
    }
}

export function parseArgvTokens(commandDef) {
    if (Array.isArray(commandDef)) {
        return commandDef.map((s) => String(s).trim()).filter(Boolean);
    }
    if (typeof commandDef !== "string") return [];
    const str = commandDef.trim();
    if (!str) return [];

    const tokens = [];
    let current = "";
    let inQuote = null;

    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        if (inQuote) {
            if (char === inQuote) {
                inQuote = null;
            } else {
                current += char;
            }
        } else if (char === '"' || char === "'") {
            inQuote = char;
        } else if (/\s/.test(char)) {
            if (current.length > 0) {
                tokens.push(current);
                current = "";
            }
        } else {
            current += char;
        }
    }
    if (inQuote) {
        throw new Error(`Malformed command string with unclosed quote: ${JSON.stringify(str)}`);
    }
    if (current.length > 0) {
        tokens.push(current);
    }
    return tokens;
}

export function validateExecPolicy(policy) {
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
        throw new Error("Execution policy must be a JSON object.");
    }

    const { version, name, allowedCommands, allowedCredentials, allowRawUnmediated, strict, canary, maxTimeout, integrity } = policy;

    if (version !== undefined && version !== 1 && version !== "1.0") {
        throw new Error(`Unsupported execution policy version: ${version}. Expected 1 or "1.0".`);
    }

    if (name !== undefined && (typeof name !== "string" || !name.trim())) {
        throw new Error("Execution policy 'name' must be a non-empty string when provided.");
    }

    if (allowedCommands !== undefined) {
        if (!Array.isArray(allowedCommands) || allowedCommands.length === 0) {
            throw new Error("Execution policy 'allowedCommands' must be a non-empty array of command strings or token arrays when specified.");
        }
        for (const cmd of allowedCommands) {
            let tokens;
            if (Array.isArray(cmd)) {
                if (cmd.length === 0 || cmd.some((token) => typeof token !== "string" || !token.trim())) {
                    throw new Error(`Invalid command token array in allowedCommands: ${JSON.stringify(cmd)}. Expected non-empty string tokens.`);
                }
                tokens = cmd;
            } else if (typeof cmd === "string" && cmd.trim()) {
                tokens = parseArgvTokens(cmd);
            } else {
                throw new Error(`Invalid command in allowedCommands: ${JSON.stringify(cmd)}. Expected non-empty string or token array.`);
            }
            for (const token of tokens) {
                if (containsShellMetacharacters(token)) {
                    throw new Error(`Invalid command rule in allowedCommands: ${JSON.stringify(cmd)} contains shell metacharacters.`);
                }
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

    if (allowRawUnmediated !== undefined) {
        if (!Array.isArray(allowRawUnmediated)) {
            throw new Error("Execution policy 'allowRawUnmediated' must be an array of credential names when specified.");
        }
        for (const cred of allowRawUnmediated) {
            if (typeof cred !== "string" || !cred.trim()) {
                throw new Error(`Invalid credential name in allowRawUnmediated: ${JSON.stringify(cred)}.`);
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
        allowedCommands: allowedCommands ? allowedCommands.map((c) => Array.isArray(c) ? c.map((t) => t.trim()) : c.trim()) : undefined,
        allowedCredentials: allowedCredentials ? allowedCredentials.map((c) => c.trim()) : undefined,
        allowRawUnmediated: allowRawUnmediated ? allowRawUnmediated.map((c) => c.trim()) : [],
        strict: Boolean(strict),
        canary: Boolean(canary),
        maxTimeout: maxTimeout || undefined,
        maxTimeoutMs,
        integrity: integrity && typeof integrity === "object" ? { ...integrity } : undefined,
    };
}

export function canonicalizeJson(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return "[" + value.map((item) => item === undefined ? "null" : canonicalizeJson(item)).join(",") + "]";
    }
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return "{" + keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(value[k])}`).join(",") + "}";
}

export function computeEmbeddedPolicyHash(parsedPolicy) {
    if (!parsedPolicy || typeof parsedPolicy !== "object") {
        throw new Error("Policy object required to compute embedded hash.");
    }
    const { integrity, ...rest } = parsedPolicy;
    return crypto.createHash("sha256").update(canonicalizeJson(rest)).digest("hex");
}

export function loadExecPolicy(policyFile, root = process.cwd(), { expectedHash } = {}) {
    if (!policyFile || typeof policyFile !== "string") {
        throw new Error("Policy file path must be provided.");
    }
    const resolvedPath = path.isAbsolute(policyFile) ? policyFile : path.resolve(root, policyFile);
    if (!fs.existsSync(resolvedPath)) {
        throw new Error(`Execution policy file not found: '${resolvedPath}'`);
    }

    const lstat = fs.lstatSync(resolvedPath);
    if (lstat.isSymbolicLink()) {
        throw new Error(`Execution policy path cannot be a symbolic link: '${resolvedPath}'`);
    }
    if (!lstat.isFile()) {
        throw new Error(`Execution policy path must be a regular file: '${resolvedPath}'`);
    }

    // POSIX trust root verification: verify policy file permissions and ownership
    if (process.platform !== "win32") {
        const mode = lstat.mode;
        if ((mode & 0o002) !== 0) {
            throw new Error(`Execution policy file '${resolvedPath}' is insecure: world-writable.`);
        }
        if ((mode & 0o020) !== 0) {
            throw new Error(`Execution policy file '${resolvedPath}' is insecure: group-writable.`);
        }
        if (typeof process.getuid === "function") {
            const uid = process.getuid();
            if (lstat.uid !== uid && lstat.uid !== 0) {
                throw new Error(`Execution policy file '${resolvedPath}' is not owned by the current user or root.`);
            }
        }
    }

    const rawContent = fs.readFileSync(resolvedPath, "utf8");
    const policyHash = crypto.createHash("sha256").update(rawContent).digest("hex");

    let parsed;
    try {
        parsed = JSON.parse(rawContent);
    } catch (err) {
        throw new Error(`Failed to parse execution policy JSON in '${resolvedPath}': ${err.message}`);
    }

    const validated = validateExecPolicy(parsed);

    // 1. Detached hash verification (via option or detached .sha256 file)
    let detachedExpected = expectedHash;
    if (!detachedExpected) {
        const detachedFile = `${resolvedPath}.sha256`;
        if (fs.existsSync(detachedFile)) {
            try {
                const detachedContent = fs.readFileSync(detachedFile, "utf8").trim();
                const match = detachedContent.match(/^[a-f0-9]{64}/i);
                if (match) detachedExpected = match[0];
            } catch {
                // ignore unreadable detached file
            }
        }
    }

    if (detachedExpected && detachedExpected.toLowerCase() !== policyHash.toLowerCase()) {
        const err = new Error(
            `Policy detached integrity verification failed for '${resolvedPath}'.\n` +
            `Expected SHA-256: ${detachedExpected}\n` +
            `Actual SHA-256:   ${policyHash}`
        );
        err.code = "ERR_POLICY_INTEGRITY_FAILED";
        err.exitCode = 1;
        throw err;
    }

    // 2. Embedded integrity verification (excluding integrity field itself)
    let embeddedHash;
    if (parsed.integrity?.sha256) {
        embeddedHash = computeEmbeddedPolicyHash(parsed);
        if (parsed.integrity.sha256.toLowerCase() !== embeddedHash.toLowerCase()) {
            const err = new Error(
                `Policy embedded integrity verification failed for '${resolvedPath}'.\n` +
                `Expected SHA-256: ${parsed.integrity.sha256}\n` +
                `Actual SHA-256:   ${embeddedHash}`
            );
            err.code = "ERR_POLICY_INTEGRITY_FAILED";
            err.exitCode = 1;
            throw err;
        }
    }

    return {
        ...validated,
        policyFile: resolvedPath,
        policyHash,
        embeddedHash,
    };
}

function matchBinary(ruleBin, invokedBin) {
    if (ruleBin === invokedBin) return true;
    const ruleBase = path.basename(ruleBin).toLowerCase();
    const invokedBase = path.basename(invokedBin).toLowerCase();
    if (ruleBase === invokedBase) return true;
    if (process.platform === "win32") {
        const strippedRule = ruleBase.replace(/\.(exe|cmd|bat)$/i, "");
        const strippedInvoked = invokedBase.replace(/\.(exe|cmd|bat)$/i, "");
        if (strippedRule === strippedInvoked) return true;
    }
    return false;
}

export function matchesAllowedCommand(command, commandArgs = [], allowedCommands = []) {
    if (!allowedCommands || allowedCommands.length === 0) return true;

    // Fail closed if any token contains shell metacharacters
    const invoked = [command, ...(commandArgs || [])];
    for (const token of invoked) {
        if (containsShellMetacharacters(token)) {
            return false;
        }
    }

    return allowedCommands.some((allowedRule) => {
        let ruleTokens;
        try {
            ruleTokens = parseArgvTokens(allowedRule);
        } catch {
            return false;
        }
        if (ruleTokens.length === 0) return false;

        // Binary matching (ruleTokens[0] vs invoked[0])
        if (!matchBinary(ruleTokens[0], invoked[0])) {
            return false;
        }

        const ruleArgs = ruleTokens.slice(1);
        const invokedArgs = invoked.slice(1);

        // Greedy wildcard '**' match at the end
        if (ruleArgs.length > 0 && ruleArgs[ruleArgs.length - 1] === "**") {
            const prefixRuleArgs = ruleArgs.slice(0, -1);
            if (invokedArgs.length < prefixRuleArgs.length) return false;
            for (let i = 0; i < prefixRuleArgs.length; i++) {
                if (prefixRuleArgs[i] !== "*" && prefixRuleArgs[i] !== invokedArgs[i]) {
                    return false;
                }
            }
            return true;
        }

        // Exact argument count required (no prefix matching!)
        if (ruleArgs.length !== invokedArgs.length) {
            return false;
        }

        // Exact positional argument matching
        for (let i = 0; i < ruleArgs.length; i++) {
            if (ruleArgs[i] === "*") continue; // single wildcard token
            if (ruleArgs[i] !== invokedArgs[i]) return false;
        }

        return true;
    });
}

export function applyExecPolicy(policy, options) {
    if (!policy) return options;

    const validated = validateExecPolicy(policy);
    const result = { ...options };

    // Reject shell metacharacters in command or commandArgs
    assertNoShellMetacharacters(result.command, result.commandArgs);

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

    if (result.allowRawUnmediated?.length) {
        const permittedRaw = new Set(validated.allowRawUnmediated.map((name) => name.toLowerCase()));
        const forbiddenRaw = result.allowRawUnmediated.filter((name) => !permittedRaw.has(String(name).toLowerCase()));
        if (forbiddenRaw.length > 0) {
            const err = new Error(
                `Policy violation [${validated.name}]: Raw unmediated credential(s) ${JSON.stringify(forbiddenRaw)} are not permitted.\n`
                + `Policy permits raw use only for: ${JSON.stringify(validated.allowRawUnmediated)}`
            );
            err.code = "ERR_POLICY_RAW_UNMEDIATED_FORBIDDEN";
            err.exitCode = 1;
            throw err;
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
