import fs from "node:fs";
import path from "node:path";

import { isCanaryCredential, triggerCanaryAlert } from "../cli/vault/canary.mjs";
import { executeProcess } from "../cli/vault/exec.mjs";
import { Grimoire, parseSecretRef, resolveVaultPath } from "../cli/vault/hetzer-vault.mjs";
import {
    HetzerSdkError,
    invalidCredentialId,
    invalidCredentialReference,
    invalidSdkConfig,
    SDK_ERROR_CODES,
} from "./errors.mjs";
import { toSafeCredentialList, toSafeCredentialMetadata } from "./metadata.mjs";

const CREDENTIAL_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const ACTION_PATTERN = /^[a-z0-9]+(?:[.:_/-][a-z0-9]+)*$/;
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

function resolveRoot(root) {
    const candidate = root === undefined ? process.cwd() : root;
    if (typeof candidate !== "string" || !candidate.trim()) {
        throw invalidSdkConfig("root must be a non-empty directory path.");
    }
    const resolved = path.resolve(candidate);
    let stats;
    try {
        stats = fs.statSync(resolved);
    } catch (cause) {
        throw invalidSdkConfig("root must point to an existing directory.", { cause });
    }
    if (!stats.isDirectory()) throw invalidSdkConfig("root must point to an existing directory.");
    return resolved;
}

function resolveDatabasePath(root, vaultPath) {
    if (vaultPath === ":memory:") return vaultPath;
    if (vaultPath !== undefined && (typeof vaultPath !== "string" || !vaultPath.trim())) {
        throw invalidSdkConfig("vaultPath must be a non-empty path or ':memory:'.");
    }
    const configured = vaultPath || resolveVaultPath(root);
    return configured
        ? (path.isAbsolute(configured) ? configured : path.resolve(root, configured))
        : path.join(root, "data", "hetzer-vault.db");
}

function validateCredentialId(id) {
    if (typeof id !== "string" || !CREDENTIAL_ID_PATTERN.test(id)) {
        throw invalidCredentialId();
    }
    return id;
}

function normalizeReference(reference) {
    if (typeof reference !== "string" || !reference.trim()) {
        throw invalidCredentialReference();
    }
    const value = reference.trim();
    let id;
    try {
        id = value.startsWith("secretRef:") ? parseSecretRef(value) : validateCredentialId(value);
    } catch (cause) {
        throw invalidCredentialReference("credential reference is not valid.", { cause });
    }
    return { id, reference: `secretRef:${id}` };
}

function normalizeValidationContext(context) {
    if (context === undefined) return { targetId: "", action: "" };
    if (!context || typeof context !== "object" || Array.isArray(context)) {
        throw invalidSdkConfig("credential validation context must be an object.");
    }
    const targetId = context.targetId === undefined ? "" : String(context.targetId).trim().toLowerCase();
    const action = context.action === undefined ? "" : String(context.action).trim().toLowerCase();
    if (targetId && !CREDENTIAL_ID_PATTERN.test(targetId)) {
        throw invalidSdkConfig("credential validation targetId is invalid.");
    }
    if (action && !ACTION_PATTERN.test(action)) {
        throw invalidSdkConfig("credential validation action is invalid.");
    }
    return { targetId, action };
}

function resolveOptionalPath(root, value, name) {
    if (value === undefined) return undefined;
    if (typeof value !== "string" || !value.trim()) {
        throw invalidSdkConfig(`${name} must be a non-empty path.`);
    }
    return path.isAbsolute(value) ? value : path.resolve(root, value);
}

function normalizeAllowNames(value, name) {
    if (value === undefined) return [];
    if (!Array.isArray(value)) throw invalidSdkConfig(`${name} must be an array.`);
    return value.map((item) => {
        if (typeof item !== "string" || !item.trim()) {
            throw invalidSdkConfig(`${name} must contain non-empty strings.`);
        }
        const candidate = item.trim();
        if (candidate.startsWith("secretRef:")) return normalizeReference(candidate).id;
        if (CREDENTIAL_ID_PATTERN.test(candidate) || ENV_NAME_PATTERN.test(candidate)) return candidate;
        throw invalidSdkConfig(`${name} contains an invalid credential id or environment name.`);
    });
}

function assertWritableStream(stream, name) {
    if (!stream || typeof stream.write !== "function") {
        throw invalidSdkConfig(`${name} must expose a write(chunk) function.`);
    }
    return stream;
}

function wrapExecutionError(error) {
    if (error instanceof HetzerSdkError) return error;
    const code = typeof error?.code === "string" && /^ERR_[A-Z0-9_]+$/.test(error.code)
        ? error.code
        : "ERR_SDK_EXECUTION_FAILED";
    const wrapped = new HetzerSdkError(code, `Hetzer execution failed (${code}).`);
    if (Number.isInteger(error?.exitCode)) wrapped.exitCode = error.exitCode;
    return wrapped;
}

/**
 * Create the public, metadata-first Hetzer SDK client.
 *
 * Construction is lazy: it validates paths but does not open or decrypt the
 * vault. Secret resolution and scoped execution will be added behind this
 * facade in later SDK PRs.
 */
export function createHetzer(options = {}) {
    if (!options || typeof options !== "object" || Array.isArray(options)) {
        throw invalidSdkConfig("options must be an object.");
    }

    const root = resolveRoot(options.root);
    const dbPath = resolveDatabasePath(root, options.vaultPath);
    let vault = null;

    const openVault = () => {
        if (!vault) {
            // Metadata operations do not require a master key and never decrypt
            // credential values. Resolution belongs to a later capability API.
            vault = new Grimoire({ dbPath });
        }
        return vault;
    };

    const client = {
        kind: "hetzer-sdk",
        apiVersion: "experimental-1",
        credentials: {
            list() {
                return toSafeCredentialList(openVault().list());
            },
            metadata(id) {
                return toSafeCredentialMetadata(openVault().find(validateCredentialId(id)));
            },
            validate(reference, context) {
                const normalized = normalizeReference(reference);
                const validation = normalizeValidationContext(context);
                if (isCanaryCredential(normalized.id)) {
                    triggerCanaryAlert({
                        id: normalized.id,
                        actor: options.actor || "hetzer-sdk",
                        action: "sdk.credentials.validate",
                        root,
                    });
                }

                const metadata = toSafeCredentialMetadata(openVault().find(normalized.id));
                if (!metadata) {
                    throw new HetzerSdkError(
                        SDK_ERROR_CODES.NOT_FOUND,
                        `Credential '${normalized.id}' was not found.`,
                    );
                }
                if (validation.targetId && metadata.projectId !== validation.targetId) {
                    throw new HetzerSdkError(
                        SDK_ERROR_CODES.TARGET_MISMATCH,
                        `Credential '${normalized.id}' is not authorized for the requested target.`,
                    );
                }
                if (
                    metadata.allowedActions.length
                    && (!validation.action || !metadata.allowedActions.includes(validation.action))
                ) {
                    throw new HetzerSdkError(
                        SDK_ERROR_CODES.NOT_ALLOWED,
                        `Credential '${normalized.id}' is not authorized for the requested action.`,
                    );
                }
                if (metadata.expiresAt && Date.parse(metadata.expiresAt) <= Date.now()) {
                    throw new HetzerSdkError(
                        SDK_ERROR_CODES.EXPIRED,
                        `Credential '${normalized.id}' is expired.`,
                    );
                }
                return Object.freeze({
                    valid: true,
                    reference: normalized.reference,
                    id: normalized.id,
                    targetId: metadata.projectId,
                    action: validation.action,
                    metadata,
                });
            },
        },
        execution: {
            async run(executionOptions = {}) {
                if (!executionOptions || typeof executionOptions !== "object" || Array.isArray(executionOptions)) {
                    throw invalidSdkConfig("execution options must be an object.");
                }
                const command = executionOptions.command;
                if (typeof command !== "string" || !command.trim()) {
                    throw invalidSdkConfig("execution command must be a non-empty string.");
                }
                const args = executionOptions.args === undefined ? [] : executionOptions.args;
                if (!Array.isArray(args) || args.some((arg) => typeof arg !== "string")) {
                    throw invalidSdkConfig("execution args must be an array of strings.");
                }

                const allowNames = normalizeAllowNames(executionOptions.allow, "allow");
                const allowRawUnmediated = normalizeAllowNames(
                    executionOptions.allowRawUnmediated,
                    "allowRawUnmediated",
                );
                const brokerPolicyFiles = executionOptions.brokerPolicyFiles === undefined
                    ? []
                    : executionOptions.brokerPolicyFiles;
                if (!Array.isArray(brokerPolicyFiles)) {
                    throw invalidSdkConfig("brokerPolicyFiles must be an array.");
                }
                if (dbPath === ":memory:" && allowNames.length > 0) {
                    throw invalidSdkConfig("credential-backed execution requires a persistent vault path.");
                }

                const stdout = assertWritableStream(executionOptions.stdout || process.stdout, "stdout");
                const stderr = assertWritableStream(executionOptions.stderr || process.stderr, "stderr");
                const effectiveOptions = {
                    root,
                    vaultPath: dbPath,
                    envFile: resolveOptionalPath(root, executionOptions.envFile, "envFile") || path.join(root, ".env"),
                    policyFile: resolveOptionalPath(root, executionOptions.policyFile, "policyFile"),
                    policyHash: executionOptions.policyHash,
                    policy: executionOptions.policy,
                    brokerPolicyFiles: brokerPolicyFiles.map((file) =>
                        resolveOptionalPath(root, file, "brokerPolicyFiles")),
                    allowNames,
                    allowRawUnmediated,
                    strict: true,
                    canary: executionOptions.canary !== false,
                    sandbox: executionOptions.sandbox || false,
                    sandboxImage: executionOptions.sandboxImage,
                    sandboxNetwork: executionOptions.sandboxNetwork,
                    sandboxRo: Boolean(executionOptions.sandboxRo),
                    timeout: executionOptions.timeout,
                    timeoutMs: executionOptions.timeoutMs,
                    command,
                    commandArgs: args,
                };

                try {
                    const result = await executeProcess(effectiveOptions, {
                        outStream: stdout,
                        errStream: stderr,
                    });
                    return Object.freeze({
                        status: Number(result?.status ?? 0),
                    });
                } catch (error) {
                    throw wrapExecutionError(error);
                }
            },
        },
        close() {
            if (vault) {
                vault.close();
                vault = null;
            }
        },
    };

    return Object.freeze({
        ...client,
        credentials: Object.freeze(client.credentials),
        execution: Object.freeze(client.execution),
    });
}
