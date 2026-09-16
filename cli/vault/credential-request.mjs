import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import { assertInteractiveHumanSession, promptSecret, setCredential } from "./creds.mjs";

const REQUEST_TTL_MS = 15 * 60 * 1000;
const REQUEST_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CREDENTIAL_ID_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;

function requestDirectory(root) {
    return path.join(root, "data", "credential-requests");
}

function requestFile(root, requestId) {
    if (!REQUEST_ID_PATTERN.test(requestId)) {
        throw new Error("Credential request ID is invalid.");
    }
    return path.join(requestDirectory(root), `${requestId}.json`);
}

function validateCredentialId(id) {
    if (!CREDENTIAL_ID_PATTERN.test(String(id || ""))) {
        throw new Error("Credential ID must contain only letters, numbers, '.', '_' or '-'.");
    }
    return id;
}

function atomicWrite(file, value) {
    const tempFile = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
        fs.writeFileSync(tempFile, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
        fs.renameSync(tempFile, file);
    } finally {
        if (fs.existsSync(tempFile)) fs.rmSync(tempFile, { force: true });
    }
}

function readRequest({ root, requestId }) {
    const file = requestFile(root, requestId);
    if (!fs.existsSync(file)) {
        throw new Error(`Credential request '${requestId}' was not found.`);
    }
    let request;
    try {
        request = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
        throw new Error(`Credential request '${requestId}' is unreadable.`);
    }
    if (request?.version !== 1 || request.requestId !== requestId || !CREDENTIAL_ID_PATTERN.test(request.credentialId)) {
        throw new Error(`Credential request '${requestId}' is invalid.`);
    }
    return { file, request };
}

function effectiveStatus(request, now) {
    if (request.status === "pending" && now >= request.expiresAt) return "expired";
    return request.status;
}

export function createCredentialRequest({ root, id, ttlMs = REQUEST_TTL_MS, now = Date.now(), randomUUID = crypto.randomUUID } = {}) {
    const credentialId = validateCredentialId(id);
    if (!Number.isInteger(ttlMs) || ttlMs < 1000 || ttlMs > 24 * 60 * 60 * 1000) {
        throw new Error("Credential request TTL must be between 1 second and 24 hours.");
    }
    const requestId = randomUUID();
    if (!REQUEST_ID_PATTERN.test(requestId)) throw new Error("Credential request ID generator returned an invalid ID.");
    const directory = requestDirectory(root);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const request = {
        version: 1,
        requestId,
        credentialId,
        status: "pending",
        createdAt: now,
        expiresAt: now + ttlMs,
    };
    atomicWrite(path.join(directory, `${requestId}.json`), request);
    return request;
}

export function getCredentialRequest({ root, requestId, now = Date.now() } = {}) {
    const { request } = readRequest({ root, requestId });
    return { ...request, status: effectiveStatus(request, now) };
}

export async function approveCredentialRequest({
    root,
    envFile,
    requestId,
    input = process.stdin,
    output = process.stderr,
    env = process.env,
    ancestor,
    readSecret = promptSecret,
    now = Date.now(),
} = {}) {
    assertInteractiveHumanSession({
        input,
        env,
        ancestor,
        operation: "'hetzer creds approve'",
    });
    const { file, request } = readRequest({ root, requestId });
    if (effectiveStatus(request, now) !== "pending") {
        throw new Error(`Credential request '${requestId}' is ${effectiveStatus(request, now)}.`);
    }
    const secret = await readSecret(`Enter secret value for '${request.credentialId}': `, { input, output });
    if (!secret) throw new Error("Secret value is required.");
    const result = setCredential({ root, envFile, id: request.credentialId, secret });
    const approved = {
        ...request,
        status: "approved",
        approvedAt: now,
    };
    atomicWrite(file, approved);
    return { ...result, requestId, status: approved.status };
}

export { REQUEST_TTL_MS };
