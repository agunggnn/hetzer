import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    approveCredentialRequest,
    createCredentialRequest,
    getCredentialRequest,
} from "./credential-request.mjs";

function fixture() {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-credential-request-"));
    fs.mkdirSync(path.join(root, "data"), { recursive: true });
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "HETZER_GRIMOIRE_KEY=credential-request-test-key-32-chars\n");
    return { root, envFile };
}

test("credential requests store metadata only and report pending status", () => {
    const { root } = fixture();
    try {
        const request = createCredentialRequest({
            root,
            id: "github-token",
            now: 1000,
            ttlMs: 60_000,
            randomUUID: () => "11111111-1111-4111-8111-111111111111",
        });
        assert.equal(request.status, "pending");
        assert.equal(getCredentialRequest({ root, requestId: request.requestId, now: 2000 }).status, "pending");
        const serialized = fs.readFileSync(path.join(root, "data", "credential-requests", `${request.requestId}.json`), "utf8");
        assert.doesNotMatch(serialized, /token-value|human-entered-secret/i);
        assert.deepEqual(Object.keys(JSON.parse(serialized)).sort(), [
            "createdAt", "credentialId", "expiresAt", "requestId", "status", "version",
        ]);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("expired requests cannot be approved", async () => {
    const { root, envFile } = fixture();
    try {
        const request = createCredentialRequest({
            root,
            id: "github-token",
            now: 1000,
            ttlMs: 1000,
            randomUUID: () => "22222222-2222-4222-8222-222222222222",
        });
        assert.equal(getCredentialRequest({ root, requestId: request.requestId, now: 2000 }).status, "expired");
        await assert.rejects(
            () => approveCredentialRequest({
                root,
                envFile,
                requestId: request.requestId,
                input: { isTTY: true },
                env: {},
                ancestor: { isAgent: false },
                now: 2000,
                readSecret: async () => "unused",
            }),
            /is expired/
        );
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("approval requires a human TTY and stores the secret only in the vault", async () => {
    const { root, envFile } = fixture();
    try {
        const request = createCredentialRequest({
            root,
            id: "github-token",
            now: 1000,
            randomUUID: () => "33333333-3333-4333-8333-333333333333",
        });
        await assert.rejects(
            () => approveCredentialRequest({
                root,
                envFile,
                requestId: request.requestId,
                input: { isTTY: false },
                env: {},
                ancestor: { isAgent: false },
                readSecret: async () => "should-not-run",
            }),
            /requires a direct human interactive TTY/
        );

        const result = await approveCredentialRequest({
            root,
            envFile,
            requestId: request.requestId,
            input: { isTTY: true },
            env: {},
            ancestor: { isAgent: false },
            now: 2000,
            readSecret: async () => "human-entered-secret",
        });
        assert.equal(result.status, "approved");
        assert.equal(getCredentialRequest({ root, requestId: request.requestId, now: 3000 }).status, "approved");
        assert.match(fs.readFileSync(envFile, "utf8"), /GITHUB_TOKEN=secretRef:github-token/);
        const serialized = fs.readFileSync(path.join(root, "data", "credential-requests", `${request.requestId}.json`), "utf8");
        assert.doesNotMatch(serialized, /human-entered-secret/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("request IDs and credential IDs reject path traversal", () => {
    const { root } = fixture();
    try {
        assert.throws(() => createCredentialRequest({ root, id: "../secret" }), /Credential ID/);
        assert.throws(() => getCredentialRequest({ root, requestId: "..\\secret" }), /request ID/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});
