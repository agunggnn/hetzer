import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { executeBrokeredProcess, parseBrokerArguments, startHttpCredentialBroker, validateBrokerPolicy } from "./http-broker.mjs";
import { Grimoire } from "./hetzer-vault.mjs";

function policy(overrides = {}) {
    return {
        version: 1,
        target: "https://api.example.test",
        credential: "secretRef:service-api-key",
        baseUrlEnv: "SERVICE_BASE_URL",
        tokenEnv: "SERVICE_API_KEY",
        basePath: "/v1",
        clientAuth: { header: "authorization", scheme: "Bearer" },
        upstreamAuth: { header: "x-api-key", scheme: "" },
        allowedMethods: ["GET", "POST"],
        allowedPathPrefixes: ["/v1"],
        ttlSeconds: 30,
        maxRequests: 4,
        ...overrides,
    };
}

test("parseBrokerArguments requires a policy and a child command", () => {
    assert.throws(() => parseBrokerArguments(["--policy", "policy.json"]), /Usage/);
    assert.throws(() => parseBrokerArguments(["--", "node"]), /requires --policy/);
    const parsed = parseBrokerArguments(["--root", ".", "--env-file", ".env", "--policy", "policy.json", "--", "node", "client.mjs"]);
    assert.equal(parsed.command, "node");
    assert.deepEqual(parsed.commandArgs, ["client.mjs"]);
    assert.match(parsed.policyFile, /policy\.json$/);
});

test("validateBrokerPolicy rejects unsafe targets and over-broad path configuration", async () => {
    assert.throws(() => validateBrokerPolicy(policy({ target: "http://api.example.test" })), /HTTPS origin/);
    assert.throws(() => validateBrokerPolicy(policy({ target: "https://api.example.test/v1" })), /without credentials, path/);
    assert.throws(() => validateBrokerPolicy(policy({ allowedPathPrefixes: [] })), /at least one explicit path prefix/);
    assert.throws(() => validateBrokerPolicy(policy({ allowedPathPrefixes: ["/"] })), /root path cannot be used/);
    assert.throws(() => validateBrokerPolicy(policy({ tokenEnv: "PATH" })), /non-reserved/);
    assert.throws(() => validateBrokerPolicy(policy({ baseUrlEnv: "HOME" })), /non-reserved/);
    assert.throws(() => validateBrokerPolicy(policy({ upstreamAuth: { header: "authorization", scheme: "Basic" } })), /empty or Bearer/);
    await assert.rejects(
        startHttpCredentialBroker({ policy: { targetOrigin: "http://unsafe.example.test" }, secret: "synthetic" }),
        /version 1/,
    );
});

test("broker replaces a short-lived client capability with the real upstream credential", async () => {
    let captured;
    const broker = await startHttpCredentialBroker({
        policy: policy(),
        secret: "synthetic-service-secret",
        randomBytes: () => Buffer.alloc(32, 7),
        fetchFn: async (url, options) => {
            captured = { url: String(url), options };
            return new Response(JSON.stringify({ echoed: "synthetic-service-secret" }), {
                status: 200,
                headers: { "content-type": "application/json", "x-request-id": "request-synthetic-service-secret" },
            });
        },
    });

    try {
        const response = await fetch(`${broker.url}/v1/items?limit=2`, {
            method: "POST",
            headers: {
                authorization: `Bearer ${broker.capability}`,
                "content-type": "application/json",
                "x-unapproved-header": "drop-me",
            },
            body: JSON.stringify({ name: "sample" }),
        });
        const text = await response.text();

        assert.equal(response.status, 200);
        assert.equal(captured.url, "https://api.example.test/v1/items?limit=2");
        assert.equal(captured.options.headers["x-api-key"], "synthetic-service-secret");
        assert.equal(captured.options.headers.authorization, undefined);
        assert.equal(captured.options.headers["x-unapproved-header"], undefined);
        assert.equal(captured.options.redirect, "manual");
        assert.doesNotMatch(text, /synthetic-service-secret/);
        assert.match(text, /secretRef:service-api-key/);
        assert.doesNotMatch(response.headers.get("x-request-id"), /synthetic-service-secret/);
    } finally {
        await broker.close();
    }
});

test("broker redacts credentials from transport errors", async () => {
    const broker = await startHttpCredentialBroker({
        policy: policy(),
        secret: "synthetic-service-secret",
        fetchFn: async () => { throw new Error("transport failed for synthetic-service-secret"); },
    });

    try {
        const response = await fetch(`${broker.url}/v1/items`, {
            headers: { authorization: `Bearer ${broker.capability}` },
        });
        const text = await response.text();
        assert.equal(response.status, 502);
        assert.doesNotMatch(text, /synthetic-service-secret/);
        assert.match(text, /secretRef:service-api-key/);
    } finally {
        await broker.close();
    }
});

test("broker denies invalid capabilities, methods, paths, and upstream redirects", async () => {
    let calls = 0;
    const broker = await startHttpCredentialBroker({
        policy: policy(),
        secret: "synthetic-service-secret",
        fetchFn: async () => {
            calls += 1;
            return new Response("redirect", {
                status: 302,
                headers: { location: "https://other.example.test/" },
            });
        },
    });

    try {
        const unauthorized = await fetch(`${broker.url}/v1/items`, {
            headers: { authorization: "Bearer wrong-capability" },
        });
        assert.equal(unauthorized.status, 401);

        const methodDenied = await fetch(`${broker.url}/v1/items`, {
            method: "DELETE",
            headers: { authorization: `Bearer ${broker.capability}` },
        });
        assert.equal(methodDenied.status, 403);

        const pathDenied = await fetch(`${broker.url}/admin`, {
            headers: { authorization: `Bearer ${broker.capability}` },
        });
        assert.equal(pathDenied.status, 403);
        assert.equal(calls, 0);

        const redirect = await fetch(`${broker.url}/v1/items`, {
            headers: { authorization: `Bearer ${broker.capability}` },
        });
        assert.equal(redirect.status, 502);
        assert.equal(calls, 1);
        assert.equal((await redirect.json()).error, "Upstream redirects are blocked by the broker policy.");
    } finally {
        await broker.close();
    }
});

test("broker enforces request and response size boundaries", async () => {
    const broker = await startHttpCredentialBroker({
        policy: policy({ maxRequests: 1, maxRequestBytes: 4, maxResponseBytes: 4 }),
        secret: "synthetic-service-secret",
        fetchFn: async () => new Response("12345", { headers: { "content-type": "text/plain" } }),
    });
    const headers = { authorization: `Bearer ${broker.capability}` };

    try {
        const requestTooLarge = await fetch(`${broker.url}/v1/items`, { method: "POST", headers, body: "12345" });
        assert.equal(requestTooLarge.status, 413);

        const responseTooLarge = await fetch(`${broker.url}/v1/items`, { headers });
        assert.equal(responseTooLarge.status, 502);
        assert.equal((await responseTooLarge.json()).error, "Upstream response exceeds broker policy limit.");

        const requestLimit = await fetch(`${broker.url}/v1/items`, { headers });
        assert.equal(requestLimit.status, 429);
    } finally {
        await broker.close();
    }
});

test("brokered child receives only the capability while upstream receives the vault credential", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-http-broker-"));
    const envFile = path.join(root, ".env");
    const policyFile = path.join(root, "broker-policy.json");
    const childFile = path.join(root, "client.mjs");
    const masterKey = "m".repeat(48);
    const secret = "synthetic-vault-credential";
    let upstreamCredential = "";
    let stdout = "";
    let stderr = "";

    fs.mkdirSync(path.join(root, "data"));
    fs.writeFileSync(envFile, "HETZER_PROJECT_NAME=test\n");
    fs.writeFileSync(policyFile, JSON.stringify(policy()));
    fs.writeFileSync(childFile, [
        "const response = await fetch(`${process.env.SERVICE_BASE_URL}/items`, {",
        "  headers: { authorization: `Bearer ${process.env.SERVICE_API_KEY}` },",
        "});",
        "process.stdout.write(await response.text());",
        "process.stderr.write(`capability=${process.env.SERVICE_API_KEY}`);",
    ].join("\n"));

    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    try {
        vault.upsertTarget({ id: "service", name: "service" });
        vault.create({
            id: "service-api-key",
            projectId: "service",
            keyName: "api-key",
            authType: "api-key",
            allowedActions: ["process.start"],
            secret,
        });
    } finally {
        vault.close();
    }

    try {
        const result = await executeBrokeredProcess({
            root,
            envFile,
            policyFile,
            command: process.execPath,
            commandArgs: [childFile],
        }, {
            baseEnv: { ...process.env, HETZER_GRIMOIRE_KEY: masterKey },
            outStream: { write(chunk) { stdout += String(chunk); return true; } },
            errStream: { write(chunk) { stderr += String(chunk); return true; } },
            fetchFn: async (_url, options) => {
                upstreamCredential = options.headers["x-api-key"];
                return new Response(`upstream echoed ${secret}`, { headers: { "content-type": "text/plain" } });
            },
        });

        assert.equal(result.status, 0);
        assert.equal(upstreamCredential, secret);
        assert.doesNotMatch(stdout, new RegExp(secret));
        assert.match(stdout, /secretRef:service-api-key/);
        assert.match(stderr, /secretRef:broker-capability/);
        assert.doesNotMatch(stderr, new RegExp(secret));
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
    }
});
