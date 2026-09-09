#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { isCanaryCredential, triggerCanaryAlert } from "./canary.mjs";
import { isReflectionCommand, pipeSanitizedChild } from "./exec.mjs";
import { Grimoire, parseSecretRef, resolveMasterKey, resolveVaultPath } from "./hetzer-vault.mjs";
import { strictBaseEnvironment } from "./secret-env.mjs";

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
const VALIDATED_POLICY = Symbol("hetzer.httpBroker.validatedPolicy");
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const FORBIDDEN_HEADERS = new Set([
    "connection", "content-length", "cookie", "host", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
]);
const RESERVED_ENV = new Set([
    "APPDATA", "COLORTERM", "COMSPEC", "HETZER_GRIMOIRE_KEY", "HETZER_ROOT",
    "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOCALAPPDATA", "NODE_OPTIONS",
    "PATH", "PATHEXT", "PROGRAMDATA", "SHELL", "SYSTEMDRIVE", "SYSTEMROOT",
    "TEMP", "TERM", "TMP", "TZ", "USERPROFILE", "WINDIR",
]);
const RESPONSE_HEADERS = new Set([
    "cache-control", "content-type", "openai-processing-ms", "request-id",
    "retry-after", "x-request-id",
]);

function plainObject(value) {
    return value && typeof value === "object" && !Array.isArray(value);
}

function integerInRange(value, fallback, min, max, label) {
    const selected = value === undefined ? fallback : value;
    if (!Number.isInteger(selected) || selected < min || selected > max) {
        throw new Error(`${label} must be an integer from ${min} to ${max}.`);
    }
    return selected;
}

function validateEnvName(value, label) {
    const name = String(value || "");
    if (!ENV_NAME.test(name) || RESERVED_ENV.has(name)) {
        throw new Error(`${label} must be a non-reserved uppercase environment variable name.`);
    }
    return name;
}

function validateHeader(value, label) {
    const header = String(value || "").trim().toLowerCase();
    if (!HEADER_NAME.test(header) || FORBIDDEN_HEADERS.has(header)) {
        throw new Error(`${label} is not an allowed HTTP header name.`);
    }
    return header;
}

function normalizePrefix(value) {
    const prefix = String(value || "").trim();
    if (!prefix.startsWith("/") || prefix.startsWith("//") || prefix.includes("\\") || prefix.includes("?")) {
        throw new Error(`Invalid allowed path prefix: ${prefix}`);
    }
    let decoded;
    try {
        decoded = decodeURIComponent(prefix);
    } catch {
        throw new Error(`Invalid encoded path prefix: ${prefix}`);
    }
    if (decoded.split("/").some((segment) => segment === "." || segment === ".." || segment.includes("\0"))) {
        throw new Error(`Unsafe allowed path prefix: ${prefix}`);
    }
    return prefix.length > 1 ? prefix.replace(/\/$/, "") : prefix;
}

export function validateBrokerPolicy(input) {
    if (!plainObject(input) || input.version !== 1) {
        throw new Error("Broker policy must be an object with version 1.");
    }

    let target;
    try {
        target = new URL(String(input.target || ""));
    } catch {
        throw new Error("Broker target must be a valid HTTPS origin.");
    }
    if (
        target.protocol !== "https:"
        || target.username
        || target.password
        || target.search
        || target.hash
        || target.pathname !== "/"
    ) {
        throw new Error("Broker target must be an HTTPS origin without credentials, path, query, or fragment.");
    }

    const credentialId = parseSecretRef(input.credential);
    const methods = [...new Set((input.allowedMethods || ["GET", "POST"]).map((item) => String(item).toUpperCase()))];
    if (!methods.length || methods.some((method) => !METHODS.has(method))) {
        throw new Error("allowedMethods contains an unsupported HTTP method.");
    }
    const pathPrefixes = [...new Set((input.allowedPathPrefixes || []).map(normalizePrefix))];
    if (!pathPrefixes.length) throw new Error("allowedPathPrefixes must contain at least one explicit path prefix.");
    if (pathPrefixes.includes("/")) throw new Error("The root path cannot be used as an allowed path prefix in broker v1.");

    const clientAuth = plainObject(input.clientAuth) ? input.clientAuth : {};
    const upstreamAuth = plainObject(input.upstreamAuth) ? input.upstreamAuth : {};
    const clientHeader = validateHeader(clientAuth.header || "authorization", "clientAuth.header");
    const upstreamHeader = validateHeader(upstreamAuth.header || "authorization", "upstreamAuth.header");
    const clientScheme = String(clientAuth.scheme ?? "Bearer").trim();
    const upstreamScheme = String(upstreamAuth.scheme ?? "Bearer").trim();
    for (const [label, scheme] of [["clientAuth.scheme", clientScheme], ["upstreamAuth.scheme", upstreamScheme]]) {
        if (scheme !== "" && scheme !== "Bearer") throw new Error(`${label} must be empty or Bearer in broker v1.`);
    }

    const forwardHeaders = [...new Set((input.forwardHeaders || ["accept", "content-type", "user-agent"])
        .map((header) => validateHeader(header, "forwardHeaders entry")))]
        .filter((header) => header !== clientHeader && header !== upstreamHeader);
    const basePath = normalizePrefix(input.basePath || "/");
    if (!pathPrefixes.some((prefix) => basePath === prefix || basePath.startsWith(`${prefix}/`) || prefix === "/")) {
        throw new Error("basePath must fall within an allowed path prefix.");
    }

    const baseUrlEnv = validateEnvName(input.baseUrlEnv, "baseUrlEnv");
    const tokenEnv = validateEnvName(input.tokenEnv, "tokenEnv");
    if (baseUrlEnv === tokenEnv) throw new Error("baseUrlEnv and tokenEnv must be different.");

    return Object.freeze({
        [VALIDATED_POLICY]: true,
        version: 1,
        targetOrigin: target.origin,
        credentialId,
        baseUrlEnv,
        tokenEnv,
        basePath,
        clientHeader,
        clientScheme,
        upstreamHeader,
        upstreamScheme,
        allowedMethods: Object.freeze(methods),
        allowedPathPrefixes: Object.freeze(pathPrefixes),
        forwardHeaders: Object.freeze(forwardHeaders),
        ttlSeconds: integerInRange(input.ttlSeconds, 300, 10, 3600, "ttlSeconds"),
        maxRequests: integerInRange(input.maxRequests, 100, 1, 1000, "maxRequests"),
        maxRequestBytes: integerInRange(input.maxRequestBytes, 1048576, 1, 10485760, "maxRequestBytes"),
        maxResponseBytes: integerInRange(input.maxResponseBytes, 8388608, 1, 16777216, "maxResponseBytes"),
        timeoutMs: integerInRange(input.timeoutMs, 30000, 1000, 120000, "timeoutMs"),
    });
}

export function loadBrokerPolicy(policyFile) {
    const resolved = path.resolve(policyFile);
    let parsed;
    try {
        parsed = JSON.parse(fs.readFileSync(resolved, "utf8"));
    } catch (error) {
        throw new Error(`Unable to read broker policy '${resolved}': ${error.message}`);
    }
    return validateBrokerPolicy(parsed);
}

function matchesCapability(actual, expected) {
    const a = Buffer.from(String(actual || ""));
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isLoopback(address) {
    return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function sendJson(response, statusCode, message) {
    const body = Buffer.from(`${JSON.stringify({ error: message })}\n`);
    response.writeHead(statusCode, {
        "content-type": "application/json; charset=utf-8",
        "content-length": body.length,
        "cache-control": "no-store",
    });
    response.end(body);
}

function pathAllowed(pathname, prefixes) {
    return prefixes.some((prefix) => prefix === "/" || pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function upstreamUrl(policy, rawUrl) {
    if (typeof rawUrl !== "string" || !rawUrl.startsWith("/") || rawUrl.startsWith("//") || rawUrl.includes("\\")) {
        throw Object.assign(new Error("Invalid broker request target."), { statusCode: 400 });
    }
    let inbound;
    let decoded;
    try {
        inbound = new URL(rawUrl, "http://127.0.0.1");
        decoded = decodeURIComponent(inbound.pathname);
    } catch {
        throw Object.assign(new Error("Invalid broker request path."), { statusCode: 400 });
    }
    if (decoded.includes("\\") || decoded.includes("\0") || decoded.split("/").some((part) => part === "." || part === "..")) {
        throw Object.assign(new Error("Unsafe broker request path."), { statusCode: 400 });
    }
    if (!pathAllowed(inbound.pathname, policy.allowedPathPrefixes)) {
        throw Object.assign(new Error("Request path is not allowed by the broker policy."), { statusCode: 403 });
    }
    const target = new URL(policy.targetOrigin);
    target.pathname = inbound.pathname;
    target.search = inbound.search;
    return target;
}

async function readNodeStream(stream, limit) {
    const chunks = [];
    let total = 0;
    for await (const chunk of stream) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += buffer.length;
        if (total > limit) throw Object.assign(new Error("Request body exceeds broker policy limit."), { statusCode: 413 });
        chunks.push(buffer);
    }
    return Buffer.concat(chunks);
}

async function readWebStream(stream, limit) {
    if (!stream) return Buffer.alloc(0);
    const reader = stream.getReader();
    const chunks = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const buffer = Buffer.from(value);
            total += buffer.length;
            if (total > limit) throw new Error("Upstream response exceeds broker policy limit.");
            chunks.push(buffer);
        }
    } catch (error) {
        try { await reader.cancel(); } catch { /* Best effort. */ }
        throw error;
    }
    return Buffer.concat(chunks);
}

function textResponse(contentType, bodyLength) {
    if (!bodyLength) return true;
    const type = String(contentType || "").split(";", 1)[0].trim().toLowerCase();
    return type.startsWith("text/") || type === "application/json" || type.endsWith("+json") || type === "application/x-ndjson";
}

function authValue(scheme, value) {
    return scheme ? `${scheme} ${value}` : value;
}

function redactBrokerValue(value, secret, credentialId) {
    return String(value || "").replaceAll(secret, `secretRef:${credentialId}`);
}

export async function startHttpCredentialBroker({
    policy: rawPolicy,
    secret,
    fetchFn = globalThis.fetch,
    randomBytes = crypto.randomBytes,
    host = "127.0.0.1",
} = {}) {
    const policy = rawPolicy?.[VALIDATED_POLICY] ? rawPolicy : validateBrokerPolicy(rawPolicy);
    if (typeof secret !== "string" || !secret) throw new Error("Broker credential is required.");
    if (typeof fetchFn !== "function") throw new Error("A Fetch-compatible transport is required.");
    if (host !== "127.0.0.1") throw new Error("Credential broker must bind to 127.0.0.1.");

    const capability = randomBytes(32).toString("base64url");
    const expectedAuth = authValue(policy.clientScheme, capability);
    const deadline = Date.now() + (policy.ttlSeconds * 1000);
    let forwardedRequests = 0;

    const server = http.createServer(async (request, response) => {
        try {
            if (!isLoopback(request.socket.remoteAddress)) return sendJson(response, 403, "Loopback clients only.");
            if (Date.now() >= deadline) return sendJson(response, 410, "Broker capability expired.");
            if (!matchesCapability(request.headers[policy.clientHeader], expectedAuth)) {
                return sendJson(response, 401, "Invalid broker capability.");
            }
            const method = String(request.method || "GET").toUpperCase();
            if (!policy.allowedMethods.includes(method)) return sendJson(response, 403, "HTTP method is not allowed by the broker policy.");
            if (forwardedRequests >= policy.maxRequests) return sendJson(response, 429, "Broker request limit reached.");
            const target = upstreamUrl(policy, request.url);
            const body = await readNodeStream(request, policy.maxRequestBytes);
            forwardedRequests += 1;

            const headers = {};
            for (const name of policy.forwardHeaders) {
                const value = request.headers[name];
                if (typeof value === "string") headers[name] = value;
                else if (Array.isArray(value)) headers[name] = value.join(", ");
            }
            headers[policy.upstreamHeader] = authValue(policy.upstreamScheme, secret);

            const upstream = await fetchFn(target, {
                method,
                headers,
                body: method === "GET" ? undefined : body,
                redirect: "manual",
                signal: AbortSignal.timeout(policy.timeoutMs),
            });
            if (upstream.status >= 300 && upstream.status < 400) {
                return sendJson(response, 502, "Upstream redirects are blocked by the broker policy.");
            }
            const contentLength = Number(upstream.headers.get("content-length") || 0);
            if (Number.isFinite(contentLength) && contentLength > policy.maxResponseBytes) {
                return sendJson(response, 502, "Upstream response exceeds broker policy limit.");
            }
            const upstreamBody = await readWebStream(upstream.body, policy.maxResponseBytes);
            const contentType = upstream.headers.get("content-type") || "";
            if (!textResponse(contentType, upstreamBody.length)) {
                return sendJson(response, 502, "Broker v1 only accepts text or JSON upstream responses.");
            }
            const sanitizedBody = Buffer.from(upstreamBody.toString("utf8").replaceAll(secret, `secretRef:${policy.credentialId}`));
            const responseHeaders = {};
            for (const name of RESPONSE_HEADERS) {
                const value = upstream.headers.get(name);
                if (value) responseHeaders[name] = redactBrokerValue(value, secret, policy.credentialId);
            }
            responseHeaders["content-length"] = String(sanitizedBody.length);
            responseHeaders["cache-control"] ||= "no-store";
            response.writeHead(upstream.status, responseHeaders);
            response.end(sanitizedBody);
        } catch (error) {
            const safeMessage = redactBrokerValue(error.message || "Broker request failed.", secret, policy.credentialId);
            if (!response.headersSent) sendJson(response, error.statusCode || 502, safeMessage);
            else response.destroy();
        }
    });

    await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, host, resolve);
    });
    const address = server.address();
    const timer = setTimeout(() => server.close(), policy.ttlSeconds * 1000);
    timer.unref();
    let closed = false;

    return {
        url: `http://${host}:${address.port}`,
        capability,
        policy,
        close() {
            if (closed) return Promise.resolve();
            closed = true;
            clearTimeout(timer);
            return new Promise((resolve) => {
                if (!server.listening) resolve();
                else server.close(resolve);
            });
        },
    };
}

export function parseBrokerArguments(argv) {
    const marker = argv.indexOf("--");
    if (marker === -1 || !argv[marker + 1]) {
        throw new Error("Usage: broker --policy <file> -- <command> [args]");
    }
    const options = argv.slice(0, marker);
    const policyIndex = options.indexOf("--policy");
    if (policyIndex === -1 || !options[policyIndex + 1]) throw new Error("Broker requires --policy <file>.");
    const value = (name) => {
        const index = options.indexOf(name);
        return index >= 0 ? options[index + 1] : "";
    };
    return {
        root: path.resolve(value("--root") || process.cwd()),
        envFile: path.resolve(value("--env-file")),
        policyFile: path.resolve(options[policyIndex + 1]),
        command: argv[marker + 1],
        commandArgs: argv.slice(marker + 2),
    };
}

export async function executeBrokeredProcess(options, {
    outStream = process.stdout,
    errStream = process.stderr,
    baseEnv = process.env,
    fetchFn = globalThis.fetch,
} = {}) {
    if (isReflectionCommand(options.command, options.commandArgs)) {
        throw Object.assign(new Error("Environment reflection commands are forbidden in broker execution."), { code: "ERR_REFLECTION_BLOCKED" });
    }
    const policy = loadBrokerPolicy(options.policyFile);
    const envValues = fs.existsSync(options.envFile) ? parseEnv(fs.readFileSync(options.envFile, "utf8")) : {};
    const masterKey = resolveMasterKey({ root: options.root, envValues, baseEnv });
    if (!masterKey || String(masterKey).startsWith("secretRef:")) throw new Error("Grimoire master key is unavailable.");
    if (isCanaryCredential(policy.credentialId)) {
        triggerCanaryAlert({ id: policy.credentialId, actor: "process.broker", action: "http.proxy", root: options.root });
    }

    const vault = new Grimoire({
        dbPath: resolveVaultPath(options.root) || path.join(options.root, "data", "hetzer-vault.db"),
        legacyFile: path.join(options.root, "data", "vault.json"),
        masterKey,
    });
    let secret;
    try {
        const credential = vault.find(policy.credentialId);
        if (!credential) throw new Error(`Credential '${policy.credentialId}' was not found.`);
        secret = vault.resolve(policy.credentialId, { targetId: credential.projectId, action: "process.start" });
        if (secret === null) throw new Error(`Credential '${policy.credentialId}' is not allowed for broker execution.`);
        vault.recordAudit({
            actor: "hetzer-cli",
            action: "http.proxy.start",
            targetId: credential.projectId,
            credentialId: policy.credentialId,
            reason: "Started a short-lived loopback credential broker",
            outcome: "allowed",
            metadata: { targetOrigin: policy.targetOrigin, ttlSeconds: policy.ttlSeconds, maxRequests: policy.maxRequests },
        });
    } finally {
        vault.close();
    }

    const broker = await startHttpCredentialBroker({ policy, secret, fetchFn });
    const childEnv = {
        ...strictBaseEnvironment(baseEnv),
        HETZER_ROOT: options.root,
        [policy.baseUrlEnv]: `${broker.url}${policy.basePath === "/" ? "" : policy.basePath}`,
        [policy.tokenEnv]: broker.capability,
    };
    const targetCmd = process.platform === "win32" && options.command.includes(" ") && !options.command.startsWith('"')
        ? `"${options.command}"`
        : options.command;
    const child = spawn(targetCmd, options.commandArgs, {
        stdio: ["inherit", "pipe", "pipe"],
        env: childEnv,
        windowsHide: true,
        shell: process.platform === "win32",
    });
    try {
        return await pipeSanitizedChild(child, [
            { id: policy.credentialId, secret },
            { id: "broker-capability", secret: broker.capability },
        ], { outStream, errStream });
    } finally {
        await broker.close();
        secret = "";
    }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const options = parseBrokerArguments(process.argv.slice(2));
        executeBrokeredProcess(options)
            .then((result) => { process.exitCode = result.status; })
            .catch((error) => {
                process.stderr.write(`Hetzer broker failed: ${error.message}\n`);
                process.exitCode = error.exitCode || 1;
            });
    } catch (error) {
        process.stderr.write(`Hetzer broker failed: ${error.message}\n`);
        process.exitCode = error.exitCode || 1;
    }
}
