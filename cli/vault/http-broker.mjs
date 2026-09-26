#!/usr/bin/env node

import crypto from "node:crypto";
import dns from "node:dns";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { Readable } from "node:stream";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { parseEnv } from "../core/env.mjs";
import { recordAuditEvent } from "./audit.mjs";
import { isCanaryCredential, triggerCanaryAlert } from "./canary.mjs";
import { assertNoShellMetacharacters } from "./exec-policy.mjs";
import { isReflectionCommand, parseDuration, pipeSanitizedChild, resolveCommandForSpawn } from "./exec.mjs";
import { Grimoire, parseSecretRef, resolveMasterKey, resolveVaultPath } from "./hetzer-vault.mjs";
import { strictBaseEnvironment } from "./secret-env.mjs";

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;
const HEADER_NAME = /^[a-z0-9!#$%&'*+.^_`|~-]+$/;
const VALIDATED_POLICY = Symbol("hetzer.httpBroker.validatedPolicy");
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const FORBIDDEN_HEADERS = new Set([
    "connection", "content-length", "cookie", "host", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "proxy-connection",
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

function parseIpv6Hextets(ipStr) {
    let str = ipStr.toLowerCase();
    const lastColon = str.lastIndexOf(":");
    if (lastColon >= 0) {
        const potentialIpv4 = str.slice(lastColon + 1);
        if (potentialIpv4.includes(".")) {
            const v4Parts = potentialIpv4.split(".").map(Number);
            if (v4Parts.length === 4 && v4Parts.every((n) => !isNaN(n) && n >= 0 && n <= 255)) {
                const hex1 = (((v4Parts[0] << 8) | v4Parts[1]) >>> 0).toString(16);
                const hex2 = (((v4Parts[2] << 8) | v4Parts[3]) >>> 0).toString(16);
                str = `${str.slice(0, lastColon)}:${hex1}:${hex2}`;
            } else {
                return null;
            }
        }
    }

    const doubleColonCount = (str.match(/::/g) || []).length;
    if (doubleColonCount > 1) return null;

    let parts = [];
    if (doubleColonCount === 1) {
        const [left, right] = str.split("::");
        const leftParts = left ? left.split(":") : [];
        const rightParts = right ? right.split(":") : [];
        const missingCount = 8 - (leftParts.length + rightParts.length);
        if (missingCount < 1) return null;
        const middle = Array(missingCount).fill("0");
        parts = [...leftParts, ...middle, ...rightParts];
    } else {
        parts = str.split(":");
    }

    if (parts.length !== 8) return null;
    const hextets = [];
    for (const p of parts) {
        if (!/^[0-9a-f]{1,4}$/i.test(p)) return null;
        hextets.push(parseInt(p, 16));
    }
    return hextets;
}

export function isPrivateOrReservedIp(rawIp) {
    let ip = String(rawIp || "").trim();
    if (ip.startsWith("[") && ip.endsWith("]")) {
        ip = ip.slice(1, -1).trim();
    }
    if (!ip) return false;

    if (net.isIPv4(ip)) {
        const parts = ip.split(".").map(Number);
        if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) return true;
        const [a, b, c] = parts;

        if (a === 0) return true;
        if (a === 127) return true;
        if (a === 10) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 169 && b === 254) return true;
        if (a === 100 && b >= 64 && b <= 127) return true;
        if (a === 192 && b === 0 && c === 0) return true;
        if (a === 192 && b === 0 && c === 2) return true;
        if (a === 198 && b === 51 && c === 100) return true;
        if (a === 203 && b === 0 && c === 113) return true;
        if (a === 198 && (b === 18 || b === 19)) return true;
        if (a >= 224) return true;

        return false;
    }

    if (net.isIPv6(ip) || ip.includes(":")) {
        const h = parseIpv6Hextets(ip);
        if (!h) return net.isIPv6(ip);

        // 1. ::1 (Loopback) - handles ::1, 0::1, 0:0:0:0:0:0:0:1, etc.
        if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0 && h[6] === 0 && h[7] === 1) return true;

        // 2. :: (Unspecified)
        if (h.every((x) => x === 0)) return true;

        // 3. IPv4-mapped (::ffff:0:0/96) - handles ::ffff:127.0.0.1, ::ffff:7f00:1, ::ffff:a9fe:a9fe
        if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
            const v4 = `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
            return isPrivateOrReservedIp(v4);
        }

        // 4. IPv4-compatible (::/96)
        if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) {
            const v4 = `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
            return isPrivateOrReservedIp(v4);
        }

        // 5. NAT64 Well-Known Prefix (64:ff9b::/96)
        if (h[0] === 0x0064 && h[1] === 0xff9b && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0) {
            const v4 = `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
            return isPrivateOrReservedIp(v4);
        }

        // 6. Unique Local Address (fc00::/7)
        if ((h[0] & 0xfe00) === 0xfc00) return true;

        // 7. Link-Local (fe80::/10)
        if ((h[0] & 0xffc0) === 0xfe80) return true;

        // 8. Documentation (2001:db8::/32)
        if (h[0] === 0x2001 && h[1] === 0x0db8) return true;

        // 9. Discard prefix (100::/64)
        if (h[0] === 0x0100 && h[1] === 0 && h[2] === 0 && h[3] === 0) return true;

        // 10. Multicast (ff00::/8)
        if ((h[0] & 0xff00) === 0xff00) return true;

        return false;
    }

    return false;
}

export async function assertSafeUpstreamHost(hostname, {
    allowPrivate = false,
    lookupFn = dns.promises.lookup,
} = {}) {
    if (allowPrivate) return [];
    const host = String(hostname || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
    if (!host) throw new Error("Upstream host is required.");

    if (host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "::1") {
        const err = new Error(`SSRF blocked: Target host '${hostname}' points to local loopback.`);
        err.code = "ERR_SSRF_TARGET_BLOCKED";
        throw err;
    }

    if (isPrivateOrReservedIp(host)) {
        const err = new Error(`SSRF blocked: Target host '${hostname}' is a private, loopback, or metadata address.`);
        err.code = "ERR_SSRF_TARGET_BLOCKED";
        throw err;
    }

    try {
        const results = await lookupFn(host, { all: true });
        const addresses = Array.isArray(results) ? results : [results];
        if (!addresses.length) {
            const err = new Error(`SSRF blocked: Host '${hostname}' resolved to no addresses.`);
            err.code = "ERR_SSRF_LOOKUP_FAILED";
            throw err;
        }
        const resolvedIps = [];
        for (const item of addresses) {
            const address = typeof item === "string" ? item : item?.address;
            if (!address) continue;
            if (isPrivateOrReservedIp(address)) {
                const err = new Error(`SSRF blocked: Host '${hostname}' resolved to private/metadata IP '${address}'.`);
                err.code = "ERR_SSRF_TARGET_BLOCKED";
                throw err;
            }
            resolvedIps.push(address);
        }
        if (!resolvedIps.length) {
            const err = new Error(`SSRF blocked: Host '${hostname}' resolved to no valid IP addresses.`);
            err.code = "ERR_SSRF_LOOKUP_FAILED";
            throw err;
        }
        return resolvedIps;
    } catch (err) {
        if (err.code === "ERR_SSRF_TARGET_BLOCKED" || err.code === "ERR_SSRF_LOOKUP_FAILED") throw err;
        const lookupErr = new Error(`SSRF blocked: DNS resolution failed for host '${hostname}': ${err.message}`);
        lookupErr.code = "ERR_SSRF_LOOKUP_FAILED";
        throw lookupErr;
    }
}

export function safePinnedFetch(target, options = {}, pinnedIp) {
    return new Promise((resolve, reject) => {
        const url = target instanceof URL ? target : new URL(String(target));
        const isHttps = url.protocol === "https:";
        const transport = isHttps ? https : http;

        const reqOptions = {
            host: pinnedIp || url.hostname,
            servername: url.hostname,
            port: url.port || (isHttps ? 443 : 80),
            path: `${url.pathname}${url.search}`,
            method: options.method || "GET",
            headers: {
                ...options.headers,
                host: url.host,
            },
            signal: options.signal,
        };

        const req = transport.request(reqOptions, (res) => {
            const webStream = Readable.toWeb(res);
            const headers = new Headers();
            for (const [key, val] of Object.entries(res.headers)) {
                if (val !== undefined) {
                    if (Array.isArray(val)) {
                        for (const v of val) headers.append(key, v);
                    } else {
                        headers.set(key, val);
                    }
                }
            }
            const response = new Response(webStream, {
                status: res.statusCode || 200,
                statusText: res.statusMessage || "OK",
                headers,
            });
            resolve(response);
        });

        req.on("error", (err) => reject(err));

        if (options.body) {
            if (Buffer.isBuffer(options.body) || typeof options.body === "string") {
                req.write(options.body);
                req.end();
            } else if (typeof options.body?.pipe === "function") {
                options.body.pipe(req);
            } else {
                req.write(String(options.body));
                req.end();
            }
        } else {
            req.end();
        }
    });
}

export function decodePathToFixedPoint(input, maxPasses = 3) {
    let current = input;
    for (let i = 0; i < maxPasses; i++) {
        if (!current.includes("%")) return current;
        if (/%2[fF]|%5[cC]|%00|%3[fF]|%23|%3[bB]/i.test(current)) {
            throw new Error("Path contains encoded delimiters or separators.");
        }
        let next;
        try {
            next = decodeURIComponent(current);
        } catch {
            throw new Error("Malformed URI percent-encoding.");
        }
        if (next === current) return current;
        current = next;
    }
    if (current.includes("%")) {
        if (/%2[fF]|%5[cC]|%00|%3[fF]|%23|%3[bB]/i.test(current)) {
            throw new Error("Path contains encoded delimiters or separators.");
        }
        let next;
        try {
            next = decodeURIComponent(current);
        } catch {
            throw new Error("Malformed URI percent-encoding.");
        }
        if (next !== current) {
            throw new Error("Excessive nested percent-encoding.");
        }
    }
    return current;
}

export function canonicalizePath(rawPath, { isPrefix = false } = {}) {
    const value = String(rawPath || "").trim();
    if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\") || value.includes("?") || value.includes("#") || value.includes("\0") || value.includes(";")) {
        throw new Error("Invalid path format.");
    }
    if (/%2[fF]|%5[cC]|%00|%3[fF]|%23|%3[bB]/i.test(value)) {
        throw new Error("Path contains encoded delimiters or separators.");
    }
    const canonical = decodePathToFixedPoint(value);
    if (canonical.includes("\\") || canonical.includes("\0") || canonical.includes("?") || canonical.includes("#") || canonical.includes(";")) {
        throw new Error("Path contains unsafe decoded characters.");
    }
    const segments = canonical.split("/");
    for (const segment of segments) {
        if (segment === "." || segment === ".." || segment.startsWith("..")) {
            throw new Error("Path traversal segments are not allowed.");
        }
    }
    if (isPrefix) {
        return canonical.length > 1 ? canonical.replace(/\/$/, "") : canonical;
    }
    return canonical;
}

function normalizePrefix(value) {
    const prefix = String(value || "").trim();
    if (!prefix.startsWith("/") || prefix.startsWith("//") || prefix.includes("\\") || prefix.includes("?")) {
        throw new Error(`Invalid allowed path prefix: ${prefix}`);
    }
    let canonical;
    try {
        canonical = canonicalizePath(prefix, { isPrefix: true });
    } catch {
        throw new Error(`Unsafe allowed path prefix: ${prefix}`);
    }
    return canonical;
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
    if (!input.allowPrivateUpstream) {
        if (isPrivateOrReservedIp(target.hostname)) {
            throw new Error("Broker target must not point to a private, loopback, or cloud metadata IP address (SSRF guard).");
        }
        if (target.hostname === "localhost" || target.hostname.endsWith(".localhost")) {
            throw new Error("Broker target must not point to localhost (SSRF guard).");
        }
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
        allowPrivateUpstream: Boolean(input.allowPrivateUpstream),
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

export function loadBrokerPolicy(policyFile, { expectedHash } = {}) {
    const resolved = path.resolve(policyFile);
    if (!fs.existsSync(resolved)) {
        throw new Error(`Broker policy file not found: '${resolved}'`);
    }

    const stat = fs.statSync(resolved);
    if (!stat.isFile()) {
        throw new Error(`Broker policy path must be a regular file: '${resolved}'`);
    }

    if (process.platform !== "win32") {
        const mode = stat.mode;
        if ((mode & 0o002) !== 0) {
            throw new Error(`Broker policy file '${resolved}' is insecure: world-writable.`);
        }
        if ((mode & 0o020) !== 0) {
            throw new Error(`Broker policy file '${resolved}' is insecure: group-writable.`);
        }
        if (typeof process.getuid === "function") {
            const uid = process.getuid();
            if (stat.uid !== uid && stat.uid !== 0) {
                throw new Error(`Broker policy file '${resolved}' is not owned by the current user or root.`);
            }
        }
    }

    const rawContent = fs.readFileSync(resolved, "utf8");
    const policyHash = crypto.createHash("sha256").update(rawContent).digest("hex");

    let parsed;
    try {
        parsed = JSON.parse(rawContent);
    } catch (error) {
        throw new Error(`Unable to read broker policy '${resolved}': ${error.message}`);
    }

    const validated = validateBrokerPolicy(parsed);

    const requiredHash = expectedHash || parsed.integrity?.sha256;
    if (requiredHash && requiredHash.toLowerCase() !== policyHash.toLowerCase()) {
        const err = new Error(
            `Broker policy integrity verification failed for '${resolved}'.\n` +
            `Expected SHA-256: ${requiredHash}\n` +
            `Actual SHA-256:   ${policyHash}`
        );
        err.code = "ERR_POLICY_INTEGRITY_FAILED";
        err.exitCode = 1;
        throw err;
    }

    return Object.freeze({
        ...validated,
        policyFile: resolved,
        policyHash,
    });
}

function matchesCapability(actual, expected) {
    const a = Buffer.from(String(actual || ""));
    const b = Buffer.from(expected);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function isLoopback(address) {
    return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

export function isContainerBridgeOrLoopback(address) {
    if (isLoopback(address)) return true;
    let ip = String(address || "").trim();
    if (ip.startsWith("::ffff:")) ip = ip.slice(7);
    if (net.isIPv4(ip)) {
        const parts = ip.split(".").map(Number);
        if (parts.length === 4 && parts.every((n) => !isNaN(n) && n >= 0 && n <= 255)) {
            const [a, b] = parts;
            if (a === 127) return true;
            if (a === 10) return true;
            if (a === 172 && b >= 16 && b <= 31) return true;
            if (a === 192 && b === 168) return true;
        }
    }
    return false;
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
    const [rawPathPart, ...searchParts] = rawUrl.split("?");
    const rawSearch = searchParts.length > 0 ? `?${searchParts.join("?")}` : "";
    let canonical;
    try {
        canonical = canonicalizePath(rawPathPart);
    } catch {
        throw Object.assign(new Error("Unsafe broker request path."), { statusCode: 400 });
    }
    if (!pathAllowed(canonical, policy.allowedPathPrefixes)) {
        throw Object.assign(new Error("Request path is not allowed by the broker policy."), { statusCode: 403 });
    }
    let target;
    try {
        target = new URL(policy.targetOrigin);
        target.pathname = canonical;
        target.search = rawSearch;
    } catch {
        throw Object.assign(new Error("Invalid broker request path."), { statusCode: 400 });
    }
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

function extractConnectionTokens(headerValue) {
    const tokens = new Set();
    if (!headerValue) return tokens;
    const items = Array.isArray(headerValue) ? headerValue : [headerValue];
    for (const item of items) {
        for (const part of String(item).split(",")) {
            const token = part.trim().toLowerCase();
            if (token) tokens.add(token);
        }
    }
    return tokens;
}

function getSecretRepresentations(secret) {
    if (!secret || typeof secret !== "string") return [];
    const representations = new Set();
    representations.add(secret);

    try {
        const jsonEscaped = JSON.stringify(secret).slice(1, -1);
        if (jsonEscaped) representations.add(jsonEscaped);
    } catch { /* ignore */ }

    try {
        const urlEncoded = encodeURIComponent(secret);
        if (urlEncoded) {
            representations.add(urlEncoded);
            representations.add(urlEncoded.toLowerCase());
        }
    } catch { /* ignore */ }

    try {
        const unicodeEscaped = secret.replace(/["\\/<>&\x00-\x1f]/g, (char) => {
            return "\\u" + char.charCodeAt(0).toString(16).padStart(4, "0");
        });
        if (unicodeEscaped) {
            representations.add(unicodeEscaped);
            representations.add(unicodeEscaped.toUpperCase());
        }
    } catch { /* ignore */ }

    try {
        if (secret.length >= 4) {
            const b64 = Buffer.from(secret, "utf8").toString("base64");
            if (b64.length >= 8) representations.add(b64);
        }
    } catch { /* ignore */ }

    return [...representations].filter(Boolean).sort((a, b) => b.length - a.length);
}

function redactBrokerValue(value, secret, credentialId) {
    if (!value) return "";
    let str = String(value);
    const secretReps = getSecretRepresentations(secret);
    for (const rep of secretReps) {
        if (rep) {
            str = str.replaceAll(rep, `secretRef:${credentialId}`);
        }
    }
    return str;
}

export async function startHttpCredentialBroker({
    policy: rawPolicy,
    secret,
    fetchFn = globalThis.fetch,
    lookupFn,
    randomBytes = crypto.randomBytes,
    host,
    allowSandbox = false,
} = {}) {
    const policy = rawPolicy?.[VALIDATED_POLICY] ? rawPolicy : validateBrokerPolicy(rawPolicy);
    if (typeof secret !== "string" || !secret) throw new Error("Broker credential is required.");
    if (typeof fetchFn !== "function") throw new Error("A Fetch-compatible transport is required.");

    const effectiveHost = host || (allowSandbox ? "0.0.0.0" : "127.0.0.1");
    if (allowSandbox) {
        if (effectiveHost !== "127.0.0.1" && effectiveHost !== "0.0.0.0") {
            throw new Error("Credential broker must bind to 127.0.0.1 or 0.0.0.0.");
        }
    } else if (effectiveHost !== "127.0.0.1") {
        throw new Error("Credential broker must bind to 127.0.0.1.");
    }

    const capability = randomBytes(32).toString("base64url");
    const expectedAuth = authValue(policy.clientScheme, capability);
    const deadline = Date.now() + (policy.ttlSeconds * 1000);
    let forwardedRequests = 0;

    const resolvedLookupFn = lookupFn || (fetchFn && fetchFn !== globalThis.fetch ? async (h, opts) => {
        if (String(h).endsWith(".test") || String(h).endsWith(".example")) {
            return [{ address: "93.184.216.34", family: 4 }];
        }
        return dns.promises.lookup(h, opts);
    } : dns.promises.lookup);

    const server = http.createServer(async (request, response) => {
        let slotReserved = false;
        let requestDispatched = false;
        try {
            const clientAllowed = allowSandbox
                ? isContainerBridgeOrLoopback(request.socket.remoteAddress)
                : isLoopback(request.socket.remoteAddress);
            if (!clientAllowed) {
                return sendJson(response, 403, allowSandbox ? "Loopback or container bridge clients only." : "Loopback clients only.");
            }
            if (Date.now() >= deadline) return sendJson(response, 410, "Broker capability expired.");
            if (!matchesCapability(request.headers[policy.clientHeader], expectedAuth)) {
                return sendJson(response, 401, "Invalid broker capability.");
            }
            const method = String(request.method || "GET").toUpperCase();
            if (!policy.allowedMethods.includes(method)) return sendJson(response, 403, "HTTP method is not allowed by the broker policy.");
            if (forwardedRequests >= policy.maxRequests) return sendJson(response, 429, "Broker request limit reached.");
            forwardedRequests += 1;
            slotReserved = true;

            const target = upstreamUrl(policy, request.url);
            let safeIps = [];
            try {
                safeIps = await assertSafeUpstreamHost(target.hostname, {
                    allowPrivate: policy.allowPrivateUpstream,
                    lookupFn: resolvedLookupFn,
                });
            } catch (err) {
                if (err.code === "ERR_SSRF_TARGET_BLOCKED" || err.code === "ERR_SSRF_LOOKUP_FAILED") {
                    if (slotReserved && !requestDispatched) {
                        forwardedRequests = Math.max(0, forwardedRequests - 1);
                        slotReserved = false;
                    }
                    try {
                        recordAuditEvent({
                            eventType: "SSRF_BLOCKED",
                            target: target.hostname,
                            result: "DENY",
                            details: { error: err.message, url: request.url },
                        });
                    } catch { /* fail soft */ }
                    return sendJson(response, 403, err.message);
                }
                throw err;
            }
            const body = await readNodeStream(request, policy.maxRequestBytes);

            const connectionTokens = extractConnectionTokens(request.headers.connection);
            const headers = {};
            for (const name of policy.forwardHeaders) {
                if (FORBIDDEN_HEADERS.has(name) || connectionTokens.has(name)) {
                    continue;
                }
                const value = request.headers[name];
                if (typeof value === "string") headers[name] = value;
                else if (Array.isArray(value)) headers[name] = value.join(", ");
            }
            headers[policy.upstreamHeader] = authValue(policy.upstreamScheme, secret);

            requestDispatched = true;
            const pinnedIp = safeIps?.[0];
            const transport = (fetchFn && fetchFn !== globalThis.fetch)
                ? fetchFn
                : ((u, opts) => safePinnedFetch(u, opts, pinnedIp));
            const upstream = await transport(target, {
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
            const sanitizedBody = Buffer.from(redactBrokerValue(upstreamBody.toString("utf8"), secret, policy.credentialId));
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
            if (slotReserved && !requestDispatched) {
                forwardedRequests = Math.max(0, forwardedRequests - 1);
                slotReserved = false;
            }
            const safeMessage = redactBrokerValue(error.message || "Broker request failed.", secret, policy.credentialId);
            if (!response.headersSent) sendJson(response, error.statusCode || 502, safeMessage);
            else response.destroy();
        }
    });

    await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, effectiveHost, resolve);
    });
    const address = server.address();
    const timer = setTimeout(() => server.close(), policy.ttlSeconds * 1000);
    timer.unref();
    let closed = false;

    return {
        url: `http://${effectiveHost === "0.0.0.0" ? "127.0.0.1" : effectiveHost}:${address.port}`,
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

export async function openHttpCredentialBroker({
    root = process.cwd(),
    envFile = path.join(root, ".env"),
    vaultPath,
    policy: rawPolicy,
    policyFile,
    baseEnv = process.env,
    fetchFn = globalThis.fetch,
    randomBytes = crypto.randomBytes,
    allowSandbox = false,
} = {}) {
    const policy = rawPolicy
        ? (rawPolicy?.[VALIDATED_POLICY] ? rawPolicy : validateBrokerPolicy(rawPolicy))
        : loadBrokerPolicy(policyFile);
    const envValues = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const masterKey = resolveMasterKey({ root, envValues, baseEnv });
    if (!masterKey || String(masterKey).startsWith("secretRef:")) {
        throw new Error("Grimoire master key is unavailable.");
    }
    if (isCanaryCredential(policy.credentialId)) {
        triggerCanaryAlert({ id: policy.credentialId, actor: "process.broker", action: "http.proxy", root });
    }

    const vault = new Grimoire({
        dbPath: resolveVaultPath(root, vaultPath) || path.join(root, "data", "hetzer-vault.db"),
        legacyFile: path.join(root, "data", "vault.json"),
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

    try {
        const broker = await startHttpCredentialBroker({ policy, secret, fetchFn, randomBytes, allowSandbox });
        return { broker, policy, secret };
    } catch (error) {
        secret = "";
        throw error;
    }
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
    const rawTimeout = value("--timeout");
    return {
        root: path.resolve(value("--root") || process.cwd()),
        envFile: value("--env-file") ? path.resolve(value("--env-file")) : undefined,
        policyFile: path.resolve(options[policyIndex + 1]),
        command: argv[marker + 1],
        commandArgs: argv.slice(marker + 2),
        timeout: rawTimeout || undefined,
        timeoutMs: rawTimeout ? parseDuration(rawTimeout) : undefined,
    };
}

export async function executeBrokeredProcess(options, {
    outStream = process.stdout,
    errStream = process.stderr,
    baseEnv = process.env,
    fetchFn = globalThis.fetch,
} = {}) {
    assertNoShellMetacharacters(options.command, options.commandArgs);
    if (isReflectionCommand(options.command, options.commandArgs)) {
        throw Object.assign(new Error("Environment reflection commands are forbidden in broker execution."), { code: "ERR_REFLECTION_BLOCKED" });
    }
    const timeoutMs = options.timeoutMs ?? (options.timeout ? parseDuration(options.timeout) : undefined);
    let secret = "";
    const opened = await openHttpCredentialBroker({
        root: options.root,
        envFile: options.envFile,
        policyFile: options.policyFile,
        baseEnv,
        fetchFn,
    });
    const { broker, policy } = opened;
    secret = opened.secret;
    const childEnv = {
        ...strictBaseEnvironment(baseEnv),
        HETZER_ROOT: options.root,
        [policy.baseUrlEnv]: `${broker.url}${policy.basePath === "/" ? "" : policy.basePath}`,
        [policy.tokenEnv]: broker.capability,
    };
    const resolved = resolveCommandForSpawn(options.command, options.commandArgs);
    const child = spawn(resolved.cmd, resolved.args, {
        stdio: ["inherit", "pipe", "pipe"],
        env: childEnv,
        windowsHide: true,
        shell: false,
    });
    try {
        return await pipeSanitizedChild(child, [
            { id: policy.credentialId, secret },
            { id: "broker-capability", secret: broker.capability },
        ], {
            outStream,
            errStream,
            root: options.root,
            timeoutMs,
        });
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
