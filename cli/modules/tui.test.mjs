import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    boxBottom,
    boxDivider,
    boxLine,
    boxTop,
    collectStatus,
    quickSniffSnapshot,
    renderTui,
    stripAnsi,
    threatSnapshot,
    vaultPostureSnapshot,
} from "./tui.mjs";

test("terminal view renders observed values without dashboard or invented gauges", () => {
    const output = renderTui({
        root: "/hetzer",
        generatedAt: "2026-08-30T00:00:00.000Z",
        docker: { state: "offline", detail: "Docker not installed" },
        vault: { state: "n/a", detail: "not initialized" },
        mcp: { state: "ready", detail: "4 registered tools" },
        services: [{
            id: "9router",
            label: "9Router",
            state: "offline",
            endpoint: "http://127.0.0.1:20140",
            detail: "unreachable",
        }],
        warnings: [],
    }, { color: false });

    assert.match(output, /Docker not installed/);
    assert.match(output, /4 registered tools/);
    assert.match(output, /Values are observed/);
    assert.doesNotMatch(output, /Dashboard|Atlas|85%|laguna|Hermes/);
});

test("tactical HUD renders full security posture with threat, vault, shield, and runtime armor", () => {
    const output = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        threat: {
            state: "ARMED",
            detail: "1 canary honeytoken deployed (exitCode 43)",
            incidentCount: 0,
            recentIncidents: [],
            canaryCount: 1,
        },
        vault: {
            state: "ready",
            detail: "database present; key available",
            keyIsolation: "ISOLATED",
            keyDetail: "~/.hetzer/grimoire.key (isolated from workspace)",
            totalStored: 4,
            secretRefCount: 4,
            rawSecretCount: 0,
            credentials: [
                { id: "npm-token", module: "core", authType: "api-key", configured: true },
            ],
        },
        shield: {
            preCommit: { state: "ACTIVE", detail: "staged diff secret sniffer installed" },
            commitMsg: { state: "ACTIVE", detail: "commit message token blocker installed" },
            detectedAgents: ["Antigravity", "Cursor IDE"],
        },
        runtime: {
            container: { state: "ready", detail: "Docker v27.1.1 (Ready for --sandbox)" },
            broker: { state: "ready", detail: "Dynamic hop-by-hop stripping, loopback isolated" },
            redactor: { state: "ready", detail: "Sub-ms 512B sliding window scan" },
            policy: { state: "ready", detail: "SHA-256 structured argv verification" },
        },
        mcp: { state: "ready", detail: "4 registered tools" },
        services: [],
        warnings: [],
    }, { color: false });

    assert.match(output, /THREAT & TRIPWIRE RADAR/);
    assert.match(output, /Canary Trap\s+ARMED/);
    assert.match(output, /VAULT & CREDENTIAL POSTURE/);
    assert.match(output, /Key Isolation\s+ISOLATED/);
    assert.match(output, /AGENT SHIELD & GIT GUARDS/);
    assert.match(output, /Git Pre-Commit\s+ACTIVE/);
    assert.match(output, /Antigravity, Cursor IDE/);
    assert.match(output, /RUNTIME ARMOR & CONTAINER SANDBOX/);
    assert.match(output, /Docker v27\.1\.1/);
    assert.match(output, /\[r\] Refresh/);
    assert.match(output, /\[c\] Canary Log/);
    assert.match(output, /\[v\] Vault Keys/);
});

test("canary view displays incident log and armed honeypot status", () => {
    // 1. Zero incidents view
    const secureOutput = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        threat: {
            state: "ARMED",
            detail: "1 canary honeytoken deployed",
            incidentCount: 0,
            recentIncidents: [],
            canaryCount: 1,
        },
    }, { color: false, view: "canary" });

    assert.match(secureOutput, /CANARY HONEYTOKEN & INCIDENT LOG/);
    assert.match(secureOutput, /No canary incidents recorded\. System secure\./);
    assert.match(secureOutput, /Honeytokens armed: 1/);
    assert.match(secureOutput, /ERR_CANARY_TRIPWIRE_TRIGGERED/);

    // 2. Incident tripped view
    const trippedOutput = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        threat: {
            state: "TRIPPED",
            detail: "1 canary active; 1 incident(s) logged!",
            incidentCount: 1,
            recentIncidents: [
                "[2026-09-14T01:00:00Z] CRITICAL: Canary 'canary-token' triggered by rogue-agent during creds.reveal",
            ],
            canaryCount: 1,
        },
    }, { color: false, view: "canary" });

    assert.match(trippedOutput, /Total Incidents: 1/);
    assert.match(trippedOutput, /rogue-agent during creds\.reveal/);
});

test("vault view displays inventory metadata without exposing secrets", () => {
    const output = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        vault: {
            state: "ready",
            detail: "database present; key available",
            credentials: [
                { id: "npm-token", module: "core", authType: "api-key", configured: true },
                { id: "github-token", module: "core", authType: "api-key", configured: true },
                { id: "unconfigured-key", module: "custom", authType: "api-key", configured: false },
            ],
        },
    }, { color: false, view: "vault" });

    assert.match(output, /VAULT INVENTORY \(METADATA ONLY - NO RAW SECRETS\)/);
    assert.match(output, /npm-token/);
    assert.match(output, /github-token/);
    assert.match(output, /STORED/);
    assert.doesNotMatch(output, /unconfigured-key/); // Only configured entries shown in inventory
});

test("sniff view displays clean status and violations accurately", () => {
    const cleanOutput = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        sniff: { status: "CLEAN", count: 0, violations: [] },
    }, { color: false, view: "sniff" });

    assert.match(cleanOutput, /STAGED DIFF SECRET SNIFFER SCAN/);
    assert.match(cleanOutput, /CLEAN: Zero secrets or leaked credentials detected/);

    const violationOutput = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        sniff: {
            status: "VIOLATIONS",
            count: 1,
            violations: [
                { file: ".env", line: 12, type: "npm_token", label: "NPM Access Token" },
            ],
        },
    }, { color: false, view: "sniff" });

    assert.match(violationOutput, /CRITICAL: 1 secret violation\(s\) detected!/);
    assert.match(violationOutput, /\[npm_token\] \.env:L12/);
});

test("box-drawing formatting primitives adhere to exact 77-column boundary", () => {
    const top = boxTop("TEST HUD");
    const bottom = boxBottom();
    const divider = boxDivider();
    const line = boxLine("Testing content");
    const coloredLine = boxLine("\x1b[32mGREEN TEXT\x1b[0m with more info");

    assert.equal(stripAnsi(top).length, 77);
    assert.equal(stripAnsi(bottom).length, 77);
    assert.equal(stripAnsi(divider).length, 77);
    assert.equal(stripAnsi(line).length, 77);
    assert.equal(stripAnsi(coloredLine).length, 77);
});

test("threatSnapshot correctly identifies incident logs and canary count", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-threat-test-"));
    try {
        const initial = threatSnapshot(tempDir, []);
        assert.equal(initial.state, "UNARMED");
        assert.equal(initial.incidentCount, 0);

        // Add canary item
        const armed = threatSnapshot(tempDir, [{ id: "canary-token" }]);
        assert.equal(armed.state, "ARMED");
        assert.equal(armed.canaryCount, 1);

        // Add incident log
        fs.mkdirSync(path.join(tempDir, "data"), { recursive: true });
        fs.writeFileSync(
            path.join(tempDir, "data", "hetzer-incidents.log"),
            "[2026-09-14T01:00:00Z] CRITICAL: Canary 'canary-token' tripped\n"
        );
        const tripped = threatSnapshot(tempDir, [{ id: "canary-token" }]);
        assert.equal(tripped.state, "TRIPPED");
        assert.equal(tripped.incidentCount, 1);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("collectStatus gathers empirical snapshot from workspace", async () => {
    const status = await collectStatus({ root: process.cwd() });
    assert.equal(typeof status.root, "string");
    assert.equal(typeof status.generatedAt, "string");
    assert.ok(status.threat);
    assert.ok(status.vault);
    assert.ok(status.shield);
    assert.ok(status.runtime);
    assert.ok(status.mcp);
    assert.ok(Array.isArray(status.services));
});
