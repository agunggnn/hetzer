import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    analyzeIssues,
    ASCII_LOGO,
    auditLedgerSnapshot,
    boxBottom,
    boxDivider,
    boxLine,
    boxTop,
    collectStatus,
    drawFrame,
    enterAltScreen,
    exitAltScreen,
    getBoxWidth,
    quickSniffSnapshot,
    refreshDimensions,
    renderIssuesView,
    renderTui,
    startTui,
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
    assert.ok(status.audit);
    assert.ok(status.vault);
    assert.ok(status.shield);
    assert.ok(status.runtime);
    assert.ok(status.mcp);
    assert.ok(Array.isArray(status.services));
});

test("audit view displays cryptographic ledger status and events", () => {
    const output = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-14T00:00:00.000Z",
        audit: {
            state: "VERIFIED",
            detail: "2 event(s); SHA-256 chain intact",
            count: 2,
            latestHash: "abcdef1234567890abcdef1234567890",
            recentEvents: [
                { timestamp: "2026-09-14T00:00:00.000Z", eventType: "EXEC", result: "ALLOW", target: "node" },
            ],
        },
    }, { color: false, view: "audit" });

    assert.match(output, /CRYPTOGRAPHIC AUDIT LEDGER/);
    assert.match(output, /VERIFIED/);
    assert.match(output, /EXEC/);
    assert.match(output, /\[a\] to toggle back to Overview/);
});

test("auditLedgerSnapshot gathers audit ledger verification status", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-tui-audit-"));
    try {
        const initial = auditLedgerSnapshot(tempDir);
        assert.equal(initial.state, "CLEAN");
        assert.equal(initial.count, 0);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("compact mode renders streamlined overview within 15 lines", () => {
    const output = renderTui({
        root: "/test/compact",
        generatedAt: "2026-09-18T00:00:00.000Z",
        threat: { state: "ARMED", detail: "1 canary honeytoken", incidentCount: 0 },
        vault: { state: "ready", detail: "ready", keyIsolation: "ISOLATED", totalStored: 2, secretRefCount: 2 },
        shield: { preCommit: { state: "ACTIVE" }, commitMsg: { state: "ACTIVE" }, detectedAgents: ["Antigravity"] },
        runtime: {
            container: { state: "ready" },
            broker: { state: "ready" },
            redactor: { state: "ready" },
        },
    }, { color: false, compact: true });

    const lines = output.split("\n");
    assert.ok(lines.length <= 15, `Compact view must have <= 15 lines (got ${lines.length})`);
    assert.match(output, /REFRESH 2s \(COMPACT\)/);
    assert.match(output, /Threat Radar\s+ARMED/);
    assert.match(output, /Vault Posture\s+READY/);
    assert.match(output, /Agent Shield/);
    assert.match(output, /Runtime Armor/);
});

test("drawFrame outputs in-place frame with cursor home and line erases in TTY mode", () => {
    let captured = "";
    const mockStream = {
        isTTY: true,
        write(chunk) {
            captured += String(chunk);
            return true;
        },
    };

    drawFrame("Line 1\nLine 2", { stream: mockStream, isTTY: true });
    assert.ok(captured.startsWith("\x1b[H"), "Must start with cursor home escape sequence");
    assert.ok(captured.includes("\x1b[K"), "Must include line erase escape sequence");
    assert.ok(captured.endsWith("\x1b[J"), "Must end with bottom-clear escape sequence");
    assert.doesNotMatch(captured, /\x1b\[2J/, "Must NOT use full-screen blanking \\x1b[2J");
});

test("alternate screen buffer enters and exits with correct ANSI escape codes", () => {
    let captured = "";
    const mockStream = {
        isTTY: true,
        write(chunk) {
            captured += String(chunk);
            return true;
        },
    };

    enterAltScreen(mockStream);
    assert.ok(captured.includes("\x1b[?1049h"), "Must switch to alternate screen buffer");
    assert.ok(captured.includes("\x1b[?25l"), "Must hide cursor");

    captured = "";
    exitAltScreen(mockStream);
    assert.ok(captured.includes("\x1b[?1049l"), "Must leave alternate screen buffer");
    assert.ok(captured.includes("\x1b[?25h"), "Must show cursor");
});

test("startTui single-shot mode runs non-interactively without timer", async () => {
    let captured = "";
    const mockStream = {
        isTTY: false,
        write(chunk) {
            captured += String(chunk);
            return true;
        },
    };

    await startTui({ root: process.cwd(), args: ["--once"], stream: mockStream });
    assert.match(captured, /HETZER \/\/ TACTICAL ARMOR HUD/);
    assert.doesNotMatch(captured, /\x1b\[\?1049h/, "Single-shot mode must not enter alternate screen");
});

test("ASCII_LOGO is exported as a 5-line art array and renders in non-compact mode", () => {
    assert.ok(Array.isArray(ASCII_LOGO));
    assert.equal(ASCII_LOGO.length, 5);
    for (const line of ASCII_LOGO) {
        assert.equal(line.length, 37, `Line '${line}' must have length 37`);
    }

    const output = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-18T00:00:00.000Z",
    }, { color: false, banner: true });

    assert.match(output, /_____/);
    assert.match(output, /DEFENSE-IN-DEPTH RUNTIME ARMOR & THREAT REMEDIATION/);
});

test("analyzeIssues detects all vulnerability categories with concrete actions and CLI commands", () => {
    const mockSnapshot = {
        root: "/test/repo",
        sniff: {
            status: "VIOLATIONS",
            count: 2,
            violations: [{ file: ".env", line: 4, type: "aws_key" }],
        },
        threat: {
            state: "TRIPPED",
            incidentCount: 3,
            canaryCount: 1,
        },
        vault: {
            state: "ready",
            keyIsolation: "EXPOSED",
            rawSecretCount: 2,
        },
        shield: {
            preCommit: { state: "MISSING" },
            commitMsg: { state: "MISSING" },
        },
        audit: {
            state: "CORRUPTED",
            detail: "hash chain broken at #12",
        },
        runtime: {
            container: { state: "offline", detail: "Docker not running" },
        },
        mcp: {
            state: "degraded",
            detail: "manifest parse error",
        },
        services: [
            { id: "worker", label: "Worker", state: "offline", endpoint: "http://127.0.0.1:8080" },
        ],
        warnings: ["Deprecated configuration key used"],
    };

    const issues = analyzeIssues(mockSnapshot);
    assert.ok(issues.length >= 8, `Expected at least 8 issues, got ${issues.length}`);

    const leakIssue = issues.find((i) => i.id === "STAGED_SECRET_LEAK");
    assert.ok(leakIssue);
    assert.equal(leakIssue.severity, "CRITICAL");
    assert.match(leakIssue.command, /git restore --staged/);

    const tripIssue = issues.find((i) => i.id === "CANARY_TRIPWIRE_TRIGGERED");
    assert.ok(tripIssue);
    assert.equal(tripIssue.severity, "CRITICAL");
    assert.match(tripIssue.command, /hetzer canary list/);

    const keyIssue = issues.find((i) => i.id === "MASTER_KEY_EXPOSED");
    assert.ok(keyIssue);
    assert.equal(keyIssue.severity, "HIGH");
    assert.match(keyIssue.command, /hetzer init/);

    const rawIssue = issues.find((i) => i.id === "RAW_SECRETS_IN_ENV");
    assert.ok(rawIssue);
    assert.equal(rawIssue.severity, "HIGH");
    assert.match(rawIssue.command, /hetzer creds set/);

    const hookIssue = issues.find((i) => i.id === "PRE_COMMIT_HOOK_MISSING");
    assert.ok(hookIssue);
    assert.equal(hookIssue.severity, "MEDIUM");
    assert.match(hookIssue.command, /hetzer hook install/);

    const auditIssue = issues.find((i) => i.id === "AUDIT_LEDGER_TAMPERED");
    assert.ok(auditIssue);
    assert.equal(auditIssue.severity, "CRITICAL");
    assert.match(auditIssue.command, /hetzer audit verify/);
});

test("renderIssuesView formats issues guide with problem, action, and resolution commands", () => {
    const output = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-18T00:00:00.000Z",
        vault: {
            state: "ready",
            keyIsolation: "EXPOSED",
            rawSecretCount: 1,
        },
        shield: {
            preCommit: { state: "MISSING" },
            commitMsg: { state: "ACTIVE" },
        },
    }, { color: false, view: "issues" });

    assert.match(output, /SECURITY POSTURE & ACTIONABLE REMEDIATION GUIDE/);
    assert.match(output, /MASTER_KEY_EXPOSED|Master encryption key exposed/);
    assert.match(output, /Resolve\s+:\s+hetzer init/);
    assert.match(output, /Resolve\s+:\s+hetzer creds set <id>/);
    assert.match(output, /Resolve\s+:\s+hetzer hook install/);
    assert.match(output, /\[Tip\] Press \[i\] to toggle back to Overview/);
});

test("renderIssuesView displays hardened confirmation checklist when zero issues exist", () => {
    const output = renderTui({
        root: "/test/secure",
        generatedAt: "2026-09-18T00:00:00.000Z",
        threat: { state: "ARMED", canaryCount: 1, incidentCount: 0 },
        vault: { state: "ready", keyIsolation: "ISOLATED", rawSecretCount: 0 },
        shield: { preCommit: { state: "ACTIVE" }, commitMsg: { state: "ACTIVE" } },
        audit: { state: "VERIFIED" },
        runtime: { container: { state: "ready" } },
        mcp: { state: "ready" },
        sniff: { status: "CLEAN", count: 0, violations: [] },
    }, { color: false, view: "issues" });

    assert.match(output, /ZERO VULNERABILITIES DETECTED/);
    assert.match(output, /Git Pre-Commit & Commit-Msg Guards\s+:\s+ACTIVE/);
    assert.match(output, /Master Key Isolation\s+:\s+ISOLATED/);
    assert.match(output, /Canary Tripwire Honeytokens\s+:\s+ARMED/);
    assert.match(output, /No remediation required/);
});

test("renderOverview displays ACTIVE ISSUES & ACTIONS REQUIRED and contextual actions", () => {
    const output = renderTui({
        root: "/test/project",
        generatedAt: "2026-09-18T00:00:00.000Z",
        threat: {
            state: "TRIPPED",
            detail: "canary alert",
            incidentCount: 1,
            canaryCount: 1,
        },
        vault: {
            state: "ready",
            keyIsolation: "EXPOSED",
            rawSecretCount: 1,
        },
        shield: {
            preCommit: { state: "MISSING", detail: "not installed" },
            commitMsg: { state: "ACTIVE", detail: "active" },
        },
    }, { color: false });

    assert.match(output, /ACTIVE ISSUES & ACTIONS REQUIRED/);
    assert.match(output, /-> hetzer canary list|-> hetzer init/);
    assert.match(output, /Action: Run 'hetzer canary list'/);
    assert.match(output, /Action: Run 'hetzer init'/);
    assert.match(output, /Action: Run 'hetzer hook install'/);
    assert.match(output, /\[i\] Issues \(\d+\)/);
});
