import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    defaultHetzerHome,
    initializeProject,
    isGlobalCliInstalled,
    isHetzerWorkspace,
    main,
    resolveProjectRoot,
    suggestCommand,
} from "./cli.mjs";
import { parseEnv } from "./env.mjs";
import { Grimoire } from "../vault/hetzer-vault.mjs";

test("initializeProject creates a secured, repeatable project contract", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-init-"));
    const initResult = initializeProject(root);
    assert.equal(initResult.root, path.resolve(root));
    const first = fs.readFileSync(path.join(root, ".env"), "utf8");
    const values = parseEnv(first);
    assert.ok(values.HETZER_GRIMOIRE_KEY.length >= 32);
    assert.equal(fs.existsSync(path.join(root, "data", "hetzer-vault.db")), true);
    assert.equal(fs.existsSync(path.join(root, ".mcp.json")), true);

    initializeProject(root);
    assert.equal(fs.readFileSync(path.join(root, ".env"), "utf8"), first);
    fs.rmSync(root, { recursive: true, force: true });
});

test("defaultHetzerHome resolves ~/.hetzer or HETZER_HOME", () => {
    const home = defaultHetzerHome();
    assert.ok(home.endsWith(".hetzer"));

    const prev = process.env.HETZER_HOME;
    try {
        process.env.HETZER_HOME = "/custom/hetzer/home";
        assert.equal(defaultHetzerHome(), path.resolve("/custom/hetzer/home"));
    } finally {
        if (prev === undefined) delete process.env.HETZER_HOME;
        else process.env.HETZER_HOME = prev;
    }
});

test("isHetzerWorkspace and resolveProjectRoot identify local workspace vs global fallback", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-resolve-test-"));
    try {
        assert.equal(isHetzerWorkspace(tempDir), false);

        const customRoot = resolveProjectRoot({ root: tempDir });
        assert.equal(customRoot, tempDir);

        // Fake hetzer workspace
        fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_PROJECT_NAME=test\n");
        assert.equal(isHetzerWorkspace(tempDir), true);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("protect command arms workspace with universal skills and git hook", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-protect-test-"));
    const originalInstallHome = process.env.HETZER_INSTALL_HOME;
    fs.mkdirSync(path.join(tempDir, ".git", "hooks"), { recursive: true });
    fs.writeFileSync(path.join(tempDir, ".env"), "SAMPLE_KEY=test-token\n");
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    try {
        process.env.HETZER_INSTALL_HOME = path.join(tempDir, "home");
        await main(["protect"], { root: tempDir });
        assert.match(output, /HETZER CREDENTIAL GUARDS CONFIGURED/);
        assert.match(output, /No credentials migrated/);
        assert.doesNotMatch(output, /Plaintext tokens vaulted/);
        assert.equal(fs.existsSync(path.join(tempDir, ".cursor", "rules", "hetzer.mdc")), true);
        assert.equal(fs.existsSync(path.join(tempDir, ".git", "hooks", "pre-commit")), true);
        assert.equal(fs.existsSync(path.join(tempDir, "AGENTS.md")), true);
    } finally {
        if (originalInstallHome === undefined) delete process.env.HETZER_INSTALL_HOME;
        else process.env.HETZER_INSTALL_HOME = originalInstallHome;
        process.stdout.write = originalStdout;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("creds set rejects positional values that would remain in shell history", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-creds-argv-"));
    fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_ENABLED_MODULES=\n");
    try {
        await assert.rejects(
            () => main(["creds", "set", "audit-id", "synthetic-positional-value"], { root: tempDir }),
            /Do not pass a secret as a command-line argument/
        );
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("credential request flow exposes only request metadata and status", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-creds-request-cli-"));
    fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_ENABLED_MODULES=\n");
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += String(chunk);
        return true;
    };
    try {
        await main(["creds", "request", "github-token"], { root: tempDir });
        const requestId = /Request ID\s+: ([0-9a-f-]{36})/i.exec(output)?.[1];
        assert.ok(requestId);
        assert.doesNotMatch(output, /secret value|human-entered-secret/i);
        output = "";
        await main(["creds", "status", requestId], { root: tempDir });
        assert.equal(output.trim(), "pending");
    } finally {
        process.stdout.write = originalStdout;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("creds set fails closed when invoked without a human TTY", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-creds-set-tty-"));
    fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_ENABLED_MODULES=\n");
    try {
        await assert.rejects(
            () => main(["creds", "set", "github-token"], { root: tempDir }),
            /requires a direct human interactive TTY/
        );
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("suggestCommand suggests closest command for typos", () => {
    assert.equal(suggestCommand("protectt"), "protect");
    assert.equal(suggestCommand("initz"), "init");
    assert.equal(suggestCommand("doc"), "doctor");
    assert.equal(suggestCommand("credi"), "creds");
    assert.equal(suggestCommand("brokr"), "broker");
    assert.equal(suggestCommand("completely_unrelated_xyz"), null);
});

test("main rejects unknown commands early with suggestion before checking env", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-unknown-cmd-"));
    try {
        await assert.rejects(
            () => main(["protectt"], { root: tempDir }),
            /Unknown command 'protectt'\. Did you mean 'hetzer protect'\? Run 'hetzer help'\./
        );
        await assert.rejects(
            () => main(["foobar_command"], { root: tempDir }),
            /Unknown command 'foobar_command'\. Run 'hetzer help'\./
        );
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("protec alias triggers protect command successfully", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-protec-alias-"));
    const originalInstallHome = process.env.HETZER_INSTALL_HOME;
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    try {
        process.env.HETZER_INSTALL_HOME = path.join(tempDir, "home");
        await main(["protec"], { root: tempDir });
        assert.match(output, /HETZER CREDENTIAL GUARDS CONFIGURED/);
    } finally {
        if (originalInstallHome === undefined) delete process.env.HETZER_INSTALL_HOME;
        else process.env.HETZER_INSTALL_HOME = originalInstallHome;
        process.stdout.write = originalStdout;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("init wizard adapts prefix and hints when CLI is not in PATH", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-init-path-"));
    const originalTestGlobal = process.env.HETZER_TEST_GLOBAL_CLI;
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    try {
        process.env.HETZER_TEST_GLOBAL_CLI = "false";
        await main(["init", tempDir], { root: tempDir });
        assert.match(output, /HETZER - INITIALIZATION SUCCESSFUL/);
        assert.match(output, /npx hetzer exec/);
        assert.match(output, /npx hetzer creds/);
    } finally {
        if (originalTestGlobal === undefined) delete process.env.HETZER_TEST_GLOBAL_CLI;
        else process.env.HETZER_TEST_GLOBAL_CLI = originalTestGlobal;
        process.stdout.write = originalStdout;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("protect command includes CLI PATH notice when running via npx", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-protect-path-"));
    const originalTestGlobal = process.env.HETZER_TEST_GLOBAL_CLI;
    const originalInstallHome = process.env.HETZER_INSTALL_HOME;
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    try {
        process.env.HETZER_TEST_GLOBAL_CLI = "false";
        process.env.HETZER_INSTALL_HOME = path.join(tempDir, "home");
        await main(["protect"], { root: tempDir });
        assert.match(output, /CLI PATH NOTICE/);
        assert.match(output, /npm install -g hetzer\n/);
    } finally {
        if (originalTestGlobal === undefined) delete process.env.HETZER_TEST_GLOBAL_CLI;
        else process.env.HETZER_TEST_GLOBAL_CLI = originalTestGlobal;
        if (originalInstallHome === undefined) delete process.env.HETZER_INSTALL_HOME;
        else process.env.HETZER_INSTALL_HOME = originalInstallHome;
        process.stdout.write = originalStdout;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("version command reports package version correctly", async () => {
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    try {
        await main(["--version"]);
        assert.match(output, /^hetzer v\d+\.\d+\.\d+/);
        output = "";
        await main(["-v"]);
        assert.match(output, /^hetzer v\d+\.\d+\.\d+/);
        output = "";
        await main(["version"]);
        assert.match(output, /^hetzer v\d+\.\d+\.\d+/);
    } finally {
        process.stdout.write = originalStdout;
    }
});

test("exec command runs through the in-process execution path", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-cli-"));
    const auditPath = path.join(tempDir, "audit.log");
    const originalStdout = process.stdout.write;
    const originalExitCode = process.exitCode;
    const originalAuditPath = process.env.HETZER_AUDIT_LOG_PATH;
    let output = "";
    process.stdout.write = (chunk) => {
        output += String(chunk);
        return true;
    };
    process.env.HETZER_AUDIT_LOG_PATH = auditPath;
    try {
        fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_GRIMOIRE_KEY=secretRef:test-master\n", "utf8");
        await main([
            "exec",
            "--host",
            "--strict",
            "--allow", "__none__",
            "--",
            process.execPath,
            "-e",
            "process.stdout.write('exec-ok')",
        ], { root: tempDir });
        assert.equal(process.exitCode, 0);
        assert.equal(output.endsWith("exec-ok"), true);
    } finally {
        process.stdout.write = originalStdout;
        process.exitCode = originalExitCode;
        if (originalAuditPath === undefined) delete process.env.HETZER_AUDIT_LOG_PATH;
        else process.env.HETZER_AUDIT_LOG_PATH = originalAuditPath;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("check-update and upgrade command direct users to npm", async () => {
    let stderr = "";
    const originalStderr = process.stderr.write;
    process.stderr.write = (chunk) => {
        stderr += chunk;
        return true;
    };
    const exitBefore = process.exitCode;
    try {
        await main(["check-update"]);
        assert.match(stderr, /Hetzer CLI upgrades are managed via npm/);
        assert.equal(process.exitCode, 1);
    } finally {
        process.stderr.write = originalStderr;
        process.exitCode = 0;
    }
});

test("orchestration commands emit deprecation notice pointing to Jagdpanzer", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-depr-test-"));
    const deprCommands = ["up", "down", "status", "logs", "modules", "install", "remove", "module", "validate", "tui", "update"];
    try {
        for (const cmd of deprCommands) {
            let stderrOutput = "";
            const originalStderr = process.stderr.write;
            process.stderr.write = (chunk) => {
                stderrOutput += chunk;
                return true;
            };
            try {
                await main([cmd], { root: tempDir });
                assert.match(stderrOutput, /\[!\] DEPRECATED: Multi-container stack orchestration in Hetzer/);
                assert.match(stderrOutput, /Use Jagdpanzer \(https:\/\/github\.com\/agunggnn\/jagdpanzer\) for full ops stacks/);
                assert.equal(process.exitCode, 1);
            } finally {
                process.stderr.write = originalStderr;
                process.exitCode = 0;
            }
        }
    } finally {
        process.exitCode = 0;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("audit verify and tail commands inspect workspace audit ledger", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-cli-"));
    let stdoutOutput = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        stdoutOutput += chunk;
        return true;
    };
    try {
        const { recordAuditEvent } = await import("../vault/audit.mjs");
        recordAuditEvent({
            eventType: "TEST_CLI_EVENT",
            target: "unit-test",
            result: "ALLOW",
            root: tempDir,
        });

        stdoutOutput = "";
        await main(["audit", "verify"], { root: tempDir });
        assert.match(stdoutOutput, /Status\s+:\s+\[v\] VERIFIED/);
        assert.match(stdoutOutput, /Total Events\s+:\s+1/);

        stdoutOutput = "";
        await main(["audit", "tail", "5"], { root: tempDir });
        assert.match(stdoutOutput, /TEST_CLI_EVENT/);
        assert.match(stdoutOutput, /unit-test/);

        // Rotation is a preview without --yes, and archives the ledger with it.
        const logFile = path.join(tempDir, ".hetzer", "audit.log");
        const before = fs.readFileSync(logFile);
        stdoutOutput = "";
        const exitBefore = process.exitCode;
        await main(["audit", "rotate"], { root: tempDir });
        assert.match(stdoutOutput, /PREVIEW, NOTHING CHANGED/);
        assert.ok(fs.readFileSync(logFile).equals(before));
        process.exitCode = exitBefore;

        // --yes needs a human session: not a pipe, not an agent environment, not an agent ancestor.
        const person = { input: { isTTY: true }, env: {}, ancestor: { isAgent: false } };
        for (const humanSession of [
            { ...person, input: { isTTY: false } },
            { ...person, env: { CURSOR_PROJECT_DIR: "fixture" } },
            { ...person, ancestor: { isAgent: true, processName: "agent" } },
        ]) {
            await assert.rejects(main(["audit", "rotate", "--yes"], { root: tempDir, humanSession }), /Access Denied/);
            assert.ok(fs.readFileSync(logFile).equals(before), "a refused rotation moves nothing");
        }

        stdoutOutput = "";
        await main(["audit", "rotate", "--yes", "--reason", "cli test"], { root: tempDir, humanSession: person });
        assert.match(stdoutOutput, /Archive\s+:/);
        const archives = fs.readdirSync(path.join(tempDir, ".hetzer")).filter((name) => /^audit\.log\.\d{8}T\d{6}Z$/.test(name));
        assert.equal(archives.length, 1);
        assert.ok(fs.readFileSync(path.join(tempDir, ".hetzer", archives[0])).equals(before));
        stdoutOutput = "";
        await main(["audit", "verify"], { root: tempDir });
        assert.match(stdoutOutput, /Total Events\s+:\s+1/);
    } finally {
        process.stdout.write = originalStdout;
        process.exitCode = 0;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
