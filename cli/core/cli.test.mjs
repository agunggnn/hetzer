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
import { Grimoire, isolateMasterKey, locateMasterKey, resolveMasterKey } from "../vault/hetzer-vault.mjs";

function listFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const full = path.join(dir, entry.name);
        return entry.isDirectory() ? listFiles(full) : [full];
    });
}

test("initializeProject keeps the master key outside the workspace and is repeatable", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-init-"));
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-home-"));
    try {
        const initResult = initializeProject(root, { homeDir });
        assert.equal(initResult.root, path.resolve(root));
        assert.equal(initResult.keySource, "instance-file");
        const first = fs.readFileSync(path.join(root, ".env"), "utf8");
        const values = parseEnv(first);
        assert.equal(values.HETZER_GRIMOIRE_KEY, undefined);
        assert.match(values.HETZER_INSTANCE_ID, /^[a-f0-9]{32}$/);
        const keyFile = path.join(homeDir, ".hetzer", "keys", `${values.HETZER_INSTANCE_ID}.key`);
        assert.equal(initResult.keyFile, keyFile);
        const masterKey = fs.readFileSync(keyFile, "utf8").trim();
        assert.ok(masterKey.length >= 32);
        if (process.platform !== "win32") assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600);
        for (const file of listFiles(root)) {
            assert.equal(fs.readFileSync(file).includes(masterKey), false, `${file} must not contain the master key`);
        }
        assert.equal(fs.existsSync(path.join(root, "data", "hetzer-vault.db")), true);
        assert.equal(fs.existsSync(path.join(root, ".mcp.json")), true);
        assert.equal(resolveMasterKey({ envValues: values, homeDir }), masterKey);

        initializeProject(root, { homeDir });
        assert.equal(fs.readFileSync(path.join(root, ".env"), "utf8"), first);
        assert.equal(fs.readFileSync(keyFile, "utf8").trim(), masterKey);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(homeDir, { recursive: true, force: true });
    }
});

test("initializeProject keeps a key already in .env and isolate-key moves it to the instance key file", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-legacy-"));
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-home-"));
    const legacyKey = ["legacy", "workspace", "key", "value", "0123456789"].join("-");
    try {
        fs.writeFileSync(path.join(root, ".env"), `HETZER_PROJECT_NAME=legacy\nHETZER_GRIMOIRE_KEY=${legacyKey}\n`);
        const result = initializeProject(root, { homeDir });
        assert.equal(result.keySource, "env-file");
        assert.equal(parseEnv(fs.readFileSync(path.join(root, ".env"), "utf8")).HETZER_GRIMOIRE_KEY, legacyKey);

        const isolated = isolateMasterKey({ root, homeDir });
        const values = parseEnv(fs.readFileSync(path.join(root, ".env"), "utf8"));
        assert.equal(values.HETZER_GRIMOIRE_KEY, undefined);
        assert.equal(isolated.isolatedFile, path.join(homeDir, ".hetzer", "keys", `${values.HETZER_INSTANCE_ID}.key`));
        assert.equal(locateMasterKey({ envValues: values, homeDir }).source, "instance-file");
        assert.equal(resolveMasterKey({ envValues: values, homeDir }), legacyKey);
        assert.equal(isolateMasterKey({ root, homeDir }).alreadyIsolated, true);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(homeDir, { recursive: true, force: true });
    }
});

test("initializeProject refuses to generate a key over an existing vault whose key is missing", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-lost-"));
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-home-"));
    try {
        const { keyFile } = initializeProject(root, { homeDir });
        fs.rmSync(keyFile);
        assert.throws(() => initializeProject(root, { homeDir }), (error) => error.code === "ERR_MASTER_KEY_NOT_FOUND");
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(homeDir, { recursive: true, force: true });
    }
});

test("a new workspace does not adopt the shared isolated key; an existing vault keeps using it", () => {
    const fresh = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-fresh-"));
    const existing = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-shared-"));
    const homeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-home-"));
    const sharedKey = ["shared", "isolated", "key", "value", "0123456789"].join("-");
    try {
        fs.mkdirSync(path.join(homeDir, ".hetzer"), { recursive: true });
        fs.writeFileSync(path.join(homeDir, ".hetzer", "grimoire.key"), `${sharedKey}\n`);

        const freshResult = initializeProject(fresh, { homeDir });
        assert.equal(freshResult.keySource, "instance-file");
        assert.notEqual(fs.readFileSync(freshResult.keyFile, "utf8").trim(), sharedKey);

        fs.mkdirSync(path.join(existing, "data"), { recursive: true });
        new Grimoire({ dbPath: path.join(existing, "data", "hetzer-vault.db"), masterKey: sharedKey }).close();
        fs.writeFileSync(path.join(existing, ".env"), "HETZER_PROJECT_NAME=shared\n");
        assert.equal(initializeProject(existing, { homeDir }).keySource, "shared-file");
        assert.equal(parseEnv(fs.readFileSync(path.join(existing, ".env"), "utf8")).HETZER_INSTANCE_ID, undefined);
    } finally {
        for (const dir of [fresh, existing, homeDir]) fs.rmSync(dir, { recursive: true, force: true });
    }
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
        await main(["init", path.join(tempDir, "ws")], { root: tempDir });
        assert.match(output, /HETZER - INITIALIZATION SUCCESSFUL/);
        assert.match(output, /Master Key {8}: .*\.hetzer[\\/]keys[\\/][a-f0-9]{32}\.key \(mode 0600\)/);
        assert.match(output, /npx hetzer exec/);
        assert.match(output, /npx hetzer creds/);
    } finally {
        if (originalTestGlobal === undefined) delete process.env.HETZER_TEST_GLOBAL_CLI;
        else process.env.HETZER_TEST_GLOBAL_CLI = originalTestGlobal;
        if (originalInstallHome === undefined) delete process.env.HETZER_INSTALL_HOME;
        else process.env.HETZER_INSTALL_HOME = originalInstallHome;
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

test("agent command runs the agent through srt with no credentials and records its start and exit", { skip: process.platform === "win32" ? "fake srt is a shell script" : false }, async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-agent-cli-"));
    const project = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-agent-project-"));
    const auditPath = path.join(tempDir, "audit.log");
    const argsFile = path.join(tempDir, "srt-args.txt");
    const fakeSrt = path.join(tempDir, "fake-srt");
    const saved = { exitCode: process.exitCode, audit: process.env.HETZER_AUDIT_LOG_PATH, srt: process.env.HETZER_SRT_BIN, stderr: process.stderr.write };
    fs.writeFileSync(fakeSrt, `#!/bin/sh\nif [ "$1" = "--version" ]; then echo 0.0.78; exit 0; fi\nprintf '%s\\n' "$@" > ${JSON.stringify(argsFile)}\nexit 7\n`, { mode: 0o755 });
    process.env.HETZER_AUDIT_LOG_PATH = auditPath;
    process.env.HETZER_SRT_BIN = fakeSrt;
    process.stderr.write = () => true;
    try {
        fs.writeFileSync(path.join(tempDir, ".env"), "API_KEY=secretRef:some-cred\n", "utf8");
        await main(["agent", "--sandbox-mount", project, "--sandbox-allow-host", "api.example.com", "--", "/bin/true", "--flag"], { root: tempDir });
        assert.equal(process.exitCode, 7, "the agent's exit status is returned");
        const srtArgs = fs.readFileSync(argsFile, "utf8").trim().split("\n");
        assert.deepEqual(srtArgs.slice(srtArgs.indexOf("--")), ["--", "/bin/true", "--flag"]);
        const events = fs.readFileSync(auditPath, "utf8").trim().split("\n").map((line) => JSON.parse(line));
        const start = events.find((event) => event.eventType === "SANDBOX_EXEC");
        assert.equal(start.details.engine, "srt");
        assert.equal(start.details.agent, true);
        assert.deepEqual(start.details.allowHosts, ["api.example.com"]);
        const exit = events.find((event) => event.eventType === "AGENT_EXIT");
        assert.equal(exit.details.status, 7);

        await assert.rejects(main(["agent", "--host", "--", "/bin/true"], { root: tempDir }), /always runs the agent in a sandbox/);
    } finally {
        process.exitCode = saved.exitCode;
        process.stderr.write = saved.stderr;
        if (saved.audit === undefined) delete process.env.HETZER_AUDIT_LOG_PATH;
        else process.env.HETZER_AUDIT_LOG_PATH = saved.audit;
        if (saved.srt === undefined) delete process.env.HETZER_SRT_BIN;
        else process.env.HETZER_SRT_BIN = saved.srt;
        fs.rmSync(tempDir, { recursive: true, force: true });
        fs.rmSync(project, { recursive: true, force: true });
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

test("orchestration commands print a removal notice and exit with code 1", async () => {
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
                assert.match(stderrOutput, /was removed in 0\.6\.0 and has no replacement in Hetzer/);
                assert.match(stderrOutput, /docs\/upgrade-0\.6\.md/);
                assert.doesNotMatch(stderrOutput, /jagdpanzer/i);
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
