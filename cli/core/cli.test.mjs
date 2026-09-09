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
    printModuleHelp,
    resolveProjectRoot,
    suggestCommand,
} from "./cli.mjs";
import { parseEnv } from "./env.mjs";
import { Grimoire } from "../vault/hetzer-vault.mjs";

test("initializeProject creates a secured, repeatable project contract", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-init-"));
    const initResult = initializeProject(root);
    assert.equal(initResult.initialPassword, undefined);
    assert.equal(initResult.initialPasswordRef, "secretRef:nine-router-initial-password");
    const first = fs.readFileSync(path.join(root, ".env"), "utf8");
    const values = parseEnv(first);
    assert.match(values.NINE_ROUTER_JWT_SECRET, /^secretRef:/);
    assert.ok(values.HETZER_GRIMOIRE_KEY.length >= 32);
    assert.equal(fs.existsSync(path.join(root, "data", "hetzer-vault.db")), true);
    assert.equal(fs.existsSync(path.join(root, "modules", "cognee", "module.json")), true);

    initializeProject(root);
    assert.equal(fs.readFileSync(path.join(root, ".env"), "utf8"), first);
    fs.rmSync(root, { recursive: true, force: true });
});

test("init output never includes the stored initial password", async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-core-init-output-"));
    let output = "";
    const originalWrite = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += String(chunk);
        return true;
    };
    try {
        await main(["init", root], { root });
        const values = parseEnv(fs.readFileSync(path.join(root, ".env"), "utf8"));
        const vault = new Grimoire({
            dbPath: path.join(root, "data", "hetzer-vault.db"),
            masterKey: values.HETZER_GRIMOIRE_KEY,
        });
        const initialPassword = vault.reveal("nine-router-initial-password");
        vault.close();
        assert.ok(initialPassword);
        assert.equal(output.includes(initialPassword), false);
        assert.match(output, /secretRef:nine-router-initial-password/);
    } finally {
        process.stdout.write = originalWrite;
        fs.rmSync(root, { recursive: true, force: true });
    }
});

test("Compose startup encodes dynamic route chunks before 9Router starts", () => {
    const template = fs.readFileSync(path.resolve(import.meta.dirname, "..", "templates", "docker-compose.yml"), "utf8");
    assert.match(template, /replaceAll\("%5B","%255B"\)/);
    assert.match(template, /replaceAll\("%5D","%255D"\)/);
    assert.ok(template.indexOf("Encoded dynamic route paths") < template.indexOf("exec node custom-server.js"));
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
        fs.writeFileSync(path.join(tempDir, "docker-compose.yml"), "services:\n  nine-router:\n    image: test\n");
        fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_PROJECT_NAME=test\n");
        assert.equal(isHetzerWorkspace(tempDir), true);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("printModuleHelp renders native module guide for 9router and cognee", () => {
    let output = "";
    const originalWrite = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    try {
        printModuleHelp("9router", ".", { NINE_ROUTER_PORT: "20140" });
        assert.match(output, /NATIVE MODULE GUIDE: 9Router/);
        assert.match(output, /hetzer up 9router/);
        assert.match(output, /nine-router-initial-password/);
    } finally {
        process.stdout.write = originalWrite;
    }
});

test("install auto-scaffolds module directory from templates if missing in workspace", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-install-test-"));
    const originalStdout = process.stdout.write;
    process.stdout.write = () => true;
    try {
        fs.writeFileSync(path.join(tempDir, "docker-compose.yml"), "services:\n");
        fs.writeFileSync(path.join(tempDir, ".env"), "HETZER_ENABLED_MODULES=\nHETZER_DISABLED_MODULES=\n");
        assert.equal(fs.existsSync(path.join(tempDir, "modules", "cognee", "module.json")), false);

        await main(["install", "cognee"], { root: tempDir });

        assert.equal(fs.existsSync(path.join(tempDir, "modules", "cognee", "module.json")), true);
        const envContent = fs.readFileSync(path.join(tempDir, ".env"), "utf8");
        assert.match(envContent, /HETZER_ENABLED_MODULES=.*cognee/);
    } finally {
        process.stdout.write = originalStdout;
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("validate CLI command validates modules successfully", async () => {
    let output = "";
    const originalStdout = process.stdout.write;
    process.stdout.write = (chunk) => {
        output += chunk;
        return true;
    };
    const createdEnv = !fs.existsSync(".env");
    if (createdEnv) {
        fs.writeFileSync(".env", "HETZER_ENABLED_MODULES=\n");
    }
    try {
        await main(["validate", "cognee"], { root: "." });
        assert.match(output, /MODULE VALIDATION: cognee/);
        assert.match(output, /Status: Module 'cognee' VALID/);
    } finally {
        if (createdEnv) {
            try { fs.unlinkSync(".env"); } catch { /* ignore */ }
        }
        process.stdout.write = originalStdout;
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

test("suggestCommand suggests closest command for typos", () => {
    assert.equal(suggestCommand("protectt"), "protect");
    assert.equal(suggestCommand("initz"), "init");
    assert.equal(suggestCommand("doc"), "doctor");
    assert.equal(suggestCommand("credi"), "creds");
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
        assert.match(output, /npx hetzer up/);
        assert.match(output, /npx hetzer creds reveal/);
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
        assert.match(output, /npm install -g hetzer/);
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
