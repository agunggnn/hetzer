import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import { assertInteractiveHumanSession, authorizeCredentialReveal, checkProcessAncestors, detectAgentAncestor, promptNativeOsConfirmation, listCredentials, promptSecret, revealCredential, setCredential } from "./creds.mjs";
import { Grimoire, isolateMasterKey, resolveMasterKey } from "./hetzer-vault.mjs";

test("creds module can list, set, and reveal credentials in Grimoire Vault", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-creds-test-"));
    fs.mkdirSync(path.join(root, "data"));
    const envFile = path.join(root, ".env");
    const masterKey = "test-master-key-for-creds-unit-testing-32chars";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    // List initially
    const listInitial = listCredentials({ root, envFile });
    assert.ok(listInitial.length >= 6);
    const initialPass = listInitial.find((item) => item.id === "nine-router-initial-password");
    assert.equal(initialPass.configured, false);

    // Set a credential
    const setResult = setCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
        secret: "my-super-secret-password-123",
    });
    assert.equal(setResult.id, "nine-router-initial-password");
    assert.equal(setResult.envVar, "NINE_ROUTER_INITIAL_PASSWORD");

    // Check .env content
    const envContent = fs.readFileSync(envFile, "utf8");
    assert.match(envContent, /NINE_ROUTER_INITIAL_PASSWORD=secretRef:nine-router-initial-password/);
    assert.doesNotMatch(envContent, /my-super-secret-password-123/);

    assert.throws(() => revealCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
    }), /Access Denied/);

    // Update credential
    setCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
        secret: "updated-password-456",
    });
    const updatedVault = new Grimoire({
        dbPath: path.join(root, "data", "hetzer-vault.db"),
        masterKey,
    });
    try {
        const entry = updatedVault.find("nine-router-initial-password");
        assert.equal(updatedVault.resolve("nine-router-initial-password", {
            targetId: entry.projectId,
            action: entry.allowedActions[0],
        }), "updated-password-456");
        assert.equal(updatedVault.resolve("nine-router-initial-password", {
            action: entry.allowedActions[0],
        }), null);
        assert.equal(updatedVault.resolve("nine-router-initial-password"), null);
        assert.equal("_decryptRaw" in updatedVault, false);
    } finally {
        updatedVault.close();
    }

    fs.rmSync(root, { recursive: true, force: true });
});

test("promptSecret reads from non-TTY input stream cleanly", async () => {
    const input = Readable.from(["my-streamed-secret\n"]);
    const secret = await promptSecret("Prompt: ", { input, output: { write: () => {} } });
    assert.equal(secret, "my-streamed-secret");
});

test("promptSecret preserves intentional leading and trailing secret whitespace", async () => {
    const input = Readable.from(["  spaced-secret  \n"]);
    const secret = await promptSecret("Prompt: ", { input, output: { write: () => {} } });
    assert.equal(secret, "  spaced-secret  ");
});

test("assertInteractiveHumanSession blocks non-TTY or agent environments", () => {
    assert.throws(() => assertInteractiveHumanSession({
        input: { isTTY: false }, env: {}, ancestor: { isAgent: false },
    }), /Access Denied/);
    assert.throws(() => assertInteractiveHumanSession({
        input: { isTTY: true }, env: { CURSOR_PROJECT_DIR: "fixture" }, ancestor: { isAgent: false },
    }), /Cursor IDE Agent runtime detected/);
    assert.doesNotThrow(() => assertInteractiveHumanSession({
        input: { isTTY: true }, env: {}, ancestor: { isAgent: false },
    }));
});

test("checkProcessAncestors runs safely and reports inspection result", () => {
    const result = checkProcessAncestors();
    assert.equal(typeof result, "object");
    assert.equal(typeof result.isAgent, "boolean");
});

test("detectAgentAncestor checks process names across a five-generation result", () => {
    assert.deepEqual(detectAgentAncestor(["pwsh", "terminal", "claude-agent", "init"]), {
        isAgent: true,
        processName: "claude-agent",
    });
    assert.deepEqual(detectAgentAncestor(["pwsh", "terminal", "init"]), { isAgent: false });
});

test("promptNativeOsConfirmation returns the native dialog result without an environment bypass", () => {
    const allow = () => ({ status: 0 });
    const deny = () => ({ status: 1 });
    assert.equal(promptNativeOsConfirmation("test-id", { platform: "linux", run: allow }), true);
    assert.equal(promptNativeOsConfirmation("test-id", { platform: "linux", run: deny }), false);
});

test("macOS native confirmation returns success only for the Reveal button", () => {
    let appleScript = "";
    const run = (_command, args) => {
        appleScript = args.at(-1);
        return { status: 0 };
    };
    assert.equal(promptNativeOsConfirmation("test-id", { platform: "darwin", run }), true);
    assert.match(appleScript, /button returned of response is not "Reveal" then error number 1/);
    assert.match(appleScript, /default button "Deny"/);
});

test("authorizeCredentialReveal always requires native confirmation after TTY checks", () => {
    let confirmations = 0;
    const options = {
        input: { isTTY: true },
        env: {},
        ancestor: { isAgent: false },
        confirm() {
            confirmations += 1;
            return true;
        },
    };
    assert.doesNotThrow(() => authorizeCredentialReveal("test-id", options));
    assert.equal(confirmations, 1);

    assert.throws(() => authorizeCredentialReveal("test-id", {
        ...options,
        confirm: () => false,
    }), /Native OS confirmation/);
});

test("resolveMasterKey and isolateMasterKey manage key isolation lifecycle", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-key-iso-"));
    const envFile = path.join(tempDir, ".env");
    const testKey = "isolation-test-key-32-characters-minimum";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${testKey}\nFOO=BAR\n`);

    // Resolution from file when runtime env is empty
    const resolved = resolveMasterKey({
        root: tempDir,
        envValues: { HETZER_GRIMOIRE_KEY: testKey },
        baseEnv: {},
    });
    assert.equal(resolved, testKey);

    // Resolution from runtime env takes precedence
    const runtimeKey = "runtime-override-key-32-chars-at-least";
    const runtimeResolved = resolveMasterKey({
        root: tempDir,
        envValues: { HETZER_GRIMOIRE_KEY: testKey },
        baseEnv: { HETZER_GRIMOIRE_KEY: runtimeKey },
    });
    assert.equal(runtimeResolved, runtimeKey);

    const isolatedHome = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-home-"));
    fs.mkdirSync(path.join(isolatedHome, ".hetzer"), { recursive: true });
    fs.writeFileSync(path.join(isolatedHome, ".hetzer", "grimoire.key"), "isolated-key-32-characters-minimum\n");
    assert.equal(resolveMasterKey({
        root: tempDir,
        envValues: {},
        baseEnv: {},
        homeDir: isolatedHome,
    }), "isolated-key-32-characters-minimum");

    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(isolatedHome, { recursive: true, force: true });
});

test("setCredential preserves allowedActions and defaults to MCP-compatible permissions", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-creds-allowed-"));
    fs.mkdirSync(path.join(root, "data"));
    const envFile = path.join(root, ".env");
    const masterKey = "test-master-key-for-creds-allowed-actions-32";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    setCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
        secret: "test-secret-value",
    });

    const vault = new Grimoire({
        dbPath: path.join(root, "data", "hetzer-vault.db"),
        masterKey,
    });
    const item = vault.find("nine-router-initial-password");
    assert.ok(item.allowedActions.includes("mcp.tools/call"));
    assert.ok(item.allowedActions.includes("mcp.tools.call"));

    // Update with custom allowedActions
    setCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
        secret: "test-secret-value-updated",
        allowedActions: ["custom.action"],
    });
    const updatedItem = vault.find("nine-router-initial-password");
    assert.deepEqual(updatedItem.allowedActions, ["custom.action"]);

    vault.db?.close?.();
    fs.rmSync(root, { recursive: true, force: true });
});

test("Grimoire recordAudit records target_id and credential_id from snake_case and camelCase", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-audit-case-"));
    const dbPath = path.join(root, "test-vault.db");
    const masterKey = "test-master-key-for-audit-case-testing-32";
    const vault = new Grimoire({ dbPath, masterKey });

    // snake_case
    vault.recordAudit({
        actor: "canary-detector",
        action: "canary.tripwire",
        target_id: "canary-honeytoken",
        credential_id: "canary-token",
        outcome: "ABORT",
    });

    // camelCase
    vault.recordAudit({
        actor: "cli",
        action: "vault.create",
        targetId: "target-123",
        credentialId: "cred-456",
        outcome: "SUCCESS",
    });

    const rows = vault.db.prepare("SELECT actor, target_id, credential_id FROM vault_audit_events ORDER BY id ASC").all();
    assert.equal(rows.length, 2);
    assert.equal(rows[0].target_id, "canary-honeytoken");
    assert.equal(rows[0].credential_id, "canary-token");
    assert.equal(rows[1].target_id, "target-123");
    assert.equal(rows[1].credential_id, "cred-456");

    vault.db?.close?.();
    fs.rmSync(root, { recursive: true, force: true });
});
