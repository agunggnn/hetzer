import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import test from "node:test";

import { assertInteractiveHumanSession, checkProcessAncestors, detectAgentAncestor, promptNativeOsConfirmation, listCredentials, promptSecret, revealCredential, setCredential } from "./creds.mjs";
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

    // Reveal credential
    const revealed = revealCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
    });
    assert.equal(revealed.secret, "my-super-secret-password-123");
    assert.equal(revealed.module, "9router");
    assert.ok(revealed.usage.length > 0);

    // Update credential
    setCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
        secret: "updated-password-456",
    });
    const updated = revealCredential({
        root,
        envFile,
        id: "nine-router-initial-password",
    });
    assert.equal(updated.secret, "updated-password-456");

    fs.rmSync(root, { recursive: true, force: true });
});

test("promptSecret reads from non-TTY input stream cleanly", async () => {
    const input = Readable.from(["my-streamed-secret\n"]);
    const secret = await promptSecret("Prompt: ", { input, output: { write: () => {} } });
    assert.equal(secret, "my-streamed-secret");
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

    fs.rmSync(tempDir, { recursive: true, force: true });
});
