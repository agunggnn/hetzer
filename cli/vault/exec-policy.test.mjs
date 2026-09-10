import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { applyExecPolicy, loadExecPolicy, matchesAllowedCommand, validateExecPolicy } from "./exec-policy.mjs";
import { executeProcess } from "./exec.mjs";
import { setCredential } from "./creds.mjs";

test("validateExecPolicy validates and normalizes policy configurations", () => {
    const valid = validateExecPolicy({
        version: 1,
        name: "test-runner",
        allowedCommands: ["npm test", "node test.js"],
        allowedCredentials: ["NPM_TOKEN"],
        strict: true,
        canary: true,
        maxTimeout: "45s",
    });

    assert.equal(valid.version, 1);
    assert.equal(valid.name, "test-runner");
    assert.deepEqual(valid.allowedCommands, ["npm test", "node test.js"]);
    assert.deepEqual(valid.allowedCredentials, ["NPM_TOKEN"]);
    assert.equal(valid.strict, true);
    assert.equal(valid.canary, true);
    assert.equal(valid.maxTimeout, "45s");
    assert.equal(valid.maxTimeoutMs, 45000);

    // Rejection tests
    assert.throws(() => validateExecPolicy(null), /JSON object/);
    assert.throws(() => validateExecPolicy("string"), /JSON object/);
    assert.throws(() => validateExecPolicy({ version: 99 }), /Unsupported execution policy version/);
    assert.throws(() => validateExecPolicy({ name: "" }), /non-empty string/);
    assert.throws(() => validateExecPolicy({ allowedCommands: [] }), /non-empty array/);
    assert.throws(() => validateExecPolicy({ allowedCommands: [123] }), /Invalid command in allowedCommands/);
    assert.throws(() => validateExecPolicy({ allowedCredentials: "not-array" }), /must be an array/);
    assert.throws(() => validateExecPolicy({ strict: "true" }), /must be a boolean/);
    assert.throws(() => validateExecPolicy({ canary: "yes" }), /must be a boolean/);
    assert.throws(() => validateExecPolicy({ maxTimeout: "invalid" }), /Invalid timeout duration/);
});

test("loadExecPolicy loads, parses, and validates policy JSON files", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-policy-load-"));
    const policyPath = path.join(tempDir, "policy.json");

    fs.writeFileSync(policyPath, JSON.stringify({
        name: "ci-policy",
        allowedCommands: ["npm run check", "npm test"],
        strict: true,
        maxTimeout: "10s",
    }));

    const loaded = loadExecPolicy(policyPath);
    assert.equal(loaded.name, "ci-policy");
    assert.deepEqual(loaded.allowedCommands, ["npm run check", "npm test"]);
    assert.equal(loaded.strict, true);
    assert.equal(loaded.maxTimeoutMs, 10000);

    assert.throws(() => loadExecPolicy(path.join(tempDir, "nonexistent.json")), /not found/);

    fs.writeFileSync(path.join(tempDir, "corrupted.json"), "{ invalid json ");
    assert.throws(() => loadExecPolicy(path.join(tempDir, "corrupted.json")), /Failed to parse execution policy JSON/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("matchesAllowedCommand matches allowed command forms and rejects forbidden commands", () => {
    const allowed = ["npm test", "node test.js", "git status", "pytest"];

    assert.equal(matchesAllowedCommand("npm", ["test"], allowed), true);
    assert.equal(matchesAllowedCommand("node", ["test.js"], allowed), true);
    assert.equal(matchesAllowedCommand("git", ["status", "--short"], allowed), true);
    assert.equal(matchesAllowedCommand("pytest", ["-v"], allowed), true);

    assert.equal(matchesAllowedCommand("curl", ["https://malicious.test"], allowed), false);
    assert.equal(matchesAllowedCommand("npm", ["publish"], allowed), false);
    assert.equal(matchesAllowedCommand("bash", ["-c", "rm -rf /"], allowed), false);
});

test("applyExecPolicy enforces policy constraints on execution options", () => {
    const policy = {
        name: "restricted-agent",
        allowedCommands: ["node index.js"],
        allowedCredentials: ["NPM_TOKEN", "DB_URL"],
        strict: true,
        canary: true,
        maxTimeout: "30s",
    };

    // Permitted command & credentials
    const applied = applyExecPolicy(policy, {
        command: "node",
        commandArgs: ["index.js"],
        allowNames: ["NPM_TOKEN"],
    });
    assert.equal(applied.strict, true);
    assert.equal(applied.canary, true);
    assert.equal(applied.timeoutMs, 30000);
    assert.deepEqual(applied.allowNames, ["NPM_TOKEN"]);

    // Forbidden command rejected
    assert.throws(
        () => applyExecPolicy(policy, { command: "curl", commandArgs: ["https://evil.test"] }),
        (err) => {
            assert.equal(err.code, "ERR_POLICY_COMMAND_FORBIDDEN");
            return true;
        }
    );

    // Forbidden credential requested rejected
    assert.throws(
        () => applyExecPolicy(policy, {
            command: "node",
            commandArgs: ["index.js"],
            allowNames: ["AWS_SECRET_KEY"],
        }),
        (err) => {
            assert.equal(err.code, "ERR_POLICY_CREDENTIAL_FORBIDDEN");
            return true;
        }
    );

    // Excessive timeout rejected
    assert.throws(
        () => applyExecPolicy(policy, {
            command: "node",
            commandArgs: ["index.js"],
            timeout: "60s",
            timeoutMs: 60000,
        }),
        (err) => {
            assert.equal(err.code, "ERR_POLICY_TIMEOUT_EXCEEDED");
            return true;
        }
    );
});

test("executeProcess with policy enforces declarative boundaries end-to-end", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-policy-e2e-"));
    const envFile = path.join(tempDir, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\nNPM_TOKEN=secretRef:npm-token\n`);

    setCredential({ root: tempDir, envFile, id: "npm-token", secret: "super-secret-npm-token" });

    const safeScript = path.join(tempDir, "safe-work.js");
    fs.writeFileSync(safeScript, `process.stdout.write("Safe task completed successfully\\n");`);

    const policyFile = path.join(tempDir, "agent-policy.json");
    fs.writeFileSync(policyFile, JSON.stringify({
        name: "agent-guard-policy",
        allowedCommands: [`node ${safeScript}`],
        allowedCredentials: ["NPM_TOKEN"],
        strict: true,
        canary: true,
        maxTimeout: "10s",
    }));

    let capturedOut = "";
    const mockOut = { write(chunk) { capturedOut += chunk; return true; } };

    // 1. Permitted execution succeeds
    const result = await executeProcess({
        root: tempDir,
        envFile,
        policyFile,
        command: "node",
        commandArgs: [safeScript],
    }, { outStream: mockOut });

    assert.equal(result.status, 0);
    assert.match(capturedOut, /Safe task completed successfully/);

    // 2. Disallowed command is blocked
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            policyFile,
            command: "node",
            commandArgs: ["-e", "process.stdout.write('unauthorized')"],
        }),
        (err) => {
            assert.equal(err.code, "ERR_POLICY_COMMAND_FORBIDDEN");
            assert.match(err.message, /not permitted by allowedCommands/);
            return true;
        }
    );

    // 3. Disallowed credential request is blocked
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            policyFile,
            allowNames: ["UNAUTHORIZED_TOKEN"],
            command: "node",
            commandArgs: [safeScript],
        }),
        (err) => {
            assert.equal(err.code, "ERR_POLICY_CREDENTIAL_FORBIDDEN");
            return true;
        }
    );

    fs.rmSync(tempDir, { recursive: true, force: true });
});
