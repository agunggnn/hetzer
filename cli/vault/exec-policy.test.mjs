import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    applyExecPolicy,
    assertNoShellMetacharacters,
    computeEmbeddedPolicyHash,
    containsShellMetacharacters,
    loadExecPolicy,
    matchesAllowedCommand,
    parseArgvTokens,
    validateExecPolicy,
} from "./exec-policy.mjs";
import { executeProcess, resolveCommandForSpawn } from "./exec.mjs";
import { loadBrokerPolicy } from "./http-broker.mjs";
import { setCredential } from "./creds.mjs";

test("validateExecPolicy validates and normalizes policy configurations", () => {
    const valid = validateExecPolicy({
        version: 1,
        name: "test-runner",
        allowedCommands: ["npm test", "node test.js"],
        allowedCredentials: ["NPM_TOKEN"],
        allowRawUnmediated: ["npm-token"],
        strict: true,
        canary: true,
        maxTimeout: "45s",
    });

    assert.equal(valid.version, 1);
    assert.equal(valid.name, "test-runner");
    assert.deepEqual(valid.allowedCommands, ["npm test", "node test.js"]);
    assert.deepEqual(valid.allowedCredentials, ["NPM_TOKEN"]);
    assert.deepEqual(valid.allowRawUnmediated, ["npm-token"]);
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
    assert.throws(() => validateExecPolicy({ allowRawUnmediated: "not-array" }), /must be an array/);
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
    const allowed = ["npm test", "node test.js", "git status --short", "pytest -v"];

    assert.equal(matchesAllowedCommand("npm", ["test"], allowed), true);
    assert.equal(matchesAllowedCommand("node", ["test.js"], allowed), true);
    assert.equal(matchesAllowedCommand("git", ["status", "--short"], allowed), true);
    assert.equal(matchesAllowedCommand("pytest", ["-v"], allowed), true);

    assert.equal(matchesAllowedCommand("curl", ["https://malicious.test"], allowed), false);
    assert.equal(matchesAllowedCommand("npm", ["publish"], allowed), false);
    assert.equal(matchesAllowedCommand("bash", ["-c", "rm -rf /"], allowed), false);

    // Exact structured argv enforcement (prefix match without wildcard must fail)
    assert.equal(matchesAllowedCommand("git", ["status", "--short", "--branch"], allowed), false);
    assert.equal(matchesAllowedCommand("git", ["status", "--short"], ["git status"]), false);
    assert.equal(matchesAllowedCommand("pytest", ["-v"], ["pytest"]), false);

    // Explicit wildcard forms
    const allowedWildcard = ["git status *", "pytest **"];
    assert.equal(matchesAllowedCommand("git", ["status", "--short"], allowedWildcard), true);
    assert.equal(matchesAllowedCommand("pytest", ["-v", "-k", "test_core"], allowedWildcard), true);
});

test("applyExecPolicy enforces policy constraints on execution options", () => {
    const policy = {
        name: "restricted-agent",
        allowedCommands: ["node index.js"],
        allowedCredentials: ["NPM_TOKEN", "DB_URL"],
        allowRawUnmediated: ["npm-token"],
        strict: true,
        canary: true,
        maxTimeout: "30s",
    };

    // Permitted command & credentials
    const applied = applyExecPolicy(policy, {
        command: "node",
        commandArgs: ["index.js"],
        allowNames: ["NPM_TOKEN"],
        allowRawUnmediated: ["npm-token"],
    });
    assert.equal(applied.strict, true);
    assert.equal(applied.canary, true);
    assert.equal(applied.timeoutMs, 30000);
    assert.deepEqual(applied.allowNames, ["NPM_TOKEN"]);
    assert.deepEqual(applied.allowRawUnmediated, ["npm-token"]);

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

    assert.throws(
        () => applyExecPolicy(policy, {
            command: "node",
            commandArgs: ["index.js"],
            allowNames: ["DB_URL"],
            allowRawUnmediated: ["DB_URL"],
        }),
        (err) => err.code === "ERR_POLICY_RAW_UNMEDIATED_FORBIDDEN"
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
        allowRawUnmediated: ["npm-token"],
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
        allowRawUnmediated: ["npm-token"],
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

test("assertNoShellMetacharacters detects and rejects command injection vectors", () => {
    // Chaining vectors
    assert.throws(() => assertNoShellMetacharacters("npm", ["test", "&&", "calc"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("npm", ["test", "&", "whoami"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("git", ["status", "|", "clip"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("git", ["status", "||", "echo", "fail"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("node", ["app.js", ";", "rm", "-rf"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");

    // Redirection vectors
    assert.throws(() => assertNoShellMetacharacters("node", ["app.js", ">", "out.txt"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("node", ["<", "secrets.env"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");

    // Substitution vectors
    assert.throws(() => assertNoShellMetacharacters("echo", ["$SECRET"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("echo", ["$(whoami)"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("echo", ["`id`"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");

    // Windows cmd variable expansion and escapes
    assert.throws(() => assertNoShellMetacharacters("echo", ["%NODE_AUTH_TOKEN%"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("echo", ["%COMSPEC%"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("echo", ["^&"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");

    // Delimiters
    assert.throws(() => assertNoShellMetacharacters("node", ["test\nwhoami"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("node", ["test\recho"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");
    assert.throws(() => assertNoShellMetacharacters("node", ["test\0exploit"]), (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN");

    // Safe arguments must not throw
    assert.doesNotThrow(() => assertNoShellMetacharacters("node", ["index.js", "--port", "8080", "C:\\path\\to\\file"]));
    assert.doesNotThrow(() => assertNoShellMetacharacters("git", ["commit", "-m", "fix: issue #42"]));
});

test("matchesAllowedCommand defeats command chaining, prefix matching, and quoting escapes", () => {
    const allowed = ["npm test", "git status --short", "node \"my script.js\"", "pytest -v"];

    // Chaining attempts
    assert.equal(matchesAllowedCommand("npm", ["test", "&&", "calc"], allowed), false);
    assert.equal(matchesAllowedCommand("npm", ["test", "&", "dir"], allowed), false);
    assert.equal(matchesAllowedCommand("git", ["status", "--short", ";", "whoami"], allowed), false);
    assert.equal(matchesAllowedCommand("git", ["status", "--short", "|", "findstr", "secret"], allowed), false);

    // Prefix extension attacks without metacharacters must be blocked by exact structured argv
    assert.equal(matchesAllowedCommand("npm", ["test", "--unauthorized-flag"], allowed), false);
    assert.equal(matchesAllowedCommand("npm", ["test", "extra-arg"], allowed), false);
    assert.equal(matchesAllowedCommand("git", ["status", "--short", "--ignored"], allowed), false);

    // Quoting preservation
    assert.equal(matchesAllowedCommand("node", ["my script.js"], allowed), true);
    assert.equal(matchesAllowedCommand("node", ["my", "script.js"], allowed), false);

    // Malformed quotes in policy rule
    assert.throws(() => parseArgvTokens('node "unclosed string'), /unclosed quote/);
});

test("executeProcess rejects Windows cmd.exe, PowerShell, and shell metacharacters end-to-end", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-adversarial-"));
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "NODE_AUTH_TOKEN=secretRef:npm-token\n");

    // 1. Chained command injection via && rejected
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "node",
            commandArgs: ["-e", "1", "&&", "calc"],
        }),
        (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN"
    );

    // 2. Chained command injection via ; rejected
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "node",
            commandArgs: ["-e", "1", ";", "whoami"],
        }),
        (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN"
    );

    // 3. Variable expansion via % rejected
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "node",
            commandArgs: ["-e", "console.log(1)", "%NODE_AUTH_TOKEN%"],
        }),
        (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN"
    );

    // 4. Windows cmd.exe environment reflection blocked
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "cmd.exe",
            commandArgs: ["/c", "set"],
        }),
        (err) => err.code === "ERR_REFLECTION_BLOCKED"
    );

    // 5. PowerShell reflection blocked
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "powershell",
            commandArgs: ["-Command", "Get-ChildItem env:"],
        }),
        (err) => err.code === "ERR_REFLECTION_BLOCKED"
    );

    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "pwsh",
            commandArgs: ["-c", "$env:NODE_AUTH_TOKEN"],
        }),
        (err) => err.code === "ERR_SHELL_METACHARACTERS_FORBIDDEN" || err.code === "ERR_REFLECTION_BLOCKED"
    );

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("policy trust roots enforce regular files, SHA-256 hashing, and integrity checks", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-policy-trust-"));
    const policyPath = path.join(tempDir, "policy.json");
    const policyData = {
        name: "audited-policy",
        allowedCommands: ["npm test"],
        strict: true,
    };
    fs.writeFileSync(policyPath, JSON.stringify(policyData, null, 2));

    // 1. Loading computes cryptographic SHA-256 policyHash
    const loaded = loadExecPolicy(policyPath);
    const expectedHash = crypto.createHash("sha256").update(fs.readFileSync(policyPath, "utf8")).digest("hex");
    assert.equal(loaded.policyHash, expectedHash);
    assert.equal(loaded.policyFile, policyPath);

    // 2. Expected hash verification succeeds when matching
    const loadedWithHash = loadExecPolicy(policyPath, tempDir, { expectedHash });
    assert.equal(loadedWithHash.policyHash, expectedHash);

    // 3. Expected hash verification fails when tampered
    assert.throws(
        () => loadExecPolicy(policyPath, tempDir, { expectedHash: "0000000000000000000000000000000000000000000000000000000000000000" }),
        (err) => {
            assert.equal(err.code, "ERR_POLICY_INTEGRITY_FAILED");
            assert.match(err.message, /integrity verification failed/i);
            return true;
        }
    );

    // 4. Directory as policy file is rejected
    assert.throws(
        () => loadExecPolicy(tempDir),
        /regular file/
    );

    // 5. Symbolic link policy file is strictly rejected
    const symlinkPath = path.join(tempDir, "symlink-policy.json");
    try {
        fs.symlinkSync(policyPath, symlinkPath);
        assert.throws(
            () => loadExecPolicy(symlinkPath),
            /cannot be a symbolic link/
        );
    } catch (e) {
        // Skip on environments where unprivileged symlink creation is restricted by OS
        if (e.code !== "EPERM") throw e;
    }

    // 6. Detached hash file (.sha256) verification
    const detachedFile = `${policyPath}.sha256`;
    fs.writeFileSync(detachedFile, `${expectedHash}  ${path.basename(policyPath)}\n`);
    const loadedDetached = loadExecPolicy(policyPath, tempDir);
    assert.equal(loadedDetached.policyHash, expectedHash);

    // Tamper the detached hash file -> fails closed
    fs.writeFileSync(detachedFile, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n");
    assert.throws(
        () => loadExecPolicy(policyPath, tempDir),
        (err) => err.code === "ERR_POLICY_INTEGRITY_FAILED"
    );
    fs.rmSync(detachedFile, { force: true });

    // 7. Embedded canonicalized hash verification
    const embeddedPolicyData = {
        version: 1,
        name: "embedded-audited-policy",
        allowedCommands: ["npm test"],
        strict: true,
    };
    const computedEmbedded = computeEmbeddedPolicyHash(embeddedPolicyData);
    embeddedPolicyData.integrity = { sha256: computedEmbedded };
    const embeddedPath = path.join(tempDir, "embedded-policy.json");
    fs.writeFileSync(embeddedPath, JSON.stringify(embeddedPolicyData, null, 2));

    const loadedEmbedded = loadExecPolicy(embeddedPath, tempDir);
    assert.equal(loadedEmbedded.embeddedHash, computedEmbedded);

    // Tampering the embedded content causes failure
    embeddedPolicyData.name = "tampered-name";
    fs.writeFileSync(embeddedPath, JSON.stringify(embeddedPolicyData, null, 2));
    assert.throws(
        () => loadExecPolicy(embeddedPath, tempDir),
        (err) => err.code === "ERR_POLICY_INTEGRITY_FAILED"
    );

    // 8. HTTP broker policy trust root
    const brokerPolicyPath = path.join(tempDir, "broker-policy.json");
    const brokerData = {
        version: 1,
        target: "https://api.github.com",
        credential: "secretRef:github-token",
        baseUrlEnv: "GITHUB_API_URL",
        tokenEnv: "GITHUB_TOKEN",
        basePath: "/repos",
        allowedPathPrefixes: ["/repos"],
    };
    fs.writeFileSync(brokerPolicyPath, JSON.stringify(brokerData, null, 2));

    const loadedBroker = loadBrokerPolicy(brokerPolicyPath);
    const expectedBrokerHash = crypto.createHash("sha256").update(fs.readFileSync(brokerPolicyPath, "utf8")).digest("hex");
    assert.equal(loadedBroker.policyHash, expectedBrokerHash);

    assert.throws(
        () => loadBrokerPolicy(brokerPolicyPath, { expectedHash: "deadbeef" }),
        (err) => err.code === "ERR_POLICY_INTEGRITY_FAILED"
    );

    fs.rmSync(tempDir, { recursive: true, force: true });
});
