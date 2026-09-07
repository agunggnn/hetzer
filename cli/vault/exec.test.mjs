import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createStreamSanitizer, executeProcess, isReflectionCommand, sanitizeStreamOutput } from "./exec.mjs";
import { setCredential } from "./creds.mjs";

test("isReflectionCommand accurately detects and blocks environment reflection attempts", () => {
    assert.equal(isReflectionCommand("printenv"), true);
    assert.equal(isReflectionCommand("env"), true);
    assert.equal(isReflectionCommand("export"), true);
    assert.equal(isReflectionCommand("set"), true);
    assert.equal(isReflectionCommand("sh", ["-c", "printenv"]), true);
    assert.equal(isReflectionCommand("node", ["-e", "console.log(process.env)"]), true);
    assert.equal(isReflectionCommand("python", ["-c", "import os; print(os.environ)"]), true);
    assert.equal(isReflectionCommand("cat", ["/proc/self/environ"]), true);

    // Legitimate build and runtime commands are permitted
    assert.equal(isReflectionCommand("node", ["index.js"]), false);
    assert.equal(isReflectionCommand("npm", ["test"]), false);
    assert.equal(isReflectionCommand("docker", ["compose", "up"]), false);
    assert.equal(isReflectionCommand("curl", ["https://api.github.com"]), false);
});

test("sanitizeStreamOutput redacts resolved secrets and raw tokens back to secretRef", () => {
    const rawSecret = "super-secret-token-xyz-123456";
    const secretsToRedact = [{ id: "db-password", secret: rawSecret }];

    // Direct echo of secret
    const output = `Database connection initiated with password: ${rawSecret}`;
    const sanitized = sanitizeStreamOutput(output, secretsToRedact);
    assert.equal(sanitized, "Database connection initiated with password: secretRef:db-password");
    assert.doesNotMatch(sanitized, new RegExp(rawSecret));

    // Detection rules redaction
    const mockToken = ["npm", "_", "abcdef1234567890abcdef12345678901234"].join("");
    const tokenOutput = `Crash log: token=${mockToken}`;
    const sanitizedToken = sanitizeStreamOutput(tokenOutput, []);
    assert.match(sanitizedToken, /secretRef:npm-token/);

    assert.equal(
        sanitizeStreamOutput("PIN=demo", [{ id: "short-value", secret: "demo" }]),
        "PIN=secretRef:short-value"
    );
});

test("createStreamSanitizer redacts secrets split across output chunks", () => {
    const sanitizer = createStreamSanitizer([{ id: "split-value", secret: "synthetic-split-value" }]);
    const output = sanitizer.write(Buffer.from("result=synthetic-"))
        + sanitizer.write(Buffer.from("split-value\n"))
        + sanitizer.end();
    assert.equal(output, "result=secretRef:split-value\n");
});

test("executeProcess blocks reflection commands from running", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-test-"));
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            command: "printenv",
            commandArgs: [],
        }),
        (err) => {
            assert.equal(err.code, "ERR_REFLECTION_BLOCKED");
            assert.match(err.message, /Security violation/);
            return true;
        }
    );

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess sanitizes stdout stream in real time", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-stream-"));
    const dataDir = path.join(tempDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(tempDir, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    const secretValue = "injected-secret-value-abc-987654";
    setCredential({
        root: tempDir,
        envFile,
        id: "npm-token",
        secret: secretValue,
    });

    let capturedOutput = "";
    const mockOutStream = {
        write(chunk) {
            capturedOutput += chunk;
            return true;
        },
    };

    // Run a node script that tries to print the secret directly
    const script = `process.stdout.write("Resolved secret: " + process.env.NODE_AUTH_TOKEN + "\\n");`;
    const scriptFile = path.join(tempDir, "test-script.js");
    fs.writeFileSync(scriptFile, script);

    const result = await executeProcess({
        root: tempDir,
        envFile,
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOutStream });

    assert.equal(result.status, 0);
    // Verified: The raw secret is REDACTED into secretRef:npm-token!
    assert.match(capturedOutput, /Resolved secret: secretRef:npm-token/);
    assert.doesNotMatch(capturedOutput, new RegExp(secretValue));

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess enforces strict scoping when requested", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-strict-"));
    const dataDir = path.join(tempDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(tempDir, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);

    setCredential({
        root: tempDir,
        envFile,
        id: "npm-token",
        secret: "strict-token-value-123456",
    });

    // Rejects in strict mode when allowNames is not provided
    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            strict: true,
            command: process.execPath,
            commandArgs: ["-e", "console.log('test')"],
        }),
        /Strict scoping enabled/
    );

    // Permitted in strict mode when explicit credential is provided
    const script = `process.stdout.write("got: " + process.env.NODE_AUTH_TOKEN);`;
    const scriptFile = path.join(tempDir, "script.js");
    fs.writeFileSync(scriptFile, script);

    let captured = "";
    const mockOut = { write(chunk) { captured += chunk; return true; } };
    const result = await executeProcess({
        root: tempDir,
        envFile,
        strict: true,
        allowNames: ["npm-token"],
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOut });

    assert.equal(result.status, 0);
    assert.match(captured, /got: secretRef:npm-token/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});
