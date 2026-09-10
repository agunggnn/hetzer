import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createStreamSanitizer, executeProcess, isReflectionCommand, parseArguments, sanitizeStreamOutput } from "./exec.mjs";
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

test("createStreamSanitizer blocks terminal-control and long scanner bypasses", () => {
    const known = ["synthetic", "-", "guard", "-", "value", "-", "987654321"].join("");
    const ansiObfuscated = known.split("").join("\u001b[0m");
    const nulObfuscated = known.split("").join("\0");
    const privateKey = [
        "-----BEGIN ",
        "PRIVATE KEY-----\n",
        "A".repeat(900),
        "\n-----END ",
        "PRIVATE KEY-----",
    ].join("");
    const databaseUrl = ["postgres://user:", "B".repeat(700), "@localhost/app"].join("");
    const longProviderToken = ["gh", "p_", "C".repeat(700)].join("");
    const sanitizer = createStreamSanitizer([{ id: "guard-value", secret: known }]);

    const output = [
        sanitizer.write(Buffer.from(ansiObfuscated.slice(0, 37))),
        sanitizer.write(Buffer.from(ansiObfuscated.slice(37) + "\n" + nulObfuscated + "\n")),
        sanitizer.write(Buffer.from(privateKey.slice(0, 300))),
        sanitizer.write(Buffer.from(privateKey.slice(300) + "\n" + databaseUrl.slice(0, 350))),
        sanitizer.write(Buffer.from(databaseUrl.slice(350) + "\n" + longProviderToken)),
        sanitizer.end(),
    ].join("");

    assert.doesNotMatch(output, new RegExp(known));
    assert.doesNotMatch(output, /A{100}/);
    assert.doesNotMatch(output, /B{100}/);
    assert.doesNotMatch(output, /C{100}/);
    assert.match(output, /secretRef:guard-value/);
    assert.match(output, /secretRef:private-key/);
    assert.match(output, /secretRef:database-url/);
    assert.match(output, /secretRef:github-token/);
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

test("executeProcess sanitizes stdout and stderr streams", async () => {
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
    let capturedError = "";
    const mockOutStream = {
        write(chunk) {
            capturedOutput += chunk;
            return true;
        },
    };
    const mockErrStream = {
        write(chunk) {
            capturedError += chunk;
            return true;
        },
    };

    // Run a child that sends the resolved value to both output pipes.
    const script = [
        `const value = process.env.NODE_AUTH_TOKEN;`,
        `process.stdout.write("Resolved secret: " + value + "\\n");`,
        `process.stderr.write("Rejected secret: " + value + "\\n");`,
    ].join("\n");
    const scriptFile = path.join(tempDir, "test-script.js");
    fs.writeFileSync(scriptFile, script);

    const result = await executeProcess({
        root: tempDir,
        envFile,
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOutStream, errStream: mockErrStream });

    assert.equal(result.status, 0);
    // Verified: The raw secret is REDACTED into secretRef:npm-token!
    assert.match(capturedOutput, /Resolved secret: secretRef:npm-token/);
    assert.doesNotMatch(capturedOutput, new RegExp(secretValue));
    assert.match(capturedError, /Rejected secret: secretRef:npm-token/);
    assert.doesNotMatch(capturedError, new RegExp(secretValue));

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

test("parseArguments parses --canary flag properly", () => {
    const parsed = parseArguments([
        "--root", process.cwd(),
        "--env-file", ".env",
        "--strict",
        "--canary",
        "--",
        "node", "-v",
    ]);
    assert.equal(parsed.strict, true);
    assert.equal(parsed.canary, true);
    assert.equal(parsed.command, "node");
    assert.deepEqual(parsed.commandArgs, ["-v"]);
});

test("createStreamSanitizer detects canary honeytoken in chunks and trips onCanaryDetected", () => {
    let trippedId = null;
    const canaryValue = "canary_trap_0123456789abcdef0123456789abcdef";
    const sanitizer = createStreamSanitizer(
        [{ id: "canary-token", secret: canaryValue, isCanary: true }],
        { onCanaryDetected: ({ id }) => { trippedId = id; } }
    );

    const chunk1 = sanitizer.write(Buffer.from("Normal output before "));
    const chunk2 = sanitizer.write(Buffer.from(`leak: ${canaryValue}\n`));
    const chunk3 = sanitizer.end();

    assert.equal(trippedId, "canary-token");
    assert.doesNotMatch(chunk1 + chunk2 + chunk3, new RegExp(canaryValue));
});

test("executeProcess kills subprocess immediately and exits with code 43 if canary token is leaked on stdout", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-canary-stdout-"));
    const dataDir = path.join(tempDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    const script = [
        `process.stdout.write("Subprocess started\\n");`,
        `process.stdout.write("Stealing: " + process.env.HETZER_CANARY_TOKEN + "\\n");`,
        `process.stdout.write("This line should never execute\\n");`,
    ].join("\n");
    const scriptFile = path.join(tempDir, "leak-script.js");
    fs.writeFileSync(scriptFile, script);

    let capturedOutput = "";
    const mockOut = { write(chunk) { capturedOutput += chunk; return true; } };

    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            canary: true,
            command: process.execPath,
            commandArgs: [scriptFile],
        }, { outStream: mockOut }),
        (err) => {
            assert.equal(err.code, "ERR_CANARY_TRIPWIRE_TRIGGERED");
            assert.equal(err.exitCode, 43);
            return true;
        }
    );

    // Subprocess output must NEVER contain the raw canary honeytoken
    assert.doesNotMatch(capturedOutput, /canary_trap_/);
    assert.doesNotMatch(capturedOutput, /This line should never execute/);

    // Incident log must record the tripwire
    const incidentLog = path.join(tempDir, "data", "hetzer-incidents.log");
    assert.ok(fs.existsSync(incidentLog));
    const logContent = fs.readFileSync(incidentLog, "utf8");
    assert.match(logContent, /Canary 'canary-token' triggered by subprocess\.leak during stream\.output/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess kills subprocess immediately and exits with code 43 if canary token is leaked on stderr", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-canary-stderr-"));
    const dataDir = path.join(tempDir, "data");
    fs.mkdirSync(dataDir, { recursive: true });
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    const script = [
        `process.stderr.write("Stderr crash leak: " + process.env.HETZER_CANARY_TOKEN + "\\n");`,
    ].join("\n");
    const scriptFile = path.join(tempDir, "stderr-leak.js");
    fs.writeFileSync(scriptFile, script);

    let capturedError = "";
    const mockErr = { write(chunk) { capturedError += chunk; return true; } };

    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            canary: true,
            command: process.execPath,
            commandArgs: [scriptFile],
        }, { errStream: mockErr }),
        (err) => {
            assert.equal(err.code, "ERR_CANARY_TRIPWIRE_TRIGGERED");
            assert.equal(err.exitCode, 43);
            return true;
        }
    );

    assert.doesNotMatch(capturedError, /canary_trap_/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess with canary enabled completes normally when canary token is not leaked", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-canary-clean-"));
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    const script = `process.stdout.write("Hello from legitimate script\\n");`;
    const scriptFile = path.join(tempDir, "clean-script.js");
    fs.writeFileSync(scriptFile, script);

    let capturedOutput = "";
    const mockOut = { write(chunk) { capturedOutput += chunk; return true; } };

    const result = await executeProcess({
        root: tempDir,
        envFile,
        canary: true,
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOut });

    assert.equal(result.status, 0);
    assert.match(capturedOutput, /Hello from legitimate script/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

