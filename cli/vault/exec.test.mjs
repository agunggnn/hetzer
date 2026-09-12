import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createStreamSanitizer, executeProcess, isReflectionCommand, parseArguments, parseDuration, resolveCommandForSpawn, sanitizeStreamOutput, terminateProcessTree } from "./exec.mjs";
import { Grimoire } from "./hetzer-vault.mjs";
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
        allowNames: ["npm-token"],
        allowRawUnmediated: ["npm-token"],
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOutStream, errStream: mockErrStream });

    assert.equal(result.status, 0);
    // Verified: The raw secret is REDACTED into secretRef:npm-token!
    assert.match(capturedOutput, /Resolved secret: secretRef:npm-token/);
    assert.doesNotMatch(capturedOutput, new RegExp(secretValue));
    assert.match(capturedError, /Rejected secret: secretRef:npm-token/);
    assert.doesNotMatch(capturedError, new RegExp(secretValue));

    const auditVault = new (await import("./hetzer-vault.mjs")).Grimoire({
        dbPath: path.join(dataDir, "hetzer-vault.db"),
        masterKey,
    });
    try {
        const audit = auditVault.db.prepare(
            "SELECT action, credential_id, outcome FROM vault_audit_events WHERE action = ? ORDER BY id DESC LIMIT 1"
        ).get("process.raw-unmediated");
        assert.equal(audit.action, "process.raw-unmediated");
        assert.equal(audit.credential_id, "npm-token");
        assert.equal(audit.outcome, "allowed");
    } finally {
        auditVault.close();
    }

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
        allowRawUnmediated: ["npm-token"],
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOut });

    assert.equal(result.status, 0);
    assert.match(captured, /got: secretRef:npm-token/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess denies raw credentials unless explicitly opted out", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-fail-closed-"));
    const envFile = path.join(tempDir, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);
    setCredential({ root: tempDir, envFile, id: "npm-token", secret: "synthetic-fail-closed-value" });

    try {
        await assert.rejects(
            () => executeProcess({
                root: tempDir,
                envFile,
                allowNames: ["npm-token"],
                command: process.execPath,
                commandArgs: ["-e", "process.stdout.write('should-not-run')"],
            }),
            (error) => error.code === "ERR_RAW_UNMEDIATED_FORBIDDEN",
        );
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("executeProcess automatically mediates credentials with a broker policy", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-mediated-"));
    const envFile = path.join(tempDir, ".env");
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    const rawSecret = "synthetic-mediated-value-123456";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\n`);
    setCredential({ root: tempDir, envFile, id: "npm-token", secret: rawSecret });
    const policyDir = path.join(tempDir, ".hetzer", "brokers");
    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(path.join(policyDir, "npm-token.json"), JSON.stringify({
        version: 1,
        target: "https://registry.example.test",
        credential: "secretRef:npm-token",
        baseUrlEnv: "SERVICE_BASE_URL",
        tokenEnv: "NODE_AUTH_TOKEN",
        basePath: "/v1",
        clientAuth: { header: "authorization", scheme: "Bearer" },
        upstreamAuth: { header: "authorization", scheme: "Bearer" },
        allowedMethods: ["GET"],
        allowedPathPrefixes: ["/v1"],
        ttlSeconds: 30,
        maxRequests: 1,
    }));
    const scriptFile = path.join(tempDir, "client.mjs");
    fs.writeFileSync(scriptFile, [
        "const response = await fetch(`${process.env.SERVICE_BASE_URL}/items`, {",
        "  headers: { authorization: `Bearer ${process.env.NODE_AUTH_TOKEN}` },",
        "});",
        "const genericMatches = process.env.HETZER_BROKER_URL === process.env.SERVICE_BASE_URL;",
        "process.stdout.write(`${response.status}:${await response.text()}:generic=${genericMatches}:proxy=${Boolean(process.env.HTTP_PROXY)}`);",
    ].join("\n"));

    let upstreamCredential = "";
    let output = "";
    try {
        const result = await executeProcess({
            root: tempDir,
            envFile,
            allowNames: ["npm-token"],
            strict: true,
            command: process.execPath,
            commandArgs: [scriptFile],
        }, {
            baseEnv: { ...process.env, HETZER_GRIMOIRE_KEY: masterKey, HTTP_PROXY: "" },
            brokerRandomBytes: () => Buffer.alloc(32, 9),
            brokerFetchFn: async (_url, options) => {
                upstreamCredential = options.headers.authorization;
                return new Response("mediated-ok", { headers: { "content-type": "text/plain" } });
            },
            outStream: { write(chunk) { output += String(chunk); return true; } },
        });
        assert.equal(result.status, 0);
        assert.equal(upstreamCredential, `Bearer ${rawSecret}`);
        assert.equal(output, "200:mediated-ok:generic=true:proxy=false");
        assert.doesNotMatch(output, new RegExp(rawSecret));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
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

test("parseArguments accepts repeatable broker policies and explicit raw credential IDs", () => {
    const parsed = parseArguments([
        "--root", process.cwd(),
        "--env-file", ".env",
        "--allow", "service-key,local-passphrase",
        "--broker-policy", "service-policy.json",
        "--broker-policy", "second-policy.json",
        "--allow-raw-unmediated", "local-passphrase",
        "--",
        "node", "client.mjs",
    ]);
    assert.deepEqual(parsed.allowNames, ["service-key", "local-passphrase"]);
    assert.deepEqual(parsed.allowRawUnmediated, ["local-passphrase"]);
    assert.equal(parsed.brokerPolicyFiles.length, 2);
    assert.match(parsed.brokerPolicyFiles[0], /service-policy\.json$/);
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

test("parseDuration correctly parses duration strings with various units", () => {
    assert.equal(parseDuration("500ms"), 500);
    assert.equal(parseDuration("10s"), 10000);
    assert.equal(parseDuration("2.5s"), 2500);
    assert.equal(parseDuration("2m"), 120000);
    assert.equal(parseDuration("1h"), 3600000);
    assert.equal(parseDuration(1500), 1500);
    assert.equal(parseDuration("250"), 250);

    assert.throws(() => parseDuration("0s"), /must be greater than 0/);
    assert.throws(() => parseDuration("-5s"), /must be greater than 0/);
    assert.throws(() => parseDuration("abc"), /Invalid timeout duration format/);
    assert.throws(() => parseDuration(""), /expected duration string/);
    assert.throws(() => parseDuration(null), /expected duration string/);
});

test("parseArguments parses --timeout flag correctly", () => {
    const args = ["--root", ".", "--env-file", ".env", "--timeout", "30s", "--", "node", "-v"];
    const parsed = parseArguments(args);
    assert.equal(parsed.timeout, "30s");
    assert.equal(parsed.timeoutMs, 30000);
});

test("executeProcess completes within timeout budget without premature abort", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-timeout-pass-"));
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    const script = `process.stdout.write("Fast completion\\n");`;
    const scriptFile = path.join(tempDir, "fast.js");
    fs.writeFileSync(scriptFile, script);

    let capturedOutput = "";
    const mockOut = { write(chunk) { capturedOutput += chunk; return true; } };

    const result = await executeProcess({
        root: tempDir,
        envFile,
        timeout: "5s",
        command: process.execPath,
        commandArgs: [scriptFile],
    }, { outStream: mockOut });

    assert.equal(result.status, 0);
    assert.match(capturedOutput, /Fast completion/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess terminates hanging subprocess when timeout budget is exceeded", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-timeout-fail-"));
    const envFile = path.join(tempDir, ".env");
    fs.writeFileSync(envFile, "FOO=bar\n");

    const script = `setInterval(() => {}, 1000);`;
    const scriptFile = path.join(tempDir, "hang.js");
    fs.writeFileSync(scriptFile, script);

    let capturedError = "";
    const mockErr = { write(chunk) { capturedError += chunk; return true; } };

    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            timeout: "200ms",
            command: process.execPath,
            commandArgs: [scriptFile],
        }, { errStream: mockErr }),
        (err) => {
            assert.equal(err.code, "ERR_SUBPROCESS_TIMEOUT");
            assert.equal(err.exitCode, 124);
            assert.match(err.message, /timed out after 200ms/);
            return true;
        }
    );

    assert.match(capturedError, /Hetzer Timeout Guard: Subprocess exceeded execution budget \(200ms\)/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("executeProcess with timeout still redacts secrets before terminating", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-exec-timeout-redact-"));
    const envFile = path.join(tempDir, ".env");
    const testSecret = "secret-token-to-redact-123456";
    const masterKey = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    fs.writeFileSync(envFile, `HETZER_GRIMOIRE_KEY=${masterKey}\nSECRET_VAR=secretRef:my-token\n`);

    setCredential({ root: tempDir, envFile, id: "my-token", secret: testSecret });

    const script = [
        `process.stdout.write("Leaking secret: " + process.env.SECRET_VAR + "\\n");`,
        `setInterval(() => {}, 1000);`,
    ].join("\n");
    const scriptFile = path.join(tempDir, "leak-hang.js");
    fs.writeFileSync(scriptFile, script);

    let capturedOut = "";
    let capturedErr = "";
    const mockOut = { write(chunk) { capturedOut += chunk; return true; } };
    const mockErr = { write(chunk) { capturedErr += chunk; return true; } };

    await assert.rejects(
        () => executeProcess({
            root: tempDir,
            envFile,
            allowNames: ["SECRET_VAR"],
            allowRawUnmediated: ["my-token"],
            timeout: "250ms",
            command: process.execPath,
            commandArgs: [scriptFile],
        }, { outStream: mockOut, errStream: mockErr }),
        (err) => {
            assert.equal(err.code, "ERR_SUBPROCESS_TIMEOUT");
            assert.equal(err.exitCode, 124);
            return true;
        }
    );

    assert.match(capturedOut, /secretRef:my-token/);
    assert.doesNotMatch(capturedOut, new RegExp(testSecret));
    assert.match(capturedErr, /Hetzer Timeout Guard/);

    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("resolveCommandForSpawn correctly resolves executables on all platforms", () => {
    if (process.platform === "win32") {
        const npmRes = resolveCommandForSpawn("npm", ["test"]);
        assert.ok(npmRes.cmd.toLowerCase().includes("node"), "npm should resolve to node binary");
        assert.ok(npmRes.args[0].includes("npm-cli.js"), "npm should pass npm-cli.js as first arg");
        assert.equal(npmRes.args[1], "test");

        const npxRes = resolveCommandForSpawn("npx", ["--version"]);
        assert.ok(npxRes.cmd.toLowerCase().includes("node"), "npx should resolve to node binary");
        assert.ok(npxRes.args[0].includes("npx-cli.js"), "npx should pass npx-cli.js as first arg");

        const nodeRes = resolveCommandForSpawn("node", ["index.js"]);
        assert.ok(nodeRes.cmd.toLowerCase().includes("node"), "node should resolve");
        assert.deepEqual(nodeRes.args, ["index.js"]);
    } else {
        const res = resolveCommandForSpawn("npm", ["test"]);
        assert.equal(res.cmd, "npm");
        assert.deepEqual(res.args, ["test"]);
    }
});

test("fuzz and property tests: createStreamSanitizer handles random chunk boundaries and ANSI/formatting escapes", () => {
    const secret = "npm_secret_token_1234567890abcdef";
    const secretsToRedact = [{ id: "npm-token", secret }];

    let seed = 424242;
    function rand() {
        seed = (seed * 1664525 + 1013904223) % 4294967296;
        return seed / 4294967296;
    }

    // 1. Property test: Random chunk boundaries
    for (let iter = 0; iter < 50; iter++) {
        const prefix = "Log output before secret: ";
        const suffix = " - Log output after secret.";
        const fullStream = prefix + secret + suffix;

        const sanitizer = createStreamSanitizer(secretsToRedact);
        let output = "";

        // Slice fullStream into random chunks between 1 and 7 characters
        let pos = 0;
        while (pos < fullStream.length) {
            const chunkSize = 1 + Math.floor(rand() * 7);
            const chunk = fullStream.slice(pos, pos + chunkSize);
            output += sanitizer.write(chunk);
            pos += chunkSize;
        }
        output += sanitizer.end();

        assert.doesNotMatch(output, new RegExp(secret), `Iteration ${iter} leaked raw secret`);
        assert.match(output, /secretRef:npm-token/, `Iteration ${iter} failed to redact secret`);
    }

    // 2. Property test: Interleaved ANSI color escapes
    const ansiVariants = [
        `npm_\x1b[31msecret\x1b[0m_token_\x1b[1;32m1234567890abcdef\x1b[0m`,
        `\x1b[33m${secret}\x1b[0m`,
        `npm_secret_\x1b[42mtoken_1234567890abcdef\x1b[49m`,
    ];

    for (const variant of ansiVariants) {
        const sanitizer = createStreamSanitizer(secretsToRedact);
        const out = sanitizer.write(variant) + sanitizer.end();
        assert.doesNotMatch(out, new RegExp(secret));
        assert.match(out, /secretRef:npm-token/);
    }

    // 3. Property test: Canary token tripped across chunk boundaries
    const canary = "canary_trap_0123456789abcdef0123456789abcdef";
    const canaryRedact = [{ id: "canary-token", secret: canary, isCanary: true }];

    for (let chunkSize = 1; chunkSize <= 5; chunkSize++) {
        let canaryAlerted = false;
        const sanitizer = createStreamSanitizer(canaryRedact, {
            onCanaryDetected: () => { canaryAlerted = true; },
        });

        const stream = `Diagnostic info: ${canary} end`;
        for (let i = 0; i < stream.length; i += chunkSize) {
            sanitizer.write(stream.slice(i, i + chunkSize));
        }
        sanitizer.end();

        assert.equal(canaryAlerted, true, `Canary failed to alert at chunk size ${chunkSize}`);
    }
});

test("parseArguments parses --policy-hash and executeProcess records policy.loaded audit event", async () => {
    const parsed = parseArguments([
        "--root", "/workspace",
        "--env-file", "/workspace/.env",
        "--policy", "/workspace/policy.json",
        "--policy-hash", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "--",
        "node", "script.js",
    ]);
    assert.equal(parsed.policyHash, "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    assert.ok(parsed.policyFile.endsWith("policy.json"));

    // Test executeProcess with valid policy records policy.loaded audit row
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-policy-audit-"));
    const envFile = path.join(tempDir, ".env");
    const policyFile = path.join(tempDir, "policy.json");
    const masterKey = "k".repeat(48);

    fs.mkdirSync(path.join(tempDir, "data"), { recursive: true });
    fs.writeFileSync(envFile, "TEST_KEY=123\n");
    const policyContent = {
        version: 1,
        name: "test-policy",
        allowedCommands: ["node -e *"],
    };
    fs.writeFileSync(policyFile, JSON.stringify(policyContent));

    const dbPath = path.join(tempDir, "data", "hetzer-vault.db");
    const vault = new Grimoire({ dbPath, masterKey });
    vault.close();

    try {
        await executeProcess({
            root: tempDir,
            envFile,
            policyFile,
            command: process.execPath,
            commandArgs: ["-e", "process.stdout.write('ok')"],
        }, {
            baseEnv: { ...process.env, HETZER_GRIMOIRE_KEY: masterKey },
        });

        // Verify audit record exists
        const readVault = new Grimoire({ dbPath, masterKey });
        try {
            const auditEvents = readVault.listAudit();
            const policyAudit = auditEvents.find((e) => e.action === "policy.loaded");
            assert.ok(policyAudit, "Expected policy.loaded audit event in vault");
            assert.equal(policyAudit.outcome, "allowed");
            assert.equal(policyAudit.target_id, "execution-policy");
        } finally {
            readVault.close();
        }
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

