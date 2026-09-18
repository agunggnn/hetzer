import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { redactExactValues, runNpmWithAuth, verifyNpmRegistryAuth } from "./npm-auth.mjs";

test("runNpmWithAuth keeps registry credentials out of argv and npmrc", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-npm-auth-test-"));
    const token = ["synthetic", "registry", "credential"].join("-");
    let captured;
    const run = (command, args, options) => {
        const userConfigIndex = args.indexOf("--userconfig");
        captured = {
            command,
            args,
            env: options.env,
            npmrc: fs.readFileSync(args[userConfigIndex + 1], "utf8"),
            npmrcFile: args[userConfigIndex + 1],
        };
        return { status: 0, stdout: "ok", stderr: "" };
    };

    runNpmWithAuth({
        args: ["whoami"],
        registry: "https://registry.npmjs.org/",
        token,
        baseEnv: { PATH: process.env.PATH || "" },
        run,
        tempRoot,
    });

    assert.equal(captured.command, "npm");
    assert.equal(captured.args.some((arg) => arg.includes(token)), false);
    assert.equal(captured.npmrc.includes(token), false);
    assert.match(captured.npmrc, /\$\{NODE_AUTH_TOKEN\}/);
    assert.equal(captured.env.NODE_AUTH_TOKEN, token);
    assert.equal(fs.existsSync(captured.npmrcFile), false);
    assert.equal(redactExactValues(`failure ${token}`, [token]), "failure secretRef:registry-credential");
    fs.rmSync(tempRoot, { recursive: true, force: true });
});

test("verifyNpmRegistryAuth succeeds with Classic token when whoami returns 0", () => {
    const mockRun = ({ args }) => {
        if (args.includes("whoami")) {
            return { status: 0, stdout: "agunggnn\n", stderr: "" };
        }
        return { status: 1, stdout: "", stderr: "failed" };
    };

    const res = verifyNpmRegistryAuth({
        token: "test-token",
        runNpm: mockRun,
    });

    assert.equal(res.ok, true);
    assert.equal(res.type, "classic");
    assert.equal(res.username, "agunggnn");
});

test("verifyNpmRegistryAuth falls back to GAT and verifies read-write permissions", () => {
    const mockRun = ({ args }) => {
        if (args.includes("whoami")) {
            return { status: 1, stdout: "", stderr: "npm error code E404\nnpm error Not Found" };
        }
        if (args.includes("collaborators")) {
            return { status: 0, stdout: JSON.stringify({ agunggnn: "read-write" }), stderr: "" };
        }
        return { status: 1, stdout: "", stderr: "failed" };
    };

    const res = verifyNpmRegistryAuth({
        token: "test-token",
        packageName: "hetzer",
        runNpm: mockRun,
    });

    assert.equal(res.ok, true);
    assert.equal(res.type, "granular");
    assert.equal(res.packageName, "hetzer");
});

test("verifyNpmRegistryAuth rejects GAT when permission is read-only", () => {
    const mockRun = ({ args }) => {
        if (args.includes("whoami")) {
            return { status: 1, stdout: "", stderr: "GAT does not support whoami" };
        }
        if (args.includes("collaborators")) {
            return { status: 0, stdout: JSON.stringify({ agunggnn: "read-only" }), stderr: "" };
        }
        return { status: 1, stdout: "", stderr: "failed" };
    };

    assert.throws(() => {
        verifyNpmRegistryAuth({
            token: "test-token",
            packageName: "hetzer",
            runNpm: mockRun,
        });
    }, (err) => {
        assert.equal(err.code, "ERR_NPM_WRITE_PERMISSION_MISSING");
        assert.match(err.message, /lacks write access/);
        return true;
    });
});

test("verifyNpmRegistryAuth classifies network/DNS outage as ERR_NPM_NETWORK instead of 401", () => {
    const mockRun = () => ({
        status: 1,
        stdout: "",
        stderr: "npm error code ENOTFOUND\nnpm error getaddrinfo ENOTFOUND registry.npmjs.org",
    });

    assert.throws(() => {
        verifyNpmRegistryAuth({
            token: "test-token",
            runNpm: mockRun,
        });
    }, (err) => {
        assert.equal(err.code, "ERR_NPM_NETWORK");
        assert.match(err.message, /Unable to reach/);
        assert.doesNotMatch(err.message, /401 Unauthorized/);
        return true;
    });
});

test("verifyNpmRegistryAuth rejects Classic token when collaborator permission is read-only", () => {
    const mockRun = ({ args }) => {
        if (args.includes("whoami")) {
            return { status: 0, stdout: "agunggnn\n", stderr: "" };
        }
        if (args.includes("collaborators")) {
            return { status: 0, stdout: JSON.stringify({ agunggnn: "read-only" }), stderr: "" };
        }
        return { status: 1, stdout: "", stderr: "failed" };
    };

    assert.throws(() => {
        verifyNpmRegistryAuth({
            token: "test-token",
            packageName: "hetzer",
            runNpm: mockRun,
        });
    }, (err) => {
        assert.equal(err.code, "ERR_NPM_WRITE_PERMISSION_MISSING");
        assert.match(err.message, /lacks write access/);
        return true;
    });
});

test("verifyNpmRegistryAuth throws ERR_NPM_AUTH_FAILED on genuine invalid token", () => {
    const mockRun = () => ({
        status: 1,
        stdout: "",
        stderr: "npm error code E401\nnpm error 401 Unauthorized - Invalid token",
    });

    assert.throws(() => {
        verifyNpmRegistryAuth({
            token: "test-token",
            runNpm: mockRun,
        });
    }, (err) => {
        assert.equal(err.code, "ERR_NPM_AUTH_FAILED");
        assert.match(err.message, /401 Unauthorized/);
        return true;
    });
});
