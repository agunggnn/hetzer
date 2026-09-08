import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { redactExactValues, runNpmWithAuth } from "./npm-auth.mjs";

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
