import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runCliUpgrade } from "./upgrade.mjs";

test("runCliUpgrade reports already up to date when current version equals latest", async () => {
    let out = "";
    const mockStdout = { write: (msg) => { out += msg; return true; } };
    const mockStderr = { write: () => true };
    const mockFetch = async () => ({
        ok: true,
        json: async () => ({ tag_name: "v0.5.6", html_url: "https://github.com/agunggnn/hetzer/releases" }),
    });

    const res = await runCliUpgrade([], {
        cliRoot: path.resolve("cli"),
        manifest: { version: "0.5.6" },
        fetchFn: mockFetch,
        stdout: mockStdout,
        stderr: mockStderr,
    });

    assert.equal(res.ok, true);
    assert.equal(res.updated, false);
    assert.match(out, /Hetzer is up to date/);
});

test("runCliUpgrade with --check only reports update without installing", async () => {
    let out = "";
    const mockStdout = { write: (msg) => { out += msg; return true; } };
    const mockStderr = { write: () => true };
    const mockFetch = async () => ({
        ok: true,
        json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
    });

    const res = await runCliUpgrade(["--check"], {
        cliRoot: path.resolve("cli"),
        manifest: { version: "0.5.6" },
        fetchFn: mockFetch,
        stdout: mockStdout,
        stderr: mockStderr,
    });

    assert.equal(res.ok, true);
    assert.equal(res.updated, false);
    assert.equal(res.updateAvailable, true);
    assert.equal(res.latestVersion, "0.5.7");
    assert.match(out, /An update is available/);
});

test("runCliUpgrade executes git pull and npm link in git clone", async () => {
    let out = "";
    const commandsRun = [];
    const mockStdout = { write: (msg) => { out += msg; return true; } };
    const mockStderr = { write: () => true };
    const mockFetch = async () => ({
        ok: true,
        json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
    });
    const mockSpawn = (cmd, args) => {
        commandsRun.push(`${cmd} ${args.join(" ")}`);
        return { status: 0 };
    };

    const res = await runCliUpgrade(["--yes"], {
        cliRoot: path.resolve("cli"),
        manifest: { version: "0.5.6" },
        spawnFn: mockSpawn,
        fetchFn: mockFetch,
        stdout: mockStdout,
        stderr: mockStderr,
    });

    assert.equal(res.ok, true);
    assert.equal(res.updated, true);
    assert.ok(commandsRun.some((c) => c.includes("git pull")));
    assert.ok(commandsRun.some((c) => c.includes("npm link")));
    assert.match(out, /Successfully upgraded Hetzer to v0.5.7/);
});
