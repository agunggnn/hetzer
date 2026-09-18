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

test("runCliUpgrade rejects git upgrade when active branch is a feature branch", async () => {
    let errOut = "";
    const mockStdout = { write: () => true };
    const mockStderr = { write: (msg) => { errOut += msg; return true; } };
    const mockFetch = async () => ({
        ok: true,
        json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
    });
    const mockSpawn = (cmd, args) => {
        if (args.includes("--abbrev-ref")) {
            return { status: 0, stdout: "feat/security-hardening-v0.5.6\n" };
        }
        return { status: 0, stdout: "" };
    };

    const res = await runCliUpgrade(["--yes"], {
        cliRoot: path.resolve("cli"),
        manifest: { version: "0.5.6" },
        spawnFn: mockSpawn,
        fetchFn: mockFetch,
        stdout: mockStdout,
        stderr: mockStderr,
    });

    assert.equal(res.ok, false);
    assert.equal(res.error, "git_branch_mismatch");
    assert.match(errOut, /Active git branch is 'feat\/security-hardening-v0\.5\.6'/);
});

test("runCliUpgrade rejects git upgrade when working tree is dirty", async () => {
    let errOut = "";
    const mockStdout = { write: () => true };
    const mockStderr = { write: (msg) => { errOut += msg; return true; } };
    const mockFetch = async () => ({
        ok: true,
        json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
    });
    const mockSpawn = (cmd, args) => {
        if (args.includes("--abbrev-ref")) {
            return { status: 0, stdout: "main\n" };
        }
        if (args.includes("--porcelain")) {
            return { status: 0, stdout: " M package.json\n" };
        }
        return { status: 0, stdout: "" };
    };

    const res = await runCliUpgrade(["--yes"], {
        cliRoot: path.resolve("cli"),
        manifest: { version: "0.5.6" },
        spawnFn: mockSpawn,
        fetchFn: mockFetch,
        stdout: mockStdout,
        stderr: mockStderr,
    });

    assert.equal(res.ok, false);
    assert.equal(res.error, "git_dirty_working_tree");
    assert.match(errOut, /uncommitted changes/);
});

