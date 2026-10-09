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

test("runCliUpgrade executes git pull origin master when active branch is master", async () => {
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
        if (args.includes("--abbrev-ref")) {
            return { status: 0, stdout: "master\n" };
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

    assert.equal(res.ok, true);
    assert.equal(res.updated, true);
    assert.ok(commandsRun.some((c) => c === "git pull origin master"));
    assert.match(out, /Pulling latest changes from git origin \(master\)/);
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

test("runCliUpgrade fails closed when release checksum returns 404", async () => {
    let errOut = "";
    const mockStdout = { write: () => true };
    const mockStderr = { write: (msg) => { errOut += msg; return true; } };
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-non-git-"));
    const mockFetch = async (url) => {
        if (url.includes("releases/latest")) {
            return {
                ok: true,
                json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
            };
        }
        if (url.endsWith(".tgz")) {
            return {
                ok: true,
                arrayBuffer: async () => Buffer.from("fake-tarball-content"),
            };
        }
        if (url.endsWith("SHASUMS256.txt")) {
            return { ok: false, status: 404 };
        }
        return { ok: false, status: 500 };
    };

    try {
        const res = await runCliUpgrade(["--yes"], {
            cliRoot: path.join(tempDir, "cli"),
            manifest: { version: "0.5.6" },
            fetchFn: mockFetch,
            stdout: mockStdout,
            stderr: mockStderr,
        });

        assert.equal(res.ok, false);
        assert.equal(res.error, "checksum_unavailable");
        assert.match(errOut, /Release checksum asset unavailable/);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("runCliUpgrade fails closed when release checksum does not match", async () => {
    let errOut = "";
    const mockStdout = { write: () => true };
    const mockStderr = { write: (msg) => { errOut += msg; return true; } };
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-non-git-"));
    const mockFetch = async (url) => {
        if (url.includes("releases/latest")) {
            return {
                ok: true,
                json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
            };
        }
        if (url.endsWith(".tgz")) {
            return {
                ok: true,
                arrayBuffer: async () => Buffer.from("fake-tarball-content"),
            };
        }
        if (url.endsWith("SHASUMS256.txt")) {
            return {
                ok: true,
                text: async () => "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  hetzer-0.5.7.tgz\n",
            };
        }
        return { ok: false, status: 500 };
    };

    try {
        const res = await runCliUpgrade(["--yes"], {
            cliRoot: path.join(tempDir, "cli"),
            manifest: { version: "0.5.6" },
            fetchFn: mockFetch,
            stdout: mockStdout,
            stderr: mockStderr,
        });

        assert.equal(res.ok, false);
        assert.equal(res.error, "integrity_check_failed");
        assert.match(errOut, /Release checksum mismatch/);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("runCliUpgrade correctly disambiguates hetzer-X.tgz from scoped agunggnn-hetzer-X.tgz in multi-line checksums", async () => {
    let out = "";
    const mockStdout = { write: (msg) => { out += msg; return true; } };
    const mockStderr = { write: () => true };
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-multi-checksum-"));

    const tarballBuffer = Buffer.from("valid-tarball-bytes-0.5.7");
    const crypto = await import("node:crypto");
    const expectedSha = crypto.createHash("sha256").update(tarballBuffer).digest("hex");
    const wrongSha = "0".repeat(64);

    const multiLineChecksum = [
        "# SHA-256 Checksums",
        `${wrongSha}  agunggnn-hetzer-0.5.7.tgz`,
        `${expectedSha}  hetzer-0.5.7.tgz`,
    ].join("\n");

    const commandsRun = [];
    const mockSpawn = (cmd, args) => {
        commandsRun.push(`${cmd} ${args.join(" ")}`);
        return { status: 0 };
    };

    const mockFetch = async (url) => {
        if (url.includes("releases/latest")) {
            return {
                ok: true,
                json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
            };
        }
        if (url.endsWith(".tgz")) {
            return {
                ok: true,
                arrayBuffer: async () => tarballBuffer,
            };
        }
        if (url.endsWith("SHASUMS256.txt") || url.endsWith("checksums.txt")) {
            return {
                ok: true,
                text: async () => multiLineChecksum,
            };
        }
        return { ok: false, status: 500 };
    };

    try {
        const res = await runCliUpgrade(["--yes"], {
            cliRoot: path.join(tempDir, "cli"),
            manifest: { version: "0.5.6" },
            spawnFn: mockSpawn,
            fetchFn: mockFetch,
            stdout: mockStdout,
            stderr: mockStderr,
        });

        assert.equal(res.ok, true);
        assert.equal(res.updated, true);
        assert.match(out, /Release integrity verified via SHA-256/);
        assert.ok(commandsRun.some((c) => c.includes("install -g")));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("runCliUpgrade falls back to checksums.txt when SHASUMS256.txt returns 404", async () => {
    let out = "";
    const mockStdout = { write: (msg) => { out += msg; return true; } };
    const mockStderr = { write: () => true };
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-fallback-checksum-"));

    const tarballBuffer = Buffer.from("legacy-release-tarball-bytes");
    const crypto = await import("node:crypto");
    const expectedSha = crypto.createHash("sha256").update(tarballBuffer).digest("hex");

    const legacyChecksumsContent = [
        "# SHA-256 Checksums",
        `${expectedSha}  hetzer-0.5.7.tgz`,
    ].join("\n");

    const commandsRun = [];
    const mockSpawn = (cmd, args) => {
        commandsRun.push(`${cmd} ${args.join(" ")}`);
        return { status: 0 };
    };

    let shasumsRequested = false;
    let checksumsRequested = false;

    const mockFetch = async (url) => {
        if (url.includes("releases/latest")) {
            return {
                ok: true,
                json: async () => ({ tag_name: "v0.5.7", html_url: "https://github.com/agunggnn/hetzer/releases" }),
            };
        }
        if (url.endsWith(".tgz")) {
            return {
                ok: true,
                arrayBuffer: async () => tarballBuffer,
            };
        }
        if (url.endsWith("SHASUMS256.txt")) {
            shasumsRequested = true;
            return { ok: false, status: 404 };
        }
        if (url.endsWith("checksums.txt")) {
            checksumsRequested = true;
            return {
                ok: true,
                text: async () => legacyChecksumsContent,
            };
        }
        return { ok: false, status: 500 };
    };

    try {
        const res = await runCliUpgrade(["--yes"], {
            cliRoot: path.join(tempDir, "cli"),
            manifest: { version: "0.5.6" },
            spawnFn: mockSpawn,
            fetchFn: mockFetch,
            stdout: mockStdout,
            stderr: mockStderr,
        });

        assert.equal(res.ok, true);
        assert.equal(res.updated, true);
        assert.equal(shasumsRequested, true, "Should have attempted SHASUMS256.txt first");
        assert.equal(checksumsRequested, true, "Should have fallen back to checksums.txt");
        assert.match(out, /Release integrity verified via SHA-256/);
        assert.ok(commandsRun.some((c) => c.includes("install -g")));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
