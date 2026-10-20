import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { parseArguments } from "./exec.mjs";
import { Grimoire } from "./hetzer-vault.mjs";
import { executeSandboxedProcess, selectSandboxEngine } from "./sandbox.mjs";
import {
    buildSrtArgs,
    buildSrtSettings,
    createSrtRunDir,
    detectSrt,
    findUnreadableCommand,
    SRT_TESTED_VERSION,
    validateSandboxHosts,
    writeSrtSettings,
} from "./srt-sandbox.mjs";

function tempDir(prefix) {
    return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

test("validateSandboxHosts accepts host names and rejects wildcards-for-all, URLs and bad ports", () => {
    assert.deepEqual(validateSandboxHosts(["API.github.com", "*.npmjs.org", "registry.npmjs.org:443", "api.github.com"]),
        ["api.github.com", "*.npmjs.org", "registry.npmjs.org:443"]);
    for (const bad of ["*", "https://example.com", "exa mple.com", "example.com:0", "example.com:70000", "", "-bad.com", "*.*.com"]) {
        assert.throws(() => validateSandboxHosts([bad]), (error) => error.code === "ERR_SANDBOX_HOST_INVALID", bad);
    }
});

test("buildSrtSettings denies the home directory, re-allows the project and keeps Hetzer paths hidden", () => {
    const home = tempDir("hetzer-srt-home-");
    const runTmp = path.join(tempDir("hetzer-srt-run-"), "tmp");
    try {
        const project = path.join(home, "work", "app");
        fs.mkdirSync(project, { recursive: true });
        fs.mkdirSync(path.join(home, ".ssh"));
        fs.mkdirSync(path.join(home, ".hetzer", "keys"), { recursive: true });
        const envFile = path.join(project, ".env");
        fs.writeFileSync(envFile, "X=secretRef:x\n");
        const settings = buildSrtSettings({
            mountDir: project,
            masks: { files: [{ hostPath: envFile }], dirs: [] },
            homeDir: home,
            allowHosts: ["registry.npmjs.org"],
            tmpDir: runTmp,
            settingsFile: path.join(path.dirname(runTmp), "srt-settings.json"),
        });
        assert.deepEqual(settings.network, { allowedDomains: ["registry.npmjs.org"], deniedDomains: [] });
        for (const denied of [home, path.join(home, ".hetzer"), path.join(home, ".ssh"), envFile]) {
            assert.ok(settings.filesystem.denyRead.includes(denied), `${denied} must be read-denied`);
        }
        // Credential directories that do not exist are covered by the home deny and are not listed.
        assert.equal(settings.filesystem.denyRead.includes(path.join(home, ".aws")), false);
        assert.deepEqual(settings.filesystem.allowRead, [project]);
        assert.ok(settings.filesystem.allowWrite.includes(project));
        assert.ok(settings.filesystem.allowWrite.includes(runTmp));
        assert.equal(settings.filesystem.allowWrite.includes(fs.realpathSync.native(os.tmpdir())), false,
            "the shared system temporary directory is not writable");
        assert.ok(settings.filesystem.denyWrite.includes(envFile));
        assert.ok(settings.filesystem.denyWrite.includes(path.join(path.dirname(runTmp), "srt-settings.json")));
        assert.ok(settings.filesystem.denyWrite.includes(path.join(home, ".hetzer")));

        const readOnly = buildSrtSettings({ mountDir: project, homeDir: home, readOnly: true, tmpDir: runTmp });
        assert.equal(readOnly.filesystem.allowWrite.includes(project), false);
        assert.deepEqual(readOnly.network.allowedDomains, [], "no host listed means no network");
        assert.throws(() => buildSrtSettings({ mountDir: project, homeDir: home }), (error) => error.code === "ERR_SANDBOX_TMP_REQUIRED");
        assert.throws(() => buildSrtSettings({ mountDir: project, homeDir: home, tmpDir: path.dirname(home) }),
            (error) => error.code === "ERR_SANDBOX_PATH_UNSAFE", "a temporary directory that contains the home directory is refused");
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(path.dirname(runTmp), { recursive: true, force: true });
    }
});

test("buildSrtSettings refuses extra paths that expose credentials or the home directory", () => {
    const home = tempDir("hetzer-srt-home-");
    const runTmp = tempDir("hetzer-srt-run-");
    try {
        const project = path.join(home, "app");
        const toolchain = path.join(home, ".nvm");
        fs.mkdirSync(project);
        fs.mkdirSync(toolchain);
        fs.mkdirSync(path.join(home, ".ssh"));
        const build = (extra) => buildSrtSettings({ mountDir: project, homeDir: home, tmpDir: runTmp, ...extra });
        for (const extra of [
            { allowRead: [path.join(home, ".ssh")] },
            { allowRead: [path.join(home, ".hetzer", "keys")] },
            { allowWrite: [home] },
            { allowWrite: [path.dirname(home)] },
            { allowWrite: [path.join(home, ".hetzer")] },
            { allowRead: ["/"] },
        ]) {
            assert.throws(() => build(extra), (error) => error.code === "ERR_SANDBOX_PATH_UNSAFE", JSON.stringify(extra));
        }
        // A toolchain directory may be re-opened; the home directory itself may be read (the credential
        // directories under it stay denied because a more specific deny wins).
        const settings = build({ allowRead: [toolchain, home] });
        assert.ok(settings.filesystem.allowRead.includes(toolchain));
        assert.ok(settings.filesystem.denyRead.includes(path.join(home, ".ssh")));
        // A path inside the project adds nothing.
        assert.deepEqual(build({ allowWrite: [path.join(project, "dist")] }).filesystem.allowWrite.filter((entry) => entry.startsWith(project)), [project]);
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(runTmp, { recursive: true, force: true });
    }
});

test("parseArguments reads the srt options, and they imply a sandbox", () => {
    const parsed = parseArguments([
        "--sandbox-allow-host", "api.github.com,registry.npmjs.org", "--sandbox-allow-host", "example.com",
        "--sandbox-allow-read", "toolchain", "--sandbox-allow-write", "/var/cache/app", "--", "node", "-v",
    ]);
    assert.equal(parsed.sandbox, true);
    assert.deepEqual(parsed.sandboxAllowHosts, ["api.github.com", "registry.npmjs.org", "example.com"]);
    assert.deepEqual(parsed.sandboxAllowRead, [path.resolve("toolchain")]);
    assert.deepEqual(parsed.sandboxAllowWrite, [path.resolve("/var/cache/app")]);
    assert.equal(parseArguments(["--sandbox-engine", "srt", "--", "x"]).sandbox, true);
    assert.equal(parseArguments(["--sandbox-engine", "srt", "--host", "--", "x"]).sandbox, false, "--host still wins");
    assert.equal(parseArguments(["--", "x"]).sandbox, false);
});

test("findUnreadableCommand names a command or interpreter installed under the home directory", () => {
    const home = tempDir("hetzer-srt-cmd-home-");
    try {
        const binDir = path.join(home, ".local", "bin");
        const nodeDir = path.join(home, ".nvm", "bin");
        fs.mkdirSync(binDir, { recursive: true });
        fs.mkdirSync(nodeDir, { recursive: true });
        fs.writeFileSync(path.join(binDir, "agent-cli"), "#!/usr/bin/env fake-node\n", { mode: 0o755 });
        fs.writeFileSync(path.join(nodeDir, "fake-node"), "", { mode: 0o755 });
        const pathEnv = [binDir, nodeDir, "/usr/bin"].join(path.delimiter);
        const check = (readable) => findUnreadableCommand({ command: "agent-cli", pathEnv, homeDir: home, readable });

        assert.deepEqual(check([]), { path: path.join(binDir, "agent-cli"), suggestion: binDir });
        assert.deepEqual(check([binDir]), { path: path.join(nodeDir, "fake-node"), suggestion: nodeDir });
        assert.equal(check([binDir, nodeDir]), null);
        assert.equal(findUnreadableCommand({ command: "/bin/sh", pathEnv, homeDir: home }), null, "a system command is readable");
        assert.equal(findUnreadableCommand({ command: "does-not-exist", pathEnv, homeDir: home }), null);
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
    }
});

test("buildSrtArgs ends srt options before the command", () => {
    assert.deepEqual(buildSrtArgs({ settingsFile: "/tmp/s.json", command: "curl", commandArgs: ["-sS", "https://example.com"] }),
        ["--settings", "/tmp/s.json", "--", "curl", "-sS", "https://example.com"]);
    assert.throws(() => buildSrtArgs({ command: "x" }), (error) => error.code === "ERR_SANDBOX_SETTINGS_REQUIRED");
});

test("detectSrt reports the version, the install hint and unsupported platforms", () => {
    const found = detectSrt(() => ({ status: 0, stdout: `${SRT_TESTED_VERSION}\n` }), {}, "linux");
    assert.equal(found.ok, true);
    assert.equal(found.bin, "srt");
    assert.equal(found.version, SRT_TESTED_VERSION);
    assert.equal(detectSrt(() => ({ status: 0, stdout: "x" }), { HETZER_SRT_BIN: "/opt/srt" }, "darwin").bin, "/opt/srt");
    const missing = detectSrt(() => ({ status: null, error: new Error("ENOENT") }), {}, "linux");
    assert.equal(missing.ok, false);
    assert.match(missing.error, /npm install -g @anthropic-ai\/sandbox-runtime@/);
    assert.equal(detectSrt(() => ({ status: 0, stdout: "x" }), {}, "win32").ok, false);
});

test("selectSandboxEngine picks srt for allowlist options and refuses contradictory requests", () => {
    const docker = (cmd) => ({ status: cmd === "srt" ? 0 : 0, stdout: "1.0.0" });
    const noContainer = (cmd) => (cmd === "srt" ? { status: 0, stdout: "0.0.78" } : { status: 1, stdout: "" });
    const nothing = () => ({ status: 1, stdout: "" });
    const select = (options, exec, baseEnv = {}) => selectSandboxEngine(options, { execSyncFn: exec, baseEnv, platform: "linux" });

    assert.equal(select({}, docker).type, "docker");
    assert.equal(select({}, noContainer).type, "srt", "auto falls back to srt when no container engine runs");
    assert.equal(select({ sandboxAllowHosts: ["api.github.com"] }, docker).type, "srt");
    assert.equal(select({ sandboxEngine: "srt" }, docker).type, "srt");
    assert.equal(select({}, docker, { HETZER_SANDBOX_ENGINE: "srt" }).type, "srt");

    const code = (fn) => { try { fn(); return "none"; } catch (error) { return error.code; } };
    assert.equal(code(() => select({ sandboxEngine: "lxc" }, docker)), "ERR_SANDBOX_ENGINE_INVALID");
    assert.equal(code(() => select({ sandboxAllowHosts: ["x.com"], sandboxImage: "alpine:3.20" }, docker)), "ERR_SANDBOX_OPTIONS_CONFLICT");
    assert.equal(code(() => select({ sandboxEngine: "docker", sandboxAllowRead: ["/opt"] }, docker)), "ERR_SANDBOX_OPTIONS_CONFLICT");
    assert.equal(code(() => select({ sandboxEngine: "srt", sandboxNetwork: "bridge" }, docker)), "ERR_SANDBOX_OPTIONS_CONFLICT");
    assert.equal(code(() => select({ sandboxEngine: "srt", sandboxNetwork: "none" }, docker)), "none");
    assert.equal(code(() => select({ sandboxEngine: "srt" }, nothing)), "ERR_SANDBOX_ENGINE_UNAVAILABLE");
    assert.equal(code(() => select({}, nothing)), "ERR_DOCKER_SANDBOX_UNAVAILABLE");
    assert.equal(code(() => select({ sandboxImage: "alpine:3.20" }, noContainer)), "ERR_DOCKER_SANDBOX_UNAVAILABLE",
        "an image never falls back to srt");
});

function fakeChild() {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.pid = 0;
    setImmediate(() => {
        child.stdout.end();
        child.stderr.end();
        child.emit("close", 0, null);
    });
    return child;
}

test("executeSandboxedProcess with srt passes settings by file, keeps the master key out and removes the file", async () => {
    const root = tempDir("hetzer-srt-root-");
    const project = tempDir("hetzer-srt-project-");
    const masterKey = ["synthetic", "srt", "master", "key", "0123456789abcdef"].join("-");
    const secret = ["SYNTH", "srt", "raw", "value", "0123456789"].join("-");
    try {
        fs.mkdirSync(path.join(root, "data"));
        const dbPath = path.join(root, "data", "hetzer-vault.db");
        const vault = new Grimoire({ dbPath, masterKey });
        vault.create({ id: "raw-cred", projectId: "proj", secret, allowedActions: ["process.start"], rawInjection: "allow" });
        vault.close();
        fs.writeFileSync(path.join(root, ".env"), "API_KEY=secretRef:raw-cred\n");

        let captured;
        const errStream = new PassThrough();
        let errText = "";
        errStream.on("data", (chunk) => { errText += chunk; });
        const result = await executeSandboxedProcess({
            root,
            envFile: path.join(root, ".env"),
            vaultPath: dbPath,
            allowNames: ["raw-cred"],
            allowRawUnmediated: ["raw-cred"],
            sandbox: true,
            sandboxEngine: "srt",
            sandboxAllowHosts: ["api.github.com"],
            sandboxMountDir: project,
            command: "node",
            commandArgs: ["-e", "1"],
        }, {
            baseEnv: { PATH: "/usr/bin", HOME: "/home/x", HETZER_GRIMOIRE_KEY: masterKey, OTHER_HOST_TOKEN: "host-only", TERM: "xterm" },
            execSyncFn: (cmd) => (cmd === "srt" ? { status: 0, stdout: SRT_TESTED_VERSION } : { status: 1 }),
            spawnFn: (file, args, options) => {
                const settingsFile = args[args.indexOf("--settings") + 1];
                captured = { file, args, options, settingsFile, settings: JSON.parse(fs.readFileSync(settingsFile, "utf8")) };
                return fakeChild();
            },
            outStream: new PassThrough(),
            errStream,
        });
        assert.equal(result.status, 0);
        assert.equal(captured.file, "srt");
        assert.equal(captured.options.shell, false);
        assert.equal(captured.options.cwd, project, "srt runs from the project, where its built-in protections apply");
        assert.deepEqual(captured.args.slice(captured.args.indexOf("--")), ["--", "node", "-e", "1"]);
        assert.equal(captured.args.join("\n").includes(secret), false);
        assert.equal(captured.options.env.API_KEY, secret);
        assert.equal(Object.hasOwn(captured.options.env, "HETZER_GRIMOIRE_KEY"), false);
        assert.equal(Object.hasOwn(captured.options.env, "OTHER_HOST_TOKEN"), false);
        assert.deepEqual(captured.settings.network.allowedDomains, ["api.github.com"]);
        assert.ok(captured.settings.filesystem.allowRead.includes(project));
        assert.equal(captured.options.env.TMPDIR, captured.settings.filesystem.allowWrite.find((entry) => entry.endsWith(`${path.sep}tmp`)));
        assert.equal(fs.existsSync(captured.settingsFile), false, "the settings file is removed after the run");
        assert.match(errText, /sandbox \(srt 0\.0\.78\).*network: only api\.github\.com/);
    } finally {
        fs.rmSync(root, { recursive: true, force: true });
        fs.rmSync(project, { recursive: true, force: true });
    }
});

test("executeSandboxedProcess with srt refuses brokered credentials before resolving them", async () => {
    let spawned = false;
    await assert.rejects(executeSandboxedProcess({
        root: os.tmpdir(),
        sandbox: true,
        sandboxEngine: "srt",
        sandboxMountDir: os.tmpdir(),
        brokerPolicyFiles: ["/nonexistent/policy.json"],
        command: "node",
        commandArgs: [],
    }, {
        baseEnv: {},
        execSyncFn: () => ({ status: 0, stdout: SRT_TESTED_VERSION }),
        spawnFn: () => { spawned = true; return fakeChild(); },
    }), (error) => error.code === "ERR_SANDBOX_BROKER_UNSUPPORTED");
    assert.equal(spawned, false);
});

// Runs against a real srt when one is installed (CI installs it on Linux and macOS). It checks the settings
// Hetzer generates against the enforcement srt applies, using a temporary home directory.
const realSrt = detectSrt();
// CI sets HETZER_SRT_REQUIRED=1 on the job that installs srt, so a broken install fails instead of skipping.
test("srt is installed where it is required", { skip: process.env.HETZER_SRT_REQUIRED === "1" ? false : "HETZER_SRT_REQUIRED is not set" }, () => {
    assert.equal(realSrt.ok, true, realSrt.error);
});
test("srt enforces the generated settings: home and Hetzer files unreadable, writes confined", { skip: realSrt.ok ? false : "srt is not installed" }, () => {
    const home = tempDir("hetzer-srt-real-home-");
    const run = createSrtRunDir();
    try {
        const project = path.join(home, "proj");
        fs.mkdirSync(project);
        fs.mkdirSync(path.join(home, ".ssh"));
        const keyFile = path.join(home, ".ssh", "id_ed25519");
        fs.writeFileSync(keyFile, "synthetic-not-a-key\n");
        const envFile = path.join(project, ".env");
        fs.writeFileSync(envFile, "API_KEY=secretRef:x\n");
        fs.writeFileSync(path.join(project, "readme.txt"), "project-file\n");
        fs.mkdirSync(path.join(project, ".git", "hooks"), { recursive: true });
        fs.writeFileSync(path.join(project, ".git", "config"), "[core]\n");
        fs.mkdirSync(path.join(project, ".husky"));
        writeSrtSettings(run.settingsFile, buildSrtSettings({
            mountDir: project,
            masks: { files: [{ hostPath: envFile }], dirs: [] },
            homeDir: home,
            tmpDir: run.tmpDir,
            settingsFile: run.settingsFile,
        }));
        const sandboxed = (command, args) => spawnSync(realSrt.bin, buildSrtArgs({ settingsFile: run.settingsFile, command, commandArgs: args }), {
            cwd: project, encoding: "utf8", timeout: 60000,
            env: { PATH: process.env.PATH, HOME: home, LANG: "C", TMPDIR: run.tmpDir },
        });
        const readable = sandboxed("cat", [path.join(project, "readme.txt")]);
        assert.equal(readable.status, 0, `project file must be readable: ${readable.stderr}`);
        assert.match(readable.stdout, /project-file/);
        assert.notEqual(sandboxed("cat", [keyFile]).status, 0, "a file under the home directory must not be readable");
        const env = sandboxed("cat", [envFile]);
        assert.equal(env.status === 0 && env.stdout.includes("secretRef"), false, "the workspace .env must stay hidden");
        const write = sandboxed("touch", [path.join(project, "written.txt")]);
        assert.equal(write.status, 0, `a write inside the project must succeed: ${write.stderr}`);
        assert.equal(sandboxed("touch", [path.join(run.tmpDir, "scratch")]).status, 0, "the run's temporary directory is writable");
        sandboxed("touch", [path.join(home, "outside.txt")]);
        assert.equal(fs.existsSync(path.join(home, "outside.txt")), false, "a write outside the project must not reach the host");
        sandboxed("touch", [path.join(os.tmpdir(), `hetzer-srt-escape-${process.pid}`)]);
        assert.equal(fs.existsSync(path.join(os.tmpdir(), `hetzer-srt-escape-${process.pid}`)), false, "the shared temporary directory is not writable");
        for (const target of [path.join(project, ".git", "hooks", "pre-commit"), path.join(project, ".husky", "pre-commit")]) {
            sandboxed("sh", ["-c", `echo 'exit 0' > ${JSON.stringify(target)}`]);
            assert.equal(fs.existsSync(target), false, `${target} must not be writable: a hook would run on the host`);
        }
        sandboxed("sh", ["-c", `echo '[core] fsmonitor = x' >> ${JSON.stringify(path.join(project, ".git", "config"))}`]);
        assert.equal(fs.readFileSync(path.join(project, ".git", "config"), "utf8"), "[core]\n", ".git/config must not be writable");
        sandboxed("sh", ["-c", `echo '{}' > ${JSON.stringify(run.settingsFile)}`]);
        assert.notEqual(fs.readFileSync(run.settingsFile, "utf8").trim(), "{}", "the settings file is not writable from inside");
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(run.dir, { recursive: true, force: true });
    }
});

// Needs outbound network and a working srt proxy; CI sets HETZER_SRT_NETWORK_TEST=1 on the hosts that have both.
const networkTest = realSrt.ok && process.env.HETZER_SRT_NETWORK_TEST === "1";
test("srt network allowlist: a listed host is reachable and an unlisted one is not", { skip: networkTest ? false : "set HETZER_SRT_NETWORK_TEST=1 with srt installed" }, () => {
    const home = tempDir("hetzer-srt-net-home-");
    const run = createSrtRunDir();
    try {
        const project = path.join(home, "proj");
        fs.mkdirSync(project);
        writeSrtSettings(run.settingsFile, buildSrtSettings({
            mountDir: project, homeDir: home, tmpDir: run.tmpDir, settingsFile: run.settingsFile, allowHosts: ["example.com"],
        }));
        const sandboxed = (url) => spawnSync(realSrt.bin, buildSrtArgs({ settingsFile: run.settingsFile, command: "curl", commandArgs: ["-sS", "-o", "/dev/null", "-w", "%{http_code}", "-m", "20", url] }), {
            cwd: project, encoding: "utf8", timeout: 60000,
            env: { PATH: process.env.PATH, HOME: home, LANG: "C", TMPDIR: run.tmpDir },
        });
        const allowed = sandboxed("https://example.com/");
        assert.equal(allowed.status, 0, `the listed host must be reachable: ${allowed.stderr}`);
        const denied = sandboxed("https://www.iana.org/");
        assert.notEqual(denied.status === 0 && denied.stdout.startsWith("2"), true, "an unlisted host must not be reachable");
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(run.dir, { recursive: true, force: true });
    }
});
