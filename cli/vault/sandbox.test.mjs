import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";

import { Grimoire } from "./hetzer-vault.mjs";
import {
    buildContainerCliEnv,
    buildSandboxDockerArgs,
    checkDockerAvailable,
    detectContainerEngine,
    executeSandboxedProcess,
    resolveSandboxMount,
    selectContainerEnv,
} from "./sandbox.mjs";

test("buildSandboxDockerArgs constructs isolated docker execution parameters", () => {
    const root = path.resolve("/tmp/test-project");

    const args = buildSandboxDockerArgs({
        mountDir: root,
        envNames: ["OPENAI_BASE_URL", "PROJECT_NAME"],
        image: "node:22-alpine",
        network: "bridge",
        readOnly: false,
        containerName: "test-sandbox-01",
        command: "node.exe",
        commandArgs: ["index.js"],
    });

    // 1. Ephemeral and interactive flags
    assert.ok(args.includes("--rm"));
    assert.ok(args.includes("-i"));
    assert.ok(args.includes("--name"));
    assert.equal(args[args.indexOf("--name") + 1], "test-sandbox-01");

    // 2. Linux capability dropping and privilege mitigation
    assert.ok(args.includes("--cap-drop=ALL"));
    assert.ok(args.includes("--security-opt=no-new-privileges"));
    assert.ok(args.includes("--pids-limit=100"));

    // 3. Workspace mount and working directory
    assert.ok(args.includes("-w"));
    assert.equal(args[args.indexOf("-w") + 1], "/workspace");
    const mountIndex = args.indexOf("-v");
    assert.ok(mountIndex >= 0);
    assert.equal(args[mountIndex + 1], `${root}:/workspace:rw`);

    // 4. Environment variables are forwarded by name only; values never appear in argv
    const envEntries = args.filter((_, i) => args[i - 1] === "-e");
    assert.deepEqual(envEntries, ["OPENAI_BASE_URL", "PROJECT_NAME"]);
    assert.equal(args.some((arg) => arg.includes("=") && envEntries.includes(arg.split("=")[0])), false);

    // 5. Normalization of Windows node.exe to node
    const imageIndex = args.indexOf("node:22-alpine");
    assert.ok(imageIndex >= 0);
    assert.equal(args[imageIndex + 1], "node");
    assert.equal(args[imageIndex + 2], "index.js");
});

test("buildSandboxDockerArgs refuses environment values and invalid variable names", () => {
    assert.throws(
        () => buildSandboxDockerArgs({ mountDir: "/tmp/p", env: { API_KEY: "synthetic-value" }, command: "node" }),
        /no longer accepts environment values/i,
    );
    assert.throws(
        () => buildSandboxDockerArgs({ mountDir: "/tmp/p", envNames: ["BAD NAME"], command: "node" }),
        /Invalid sandbox environment variable name/i,
    );
    assert.throws(
        () => buildSandboxDockerArgs({ mountDir: "/tmp/p", envNames: ["A=B"], command: "node" }),
        /Invalid sandbox environment variable name/i,
    );
});

test("selectContainerEnv forwards only injected variables and a terminal allowlist", () => {
    const hostEnv = {
        PATH: "C:/Windows/System32",
        USERPROFILE: "C:/Users/someone",
        HETZER_GRIMOIRE_KEY: "synthetic-master-key",
        HETZER_ROOT: "C:/instance",
        SOME_OTHER_HOST_TOKEN: "host-only-value",
        TERM: "xterm",
        LANG: "en_US.UTF-8",
        LC_TIME: "C",
        // Injected by Hetzer:
        API_KEY: "synthetic-secret-with-localhost-in-value",
        UP_URL: "http://127.0.0.1:41234/v1",
        HETZER_BROKER_URL: "http://localhost:41234/v1",
    };
    const { values, names } = selectContainerEnv({
        env: hostEnv,
        injectedNames: ["API_KEY", "UP_URL", "HETZER_BROKER_URL", "HETZER_GRIMOIRE_KEY"],
        brokerUrlNames: ["UP_URL", "HETZER_BROKER_URL"],
    });

    assert.deepEqual(new Set(names), new Set(["API_KEY", "UP_URL", "HETZER_BROKER_URL", "TERM", "LANG", "LC_TIME"]));
    for (const forbidden of ["PATH", "USERPROFILE", "HETZER_GRIMOIRE_KEY", "HETZER_ROOT", "SOME_OTHER_HOST_TOKEN"]) {
        assert.equal(Object.hasOwn(values, forbidden), false, `${forbidden} must not reach the container`);
    }
    // Loopback is rewritten for broker URL variables only; a credential value is never altered.
    assert.equal(values.UP_URL, "http://host.docker.internal:41234/v1");
    assert.equal(values.HETZER_BROKER_URL, "http://host.docker.internal:41234/v1");
    assert.equal(values.API_KEY, "synthetic-secret-with-localhost-in-value");
});

test("selectContainerEnv rejects invalid names and NUL bytes", () => {
    assert.throws(() => selectContainerEnv({ env: { "BAD NAME": "x" }, injectedNames: ["BAD NAME"] }), /invalid environment variable name/i);
    assert.throws(() => selectContainerEnv({ env: { API_KEY: "a\0b" }, injectedNames: ["API_KEY"] }), /NUL byte/i);
});

test("buildContainerCliEnv keeps the engine CLI working without the master key or unrelated host variables", () => {
    const baseEnv = {
        PATH: "/usr/bin",
        HOME: "/home/someone",
        DOCKER_HOST: "unix:///var/run/docker.sock",
        HETZER_GRIMOIRE_KEY: "synthetic-master-key",
        SOME_OTHER_HOST_TOKEN: "host-only-value",
        TERM: "xterm",
    };
    const cliEnv = buildContainerCliEnv({ baseEnv, containerValues: { API_KEY: "synthetic-secret", TERM: "xterm" } });
    assert.equal(cliEnv.PATH, "/usr/bin");
    assert.equal(cliEnv.DOCKER_HOST, "unix:///var/run/docker.sock");
    assert.equal(cliEnv.API_KEY, "synthetic-secret");
    assert.equal(Object.hasOwn(cliEnv, "HETZER_GRIMOIRE_KEY"), false);
    assert.equal(Object.hasOwn(cliEnv, "SOME_OTHER_HOST_TOKEN"), false);

    assert.throws(
        () => buildContainerCliEnv({ baseEnv, containerValues: { path: "/malicious" } }),
        (error) => error.code === "ERR_SANDBOX_ENV_COLLISION",
    );
});

function fakeEngineChild() {
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

for (const strict of [true, false]) {
    test(`executeSandboxedProcess keeps secrets and the master key off the engine command line (strict=${strict})`, async () => {
        const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sandbox-env-"));
        const project = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-sandbox-env-project-"));
        const masterKey = "synthetic-master-key-0123456789abcdef0123456789";
        const secret = "SYNTH-sandbox-secret-value-0123456789";
        const hostToken = "host-only-token-value-0123456789";
        try {
            fs.mkdirSync(path.join(root, "data"), { recursive: true });
            const dbPath = path.join(root, "data", "hetzer-vault.db");
            const vault = new Grimoire({ dbPath, masterKey });
            vault.create({ id: "raw-cred", projectId: "proj", secret, allowedActions: ["process.start"], rawInjection: "allow" });
            vault.close();
            fs.writeFileSync(path.join(root, ".env"), "API_KEY=secretRef:raw-cred\n");

            let captured;
            const result = await executeSandboxedProcess({
                root,
                envFile: path.join(root, ".env"),
                vaultPath: dbPath,
                allowNames: ["raw-cred"],
                allowRawUnmediated: ["raw-cred"],
                strict,
                sandbox: true,
                sandboxMountDir: project,
                sandboxImage: "alpine:3.20",
                command: "/bin/true",
                commandArgs: [],
            }, {
                baseEnv: { PATH: "/usr/bin", USERPROFILE: "/home/x", HETZER_GRIMOIRE_KEY: masterKey, SOME_OTHER_HOST_TOKEN: hostToken, TERM: "xterm" },
                execSyncFn: () => ({ status: 0, stdout: "ok" }),
                spawnFn: (engine, args, options) => {
                    captured = { engine, args, options };
                    return fakeEngineChild();
                },
                outStream: new PassThrough(),
                errStream: new PassThrough(),
            });

            assert.equal(result.status, 0);
            const argvText = captured.args.join("\n");
            for (const needle of [secret, masterKey, hostToken]) {
                assert.equal(argvText.includes(needle), false, "engine argv must not contain secret material");
            }
            assert.ok(captured.args.includes("API_KEY"), "the credential variable is forwarded by name");
            const forwarded = captured.args.filter((_, i) => captured.args[i - 1] === "-e");
            assert.equal(forwarded.includes("PATH"), false);
            assert.equal(forwarded.includes("USERPROFILE"), false);
            assert.equal(forwarded.includes("HETZER_GRIMOIRE_KEY"), false);
            assert.equal(forwarded.includes("SOME_OTHER_HOST_TOKEN"), false);
            assert.equal(forwarded.includes("HETZER_ROOT"), false);

            // The value reaches the engine through its own environment, which does not hold the master key.
            assert.equal(captured.options.env.API_KEY, secret);
            assert.equal(Object.hasOwn(captured.options.env, "HETZER_GRIMOIRE_KEY"), false);
            assert.equal(Object.hasOwn(captured.options.env, "SOME_OTHER_HOST_TOKEN"), false);
        } finally {
            fs.rmSync(root, { recursive: true, force: true });
            fs.rmSync(project, { recursive: true, force: true });
        }
    });
}

test("checkDockerAvailable inspects Docker CLI and daemon connectivity", () => {
    // 1. Successful check
    const mockSuccessExec = (cmd, args) => {
        if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.2.0\n" };
        if (args.includes("info")) return { status: 0, stdout: "Server Version: 27.2.0\n" };
        return { status: 0 };
    };
    const successRes = checkDockerAvailable(mockSuccessExec);
    assert.equal(successRes.ok, true);

    // 2. Missing CLI and daemon
    const mockMissingCli = () => ({ status: 127, stderr: "not found\n" });
    const missingRes = checkDockerAvailable(mockMissingCli);
    assert.equal(missingRes.ok, false);
    assert.match(missingRes.error, /Neither Docker nor Podman is installed/i);
});

test("detectContainerEngine detects Podman when Docker is missing", () => {
    const mockExec = (cmd, args) => {
        if (cmd === "docker") return { status: 127, stderr: "docker: not found" };
        if (cmd === "podman" && args.includes("--version")) return { status: 0, stdout: "podman version 5.0.0\n" };
        if (cmd === "podman" && args.includes("info")) return { status: 0, stdout: "host: ...\n" };
        return { status: 1 };
    };

    const res = detectContainerEngine(mockExec);
    assert.equal(res.ok, true);
    assert.equal(res.engine, "podman");
    assert.equal(res.type, "podman");
});

test("detectContainerEngine respects HETZER_CONTAINER_ENGINE override", () => {
    const orig = process.env.HETZER_CONTAINER_ENGINE;
    try {
        process.env.HETZER_CONTAINER_ENGINE = "podman";
        let invoked = [];
        const mockExec = (cmd, args) => {
            invoked.push(cmd);
            return { status: 0, stdout: "ok" };
        };
        const res = detectContainerEngine(mockExec);
        assert.equal(res.ok, true);
        assert.equal(res.engine, "podman");
        assert.equal(invoked.includes("docker"), false);
    } finally {
        if (orig !== undefined) process.env.HETZER_CONTAINER_ENGINE = orig;
        else delete process.env.HETZER_CONTAINER_ENGINE;
    }
});

test("buildSandboxDockerArgs adds :Z mount and host.containers.internal for Podman on Linux", () => {
    const root = path.resolve("/tmp/test-project");
    const args = buildSandboxDockerArgs({
        mountDir: root,
        engine: "podman",
        platform: "linux",
        command: "node",
    });

    assert.ok(args.includes("--add-host=host.docker.internal:host-gateway"));
    assert.ok(args.includes("--add-host=host.containers.internal:host-gateway"));
    const mountIndex = args.indexOf("-v");
    assert.ok(mountIndex >= 0);
    assert.equal(args[mountIndex + 1], `${root}:/workspace:rw,Z`);
});

test("executeSandboxedProcess fails closed when Docker and Podman are unavailable", async () => {
    const mockMissingExec = () => ({ status: 1, stderr: "Cannot connect to container daemon\n" });

    await assert.rejects(
        () => executeSandboxedProcess({
            root: process.cwd(),
            command: "npm",
            commandArgs: ["test"],
        }, {
            execSyncFn: mockMissingExec,
        }),
        (err) => {
            assert.equal(err.code, "ERR_DOCKER_SANDBOX_UNAVAILABLE");
            assert.equal(err.exitCode, 1);
            assert.match(err.message, /sandbox unavailable/i);
            return true;
        }
    );
});

test("buildSandboxDockerArgs rejects CLI option injection and malformed image names", () => {
    const dangerousImages = [
        "--privileged",
        "--cap-add=ALL",
        "-it",
        "--volume /:/host",
        "alpine; rm -rf /",
        "node:22 --entrypoint /bin/sh",
        "   ",
        "",
        "-invalid",
    ];

    for (const badImage of dangerousImages) {
        assert.throws(
            () => buildSandboxDockerArgs({ mountDir: "/tmp/p", image: badImage, command: "node" }),
            /Invalid sandbox image/i,
            `Expected '${badImage}' to be rejected`
        );
    }

    // Valid OCI images must pass
    const validImages = [
        "node:22-alpine",
        "alpine",
        "ubuntu:24.04",
        "ghcr.io/agunggnn/hetzer:latest",
        "docker.io/library/node:20",
        "registry.corp.internal:5000/sec/agent-box:v1.2.3",
    ];

    for (const validImage of validImages) {
        const args = buildSandboxDockerArgs({ mountDir: "/tmp/p", image: validImage, command: "node" });
        assert.ok(args.includes(validImage));
    }
});

function makeTree(prefix, spec) {
    const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
    for (const [relative, kind] of Object.entries(spec)) {
        const target = path.join(base, ...relative.split("/"));
        if (kind === "dir") {
            fs.mkdirSync(target, { recursive: true });
        } else {
            fs.mkdirSync(path.dirname(target), { recursive: true });
            fs.writeFileSync(target, "synthetic fixture\n");
        }
    }
    return base;
}

test("resolveSandboxMount requires an existing directory", () => {
    assert.throws(() => resolveSandboxMount({}), (e) => e.code === "ERR_SANDBOX_MOUNT_REQUIRED");
    assert.throws(
        () => resolveSandboxMount({ mountDir: path.join(os.tmpdir(), "hetzer-does-not-exist-xyz") }),
        (e) => e.code === "ERR_SANDBOX_MOUNT_INVALID",
    );
    const file = makeTree("hetzer-mount-file-", { "a.txt": "file" });
    try {
        assert.throws(
            () => resolveSandboxMount({ mountDir: path.join(file, "a.txt") }),
            (e) => e.code === "ERR_SANDBOX_MOUNT_INVALID",
        );
    } finally {
        fs.rmSync(file, { recursive: true, force: true });
    }
});

test("resolveSandboxMount refuses the filesystem root, the home directory, the Hetzer home and their ancestors", () => {
    const home = makeTree("hetzer-mount-home-", { ".hetzer/grimoire.key": "file", "code/project/readme.md": "file" });
    try {
        const unsafe = [
            path.parse(home).root,
            path.dirname(home), // an ancestor of the home directory
            home,
            path.join(home, ".hetzer"),
            path.join(home, ".hetzer", "nested-inside-hetzer-home"),
        ];
        fs.mkdirSync(path.join(home, ".hetzer", "nested-inside-hetzer-home"), { recursive: true });
        for (const mountDir of unsafe) {
            assert.throws(
                () => resolveSandboxMount({ mountDir, root: mountDir, homeDir: home, hetzerHome: path.join(home, ".hetzer") }),
                (e) => e.code === "ERR_SANDBOX_MOUNT_UNSAFE",
                `expected ${mountDir} to be refused`,
            );
        }
        // A project below the home directory is fine.
        const plan = resolveSandboxMount({ mountDir: path.join(home, "code", "project"), root: path.join(home, ".hetzer"), homeDir: home, hetzerHome: path.join(home, ".hetzer") });
        assert.equal(plan.mountDir, path.join(home, "code", "project"));
        assert.deepEqual(plan.masks, { files: [], dirs: [] });
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
    }
});

test("resolveSandboxMount hides Hetzer-owned paths that sit inside the mount, and only those that exist", () => {
    const home = makeTree("hetzer-mount-mask-home-", {});
    const project = makeTree("hetzer-mount-mask-project-", {
        "src/index.js": "file",
        "README.md": "file",
        ".env": "file",
        "data/hetzer-vault.db": "file",
        "data/hetzer-vault.db-wal": "file",
        "data/hetzer-incidents.log": "file",
        "data/credential-requests/req.json": "file",
        ".hetzer/audit.log": "file",
        ".hetzer/audit.log.head": "file",
    });
    try {
        const plan = resolveSandboxMount({ mountDir: project, root: project, envFile: path.join(project, ".env"), homeDir: home, hetzerHome: path.join(home, ".hetzer") });
        const files = plan.masks.files.map((item) => item.containerPath).sort();
        const dirs = plan.masks.dirs.map((item) => item.containerPath).sort();
        assert.deepEqual(files, [
            "/workspace/.env",
            "/workspace/.hetzer/audit.log",
            "/workspace/.hetzer/audit.log.head",
            "/workspace/data/hetzer-incidents.log",
            "/workspace/data/hetzer-vault.db",
            "/workspace/data/hetzer-vault.db-wal",
        ]);
        assert.deepEqual(dirs, ["/workspace/.hetzer", "/workspace/data/credential-requests"]);
        // Files that are not there are not masked (a bind target would otherwise be created in the project).
        assert.equal(files.some((item) => item.endsWith("-shm") || item.endsWith("vault.json")), false);
        // Project files are not masked.
        assert.equal(files.some((item) => item.includes("src/") || item.endsWith("README.md")), false);
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(project, { recursive: true, force: true });
    }
});

test("resolveSandboxMount masks a vault path override and an env file kept inside the project", () => {
    const home = makeTree("hetzer-mount-override-home-", {});
    const project = makeTree("hetzer-mount-override-project-", { "secrets/my.db": "file", "config/instance.env": "file", "app.js": "file" });
    const instance = makeTree("hetzer-mount-override-instance-", { "data/hetzer-vault.db": "file", ".env": "file" });
    try {
        const plan = resolveSandboxMount({
            mountDir: project,
            root: instance,
            envFile: path.join(project, "config", "instance.env"),
            vaultPath: path.join(project, "secrets", "my.db"),
            homeDir: home,
        });
        assert.deepEqual(plan.masks.files.map((item) => item.containerPath).sort(), ["/workspace/config/instance.env", "/workspace/secrets/my.db"]);
        assert.deepEqual(plan.masks.dirs, []);
    } finally {
        for (const dir of [home, project, instance]) fs.rmSync(dir, { recursive: true, force: true });
    }
});

test("resolveSandboxMount fails closed when a sensitive path cannot be hidden", () => {
    const home = makeTree("hetzer-mount-wrongtype-home-", {});
    // A directory where the vault database should be a file.
    const project = makeTree("hetzer-mount-wrongtype-project-", { "data/hetzer-vault.db/inner.txt": "file" });
    try {
        assert.throws(
            () => resolveSandboxMount({ mountDir: project, root: project, homeDir: home }),
            (e) => e.code === "ERR_SANDBOX_SENSITIVE_PATH_IN_MOUNT",
        );
    } finally {
        fs.rmSync(home, { recursive: true, force: true });
        fs.rmSync(project, { recursive: true, force: true });
    }
});

test("buildSandboxDockerArgs applies masks after the main mount and needs an explicit mount directory", () => {
    const mountDir = path.resolve("/tmp/test-project");
    const args = buildSandboxDockerArgs({
        mountDir,
        maskFile: "/tmp/mask/empty",
        masks: {
            files: [{ hostPath: "/tmp/test-project/.env", containerPath: "/workspace/.env" }],
            dirs: [{ hostPath: "/tmp/test-project/.hetzer", containerPath: "/workspace/.hetzer" }],
        },
        command: "node",
    });
    const mounts = args.filter((_, i) => args[i - 1] === "-v");
    assert.equal(mounts[0], `${mountDir}:/workspace:rw`);
    assert.ok(mounts.includes("/tmp/mask/empty:/workspace/.env:ro"));
    assert.equal(mounts.length, 2);
    const tmpfsIndex = args.indexOf("--tmpfs");
    assert.ok(tmpfsIndex > args.indexOf("-v"));
    assert.equal(args[tmpfsIndex + 1], "/workspace/.hetzer:ro,noexec,nosuid,size=4k");

    assert.throws(() => buildSandboxDockerArgs({ command: "node" }), (e) => e.code === "ERR_SANDBOX_MOUNT_REQUIRED");
    assert.throws(
        () => buildSandboxDockerArgs({ mountDir, masks: { files: [{ hostPath: "a", containerPath: "/workspace/a" }], dirs: [] }, command: "node" }),
        (e) => e.code === "ERR_SANDBOX_MASK_INVALID",
    );
});

test("executeSandboxedProcess validates the mount before resolving credentials or starting the engine", async () => {
    let spawned = false;
    await assert.rejects(
        () => executeSandboxedProcess({ root: process.cwd(), command: "node", commandArgs: [] }, {
            execSyncFn: () => ({ status: 0, stdout: "ok" }),
            spawnFn: () => { spawned = true; return fakeEngineChild(); },
        }),
        (e) => e.code === "ERR_SANDBOX_MOUNT_REQUIRED",
    );
    assert.equal(spawned, false);
});
