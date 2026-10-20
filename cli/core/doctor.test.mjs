import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
    applyDoctorFixes,
    checkDockerCli,
    checkDockerCompose,
    checkDockerDaemon,
    checkFilePermissions,
    checkNodeRuntime,
    checkAgentContextHealth,
    checkAgentSandboxSafety,
    getOperatingSystemInfo,
    runDoctor,
} from "./doctor.mjs";

test("getOperatingSystemInfo detects current platform and architecture", () => {
    const info = getOperatingSystemInfo();
    assert.equal(typeof info.platform, "string");
    assert.equal(typeof info.arch, "string");
    assert.equal(typeof info.name, "string");
    assert.equal(typeof info.isUbuntu, "boolean");
});

test("checkNodeRuntime validates current Node.js runtime", () => {
    const check = checkNodeRuntime();
    assert.equal(check.ok, true);
    assert.ok(check.major >= 22);
    assert.match(check.version, /^v\d+/);

    const tooOld = checkNodeRuntime("v22.12.0");
    assert.equal(tooOld.ok, false);
    assert.match(tooOld.message, /Requires Node\.js \^22\.13\.0/);
});

test("checkDockerCli handles success and missing command", () => {
    const successExec = () => ({ status: 0, stdout: "Docker version 27.1.1\n" });
    const success = checkDockerCli(successExec);
    assert.equal(success.ok, true);
    assert.equal(success.version, "Docker version 27.1.1");

    const failExec = () => ({ status: 127, stderr: "docker: command not found\n" });
    const failed = checkDockerCli(failExec);
    assert.equal(failed.ok, false);
    assert.match(failed.error, /command not found/);
});

test("checkDockerDaemon handles permission denied on Linux Ubuntu", () => {
    const permDeniedExec = () => ({
        status: 1,
        stderr: "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock",
    });
    const linuxOs = { platform: "linux", arch: "x64", name: "Ubuntu 24.04 LTS", isUbuntu: true };
    const check = checkDockerDaemon(permDeniedExec, linuxOs);
    assert.equal(check.ok, false);
    assert.equal(check.isPermissionDenied, true);
    assert.match(check.guide, /sudo usermod -aG docker/);
});

test("checkDockerDaemon handles stopped docker daemon", () => {
    const stoppedExec = () => ({
        status: 1,
        stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
    });
    const linuxOs = { platform: "linux", arch: "x64", name: "Ubuntu 24.04 LTS", isUbuntu: true };
    const check = checkDockerDaemon(stoppedExec, linuxOs);
    assert.equal(check.ok, false);
    assert.equal(check.isNotRunning, true);
    assert.match(check.guide, /systemctl start docker/);
});

test("checkDockerDaemon reads a missing socket as a stopped daemon, not a permission problem", () => {
    const missingSocketExec = () => ({
        status: 1,
        stderr: "failed to connect to the docker API at unix:///var/run/docker.sock; check if the path is correct and if the daemon is running: dial unix /var/run/docker.sock: connect: no such file or directory",
    });
    const linuxOs = { platform: "linux", arch: "x64", name: "Ubuntu 24.04 LTS", isUbuntu: true };
    const check = checkDockerDaemon(missingSocketExec, linuxOs);
    assert.equal(check.isPermissionDenied, false);
    assert.equal(check.isNotRunning, true);
    assert.match(check.guide, /systemctl start docker/);
    assert.doesNotMatch(check.guide, /usermod/);
});

test("runDoctor reports one sandbox-engine issue, not one per Docker part, and skips Compose without a Compose file", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-noengine-"));
    let output = "";
    try {
        const exec = (cmd, args) => {
            if (cmd === "docker" && args.includes("--version")) return { status: 0, stdout: "Docker version 29.0.0\n" };
            return { status: 1, stdout: "", stderr: "dial unix /var/run/docker.sock: connect: no such file or directory" };
        };
        const result = runDoctor({ root: tempRoot, defaultHome: "", exec, out: { write: (chunk) => { output += chunk; } } });
        const dockerIssues = result.issues.filter((issue) => /Docker|sandbox/i.test(issue.title));
        assert.equal(dockerIssues.length, 1);
        assert.match(dockerIssues[0].title, /No sandbox engine/);
        assert.match(dockerIssues[0].detail, /work without one/);
        if (process.platform !== "win32") assert.match(dockerIssues[0].solution, /sandbox-runtime/);
        assert.doesNotMatch(output, /Docker Compose/);
        assert.match(output, /Docker Engine {5}: Not running \[FAIL\]/);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test("checkDockerCompose handles missing compose v2 plugin on Linux", () => {
    const missingExec = () => ({
        status: 1,
        stderr: "docker: 'compose' is not a docker command.",
    });
    const linuxOs = { platform: "linux", arch: "x64", name: "Ubuntu 24.04 LTS", isUbuntu: true };
    const check = checkDockerCompose(missingExec, linuxOs);
    assert.equal(check.ok, false);
    assert.match(check.guide, /apt-get install -y docker-compose-plugin/);
});

test("checkFilePermissions checks file mode", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-test-"));
    const perm = checkFilePermissions(tempDir);
    assert.equal(typeof perm.ok, "boolean");
    fs.rmSync(tempDir, { recursive: true, force: true });
});

test("runDoctor formats report and returns health status", () => {
    let output = "";
    const mockOut = {
        write: (chunk) => {
            output += chunk;
        },
    };
    const mockExec = (cmd, args) => {
        if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.1.1\n" };
        if (args.includes("info")) return { status: 0, stdout: '"27.1.1"\n' };
        if (args.includes("compose")) return { status: 0, stdout: "Docker Compose version v2.29.1\n" };
        return { status: 0 };
    };

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-run-"));
    const result = runDoctor({
        root: tempRoot,
        defaultHome: tempRoot,
        exec: mockExec,
        out: mockOut,
    });
    assert.equal(result.ok, true);
    assert.equal(result.issues.length, 0);
    assert.match(output, /HETZER CORE - COMPATIBILITY & SYSTEM DOCTOR/);
    assert.match(output, /Global User Home/);

    fs.rmSync(tempRoot, { recursive: true, force: true });
});

test("runDoctor treats Docker as optional when the srt sandbox engine is installed", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-srt-"));
    let output = "";
    try {
        const exec = (cmd) => (cmd === "srt" ? { status: 0, stdout: "0.0.78\n" } : { status: 1, stdout: "", stderr: "not found" });
        const result = runDoctor({ root: tempRoot, defaultHome: "", exec, out: { write: (chunk) => { output += chunk; } } });
        assert.match(output, process.platform === "win32" ? /Docker CLI {8}: Not detected \[FAIL\]/ : /Docker CLI {8}: Not detected \[INFO\]/);
        if (process.platform === "win32") {
            // Hetzer does not run srt on Windows, so a missing Docker stays a reported issue there, pointing at Docker.
            assert.match(output, /Sandbox \(srt\) {5}: Not supported on this platform/);
            const sandboxIssue = result.issues.find((issue) => /No sandbox engine/.test(issue.title));
            assert.ok(sandboxIssue, "Windows without Docker reports the missing sandbox engine");
            assert.match(sandboxIssue.solution, /Docker Desktop/);
            assert.doesNotMatch(sandboxIssue.solution, /sandbox-runtime/);
        } else {
            assert.match(output, /Sandbox \(srt\) {5}: 0\.0\.78 \[OK\]/);
            assert.equal(result.issues.some((issue) => /Docker|sandbox engine/i.test(issue.title)), false);
        }
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test("runDoctor warns when the master key is stored in the workspace .env", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-key-"));
    const exec = (cmd, args) => {
        if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.1.1\n" };
        if (args.includes("info")) return { status: 0, stdout: '"27.1.1"\n' };
        if (args.includes("compose")) return { status: 0, stdout: "Docker Compose version v2.29.1\n" };
        return { status: 0 };
    };
    const run = () => {
        let output = "";
        const result = runDoctor({ root: tempRoot, defaultHome: "", exec, out: { write: (chunk) => { output += chunk; } } });
        return { result, output };
    };
    try {
        fs.writeFileSync(path.join(tempRoot, ".env"), `HETZER_GRIMOIRE_KEY=${["doctor", "key", "value"].join("-")}\n`);
        const inWorkspace = run();
        assert.match(inWorkspace.output, /Master Key {8}: Stored in the workspace \.env, next to the vault \[WARN\]/);
        assert.ok(inWorkspace.result.issues.some((issue) => issue.title === "Master Key Stored in the Workspace"));

        fs.writeFileSync(path.join(tempRoot, ".env"), "HETZER_INSTANCE_ID=0123456789abcdef0123456789abcdef\nHETZER_GRIMOIRE_KEY=\n");
        const isolated = run();
        assert.match(isolated.output, /Master Key {8}: Not stored in the workspace \[OK\]/);
        assert.equal(isolated.result.issues.some((issue) => issue.title === "Master Key Stored in the Workspace"), false);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test("runDoctor validates a Compose file only when the project has one", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-compose-"));
    fs.writeFileSync(path.join(tempRoot, ".env"), "HETZER_VAULT_PATH=\n");
    const run = () => {
        let output = "";
        const composeConfigCalls = [];
        const exec = (cmd, args) => {
            if (args.includes("config")) {
                composeConfigCalls.push(args);
                return { status: 1, stderr: "no configuration file provided: not found" };
            }
            if (args.includes("--version")) return { status: 0, stdout: "Docker version 27.1.1\n" };
            if (args.includes("info")) return { status: 0, stdout: '"27.1.1"\n' };
            if (args.includes("compose")) return { status: 0, stdout: "Docker Compose version v2.29.1\n" };
            return { status: 0 };
        };
        const result = runDoctor({ root: tempRoot, defaultHome: tempRoot, exec, out: { write: (chunk) => { output += chunk; } } });
        return { result, output, composeConfigCalls };
    };
    try {
        // A project as 'hetzer init' leaves it: no Compose file, so nothing to validate and nothing to fail on.
        const initialized = run();
        assert.equal(initialized.composeConfigCalls.length, 0);
        assert.equal(initialized.result.issues.some((issue) => issue.title === "Docker Compose Validation Failed"), false);
        assert.doesNotMatch(initialized.output, /Compose Config/);

        // A project that brings its own Compose file still gets it checked.
        fs.writeFileSync(path.join(tempRoot, "docker-compose.yml"), "services: {}\n");
        const withCompose = run();
        assert.equal(withCompose.composeConfigCalls.length, 1);
        assert.equal(withCompose.result.issues.some((issue) => issue.title === "Docker Compose Validation Failed"), true);
        assert.match(withCompose.output, /Compose Config\s+: Configuration issue \[FAIL\]/);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test("applyDoctorFixes automatically creates missing data directory", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-fix-"));
    try {
        assert.equal(fs.existsSync(path.join(tempRoot, "data")), false);
        const fixes = applyDoctorFixes({ root: tempRoot, out: { write: () => {} } });
        assert.ok(fixes.some((f) => f.includes("data/")));
        assert.equal(fs.existsSync(path.join(tempRoot, "data")), true);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test("checkAgentContextHealth returns audit summary for workspace", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-context-"));
    try {
        const res = checkAgentContextHealth(tempRoot);
        assert.equal(res.configured, false);
        assert.equal(res.ok, true);
        assert.equal(res.summary, "Not configured");
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});

test("checkAgentSandboxSafety flags plaintext API keys and bare-metal agent execution", () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-doctor-sandbox-"));
    try {
        // 1. Clean workspace returns clean report
        const cleanRes = checkAgentSandboxSafety(tempRoot, { homeDir: null });
        assert.equal(cleanRes.ok, true);
        assert.equal(cleanRes.issues.length, 0);

        // 2. Plaintext API key inside agent config triggers issue
        const hermesDir = path.join(tempRoot, ".hermes");
        fs.mkdirSync(hermesDir, { recursive: true });
        const testToken = ["npm_", "0123456789abcdef0123456789abcdef0123"].join("");
        fs.writeFileSync(path.join(hermesDir, "config.yaml"), `api_token: "${testToken}"\nmodel: "claude-3-5"\n`);

        const leakRes = checkAgentSandboxSafety(tempRoot, { homeDir: null });
        assert.equal(leakRes.ok, false);
        assert.ok(leakRes.rawTokensCount >= 1);
        const secretIssue = leakRes.issues.find((i) => i.type === "PLAINTEXT_AGENT_SECRET");
        assert.ok(secretIssue);
        assert.match(secretIssue.detail, /config\.yaml/);
    } finally {
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
});


