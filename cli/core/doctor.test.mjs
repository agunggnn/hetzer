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
    assert.ok(check.major >= 20);
    assert.match(check.version, /^v\d+/);
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

