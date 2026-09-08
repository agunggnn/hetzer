import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function getOperatingSystemInfo() {
    const platform = process.platform;
    const arch = process.arch;
    let name = platform;
    let isUbuntu = false;

    if (platform === "linux") {
        name = "Linux";
        if (fs.existsSync("/etc/os-release")) {
            try {
                const osRelease = fs.readFileSync("/etc/os-release", "utf8");
                const match = osRelease.match(/^PRETTY_NAME=["']?([^"'\r\n]+)["']?/m);
                if (match) name = match[1];
                if (/ubuntu/i.test(name) || /ubuntu/i.test(osRelease)) isUbuntu = true;
            } catch {
                /* fallback to Linux */
            }
        }
    } else if (platform === "win32") {
        name = `Windows (${os.release()})`;
    } else if (platform === "darwin") {
        name = `macOS (${os.release()})`;
    }

    return { platform, arch, name, isUbuntu };
}

export function checkNodeRuntime() {
    const version = process.version;
    const match = version.match(/^v(\d+)\.(\d+)/);
    const major = match ? parseInt(match[1], 10) : 0;
    const ok = major >= 20;
    let sqliteSupported = true;
    try {
        if (major < 22 && !process.features?.sqlite) {
            sqliteSupported = false;
        }
    } catch {
        sqliteSupported = false;
    }
    return {
        version,
        major,
        ok,
        sqliteSupported,
        message: ok ? `${version} (OK)` : `${version} (Requires Node.js v20+)`,
    };
}

export function checkDockerCli(exec = spawnSync) {
    try {
        const result = exec("docker", ["--version"], { encoding: "utf8", windowsHide: true });
        if (result.status === 0) {
            const versionStr = String(result.stdout || "").trim();
            return { ok: true, version: versionStr };
        }
        return {
            ok: false,
            error: String(result.stderr || result.stdout || "Command 'docker' not found in PATH.").trim(),
        };
    } catch (err) {
        return { ok: false, error: err.message };
    }
}

export function checkDockerDaemon(exec = spawnSync, osInfo = getOperatingSystemInfo()) {
    try {
        const result = exec("docker", ["info", "--format", "{{json .ServerVersion}}"], {
            encoding: "utf8",
            windowsHide: true,
        });
        if (result.status === 0) {
            const version = String(result.stdout || "").trim().replace(/^"|"$/g, "");
            return { ok: true, version: version || "Running" };
        }
        const errText = String(result.stderr || result.stdout || "");
        const errLower = errText.toLowerCase();
        const isPermissionDenied = errLower.includes("permission denied") || errLower.includes("dial unix /var/run/docker.sock");
        const isNotRunning = errLower.includes("is the docker daemon running") || errLower.includes("connection refused") || errLower.includes("cannot connect");

        let guide = "";
        let errorSummary = "";

        if (isPermissionDenied) {
            errorSummary = "Docker socket access denied (Permission Denied).";
            let user = "current-user";
            try {
                user = os.userInfo().username || user;
            } catch {
                user = process.env.USERNAME || process.env.USER || user;
            }
            guide = osInfo.platform === "linux"
                ? `On Linux Ubuntu/Debian, user '${user}' needs to be added to the 'docker' group:\n    sudo usermod -aG docker ${user}\n    newgrp docker\n    (or log out and log in again)`
                : "Ensure your user account has permission to access the Docker daemon.";
        } else if (isNotRunning) {
            errorSummary = "Docker daemon / service is not running.";
            guide = osInfo.platform === "linux"
                ? "Start the Docker service on Ubuntu/Debian:\n    sudo systemctl start docker\n    sudo systemctl enable docker"
                : "Please open Docker Desktop and ensure the Engine status is 'Running'.";
        } else {
            errorSummary = errText.trim() || "Cannot connect to Docker daemon.";
            guide = "Ensure the Docker service is running.";
        }

        return {
            ok: false,
            isPermissionDenied,
            isNotRunning,
            error: errorSummary,
            rawError: errText.trim(),
            guide,
        };
    } catch (err) {
        return {
            ok: false,
            error: err.message,
            guide: "Ensure Docker is installed and the service is running.",
        };
    }
}

export function checkDockerCompose(exec = spawnSync, osInfo = getOperatingSystemInfo()) {
    try {
        const result = exec("docker", ["compose", "version"], { encoding: "utf8", windowsHide: true });
        if (result.status === 0) {
            const versionStr = String(result.stdout || "").trim();
            return { ok: true, version: versionStr };
        }
        const guide = osInfo.platform === "linux"
            ? "Docker Compose v2 plugin not found. On Ubuntu install with:\n    sudo apt-get update && sudo apt-get install -y docker-compose-plugin"
            : "Docker Compose v2 not found. Ensure Docker Desktop is properly installed.";
        return {
            ok: false,
            error: String(result.stderr || result.stdout || "Docker Compose v2 plugin not found.").trim(),
            guide,
        };
    } catch (err) {
        return { ok: false, error: err.message, guide: "Ensure Docker Compose v2 plugin is installed." };
    }
}

export function checkFilePermissions(targetPath) {
    if (process.platform === "win32") {
        return { ok: true, mode: "Windows ACL", note: "Managed by Windows ACL" };
    }
    if (!fs.existsSync(targetPath)) {
        return { ok: true, mode: "N/A", note: "File/directory not yet created" };
    }
    try {
        const stat = fs.statSync(targetPath);
        const mode = (stat.mode & 0o777).toString(8);
        const isSecure = ["600", "400", "700"].includes(mode);
        return {
            ok: isSecure,
            mode,
            note: isSecure ? `Secure (${mode})` : `Warning: permission ${mode} is too permissive (recommend 0600 / 0700)`,
        };
    } catch {
        return { ok: true, mode: "unknown", note: "Unable to inspect permissions" };
    }
}

export function applyDoctorFixes({ root, out = process.stdout }) {
    const fixes = [];
    const envFile = path.join(root, ".env");
    const dataDir = path.join(root, "data");

    // 1. Ensure data directory exists with 0700
    if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
        try { fs.chmodSync(dataDir, 0o700); } catch { /* Windows */ }
        fixes.push("Created data/ directory with secure permissions (0700)");
    } else if (process.platform !== "win32") {
        try {
            const stat = fs.statSync(dataDir);
            const mode = (stat.mode & 0o777).toString(8);
            if (mode !== "700") {
                fs.chmodSync(dataDir, 0o700);
                fixes.push(`Fixed data/ directory permissions from ${mode} to 0700`);
            }
        } catch { /* ignore */ }
    }

    // 2. Ensure .env permissions are 0600 on Unix
    if (fs.existsSync(envFile) && process.platform !== "win32") {
        try {
            const stat = fs.statSync(envFile);
            const mode = (stat.mode & 0o777).toString(8);
            if (mode !== "600") {
                fs.chmodSync(envFile, 0o600);
                fixes.push(`Fixed .env file permissions from ${mode} to 0600`);
            }
        } catch { /* ignore */ }
    }

    // 3. Ensure root directory permissions on Unix
    if (fs.existsSync(root) && process.platform !== "win32") {
        try {
            const stat = fs.statSync(root);
            const mode = (stat.mode & 0o777).toString(8);
            if (!["700", "750"].includes(mode)) {
                fs.chmodSync(root, 0o700);
                fixes.push(`Fixed workspace root permissions from ${mode} to 0700`);
            }
        } catch { /* ignore */ }
    }

    // 4. Missing .env from .env.example
    const envExample = path.join(root, ".env.example");
    if (!fs.existsSync(envFile) && fs.existsSync(envExample)) {
        fs.copyFileSync(envExample, envFile);
        try { fs.chmodSync(envFile, 0o600); } catch { /* Windows */ }
        fixes.push("Copied .env from .env.example (run 'hetzer init' to generate credentials)");
    }

    if (fixes.length > 0) {
        out.write("--------------------------------------------------------------------------------\n");
        out.write("  AUTOMATIC REPAIRS (--fix):\n");
        for (const f of fixes) {
            out.write(`  [v] ${f}\n`);
        }
        out.write("--------------------------------------------------------------------------------\n\n");
    }

    return fixes;
}

export function runDoctor({ root, defaultHome, exec = spawnSync, out = process.stdout, fix = false }) {
    if (fix) {
        applyDoctorFixes({ root, out });
    }
    const osInfo = getOperatingSystemInfo();
    const nodeCheck = checkNodeRuntime();
    const cliCheck = checkDockerCli(exec);
    const daemonCheck = checkDockerDaemon(exec, osInfo);
    const composeCheck = checkDockerCompose(exec, osInfo);

    const isGlobal = Boolean(defaultHome && root === defaultHome);
    const envFile = path.join(root, ".env");
    const envExists = fs.existsSync(envFile);
    const permCheck = envExists ? checkFilePermissions(envFile) : checkFilePermissions(root);

    let composeConfigValid = null;
    let composeConfigError = "";
    if (envExists && composeCheck.ok && daemonCheck.ok) {
        try {
            const result = exec(
                "docker",
                ["compose", "--project-directory", root, "--env-file", envFile, "config", "--quiet"],
                { cwd: root, encoding: "utf8", windowsHide: true }
            );
            if (result.status === 0) {
                composeConfigValid = true;
            } else {
                composeConfigValid = false;
                composeConfigError = String(result.stderr || result.stdout || "").trim();
            }
        } catch (err) {
            composeConfigValid = false;
            composeConfigError = err.message;
        }
    }

    out.write("================================================================================\n");
    out.write("  HETZER CORE - COMPATIBILITY & SYSTEM DOCTOR\n");
    out.write("================================================================================\n");

    // OS
    out.write(`  Operating System  : ${osInfo.name} (${osInfo.arch}) [OK]\n`);

    // Node.js
    const nodeTag = nodeCheck.ok ? "[OK]" : "[FAIL]";
    out.write(`  Node.js Runtime   : ${nodeCheck.message} ${nodeTag}\n`);

    // Docker CLI
    if (cliCheck.ok) {
        out.write(`  Docker CLI        : ${cliCheck.version} [OK]\n`);
    } else {
        out.write(`  Docker CLI        : Not detected [FAIL]\n`);
    }

    // Docker Engine / Daemon
    if (daemonCheck.ok) {
        out.write(`  Docker Engine     : Running (v${daemonCheck.version}) [OK]\n`);
    } else {
        out.write(`  Docker Engine     : FAILED / Cannot connect [FAIL]\n`);
    }

    // Docker Compose
    if (composeCheck.ok) {
        out.write(`  Docker Compose    : ${composeCheck.version} [OK]\n`);
    } else {
        out.write(`  Docker Compose    : Plugin v2 Not Found [FAIL]\n`);
    }

    // Hetzer Root & Instance
    const rootLabel = isGlobal ? `${root} (Global User Home)` : `${root} (Local Workspace)`;
    out.write(`  Hetzer Root       : ${rootLabel}\n`);

    // Instance Status
    if (envExists) {
        out.write(`  Instance Status   : Initialized (.env active) [OK]\n`);
        out.write(`  File Permissions  : ${permCheck.note} ${permCheck.ok ? "[OK]" : "[WARN]"}\n`);
        if (composeConfigValid === true) {
            out.write(`  Compose Config    : Configuration valid [OK]\n`);
        } else if (composeConfigValid === false) {
            out.write(`  Compose Config    : Configuration issue [FAIL]\n`);
        }
    } else {
        out.write(`  Instance Status   : Not yet initialized (Run 'hetzer init') [INFO]\n`);
    }

    out.write("================================================================================\n");

    const issues = [];
    if (!nodeCheck.ok) {
        issues.push({
            title: "Node.js Version Does Not Meet Requirements",
            detail: `Current Node version (${nodeCheck.version}) is below minimum requirement of v20.x.`,
            solution: "Update Node.js to v20 LTS or v22 LTS (https://nodejs.org).",
        });
    }
    if (!cliCheck.ok) {
        issues.push({
            title: "Docker CLI Not Found",
            detail: cliCheck.error,
            solution: osInfo.platform === "linux"
                ? "On Ubuntu run:\n    sudo apt-get update && sudo apt-get install -y docker.io"
                : "Download and install Docker Desktop from https://www.docker.com/products/docker-desktop",
        });
    }
    if (!daemonCheck.ok) {
        issues.push({
            title: daemonCheck.error || "Docker Engine Not Connected",
            detail: daemonCheck.rawError,
            solution: daemonCheck.guide,
        });
    }
    if (!composeCheck.ok) {
        issues.push({
            title: "Docker Compose v2 Plugin Not Found",
            detail: composeCheck.error,
            solution: composeCheck.guide,
        });
    }
    if (composeConfigValid === false) {
        issues.push({
            title: "Docker Compose Validation Failed",
            detail: composeConfigError,
            solution: "Check docker-compose.yml syntax or re-run 'hetzer init'.",
        });
    }

    if (issues.length === 0) {
        out.write("[v] STATUS: Your system is fully compatible and ready to run Hetzer Core!\n");
        if (!envExists) {
            out.write("[i] Next step: run 'hetzer init' to create initial credentials.\n");
        }
        return { ok: true, issues: [] };
    }

    out.write(`[!] FOUND ${issues.length} ISSUE(S) THAT NEED RESOLUTION:\n`);
    for (let i = 0; i < issues.length; i += 1) {
        const issue = issues[i];
        out.write(`\n  ${i + 1}. [ISSUE] ${issue.title}\n`);
        if (issue.detail) {
            out.write(`     Detail   : ${issue.detail}\n`);
        }
        out.write(`     Solution :\n`);
        for (const line of issue.solution.split("\n")) {
            out.write(`       ${line}\n`);
        }
    }
    out.write("\n================================================================================\n");
    return { ok: false, issues };
}
