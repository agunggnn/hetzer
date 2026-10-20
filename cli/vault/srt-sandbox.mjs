import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// The sandbox-runtime release this integration was written and tested against. Hetzer does not bundle it
// (no runtime dependencies); install it with `npm install -g @anthropic-ai/sandbox-runtime@0.0.78`.
export const SRT_TESTED_VERSION = "0.0.78";
export const SRT_PACKAGE = "@anthropic-ai/sandbox-runtime";

// Credential stores under the home directory. The whole home directory is already read-denied; these are
// listed again so a narrower --sandbox-allow-read (for example the home directory itself, to reach a
// toolchain) still leaves them hidden: a more specific deny stays in force under a broader allow.
export const HOST_CREDENTIAL_PATHS = [
    ".ssh", ".aws", ".azure", ".config/gcloud", ".kube", ".docker", ".gnupg", ".config/gh",
    ".npmrc", ".netrc", ".git-credentials", ".pypirc", ".hetzer",
    // OS keyrings and browser profiles (cookies, saved logins)
    ".local/share/keyrings", "Library/Keychains", "Library/Cookies", ".mozilla", ".config/google-chrome",
    ".config/chromium", ".config/BraveSoftware", "Library/Application Support/Google/Chrome",
    "Library/Application Support/Firefox", "Library/Application Support/BraveSoftware",
];

// Project files that other tools execute later on the host. srt itself protects .git/hooks, .git/config, shell rc
// files, .mcp.json, .vscode/, .idea/, .claude/commands and .claude/agents relative to its working directory; these are
// added when they exist (srt 0.0.78 cannot deny a path that does not exist yet on Linux).
export const PROJECT_EXECUTED_PATHS = [".husky", ".githooks", ".envrc", ".claude/settings.json", ".claude/settings.local.json"];

// A host, a `*.` wildcard host, or either with a `:port`. No bare `*`: the allowlist names destinations.
const HOST_PATTERN = /^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::\d{1,5})?$/i;

function srtError(code, message) {
    return Object.assign(new Error(message), { code, exitCode: 1 });
}

function realPathOrResolved(target) {
    try {
        return fs.realpathSync.native(target);
    } catch {
        return path.resolve(target);
    }
}

function isSameOrInside(child, parent) {
    const relative = path.relative(parent, child);
    return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/** Validates `--sandbox-allow-host` entries. Throws `ERR_SANDBOX_HOST_INVALID` on the first bad one. */
export function validateSandboxHosts(hosts = []) {
    const result = [];
    for (const raw of hosts) {
        const host = String(raw || "").trim().toLowerCase();
        const port = host.includes(":") ? Number(host.split(":").pop()) : 0;
        if (!HOST_PATTERN.test(host) || (host.includes(":") && (port < 1 || port > 65535))) {
            throw srtError("ERR_SANDBOX_HOST_INVALID",
                `Invalid --sandbox-allow-host entry ${JSON.stringify(String(raw))}. Use a host name, '*.example.com', or either with ':<port>'.`);
        }
        if (!result.includes(host)) result.push(host);
    }
    return result;
}

export function detectSrt(exec = spawnSync, env = process.env, platform = process.platform) {
    if (platform !== "darwin" && platform !== "linux") {
        return { ok: false, error: `The srt sandbox engine is supported by Hetzer on macOS and Linux only (this host: ${platform}).` };
    }
    const bin = String(env.HETZER_SRT_BIN || "").trim() || "srt";
    try {
        const result = exec(bin, ["--version"], { encoding: "utf8", windowsHide: true, stdio: "pipe" });
        if (!result.error && result.status === 0) {
            const version = String(result.stdout || "").trim().split(/\s+/).pop() || "";
            return { ok: true, engine: "srt", type: "srt", bin, version };
        }
    } catch {
        // fall through
    }
    return {
        ok: false,
        error: `The srt sandbox engine was not found ('${bin}'). Install it with: npm install -g ${SRT_PACKAGE}@${SRT_TESTED_VERSION}`,
    };
}

function validateExtraPaths(kind, entries, { homeDir, hetzerHome, mountDir }) {
    const protectedPaths = [hetzerHome, path.join(homeDir, ".hetzer"), ...HOST_CREDENTIAL_PATHS.map((rel) => path.join(homeDir, rel))]
        .map(realPathOrResolved);
    const home = realPathOrResolved(homeDir);
    const result = [];
    for (const raw of entries) {
        const resolved = realPathOrResolved(path.resolve(String(raw || "")));
        if (!String(raw || "").trim() || resolved === path.parse(resolved).root) {
            throw srtError("ERR_SANDBOX_PATH_UNSAFE", `Refusing ${kind} '${raw}': name a directory below the filesystem root.`);
        }
        for (const protectedPath of protectedPaths) {
            if (isSameOrInside(resolved, protectedPath) || (kind === "--sandbox-allow-write" && isSameOrInside(protectedPath, resolved))) {
                throw srtError("ERR_SANDBOX_PATH_UNSAFE",
                    `Refusing ${kind} '${resolved}': it is, lies inside${kind === "--sandbox-allow-write" ? " or contains" : ""} '${protectedPath}', which holds credentials or Hetzer key material.`);
            }
        }
        if (kind === "--sandbox-allow-write" && isSameOrInside(home, resolved)) {
            throw srtError("ERR_SANDBOX_PATH_UNSAFE",
                `Refusing ${kind} '${resolved}': it is or contains the home directory, where a process could plant start-up files. Name a narrower directory.`);
        }
        if (!isSameOrInside(resolved, mountDir) && !result.includes(resolved)) result.push(resolved);
    }
    return result;
}

/**
 * Builds the sandbox-runtime settings for one run. Reads are denied for the home directory and the Hetzer
 * home and re-allowed for the mounted project (and any --sandbox-allow-read path); the Hetzer-owned paths
 * inside the project stay denied because a more specific deny wins over a broader allow. Writes are allowed
 * only in the project (unless read-only), the run's own temporary directory and any --sandbox-allow-write
 * path; the shared system temporary directory is not writable, because it can hold other users' or other
 * runs' files. Network access is denied except for the listed hosts; an empty list means no network.
 */
export function buildSrtSettings({
    mountDir,
    masks = { files: [], dirs: [] },
    homeDir = os.homedir(),
    hetzerHome,
    allowHosts = [],
    allowRead = [],
    allowWrite = [],
    readOnly = false,
    tmpDir,
    settingsFile,
} = {}) {
    if (typeof mountDir !== "string" || !mountDir) {
        throw srtError("ERR_SANDBOX_MOUNT_REQUIRED", "buildSrtSettings requires an explicit mountDir.");
    }
    if (typeof tmpDir !== "string" || !tmpDir) {
        throw srtError("ERR_SANDBOX_TMP_REQUIRED", "buildSrtSettings requires the run's own temporary directory (tmpDir).");
    }
    const home = realPathOrResolved(homeDir);
    const hetzer = realPathOrResolved(hetzerHome || path.join(homeDir, ".hetzer"));
    const context = { homeDir: home, hetzerHome: hetzer, mountDir };
    const extraRead = validateExtraPaths("--sandbox-allow-read", allowRead, context);
    const extraWrite = validateExtraPaths("--sandbox-allow-write", allowWrite, context);
    const runTmp = realPathOrResolved(tmpDir);
    if (isSameOrInside(home, runTmp) || isSameOrInside(hetzer, runTmp)) {
        throw srtError("ERR_SANDBOX_PATH_UNSAFE", `The sandbox temporary directory '${runTmp}' must not contain the home directory or the Hetzer home.`);
    }
    const hidden = [...(masks.files || []), ...(masks.dirs || [])].map((entry) => entry.hostPath);

    const denyRead = [...new Set([
        home,
        hetzer,
        path.join(home, ".hetzer"),
        ...HOST_CREDENTIAL_PATHS.map((rel) => path.join(home, rel)).filter((candidate) => fs.existsSync(candidate)),
        ...hidden,
    ])];
    const writable = readOnly ? [] : [mountDir];
    return {
        network: {
            allowedDomains: validateSandboxHosts(allowHosts),
            deniedDomains: [],
        },
        filesystem: {
            denyRead,
            // A path the command may write is one it may read back.
            allowRead: [...new Set([mountDir, ...extraRead, ...extraWrite])],
            allowWrite: [...new Set([...writable, runTmp, ...extraWrite])],
            denyWrite: [...new Set([
                hetzer,
                path.join(home, ".hetzer"),
                ...hidden,
                ...PROJECT_EXECUTED_PATHS.map((rel) => path.join(mountDir, rel)).filter((candidate) => fs.existsSync(candidate)),
                ...(settingsFile ? [settingsFile] : []),
            ])],
        },
    };
}

function findOnPath(command, pathEnv = "") {
    if (command.includes("/")) return path.resolve(command);
    for (const dir of String(pathEnv).split(path.delimiter).filter(Boolean)) {
        const candidate = path.join(dir, command);
        try {
            if (fs.statSync(candidate).isFile()) return candidate;
        } catch {
            // next directory
        }
    }
    return "";
}

function interpreterOf(file, pathEnv) {
    let head;
    try {
        const fd = fs.openSync(file, "r");
        try {
            const buffer = Buffer.alloc(256);
            head = buffer.subarray(0, fs.readSync(fd, buffer, 0, 256, 0)).toString("utf8");
        } finally {
            fs.closeSync(fd);
        }
    } catch {
        return "";
    }
    const match = /^#!\s*(\S+)(?:[ \t]+(\S+))?/.exec(head);
    if (!match) return "";
    const [, program, firstArg] = match;
    return path.basename(program) === "env" && firstArg ? findOnPath(firstArg, pathEnv) : program;
}

/**
 * The home directory is unreadable inside the srt sandbox, so a command installed there (a per-user agent
 * install, a version manager's node) cannot start. Finds the command, and the interpreter its `#!` line names,
 * and returns the first one that lies under the home directory outside every readable path, with the directory
 * to pass to --sandbox-allow-read. Returns null when both are readable or cannot be found.
 */
export function findUnreadableCommand({ command, pathEnv = process.env.PATH, homeDir = os.homedir(), readable = [] } = {}) {
    const home = realPathOrResolved(homeDir);
    const open = readable.map(realPathOrResolved);
    const executable = findOnPath(String(command || ""), pathEnv);
    for (const candidate of [executable, executable ? interpreterOf(realPathOrResolved(executable), pathEnv) : ""]) {
        if (!candidate) continue;
        const real = realPathOrResolved(candidate);
        if (!isSameOrInside(real, home) || open.some((dir) => isSameOrInside(real, dir))) continue;
        // Suggest a narrow directory (~/.local/share/claude, ~/.nvm/versions/node): up to three levels below the
        // home directory, and never the file itself.
        const parts = path.relative(home, real).split(path.sep);
        return { path: real, suggestion: path.join(home, ...parts.slice(0, Math.min(3, parts.length - 1))) };
    }
    return null;
}

/** `srt --settings <file> -- <command> [args]`. srt shell-quotes each argument before its own wrapper runs it. */
export function buildSrtArgs({ settingsFile, command, commandArgs = [] } = {}) {
    if (!settingsFile) throw srtError("ERR_SANDBOX_SETTINGS_REQUIRED", "buildSrtArgs requires a settings file.");
    if (!command) throw srtError("ERR_SANDBOX_COMMAND_REQUIRED", "buildSrtArgs requires a command.");
    return ["--settings", settingsFile, "--", command, ...commandArgs.map(String)];
}

/**
 * Creates the per-run directory: `tmp/` is the command's temporary directory (TMPDIR), and the settings file
 * sits beside it, outside the writable area. The caller removes `dir` afterwards.
 */
export function createSrtRunDir() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-srt-"));
    try { fs.chmodSync(dir, 0o700); } catch { /* best effort */ }
    const tmpDir = path.join(dir, "tmp");
    fs.mkdirSync(tmpDir, { mode: 0o700 });
    return { dir, tmpDir, settingsFile: path.join(dir, "srt-settings.json") };
}

export function writeSrtSettings(settingsFile, settings) {
    fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2), { encoding: "utf8", mode: 0o600, flag: "wx" });
    return settingsFile;
}
