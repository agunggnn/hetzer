import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { strictBaseEnvironment } from "../vault/secret-env.mjs";

export function redactExactValues(text, values = []) {
    let result = String(text || "");
    for (const value of values) {
        if (typeof value === "string" && value) result = result.replaceAll(value, "secretRef:registry-credential");
    }
    return result;
}

export function runNpmWithAuth({
    args,
    registry,
    token,
    otp = "",
    cwd = process.cwd(),
    baseEnv = process.env,
    run = spawnSync,
    tempRoot = os.tmpdir(),
    stdio,
    encoding = "utf8",
} = {}) {
    if (!Array.isArray(args)) throw new Error("npm arguments are required.");
    if (typeof token !== "string" || !token) throw new Error("Registry credential is required.");

    const registryUrl = new URL(registry);
    if (registryUrl.protocol !== "https:") throw new Error("npm registry must use HTTPS.");
    const registryPath = registryUrl.pathname.endsWith("/") ? registryUrl.pathname : `${registryUrl.pathname}/`;
    const npmrcDirectory = fs.mkdtempSync(path.join(tempRoot, "hetzer-npm-auth-"));
    const npmrcFile = path.join(npmrcDirectory, ".npmrc");
    const npmrc = [
        `registry=${registryUrl.href}`,
        `//${registryUrl.host}${registryPath}:_authToken=\${NODE_AUTH_TOKEN}`,
        "always-auth=true",
        "",
    ].join("\n");
    fs.writeFileSync(npmrcFile, npmrc, { encoding: "utf8", mode: 0o600 });
    try { fs.chmodSync(npmrcFile, 0o600); } catch { /* Windows ACLs are managed by the host. */ }

    const env = {
        ...strictBaseEnvironment(baseEnv),
        NODE_AUTH_TOKEN: token,
    };
    if (otp) env.npm_config_otp = otp;

    try {
        return run("npm", [...args, "--userconfig", npmrcFile], {
            cwd,
            encoding,
            stdio,
            windowsHide: true,
            shell: process.platform === "win32",
            env,
        });
    } finally {
        fs.rmSync(npmrcDirectory, { recursive: true, force: true });
    }
}

export function verifyNpmRegistryAuth({
    registry = "https://registry.npmjs.org/",
    token,
    packageName = "hetzer",
    cwd = process.cwd(),
    baseEnv = process.env,
    runNpm = runNpmWithAuth,
} = {}) {
    if (!token) throw new Error("Registry credential is required.");

    const networkPatterns = /\b(ENOTFOUND|ETIMEDOUT|ECONNREFUSED|EAI_AGAIN|ECONNRESET|ERR_SOCKET_TIMEOUT)\b|FetchError|network|offline|\b(502|503|504)\b/i;

    // 1. Try legacy whoami check (works for Classic/Automation tokens)
    const whoami = runNpm({
        args: ["whoami", "--registry", registry],
        registry,
        token,
        cwd,
        baseEnv,
    });

    if (whoami.status === 0) {
        const username = String(whoami.stdout || "").trim();

        // Verify write access for the authenticated Classic user on the target package
        const accessCheck = runNpm({
            args: ["access", "list", "collaborators", packageName, "--json", "--registry", registry],
            registry,
            token,
            cwd,
            baseEnv,
        });

        if (accessCheck.status !== 0) {
            const accessStderr = String(accessCheck.stderr || "");
            if (networkPatterns.test(accessStderr)) {
                const err = new Error(
                    `NPM registry connection failed: Unable to reach '${registry}'.\n` +
                    `  Network error: ${redactExactValues(accessStderr.trim(), [token])}`
                );
                err.code = "ERR_NPM_NETWORK";
                throw err;
            }
            const err = new Error(
                `Classic token authenticated as '@${username}', but npm write permission for '${packageName}' could not be verified.`
            );
            err.code = "ERR_NPM_WRITE_PERMISSION_UNVERIFIED";
            throw err;
        }

        let permissions;
        try {
            permissions = JSON.parse(String(accessCheck.stdout || "").trim());
        } catch {
            permissions = null;
        }
        const userPermission = permissions && typeof permissions === "object"
            ? permissions[username]
            : undefined;
        if (userPermission !== "read-write" && userPermission !== "write") {
            const err = new Error(
                `Classic token authenticated as '@${username}', but lacks write access to '${packageName}'.\n` +
                "  The token has read-only access. Publish requires read-write permissions."
            );
            err.code = "ERR_NPM_WRITE_PERMISSION_MISSING";
            throw err;
        }

        return { ok: true, type: "classic", username, packageName };
    }

    const whoamiStderr = String(whoami.stderr || "");

    // 2. Check for network / DNS / server errors first from whoami
    if (networkPatterns.test(whoamiStderr)) {
        const err = new Error(
            `NPM registry connection failed: Unable to reach '${registry}'.\n` +
            `  Network error: ${redactExactValues(whoamiStderr.trim(), [token])}`
        );
        err.code = "ERR_NPM_NETWORK";
        throw err;
    }

    // 3. Fallback: npm Granular Access Tokens (GAT) only have package-scoped permissions and do not support whoami.
    const accessCheck = runNpm({
        args: ["access", "list", "collaborators", packageName, "--json", "--registry", registry],
        registry,
        token,
        cwd,
        baseEnv,
    });

    if (accessCheck.status === 0) {
        // npm returns the complete collaborator map here. Without a whoami
        // identity, another collaborator's write permission is not proof that
        // this GAT can publish. The real publish operation remains authoritative.
        return { ok: true, type: "granular", packageName, writeVerified: false };
    }

    // 4. Check for network errors in fallback accessCheck
    const accessStderr = String(accessCheck.stderr || "");
    if (networkPatterns.test(accessStderr)) {
        const err = new Error(
            `NPM registry connection failed: Unable to reach '${registry}'.\n` +
            `  Network error: ${redactExactValues(accessStderr.trim(), [token])}`
        );
        err.code = "ERR_NPM_NETWORK";
        throw err;
    }

    // 5. Genuine 401 / 403 authentication or authorization failure
    const err = new Error(
        "NPM registry authentication failed (401 Unauthorized).\n" +
        `  The token in Grimoire Vault is invalid, expired, or lacks write access to '${packageName}'.\n` +
        "  Please generate a new token at https://www.npmjs.com/settings/~/tokens:\n" +
        "    - Recommended: 'Classic Token' (Type: Automation)\n" +
        `    - Or: 'Granular Access Token' with Read & Write on package '${packageName}' and 2FA bypass\n` +
        "  Then update the vault: node cli/bin/hetzer.js creds set npm-token"
    );
    err.code = "ERR_NPM_AUTH_FAILED";
    throw err;
}
