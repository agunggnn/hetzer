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
