#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { promptSecret, setCredential } from "../cli/vault/creds.mjs";
import { resolveSecretEnvironment } from "../cli/vault/secret-env.mjs";
import { redactExactValues, runNpmWithAuth } from "../cli/core/npm-auth.mjs";
import { parseEnv } from "../cli/core/env.mjs";

const root = path.resolve(process.env.HETZER_ROOT || process.cwd());
const envFile = path.resolve(process.env.HETZER_ENV_FILE || path.join(root, ".env"));
const npmRegistry = "https://registry.npmjs.org/";

function resolveConfiguredToken(ids) {
    const fileValues = parseEnv(fs.readFileSync(envFile, "utf8"));
    const resolved = resolveSecretEnvironment({
        root,
        envFile,
        baseEnv: process.env,
        allowNames: ids,
        strict: true,
    });
    for (const [name, reference] of Object.entries(fileValues)) {
        if (!String(reference).startsWith("secretRef:")) continue;
        const id = String(reference).slice("secretRef:".length);
        if (ids.includes(id) && typeof resolved[name] === "string") return resolved[name];
    }
    return "";
}

async function main() {
    process.stdout.write("================================================================================\n");
    process.stdout.write("  HETZER - BUILD & SECURE NPM PUBLISH\n");
    process.stdout.write("================================================================================\n");

    if (!fs.existsSync(envFile)) {
        throw new Error(".env file not found. Run 'hetzer init' first.");
    }

    // 1. Resolve or prompt for NPM Token
    let npmToken = process.env.NODE_AUTH_TOKEN || "";
    try {
        if (!npmToken) npmToken = resolveConfiguredToken(["npm-token", "npm-auth-token"]);
    } catch {
        // Credential is not configured or cannot be resolved; prompt below.
    }

    if (!npmToken) {
        process.stdout.write("[!] NPM Token is not yet stored in Grimoire Vault.\n");
        process.stdout.write("    Input will be masked when you paste the token.\n\n");
        npmToken = await promptSecret("Enter NPM Auth Token (paste & press Enter): ");
        if (!npmToken) {
            throw new Error("NPM Token cannot be empty. Publish process aborted.");
        }

        // Securely store into Grimoire Vault (AES-256-GCM)
        setCredential({ root, envFile, id: "npm-token", secret: npmToken });
        process.stdout.write("[v] NPM Token encrypted & stored in Grimoire Vault (AES-256-GCM)!\n");
        process.stdout.write("[v] .env reference: NODE_AUTH_TOKEN=secretRef:npm-token (Zero-Plaintext)\n\n");
    } else {
        process.stdout.write("[v] Using encrypted NPM Auth Token from Grimoire Vault.\n\n");
    }

    // 2. Validate NPM Authentication
    process.stdout.write("[i] Verifying NPM registry authentication (https://registry.npmjs.org/)...\n");
    const whoami = runNpmWithAuth({
        args: ["whoami", "--registry", npmRegistry],
        registry: npmRegistry,
        token: npmToken,
        cwd: root,
        baseEnv: process.env,
    });

    if (whoami.status !== 0) {
        const err = redactExactValues((whoami.stderr || whoami.stdout || "").trim(), [npmToken]);
        throw new Error(`NPM authentication failed (Status ${whoami.status}): ${err}\nEnsure your npm token is valid with Read & Publish permissions.`);
    }

    const npmUser = whoami.stdout.trim();
    process.stdout.write(`[v] Authentication successful! Connected as npm user: @${npmUser}\n\n`);

    // 3. Run Test Suite
    process.stdout.write("[i] Running test suite and static checks (node scripts/check.mjs)...\n");
    const check = spawnSync(process.execPath, [path.join(root, "scripts", "check.mjs")], {
        cwd: root,
        stdio: "inherit",
        windowsHide: true,
    });
    if (check.status !== 0) {
        throw new Error("Test suite failed. Fix test failures before publishing.");
    }
    process.stdout.write("\n[v] All internal verification checks passed.\n\n");

    // 4. Dry-run Pack Inspection
    process.stdout.write("[i] Running dry-run package bundling...\n");
    const pack = spawnSync("npm", ["pack", "--dry-run"], {
        cwd: root,
        encoding: "utf8",
        windowsHide: true,
        shell: process.platform === "win32",
    });
    if (pack.status !== 0) {
        throw new Error(`npm pack --dry-run failed: ${pack.stderr}`);
    }

    const pkgJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    process.stdout.write(`[v] Package ready: ${pkgJson.name} (v${pkgJson.version})\n\n`);

    // 5. Publish to NPM
    const otp = process.env.NPM_OTP || "";

    process.stdout.write(`[i] Publishing ${pkgJson.name}@${pkgJson.version} to npmjs.org (access: public)...\n`);
    const publish = runNpmWithAuth({
        args: ["publish", "--access", "public", "--registry", npmRegistry],
        registry: npmRegistry,
        token: npmToken,
        otp,
        cwd: root,
        baseEnv: process.env,
    });
    if (publish.stdout) process.stdout.write(redactExactValues(publish.stdout, [npmToken, otp]));
    if (publish.stderr) process.stderr.write(redactExactValues(publish.stderr, [npmToken, otp]));

    if (publish.status !== 0) {
        process.stderr.write("\n[!] If you received an E403 2FA error from npm:\n");
        process.stderr.write("    1. Create a Granular Access Token at https://www.npmjs.com/settings/~/tokens\n");
        process.stderr.write("       -> Select 'Read and write' on packages\n");
        process.stderr.write("       -> Check 'Bypass two-factor authentication (2FA)' for automation\n");
        process.stderr.write("       -> Save to vault: hetzer creds set npm-token\n");
        process.stderr.write("    2. If npm requires an OTP, supply it through the NPM_OTP environment variable.\n\n");
        throw new Error(`npm publish failed with exit code ${publish.status}`);
    }

    process.stdout.write("\n================================================================================\n");
    process.stdout.write(`  [v] PUBLISH SUCCESSFUL!\n`);
    process.stdout.write(`  Package : ${pkgJson.name}@${pkgJson.version}\n`);
    process.stdout.write(`  NPM URL : https://www.npmjs.com/package/${pkgJson.name}\n`);
    process.stdout.write("================================================================================\n");
}

main().catch((err) => {
    process.stderr.write(`\n[x] Publish Error: ${err.message}\n`);
    process.exitCode = 1;
});
