#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { promptSecret, setCredential } from "../cli/vault/creds.mjs";
import { parseEnv } from "../cli/core/env.mjs";
import { redactExactValues, runNpmWithAuth } from "../cli/core/npm-auth.mjs";
import { resolveSecretEnvironment, strictBaseEnvironment } from "../cli/vault/secret-env.mjs";
import { assertTrackedTreeClean } from "./package-stage.mjs";

const root = path.resolve(process.env.HETZER_ROOT || process.cwd());
const envFile = path.resolve(process.env.HETZER_ENV_FILE || path.join(root, ".env"));
const githubRegistry = "https://npm.pkg.github.com/";

function resolveConfiguredToken() {
    const fileValues = parseEnv(fs.readFileSync(envFile, "utf8"));
    const resolved = resolveSecretEnvironment({
        root,
        envFile,
        baseEnv: process.env,
        allowNames: ["github-token"],
        strict: true,
    });
    for (const [name, reference] of Object.entries(fileValues)) {
        if (reference === "secretRef:github-token" && typeof resolved[name] === "string") return resolved[name];
    }
    return "";
}

async function main() {
    process.stdout.write("================================================================================\n");
    process.stdout.write("  HETZER - SECURE GITHUB PACKAGES PUBLISH (npm.pkg.github.com)\n");
    process.stdout.write("================================================================================\n");

    const pkgJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    if (!pkgJson.name.startsWith("@agunggnn/")) {
        throw new Error(`Package name '${pkgJson.name}' must be scoped as '@agunggnn/hetzer' to publish to GitHub Packages.`);
    }
    assertTrackedTreeClean(root);

    // 1. Resolve or prompt for GitHub Token (with write:packages permission)
    let githubToken = process.env.GITHUB_TOKEN || process.env.NODE_AUTH_TOKEN || "";
    if (!githubToken && fs.existsSync(envFile)) {
        try {
            githubToken = resolveConfiguredToken();
        } catch {
            // Credential is not configured or cannot be resolved; prompt below.
        }
    }

    if (!githubToken) {
        process.stdout.write("[!] GitHub Personal Access Token (classic) is not yet stored in Grimoire Vault.\n");
        process.stdout.write("    Required token permissions: 'write:packages', 'read:packages', 'repo'.\n");
        process.stdout.write("    Input will be masked when you paste the token.\n\n");
        githubToken = await promptSecret("Enter GitHub Personal Access Token (paste & press Enter): ");
        if (!githubToken) {
            throw new Error("GitHub Token cannot be empty. Publish process aborted.");
        }

        // Securely store into Grimoire Vault (AES-256-GCM)
        if (fs.existsSync(envFile)) {
            setCredential({ root, envFile, id: "github-token", secret: githubToken });
            process.stdout.write("[v] GitHub Token encrypted & stored in Grimoire Vault (AES-256-GCM)!\n");
            process.stdout.write("[v] .env reference: GITHUB_TOKEN=secretRef:github-token\n\n");
        }
    } else {
        process.stdout.write("[v] Using authenticated GitHub Token from environment or Grimoire Vault.\n\n");
    }

    // 2. Validate GitHub Packages Authentication
    process.stdout.write("[i] Verifying authentication with GitHub Packages (https://npm.pkg.github.com/)...\n");
    const whoami = runNpmWithAuth({
        args: ["whoami", "--registry", githubRegistry],
        registry: githubRegistry,
        token: githubToken,
        cwd: root,
        baseEnv: process.env,
    });

    if (whoami.status !== 0) {
        const err = redactExactValues((whoami.stderr || whoami.stdout || "").trim(), [githubToken]);
        throw new Error(`GitHub Packages authentication failed (Status ${whoami.status}): ${err}\nEnsure your GitHub PAT has 'write:packages' and 'read:packages' permissions.`);
    }

    const ghUser = whoami.stdout.trim();
    process.stdout.write(`[v] Authentication successful! Connected as GitHub user: @${ghUser}\n\n`);

    // 3. Run static checks and the concise test suite without inherited credentials.
    const gateEnv = strictBaseEnvironment(process.env);
    process.stdout.write("[i] Running static security checks...\n");
    const check = spawnSync(process.execPath, [path.join(root, "scripts", "check.mjs")], {
        cwd: root,
        stdio: "inherit",
        env: gateEnv,
        windowsHide: true,
    });
    if (check.status !== 0) {
        throw new Error("Static checks failed. Fix failures before publishing.");
    }
    process.stdout.write("[i] Running unit tests...\n");
    const tests = spawnSync("npm", ["test"], {
        cwd: root,
        stdio: "inherit",
        env: gateEnv,
        windowsHide: true,
        shell: process.platform === "win32",
    });
    if (tests.status !== 0) {
        throw new Error("Test suite failed. Fix test failures before publishing.");
    }
    process.stdout.write("[i] Running empirical verification...\n");
    const verification = spawnSync("npm", ["run", "verify", "--", "--no-write"], {
        cwd: root,
        stdio: "inherit",
        env: gateEnv,
        windowsHide: true,
        shell: process.platform === "win32",
    });
    if (verification.status !== 0) {
        throw new Error("Empirical verification failed. Fix failures before publishing.");
    }
    assertTrackedTreeClean(root);
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

    process.stdout.write(`[v] Package ready: ${pkgJson.name} (v${pkgJson.version})\n\n`);

    // 5. Publish to GitHub Packages
    process.stdout.write(`[i] Publishing ${pkgJson.name}@${pkgJson.version} to https://npm.pkg.github.com/ ...\n`);
    const publish = runNpmWithAuth({
        args: ["publish", "--registry", githubRegistry],
        registry: githubRegistry,
        token: githubToken,
        cwd: root,
        baseEnv: process.env,
    });
    if (publish.stdout) process.stdout.write(redactExactValues(publish.stdout, [githubToken]));
    if (publish.stderr) process.stderr.write(redactExactValues(publish.stderr, [githubToken]));

    if (publish.status !== 0) {
        throw new Error(`npm publish failed with exit code ${publish.status}`);
    }

    process.stdout.write("\n================================================================================\n");
    process.stdout.write(`  [v] GITHUB PACKAGES PUBLISH SUCCESSFUL!\n`);
    process.stdout.write(`  Package  : ${pkgJson.name}@${pkgJson.version}\n`);
    process.stdout.write(`  Registry : https://npm.pkg.github.com/@agunggnn/hetzer\n`);
    process.stdout.write(`  Repo URL : https://github.com/agunggnn/hetzer/packages\n`);
    process.stdout.write("================================================================================\n");
}

main().catch((err) => {
    process.stderr.write(`\n[x] GitHub Publish Error: ${err.message}\n`);
    process.exitCode = 1;
});
