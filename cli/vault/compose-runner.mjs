#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import { loadModuleRegistry } from "../modules/registry.mjs";
import { resolveSecretEnvironment } from "./secret-env.mjs";

function parseArguments(argv) {
    const marker = argv.indexOf("--");
    if (marker === -1) throw new Error("Usage: compose-runner --root <path> --env-file <path> -- <compose args>");
    const options = argv.slice(0, marker);
    const composeArgs = argv.slice(marker + 1);
    const value = (name) => {
        const index = options.indexOf(name);
        return index >= 0 ? options[index + 1] : "";
    };
    return { root: path.resolve(value("--root") || process.cwd()), envFile: path.resolve(value("--env-file")), composeArgs };
}

export function composeInvocation({ root, envFile, composeArgs }) {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const registry = loadModuleRegistry({
        builtinFile: path.resolve(here, "..", "modules", "builtin.json"),
        root,
    });
    const profiles = new Set();
    for (let index = 0; index < composeArgs.length; index += 1) {
        const argument = composeArgs[index];
        if (argument === "--profile" && composeArgs[index + 1]) profiles.add(composeArgs[index + 1]);
        else if (argument.startsWith("--profile=")) profiles.add(argument.slice("--profile=".length));
    }
    const includeAll = profiles.size === 0 || profiles.has("*");
    const recipeFiles = registry.modules
        .filter((module) => module.id !== "core" && (includeAll || profiles.has(module.profile)))
        .flatMap((module) => module.composeFiles);
    const files = ["docker-compose.yml", ...recipeFiles]
        .filter((file, index, all) => all.indexOf(file) === index)
        .map((file) => path.resolve(root, file))
        .filter((file) => fs.existsSync(file));
    const args = ["compose", "--project-directory", root, "--env-file", envFile];
    for (const file of files) args.push("-f", file);
    args.push(...composeArgs);
    const secretNames = new Set();
    for (const file of files) {
        const compose = fs.readFileSync(file, "utf8");
        for (const match of compose.matchAll(/\$\{([A-Z][A-Z0-9_]*)/g)) secretNames.add(match[1]);
    }
    return { file: "docker", args, secretNames: [...secretNames] };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    try {
        const options = parseArguments(process.argv.slice(2));
        const invocation = composeInvocation(options);
        const env = resolveSecretEnvironment({
            ...options,
            action: "compose.start",
            allowNames: invocation.secretNames,
        });
        const result = spawnSync(invocation.file, invocation.args, { stdio: "inherit", env, windowsHide: true });
        if (result.error) throw result.error;
        process.exitCode = result.status === null ? 1 : result.status;
    } catch (error) {
        process.stderr.write(`Hetzer Compose failed: ${error.message}\n`);
        process.exitCode = error.exitCode || 1;
    }
}
