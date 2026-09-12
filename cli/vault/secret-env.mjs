import fs from "node:fs";
import path from "node:path";

import { parseEnv } from "../core/env.mjs";
import { generateCanaryToken, isCanaryCredential, triggerCanaryAlert } from "./canary.mjs";
import { Grimoire, resolveMasterKey, resolveVaultPath } from "./hetzer-vault.mjs";

const STRICT_BASE_ENV_NAMES = new Set([
    "APPDATA", "COLORTERM", "COMSPEC", "HOME", "LANG", "LC_ALL", "LC_CTYPE",
    "LOCALAPPDATA", "PATH", "PATHEXT", "PROGRAMDATA", "SHELL", "SYSTEMDRIVE",
    "SYSTEMROOT", "TEMP", "TERM", "TMP", "TZ", "USERPROFILE", "WINDIR",
]);

export function strictBaseEnvironment(baseEnv = {}) {
    return Object.fromEntries(
        Object.entries(baseEnv).filter(([name]) => STRICT_BASE_ENV_NAMES.has(name.toUpperCase()))
    );
}

export function resolveSecretEnvironment({
    root,
    envFile,
    baseEnv = process.env,
    action = "process.start",
    allowNames,
    strict = false,
    canary = false,
}) {
    const values = fs.existsSync(envFile) ? parseEnv(fs.readFileSync(envFile, "utf8")) : {};
    const allow = allowNames === undefined ? null : new Set(allowNames.map((n) => n.toLowerCase()));

    if (strict && allow === null) {
        throw new Error(
            "Security violation: Strict scoping enabled (--strict).\n" +
            "You must explicitly specify which credentials may be resolved via '--allow <id|env-var>'.\n" +
            "No ungranted secrets are accessible in strict mode."
        );
    }

    const bindings = Object.entries(values).filter(([name, value]) => {
        if (!String(value).startsWith("secretRef:")) return false;
        if (allow === null) return true;
        const id = String(value).slice("secretRef:".length).toLowerCase();
        return allow.has(name.toLowerCase()) || allow.has(id);
    });
    const resolved = { ...(strict ? strictBaseEnvironment(baseEnv) : baseEnv), HETZER_ROOT: root };
    if (canary) {
        resolved.HETZER_CANARY_TOKEN = generateCanaryToken();
    }
    if (!bindings.length) return resolved;

    const masterKey = resolveMasterKey({ root, envValues: values, baseEnv });
    if (!masterKey || String(masterKey).startsWith("secretRef:")) {
        throw new Error("HETZER_GRIMOIRE_KEY must be supplied at runtime (or isolated in ~/.hetzer/grimoire.key) to resolve secretRef bindings.");
    }
    const envVault = resolveVaultPath(root);
    const vault = new Grimoire({
        dbPath: envVault || path.join(root, "data", "hetzer-vault.db"),
        legacyFile: path.join(root, "data", "vault.json"),
        masterKey,
    });
    try {
        for (const [name, reference] of bindings) {
            const id = String(reference).slice("secretRef:".length);
            if (isCanaryCredential(id)) {
                triggerCanaryAlert({ id, actor: "process.exec", action: "env.resolve", root });
            }
            const credential = vault.find(id);
            if (!credential) throw new Error(`Credential '${id}' referenced by ${name} was not found.`);
            const value = vault.resolveRef(reference, { targetId: credential.projectId, action });
            if (value === null) throw new Error(`Credential '${id}' is not allowed for ${action}.`);
            resolved[name] = value;
        }
        return resolved;
    } finally {
        vault.close();
    }
}
