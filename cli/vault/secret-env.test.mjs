import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { Grimoire } from "./hetzer-vault.mjs";
import { resolveSecretEnvironment } from "./secret-env.mjs";

test("secret environment resolves explicit references without exposing unrelated credentials", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-secret-env-"));
    fs.mkdirSync(path.join(root, "data"));
    const masterKey = "test-secret-environment-master-key-long-enough";
    const vault = new Grimoire({ dbPath: path.join(root, "data", "hetzer-vault.db"), masterKey });
    vault.create({ id: "worker-token", projectId: "worker", keyName: "token", secret: "resolved-value" });
    vault.create({ id: "unrelated-token", projectId: "other", keyName: "token", secret: "must-not-leak" });
    vault.close();
    const envFile = path.join(root, ".env");
    fs.writeFileSync(envFile, "WORKER_TOKEN=secretRef:worker-token\nPLAIN_SETTING=visible\n");

    const env = resolveSecretEnvironment({
        root,
        envFile,
        baseEnv: { HETZER_GRIMOIRE_KEY: masterKey },
        allowNames: ["WORKER_TOKEN"],
    });
    assert.equal(env.WORKER_TOKEN, "resolved-value");
    assert.equal(env.UNRELATED_TOKEN, undefined);
    assert.equal(env.PLAIN_SETTING, undefined);

    const envById = resolveSecretEnvironment({
        root,
        envFile,
        baseEnv: { HETZER_GRIMOIRE_KEY: masterKey },
        allowNames: ["worker-token"],
    });
    assert.equal(envById.WORKER_TOKEN, "resolved-value");

    // Strict mode without allowNames throws
    assert.throws(() => {
        resolveSecretEnvironment({
            root,
            envFile,
            baseEnv: { HETZER_GRIMOIRE_KEY: masterKey },
            strict: true,
        });
    }, /Strict scoping enabled/);

    const empty = resolveSecretEnvironment({ root, envFile, baseEnv: {}, allowNames: [] });
    assert.equal(empty.WORKER_TOKEN, undefined);
    fs.rmSync(root, { recursive: true, force: true });
});

test("strict secret environment drops unapproved inherited values and the master key", () => {
    const resolved = resolveSecretEnvironment({
        root: process.cwd(),
        envFile: path.join(os.tmpdir(), "missing-hetzer-strict.env"),
        baseEnv: {
            PATH: process.env.PATH || "",
            UNAPPROVED_TOKEN: "synthetic-unapproved-value",
            HETZER_GRIMOIRE_KEY: "synthetic-master-key-value",
        },
        allowNames: ["approved-only"],
        strict: true,
    });

    assert.equal(resolved.PATH, process.env.PATH || "");
    assert.equal(resolved.UNAPPROVED_TOKEN, undefined);
    assert.equal(resolved.HETZER_GRIMOIRE_KEY, undefined);
});
