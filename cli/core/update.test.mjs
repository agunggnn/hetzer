import assert from "node:assert/strict";
import test from "node:test";

import {
    BUNDLED_IMAGE_UPDATES,
    migrateBundledImagePins,
    moduleIdsForProfiles,
    resolveLifecycleTarget,
    updateComposeCommands,
} from "./update.mjs";

const registry = {
    modules: [
        { id: "core", profile: "core", lifecycle: "compose" },
        { id: "9router", profile: "9router", lifecycle: "compose" },
        { id: "sample-mod", profile: "sample-mod", lifecycle: "compose" },
        { id: "external", profile: "external", lifecycle: "external" },
    ],
    services: [
        { id: "9router", module: { id: "9router" } },
        { id: "sample-mcp", module: { id: "sample-mod" } },
    ],
};

test("lifecycle targets accept module ids, service ids, and all", () => {
    assert.equal(resolveLifecycleTarget(registry, "core"), "core");
    assert.equal(resolveLifecycleTarget(registry, "9router"), "9router");
    assert.equal(resolveLifecycleTarget(registry, "all"), "*");
    assert.throws(() => resolveLifecycleTarget(registry, "missing"), /Unknown module or service/);
});

test("selected profiles map back to Compose modules", () => {
    assert.deepEqual(moduleIdsForProfiles(registry, ["core", "sample-mod"]), ["core", "sample-mod"]);
    assert.deepEqual(moduleIdsForProfiles(registry, ["*"]), ["core", "9router", "sample-mod"]);
});

test("known 9Router pins migrate while custom pins remain untouched", () => {
    const update = BUNDLED_IMAGE_UPDATES[0];
    const known = migrateBundledImagePins({
        envText: `HETZER_PROJECT_NAME=hetzer\n${update.variable}=${update.replaces[0]}\n`,
        moduleIds: ["9router"],
    });
    assert.match(known.text, new RegExp(`${update.variable}=${update.image.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.equal(known.changes.length, 1);
    assert.equal(known.custom.length, 0);

    const customImage = "registry.example/9router@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const custom = migrateBundledImagePins({
        envText: `${update.variable}=${customImage}\n`,
        moduleIds: ["9router"],
    });
    assert.equal(custom.text, `${update.variable}=${customImage}\n`);
    assert.equal(custom.changes.length, 0);
    assert.equal(custom.custom[0].current, customImage);

    assert.throws(() => migrateBundledImagePins({
        envText: `${update.variable}=registry.example/9router:latest\n`,
        moduleIds: ["9router"],
    }), /must use an immutable @sha256 digest/);
});

test("update pulls pins, recreates containers, waits, and reports state", () => {
    assert.deepEqual(updateComposeCommands(["--profile", "core"]), [
        ["--profile", "core", "pull", "--policy", "always", "--ignore-buildable"],
        ["--profile", "core", "up", "-d", "--force-recreate", "--wait", "--wait-timeout", "300"],
        ["--profile", "core", "ps", "--all"],
    ]);
});
