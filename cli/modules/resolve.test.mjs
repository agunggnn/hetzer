import assert from "node:assert/strict";
import test from "node:test";

import { resolveModuleProfiles } from "./resolve.mjs";

const module = (id, requires = [], options = {}) => ({
    id, profile: id, requires, enabled: true, lifecycle: "compose", ...options,
});

test("module resolution follows dependencies and active all selection", () => {
    const registry = { modules: [
        module("core"),
        module("sample-mod", ["core"]),
        module("later", ["core"], { enabled: false }),
    ] };
    assert.deepEqual(resolveModuleProfiles({ registry, target: "sample-mod" }), ["core", "sample-mod"]);
    assert.deepEqual(resolveModuleProfiles({ registry, target: "*" }), ["core", "sample-mod"]);
});

test("inactive modules must be explicitly installed before start", () => {
    assert.throws(() => resolveModuleProfiles({
        registry: { modules: [module("core"), module("sample-mod", ["core"], { enabled: false })] },
        target: "sample-mod",
    }), /hetzer install sample-mod/);
});

test("resolveModuleProfiles includes core plus enabled modules", () => {
    const registry = { modules: [
        module("core"),
        module("sample-mod", ["core"]),
        module("data", ["core"]),
    ] };
    assert.deepEqual(resolveModuleProfiles({ registry, target: "*" }), ["core", "sample-mod", "data"]);
    assert.deepEqual(resolveModuleProfiles({ registry, target: "sample-mod" }), ["core", "sample-mod"]);
});

test("resolveModuleProfiles falls back to core only when nothing enabled", () => {
    const registry = { modules: [module("core")] };
    assert.deepEqual(resolveModuleProfiles({ registry, target: "core" }), ["core"]);
});

test("resolveModuleProfiles handles multiple dependency levels", () => {
    const registry = { modules: [
        module("core"),
        module("data", ["core"]),
        module("analytics", ["data"]),
    ] };
    assert.deepEqual(resolveModuleProfiles({ registry, target: "analytics" }), ["core", "data", "analytics"]);
});

test("resolveModuleProfiles deduplicates shared dependencies", () => {
    const registry = { modules: [
        module("core"),
        module("a", ["core"]),
        module("b", ["core"]),
        module("c", ["a", "b"]),
    ] };
    assert.deepEqual(resolveModuleProfiles({ registry, target: "c" }), ["core", "a", "b", "c"]);
});

test("resolveModuleProfiles throws on cyclic dependency", () => {
    const registry = { modules: [
        module("core"),
        module("a", ["b"]),
        module("b", ["a"]),
    ] };
    assert.throws(() => resolveModuleProfiles({ registry, target: "a" }), /circular/i);
});