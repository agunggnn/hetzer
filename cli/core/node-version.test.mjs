import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { NODE_ENGINE_RANGE, supportsNodeSqlite, unsupportedNodeMessage } from "./node-version.mjs";

test("supportsNodeSqlite enforces the first Node releases that load node:sqlite without a flag", () => {
    assert.equal(supportsNodeSqlite("22.4.1"), false);
    assert.equal(supportsNodeSqlite("v22.5.0"), false);
    assert.equal(supportsNodeSqlite("22.12.0"), false);
    assert.equal(supportsNodeSqlite("v22.13.0"), true);
    assert.equal(supportsNodeSqlite("22.13.1"), true);
    assert.equal(supportsNodeSqlite("22.22.0"), true);
    assert.equal(supportsNodeSqlite("23.0.0"), false);
    assert.equal(supportsNodeSqlite("23.3.9"), false);
    assert.equal(supportsNodeSqlite("23.4.0"), true);
    assert.equal(supportsNodeSqlite("24.0.0"), true);
    assert.equal(supportsNodeSqlite("21.99.99"), false);
    assert.equal(supportsNodeSqlite("not-a-version"), false);
});

test("unsupportedNodeMessage identifies the requirement and active runtime", () => {
    const message = unsupportedNodeMessage("v20.18.0");
    assert.match(message, /Node\.js \^22\.13\.0 \|\| >=23\.4\.0/);
    assert.match(message, /node:sqlite/);
    assert.match(message, /v20\.18\.0/);
    assert.match(message, /which -a node/);
    assert.match(message, /Get-Command node -All/);
});

test("package.json engines matches the runtime check", () => {
    const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
    const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
    assert.equal(manifest.engines.node, NODE_ENGINE_RANGE);
    assert.equal(lock.packages[""].engines.node, NODE_ENGINE_RANGE);
});
