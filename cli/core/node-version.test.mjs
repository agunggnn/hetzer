import assert from "node:assert/strict";
import test from "node:test";
import { supportsNodeSqlite, unsupportedNodeMessage } from "./node-version.mjs";

test("supportsNodeSqlite enforces the first Node release with node:sqlite", () => {
    assert.equal(supportsNodeSqlite("22.4.1"), false);
    assert.equal(supportsNodeSqlite("v22.5.0"), true);
    assert.equal(supportsNodeSqlite("22.5.1"), true);
    assert.equal(supportsNodeSqlite("23.0.0"), true);
    assert.equal(supportsNodeSqlite("21.99.99"), false);
    assert.equal(supportsNodeSqlite("not-a-version"), false);
});

test("unsupportedNodeMessage identifies the requirement and active runtime", () => {
    const message = unsupportedNodeMessage("v20.18.0");
    assert.match(message, /Node\.js >=22\.5\.0/);
    assert.match(message, /node:sqlite/);
    assert.match(message, /v20\.18\.0/);
    assert.match(message, /Get-Command node -All/);
});
