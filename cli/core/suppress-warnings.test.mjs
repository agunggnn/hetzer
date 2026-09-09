import assert from "node:assert/strict";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const modulePath = path.join(path.dirname(fileURLToPath(import.meta.url)), "suppress-warnings.mjs");

test("SQLite experimental warning suppression preserves unrelated warnings", () => {
    const source = [
        `await import(${JSON.stringify(pathToFileURL(modulePath).href)});`,
        `process.emitWarning("SQLite is an experimental feature", "ExperimentalWarning");`,
        `process.emitWarning("visible warning", "Warning");`,
    ].join("\n");
    const result = spawnSync(process.execPath, ["--input-type=module", "--eval", source], {
        encoding: "utf8",
        windowsHide: true,
    });

    assert.equal(result.status, 0);
    assert.doesNotMatch(result.stderr, /SQLite is an experimental feature/);
    assert.match(result.stderr, /visible warning/);
});
