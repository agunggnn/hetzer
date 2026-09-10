import assert from "node:assert/strict";
import test from "node:test";
import { buildReleaseMetadata } from "./release-metadata.mjs";

const commit = "a".repeat(40);

test("buildReleaseMetadata prepares a new immutable version tag", () => {
    assert.deepEqual(buildReleaseMetadata({ version: "0.4.10", commit }), {
        version: "0.4.10",
        tag: "v0.4.10",
        tagExists: false,
    });
});

test("buildReleaseMetadata permits an idempotent rerun for the same commit", () => {
    assert.equal(buildReleaseMetadata({ version: "0.4.10", commit, taggedCommit: commit }).tagExists, true);
});

test("buildReleaseMetadata refuses malformed versions and tag movement", () => {
    assert.throws(() => buildReleaseMetadata({ version: "next", commit }), /not a supported release version/);
    assert.throws(() => buildReleaseMetadata({ version: "0.4.10", commit: "short" }), /full Git commit SHA/);
    assert.throws(
        () => buildReleaseMetadata({ version: "0.4.10", commit, taggedCommit: "b".repeat(40) }),
        /Refusing to move v0\.4\.10/,
    );
});
