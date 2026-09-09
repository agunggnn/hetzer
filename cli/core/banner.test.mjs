import assert from "node:assert/strict";
import test from "node:test";

import { getHetzerAsciiBanner } from "./banner.mjs";

test("getHetzerAsciiBanner outputs the terminal-native Hetzer credential-safety banner", () => {
    const banner = getHetzerAsciiBanner({ colored: false });
    assert.ok(banner.includes("H E T Z E R"));
    assert.ok(banner.includes("Credential Safety"));
    assert.ok(banner.includes("██╗"));
    assert.ok(banner.split("\n").length >= 8);
});
