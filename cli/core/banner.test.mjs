import assert from "node:assert/strict";
import test from "node:test";

import { getHetzerAsciiBanner } from "./banner.mjs";

test("getHetzerAsciiBanner outputs multi-line ANSI shadow banner containing Hetzer and Zero-Plaintext", () => {
    const banner = getHetzerAsciiBanner({ colored: false });
    assert.ok(banner.includes("H E T Z E R"));
    assert.ok(banner.includes("Zero-Plaintext Armor"));
    assert.ok(banner.includes("██╗"));
    assert.ok(banner.split("\n").length >= 8);
});
