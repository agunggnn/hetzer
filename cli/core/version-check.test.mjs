import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
    checkForUpdates,
    fetchLatestRelease,
    formatUpdateBanner,
    isNewerVersion,
    parseSemVer,
    readUpdateCache,
    writeUpdateCache,
} from "./version-check.mjs";

test("parseSemVer correctly parses standard, prefixed, and prerelease versions", () => {
    assert.deepEqual(parseSemVer("1.2.3"), { major: 1, minor: 2, patch: 3, prerelease: null, raw: "1.2.3" });
    assert.deepEqual(parseSemVer("v0.4.17"), { major: 0, minor: 4, patch: 17, prerelease: null, raw: "0.4.17" });
    assert.deepEqual(parseSemVer("v1.0.0-beta.1"), { major: 1, minor: 0, patch: 0, prerelease: "beta.1", raw: "1.0.0-beta.1" });
    assert.equal(parseSemVer("invalid"), null);
    assert.equal(parseSemVer(""), null);
    assert.equal(parseSemVer(null), null);
    assert.equal(parseSemVer(123), null);
});

test("isNewerVersion compares versions correctly across major, minor, patch", () => {
    assert.equal(isNewerVersion("0.4.17", "0.4.18"), true);
    assert.equal(isNewerVersion("0.4.17", "0.5.0"), true);
    assert.equal(isNewerVersion("0.4.17", "1.0.0"), true);
    assert.equal(isNewerVersion("0.4.17", "0.4.17"), false);
    assert.equal(isNewerVersion("0.4.17", "0.4.16"), false);
    assert.equal(isNewerVersion("1.0.0", "0.9.9"), false);
    assert.equal(isNewerVersion("1.0.0-beta.1", "1.0.0"), true);
    assert.equal(isNewerVersion("invalid", "1.0.0"), false);
});

test("readUpdateCache and writeUpdateCache handle cache lifecycle safely", () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-cache-test-"));
    const cacheFile = path.join(tmpDir, "sub", "update-cache.json");

    try {
        assert.equal(readUpdateCache(cacheFile), null);

        const sample = { lastChecked: Date.now(), latestVersion: "0.4.18", url: "https://example.com" };
        writeUpdateCache(cacheFile, sample);

        const readBack = readUpdateCache(cacheFile);
        assert.deepEqual(readBack, sample);

        // Corrupted content handling
        fs.writeFileSync(cacheFile, "{ corrupted json", "utf8");
        assert.equal(readUpdateCache(cacheFile), null);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test("fetchLatestRelease resolves GitHub releases and falls back gracefully", async () => {
    const mockFetch = async (url) => {
        const parsedUrl = new URL(String(url));
        if (parsedUrl.hostname === "api.github.com") {
            return {
                ok: true,
                json: async () => ({
                    tag_name: "v0.4.18",
                    html_url: "https://github.com/agunggnn/hetzer/releases/tag/v0.4.18",
                    published_at: "2026-09-13T00:00:00Z",
                }),
            };
        }
        return { ok: false };
    };

    const res = await fetchLatestRelease({ fetchFn: mockFetch });
    assert.equal(res.version, "0.4.18");
    assert.equal(res.tag, "v0.4.18");
    assert.equal(res.url, "https://github.com/agunggnn/hetzer/releases/tag/v0.4.18");
});

test("fetchLatestRelease falls back to npm registry if GitHub fails", async () => {
    const mockFetch = async (url) => {
        const parsedUrl = new URL(String(url));
        if (parsedUrl.hostname === "api.github.com") {
            return { ok: false, status: 403 };
        }
        if (parsedUrl.hostname === "registry.npmjs.org") {
            return {
                ok: true,
                json: async () => ({ version: "0.4.18" }),
            };
        }
        return { ok: false };
    };

    const res = await fetchLatestRelease({ fetchFn: mockFetch });
    assert.equal(res.version, "0.4.18");
    assert.equal(res.tag, "v0.4.18");
});

test("fetchLatestRelease returns null on network exception", async () => {
    const failingFetch = async () => {
        throw new Error("DNS resolution failed");
    };

    const res = await fetchLatestRelease({ fetchFn: failingFetch });
    assert.equal(res, null);
});

test("checkForUpdates respects cache TTL and force flag", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-update-check-test-"));
    const cacheFile = path.join(tmpDir, "cache.json");

    let networkCallCount = 0;
    const mockFetch = async () => {
        networkCallCount += 1;
        return {
            ok: true,
            json: async () => ({ tag_name: "v0.4.18", html_url: "https://example.com" }),
        };
    };

    try {
        // Initial check: fresh fetch
        const first = await checkForUpdates({
            currentVersion: "0.4.17",
            cachePath: cacheFile,
            fetchFn: mockFetch,
        });
        assert.equal(first.updateAvailable, true);
        assert.equal(first.latestVersion, "0.4.18");
        assert.equal(first.fromCache, false);
        assert.equal(networkCallCount, 1);

        // Second check within TTL: should hit cache
        const second = await checkForUpdates({
            currentVersion: "0.4.17",
            cachePath: cacheFile,
            fetchFn: mockFetch,
        });
        assert.equal(second.updateAvailable, true);
        assert.equal(second.fromCache, true);
        assert.equal(networkCallCount, 1); // No new network call

        // Force check: ignores cache
        const third = await checkForUpdates({
            currentVersion: "0.4.17",
            cachePath: cacheFile,
            fetchFn: mockFetch,
            force: true,
        });
        assert.equal(third.fromCache, false);
        assert.equal(networkCallCount, 2);
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
});

test("formatUpdateBanner renders expected box framing", () => {
    const banner = formatUpdateBanner({
        currentVersion: "0.4.17",
        latestVersion: "0.4.18",
        url: "https://github.com/agunggnn/hetzer/releases",
    });

    assert.match(banner, /Update available: v0\.4\.17 -> v0\.4\.18/);
    assert.match(banner, /Changelog: https:\/\/github\.com\/agunggnn\/hetzer\/releases/);
    assert.match(banner, /Run `npm i -g @agunggnn\/hetzer` or git pull to update/);
    assert.match(banner, /^╭─+╮/m);
    assert.match(banner, /^╰─+╯/m);
});
