import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const DEFAULT_REPO = "agunggnn/hetzer";
const DEFAULT_TIMEOUT_MS = 2000;
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export function parseSemVer(versionStr) {
    if (!versionStr || typeof versionStr !== "string") return null;
    const clean = versionStr.trim().replace(/^v/i, "");
    const match = clean.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/);
    if (!match) return null;
    return {
        major: Number.parseInt(match[1], 10),
        minor: Number.parseInt(match[2], 10),
        patch: Number.parseInt(match[3], 10),
        prerelease: match[4] || null,
        raw: clean,
    };
}

export function isNewerVersion(currentVersion, candidateVersion) {
    const curr = parseSemVer(currentVersion);
    const cand = parseSemVer(candidateVersion);
    if (!curr || !cand) return false;

    if (cand.major > curr.major) return true;
    if (cand.major < curr.major) return false;

    if (cand.minor > curr.minor) return true;
    if (cand.minor < curr.minor) return false;

    if (cand.patch > curr.patch) return true;
    if (cand.patch < curr.patch) return false;

    if (curr.prerelease && !cand.prerelease) return true;
    return false;
}

export function getUpdateCachePath(customPath) {
    if (customPath) return customPath;
    try {
        const home = os.homedir();
        return path.join(home, ".hetzer", "update-cache.json");
    } catch {
        return path.join(os.tmpdir(), "hetzer-update-cache.json");
    }
}

export function readUpdateCache(cachePath) {
    try {
        if (!fs.existsSync(cachePath)) return null;
        const raw = fs.readFileSync(cachePath, "utf8");
        const data = JSON.parse(raw);
        if (typeof data === "object" && data !== null && typeof data.lastChecked === "number") {
            return data;
        }
    } catch {
        // Corrupted or unreadable cache is safely ignored
    }
    return null;
}

export function writeUpdateCache(cachePath, data) {
    try {
        const dir = path.dirname(cachePath);
        fs.mkdirSync(dir, { recursive: true });
        const tempPath = `${cachePath}.tmp.${Date.now()}`;
        fs.writeFileSync(tempPath, JSON.stringify(data, null, 2), { mode: 0o600, encoding: "utf8" });
        fs.renameSync(tempPath, cachePath);
    } catch {
        // Non-fatal if cache cannot be written
    }
}

export async function fetchLatestRelease({
    repo = DEFAULT_REPO,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    fetchFn = globalThis.fetch,
} = {}) {
    if (typeof fetchFn !== "function") return null;

    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

    try {
        const res = await fetchFn(`https://api.github.com/repos/${repo}/releases/latest`, {
            headers: {
                "User-Agent": "hetzer-cli",
                Accept: "application/vnd.github.v3+json",
            },
            signal: controller?.signal,
        });

        if (!res.ok) {
            // Fallback to npm package metadata
            return await fetchFromNpmRegistry({ timeoutMs, fetchFn, signal: controller?.signal });
        }

        const data = await res.json();
        const rawTag = data.tag_name || data.name || "";
        const parsed = parseSemVer(rawTag);
        if (!parsed) return null;

        return {
            version: parsed.raw,
            tag: `v${parsed.raw}`,
            url: data.html_url || `https://github.com/${repo}/releases`,
            publishedAt: data.published_at || null,
        };
    } catch {
        return null;
    } finally {
        if (timeoutId) clearTimeout(timeoutId);
    }
}

async function fetchFromNpmRegistry({ timeoutMs, fetchFn, signal } = {}) {
    try {
        const res = await fetchFn("https://registry.npmjs.org/hetzer/latest", {
            headers: { "User-Agent": "hetzer-cli" },
            signal,
        });
        if (!res.ok) return null;
        const data = await res.json();
        const parsed = parseSemVer(data.version);
        if (!parsed) return null;
        return {
            version: parsed.raw,
            tag: `v${parsed.raw}`,
            url: "https://www.npmjs.com/package/hetzer",
            publishedAt: null,
        };
    } catch {
        return null;
    }
}

export async function checkForUpdates({
    currentVersion,
    force = false,
    cacheTtlMs = DEFAULT_TTL_MS,
    cachePath,
    fetchFn = globalThis.fetch,
    repo = DEFAULT_REPO,
    timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
    const resolvedCachePath = getUpdateCachePath(cachePath);
    const cached = readUpdateCache(resolvedCachePath);

    const now = Date.now();
    if (!force && cached && cached.lastChecked && (now - cached.lastChecked) < cacheTtlMs) {
        const latest = cached.latestVersion;
        return {
            updateAvailable: isNewerVersion(currentVersion, latest),
            currentVersion,
            latestVersion: latest,
            url: cached.url || `https://github.com/${repo}/releases`,
            fromCache: true,
        };
    }

    const fetched = await fetchLatestRelease({ repo, timeoutMs, fetchFn });
    if (fetched && fetched.version) {
        writeUpdateCache(resolvedCachePath, {
            lastChecked: now,
            latestVersion: fetched.version,
            url: fetched.url,
        });
        return {
            updateAvailable: isNewerVersion(currentVersion, fetched.version),
            currentVersion,
            latestVersion: fetched.version,
            url: fetched.url,
            fromCache: false,
        };
    }

    // If network fails but we have stale cache, use it
    if (cached && cached.latestVersion) {
        return {
            updateAvailable: isNewerVersion(currentVersion, cached.latestVersion),
            currentVersion,
            latestVersion: cached.latestVersion,
            url: cached.url || `https://github.com/${repo}/releases`,
            fromCache: true,
            networkFailed: true,
        };
    }

    return {
        updateAvailable: false,
        currentVersion,
        latestVersion: null,
        url: `https://github.com/${repo}/releases`,
        fromCache: false,
        networkFailed: true,
    };
}

export function formatUpdateBanner({ currentVersion, latestVersion, url }) {
    const line1 = `  Update available: v${currentVersion} -> v${latestVersion}`;
    const line2 = `  Changelog: ${url}`;
    const line3 = "  Run `npm i -g @agunggnn/hetzer` or git pull to update";
    const maxLen = Math.max(line1.length, line2.length, line3.length) + 2;

    const top = `╭${"─".repeat(maxLen)}╮`;
    const bottom = `╰${"─".repeat(maxLen)}╯`;
    const pad = (str) => `│${str.padEnd(maxLen)}│`;

    return [
        "",
        top,
        pad(line1),
        pad(line2),
        pad(line3),
        bottom,
        "",
    ].join("\n");
}
