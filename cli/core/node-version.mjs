const MINIMUM_NODE_VERSION = Object.freeze({ major: 22, minor: 5, patch: 0 });

function parseNodeVersion(version) {
    const match = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(String(version ?? "").trim());
    if (!match) return null;
    return match.slice(1, 4).map(Number);
}

export function supportsNodeSqlite(version) {
    const parsed = parseNodeVersion(version);
    if (!parsed) return false;

    const required = Object.values(MINIMUM_NODE_VERSION);
    for (let index = 0; index < required.length; index += 1) {
        if (parsed[index] > required[index]) return true;
        if (parsed[index] < required[index]) return false;
    }
    return true;
}

export function unsupportedNodeMessage(version) {
    const current = String(version || "unknown");
    return [
        "Hetzer requires Node.js >=22.5.0 because its vault uses the built-in node:sqlite module.",
        `Current runtime: ${current}.`,
        "Upgrade Node.js, close and reopen the terminal, then verify `node --version` and `Get-Command node -All` before retrying.",
    ].join(" ");
}
