// node:sqlite shipped behind --experimental-sqlite in 22.5.0 and loads without a flag from
// 22.13.0 on the 22.x line and from 23.4.0 on the 23.x line.
const MINIMUM_NODE_VERSIONS = Object.freeze([
    Object.freeze({ major: 22, minor: 13, patch: 0 }),
    Object.freeze({ major: 23, minor: 4, patch: 0 }),
]);
export const NODE_ENGINE_RANGE = "^22.13.0 || >=23.4.0";

function parseNodeVersion(version) {
    const match = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(String(version ?? "").trim());
    if (!match) return null;
    return match.slice(1, 4).map(Number);
}

export function supportsNodeSqlite(version) {
    const parsed = parseNodeVersion(version);
    if (!parsed) return false;

    const lastLine = MINIMUM_NODE_VERSIONS[MINIMUM_NODE_VERSIONS.length - 1];
    if (parsed[0] > lastLine.major) return true;
    const minimum = MINIMUM_NODE_VERSIONS.find((entry) => entry.major === parsed[0]);
    if (!minimum) return false;

    const required = [minimum.major, minimum.minor, minimum.patch];
    for (let index = 0; index < required.length; index += 1) {
        if (parsed[index] > required[index]) return true;
        if (parsed[index] < required[index]) return false;
    }
    return true;
}

export function unsupportedNodeMessage(version) {
    const current = String(version || "unknown");
    return [
        `Hetzer requires Node.js ${NODE_ENGINE_RANGE} because its vault uses the built-in node:sqlite module without runtime flags.`,
        `Current runtime: ${current}.`,
        "Upgrade Node.js, close and reopen the terminal, then verify `node --version` and `which -a node` (`Get-Command node -All` on Windows) before retrying.",
    ].join(" ");
}
