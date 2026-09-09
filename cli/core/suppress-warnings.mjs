// Suppress noisy Node 22 experimental warnings for built-in node:sqlite
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
    if (typeof warning === "string" && warning.includes("SQLite")) return;
    if (typeof warning === "object" && warning?.message?.includes("SQLite")) return;
    if (args[0] === "ExperimentalWarning" && typeof warning === "string" && warning.includes("SQLite")) return;
    return originalEmitWarning.call(process, warning, ...args);
};
