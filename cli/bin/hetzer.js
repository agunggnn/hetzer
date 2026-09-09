#!/usr/bin/env node
'use strict';

// Suppress noisy Node 22 warnings for built-in experimental features (e.g. node:sqlite)
const originalEmitWarning = process.emitWarning;
process.emitWarning = function (warning, ...args) {
  if (typeof warning === 'string' && warning.includes('SQLite')) return;
  if (typeof warning === 'object' && warning?.message?.includes('SQLite')) return;
  if (args[0] === 'ExperimentalWarning' && typeof warning === 'string' && warning.includes('SQLite')) return;
  return originalEmitWarning.call(process, warning, ...args);
};

async function start() {
  const { supportsNodeSqlite, unsupportedNodeMessage } = await import('../core/node-version.mjs');
  if (!supportsNodeSqlite(process.versions.node)) {
    process.stderr.write(`${unsupportedNodeMessage(process.version)}\n`);
    process.exitCode = 1;
    return;
  }

  const { main } = await import('../core/cli.mjs');
  await main();
}

start().catch((error) => {
    process.stderr.write(`Hetzer failed: ${error.message}\n`);
    process.exitCode = error.exitCode || 1;
});
