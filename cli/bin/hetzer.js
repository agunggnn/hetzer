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

import('../core/cli.mjs')
  .then(({ main }) => main())
  .catch((error) => {
    process.stderr.write(`Hetzer failed: ${error.message}\n`);
    process.exitCode = error.exitCode || 1;
  });
