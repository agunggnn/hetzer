#!/usr/bin/env node

import readline from "node:readline";

import { createToolCatalog } from "./catalog.mjs";
import { handleMcpRequest, parseError } from "./protocol.mjs";

const catalog = createToolCatalog();
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

try {
    for await (const line of input) {
        if (!line.trim()) continue;
        let request;
        try {
            request = JSON.parse(line);
        } catch {
            process.stdout.write(`${JSON.stringify(parseError())}\n`);
            continue;
        }
        const response = await handleMcpRequest(request, catalog);
        if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
    }
} catch (err) {
    if (err?.code === "ERR_CANARY_TRIPWIRE_TRIGGERED") {
        process.exitCode = err.exitCode || 43;
    }
    throw err;
} finally {
    catalog.close();
}
