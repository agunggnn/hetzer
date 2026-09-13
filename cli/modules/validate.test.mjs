import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { formatValidationReport, validateAllModules, validateModuleRecipe } from "./validate.mjs";

test("validateModuleRecipe detects valid recipe in a module directory", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-val-valid-"));
    try {
        const modDir = path.join(tempDir, "modules", "sample-mod");
        fs.mkdirSync(modDir, { recursive: true });
        fs.writeFileSync(path.join(modDir, "module.json"), JSON.stringify({
            schemaVersion: 1,
            id: "sample-mod",
            label: "Sample Module",
            version: "1",
            profile: "sample-mod",
            lifecycle: "compose",
            surface: "headless",
            defaultEnabled: true,
            requires: ["core"],
            composeFiles: ["docker-compose.sample-mod.yml"],
            services: [{
                id: "sample-service",
                label: "Sample",
                composeService: "sample",
                profile: "sample-mod",
                mcpServer: { name: "sample-mcp", transport: "http", path: "/mcp" },
            }],
        }, null, 2));
        fs.writeFileSync(path.join(modDir, "docker-compose.sample-mod.yml"), `services:
  sample:
    image: alpine:latest
    profiles: [sample-mod]
    ports:
      - "127.0.0.1:8080:8080"
    security_opt: ["no-new-privileges:true"]
    extra_hosts: ["host.docker.internal:host-gateway"]
    mem_limit: 512m
    healthcheck:
      test: ["CMD", "true"]
`);
        fs.writeFileSync(path.join(modDir, "README.md"), "# Sample Module\nDocumentation.\n");

        const result = validateModuleRecipe({ root: tempDir, moduleId: "sample-mod" });
        assert.equal(result.valid, true);
        assert.equal(result.errors.length, 0);
        assert.ok(result.passed.length >= 8);
        const text = formatValidationReport(result);
        assert.match(text, /Status: Module 'sample-mod' VALID/);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("validateModuleRecipe catches invalid JSON and missing files", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-val-test-"));
    try {
        const modDir = path.join(tempDir, "modules", "bad-mod");
        fs.mkdirSync(modDir, { recursive: true });

        // Missing module.json
        const resMissing = validateModuleRecipe({ root: tempDir, moduleId: "bad-mod" });
        assert.equal(resMissing.valid, false);
        assert.match(resMissing.errors[0], /module.json' not found/);

        // Corrupted module.json
        fs.writeFileSync(path.join(modDir, "module.json"), "{ invalid json");
        const resCorrupt = validateModuleRecipe({ root: tempDir, moduleId: "bad-mod" });
        assert.equal(resCorrupt.valid, false);
        assert.match(resCorrupt.errors[0], /Failed to parse/);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("validateModuleRecipe flags insecure 0.0.0.0 ports and missing compose profile", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-val-test2-"));
    try {
        const modDir = path.join(tempDir, "modules", "insecure-mod");
        fs.mkdirSync(modDir, { recursive: true });

        fs.writeFileSync(path.join(modDir, "module.json"), JSON.stringify({
            schemaVersion: 1,
            id: "insecure-mod",
            label: "Insecure Mod",
            version: "1",
            profile: "insecure-mod",
            lifecycle: "compose",
            surface: "headless",
            requires: ["core"],
            composeFiles: ["docker-compose.yml"],
            services: [{ id: "srv1" }],
        }, null, 2));

        // Compose file with 0.0.0.0 open port and no profiles
        fs.writeFileSync(path.join(modDir, "docker-compose.yml"), `services:
  srv1:
    image: test:latest
    ports:
      - "8080:8080"
`);

        const res = validateModuleRecipe({ root: tempDir, moduleId: "insecure-mod" });
        assert.equal(res.valid, true); // It's valid schema-wise but has security warnings
        assert.ok(res.warnings.some((w) => w.includes("profiles: [insecure-mod]")));
        assert.ok(res.warnings.some((w) => w.includes("exposed to all interfaces")));
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});

test("validateAllModules inspects all available modules", () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-val-all-"));
    try {
        const modDir = path.join(tempDir, "modules", "custom-mod");
        fs.mkdirSync(modDir, { recursive: true });
        fs.writeFileSync(path.join(modDir, "module.json"), JSON.stringify({
            schemaVersion: 1,
            id: "custom-mod",
            label: "Custom Module",
            version: "1",
            profile: "custom-mod",
            lifecycle: "compose",
            surface: "headless",
            defaultEnabled: true,
            requires: ["core"],
            composeFiles: ["docker-compose.custom-mod.yml"],
            services: [{ id: "custom", composeService: "custom", profile: "custom-mod" }],
        }, null, 2));
        fs.writeFileSync(path.join(modDir, "docker-compose.custom-mod.yml"), `services:
  custom:
    image: alpine:latest
    profiles: [custom-mod]
    ports:
      - "127.0.0.1:8080:8080"
`);
        fs.writeFileSync(path.join(modDir, "README.md"), "# Custom\nDocumentation.\n");

        const results = validateAllModules({ root: tempDir });
        assert.ok(results.length >= 1);
        const mod = results.find((r) => r.id === "custom-mod");
        assert.ok(mod);
        assert.equal(mod.valid, true);
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
