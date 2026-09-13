import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { runInstallWizard } from "./install-wizard.mjs";

test("runInstallWizard completes standard configuration for modules", async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "hetzer-wizard-test-"));
    try {
        const envFile = path.join(tempDir, ".env");
        fs.writeFileSync(envFile, "HETZER_ENABLED_MODULES=\n");

        const result = await runInstallWizard({
            root: tempDir,
            envFile,
            moduleId: "sample-mod",
            nonInteractive: true,
        });

        assert.equal(result.configured, true);
        assert.equal(result.mode, "standard");
    } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
    }
});
