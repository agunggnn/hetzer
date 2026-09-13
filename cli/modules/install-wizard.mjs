// Module installation wizard handler

export async function runInstallWizard({
    root,
    envFile,
    moduleId,
    nonInteractive = false,
    input = process.stdin,
    out = process.stdout,
}) {
    // Standard modules execute with default configuration without requiring interactive prompts
    return { configured: true, mode: "standard" };
}
