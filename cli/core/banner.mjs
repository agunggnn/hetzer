export function getHetzerAsciiBanner({ colored = false } = {}) {
    const cCyan = colored ? "\x1b[36m" : "";
    const cGreen = colored ? "\x1b[32m" : "";
    const cBold = colored ? "\x1b[1m" : "";
    const cDim = colored ? "\x1b[2m" : "";
    const cReset = colored ? "\x1b[0m" : "";

    return [
        `${cBold}${cCyan}  ██╗  ██╗███████╗████████╗███████╗███████╗██████╗ ${cReset}`,
        `${cBold}${cCyan}  ██║  ██║██╔════╝╚══██╔══╝╚══███╔╝██╔════╝██╔══██╗${cReset}`,
        `${cBold}${cGreen}  ███████║█████╗     ██║     ███╔╝ █████╗  ██████╔╝${cReset}`,
        `${cBold}${cGreen}  ██╔══██║██╔══╝     ██║    ███╔╝  ██╔══╝  ██╔══██╗${cReset}`,
        `${cBold}${cCyan}  ██║  ██║███████╗   ██║   ███████╗███████╗██║  ██║${cReset}`,
        `${cBold}${cCyan}  ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝${cReset}`,
        `${cDim} =======================================================${cReset}`,
        `  ${cBold}${cGreen}H E T Z E R${cReset}  ${cDim}•${cReset}  ${cCyan}Credential Safety for AI Workflows${cReset}`,
        `  ${cDim}[Encrypted Vault] • [MCP Tools] • [Scoped Execution]${cReset}`,
        `${cDim} =======================================================${cReset}`,
    ].join("\n");
}

export function printHetzerBanner() {
    const isTty = process.stdout.isTTY;
    process.stdout.write(getHetzerAsciiBanner({ colored: Boolean(isTty) }) + "\n\n");
}
