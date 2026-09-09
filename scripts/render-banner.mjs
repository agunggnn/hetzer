#!/usr/bin/env node

/**
 * Hetzer Banner Generator
 *
 * Renders `assets/hetzer-banner.svg` to `assets/hetzer-banner.jpg` (900x380 px, quality 98)
 * using headless Chromium/Edge and platform image encoders.
 *
 * Usage:
 *   node scripts/render-banner.mjs
 *   npm run render:banner
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const svgFile = path.join(root, "assets", "hetzer-banner.svg");
const jpgFile = path.join(root, "assets", "hetzer-banner.jpg");
const tempPng = path.join(root, "assets", `.temp-banner-${Date.now()}.png`);

function findBrowserBinary() {
    const fromEnv = process.env.HETZER_BROWSER_BIN || process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_BIN;
    if (fromEnv && fs.existsSync(fromEnv)) return fromEnv;

    const platform = os.platform();
    const candidates = [];

    if (platform === "win32") {
        const pf86 = process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)";
        const pf = process.env["ProgramFiles"] || "C:\\Program Files";
        const local = process.env["LocalAppData"] || "";

        candidates.push(
            path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            path.join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
            path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            path.join(local, "Google", "Chrome", "Application", "chrome.exe")
        );
    } else if (platform === "darwin") {
        candidates.push(
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium"
        );
    } else {
        const which = (cmd) => {
            const res = spawnSync("which", [cmd], { encoding: "utf8" });
            return res.status === 0 ? res.stdout.trim() : null;
        };
        for (const name of ["google-chrome", "chromium", "chromium-browser", "microsoft-edge"]) {
            const found = which(name);
            if (found) candidates.push(found);
        }
    }

    for (const candidate of candidates) {
        if (candidate && fs.existsSync(candidate)) return candidate;
    }
    return null;
}

function convertPngToJpg(inputPng, outputJpg) {
    // Strategy 1: Python with PIL/Pillow
    for (const py of ["python", "python3"]) {
        const pyCheck = spawnSync(py, ["-c", "import PIL; print('ok')"], { encoding: "utf8", windowsHide: true });
        if (pyCheck.status === 0 && pyCheck.stdout.includes("ok")) {
            const script = `
from PIL import Image
img = Image.open(r"${inputPng}")
if img.size != (900, 380):
    img = img.crop((0, 0, 900, 380))
img.convert("RGB").save(r"${outputJpg}", "JPEG", quality=98)
`;
            const run = spawnSync(py, ["-c", script], { encoding: "utf8", windowsHide: true });
            if (run.status === 0 && fs.existsSync(outputJpg) && fs.statSync(outputJpg).size > 1000) {
                return "python-pillow";
            }
        }
    }

    // Strategy 2: Windows PowerShell with System.Drawing
    if (os.platform() === "win32") {
        const psScript = `
Add-Type -AssemblyName System.Drawing
$img = [System.Drawing.Image]::FromFile('${inputPng.replace(/'/g, "''")}')
$encoder = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders() | Where-Object { $_.FormatID -eq [System.Drawing.Imaging.ImageFormat]::Jpeg.Guid }
$params = New-Object System.Drawing.Imaging.EncoderParameters(1)
$params.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter([System.Drawing.Imaging.Encoder]::Quality, [long]98)
$img.Save('${outputJpg.replace(/'/g, "''")}', $encoder, $params)
$img.Dispose()
`;
        const run = spawnSync("powershell", ["-NoProfile", "-Command", psScript], { encoding: "utf8", windowsHide: true });
        if (run.status === 0 && fs.existsSync(outputJpg) && fs.statSync(outputJpg).size > 1000) {
            return "powershell-drawing";
        }
    }

    // Strategy 3: macOS sips
    if (os.platform() === "darwin") {
        const run = spawnSync("sips", ["-s", "format", "jpeg", "-s", "formatOptions", "98", inputPng, "--out", outputJpg], { encoding: "utf8" });
        if (run.status === 0 && fs.existsSync(outputJpg) && fs.statSync(outputJpg).size > 1000) {
            return "macos-sips";
        }
    }

    // Strategy 4: ImageMagick (convert / magick)
    for (const bin of ["magick", "convert"]) {
        const run = spawnSync(bin, [inputPng, "-quality", "98", outputJpg], { encoding: "utf8", windowsHide: true });
        if (run.status === 0 && fs.existsSync(outputJpg) && fs.statSync(outputJpg).size > 1000) {
            return "imagemagick";
        }
    }

    throw new Error(
        "No supported image conversion tool found. Please install Python with Pillow ('pip install Pillow') or ImageMagick."
    );
}

function main() {
    if (!fs.existsSync(svgFile)) {
        process.stderr.write(`Source SVG not found: ${svgFile}\n`);
        process.exit(1);
    }

    const browser = findBrowserBinary();
    if (!browser) {
        process.stderr.write(
            "Headless Chromium/Edge executable not found.\n" +
            "Please install Microsoft Edge or Google Chrome, or configure the HETZER_BROWSER_BIN environment variable.\n"
        );
        process.exit(1);
    }

    process.stdout.write(`Rendering ${path.relative(root, svgFile)} using ${path.basename(browser)}...\n`);

    const fileUrl = `file:///${svgFile.replace(/\\/g, "/")}`;
    const args = [
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        `--screenshot=${tempPng}`,
        "--window-size=900,380",
        "--force-device-scale-factor=1",
        fileUrl,
    ];

    const browserRun = spawnSync(browser, args, { encoding: "utf8", windowsHide: true });
    if (browserRun.status !== 0 && !fs.existsSync(tempPng)) {
        process.stderr.write(`Headless browser failed: ${browserRun.stderr || browserRun.stdout || "unknown error"}\n`);
        process.exit(1);
    }

    if (!fs.existsSync(tempPng)) {
        process.stderr.write(`Failed to generate screenshot at ${tempPng}\n`);
        process.exit(1);
    }

    try {
        const converter = convertPngToJpg(tempPng, jpgFile);
        const stats = fs.statSync(jpgFile);
        process.stdout.write(
            `[v] Successfully generated ${path.relative(root, jpgFile)} (${stats.size} bytes, 900x380) via ${converter}.\n`
        );
    } finally {
        if (fs.existsSync(tempPng)) {
            try { fs.unlinkSync(tempPng); } catch { /* best effort */ }
        }
    }
}

main();
