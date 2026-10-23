# Hetzer Windows Installer Script
# Usage: irm https://raw.githubusercontent.com/agunggnn/hetzer/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  HETZER - CREDENTIAL GUARD FOR AI AGENTS" -ForegroundColor Cyan
Write-Host "  One-line Automated Installer (Windows)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# 1. Check Node.js
try {
    $nodeVer = & node -v 2>$null
    if (-not $nodeVer) {
        throw "Node.js is not installed"
    }
    Write-Host "[v] Found Node.js: $nodeVer" -ForegroundColor Green
} catch {
    Write-Host "[x] Node.js is not installed!" -ForegroundColor Red
    Write-Host "    Download Node.js 22 LTS from https://nodejs.org/" -ForegroundColor Yellow
    exit 1
}

# 2. Install Hetzer globally via npm
Write-Host "[i] Installing Hetzer globally via npm..." -ForegroundColor Cyan
npm install -g hetzer@latest

if ($LASTEXITCODE -ne 0) {
    Write-Host "[x] npm install failed with exit code $LASTEXITCODE" -ForegroundColor Red
    Write-Host "    If you encounter permission or existing binary shim conflicts, retry with:" -ForegroundColor Yellow
    Write-Host "      npm install -g --force hetzer@latest" -ForegroundColor Yellow
    exit 1
}

# 3. Auto-deploy Universal Skills
Write-Host "[i] Auto-deploying Universal AI Agent Skills..." -ForegroundColor Cyan
try {
    & hetzer skill install
} catch {
    Write-Host "[!] Note: run 'hetzer skill install' inside your workspace." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "  🎉 HETZER CLI & AGENT SKILLS INSTALLED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Green
Write-Host "Quickstart Commands:"
Write-Host "  1. Pre-commit Git Guard  : hetzer hook install"
Write-Host "  2. Initialize Workspace  : hetzer init"
Write-Host "  3. Store a Secret        : hetzer creds set <id>   (masked prompt)"
Write-Host "  4. Doctor Diagnostic     : hetzer doctor"
Write-Host ""
