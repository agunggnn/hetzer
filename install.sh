#!/usr/bin/env bash
set -e

# Hetzer Installer Script (Linux & macOS)
# Usage: curl -fsSL https://raw.githubusercontent.com/agunggnn/hetzer/main/install.sh | bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}${BOLD}"
echo "================================================================================"
echo "  HETZER - ZERO-PLAINTEXT SECURITY ARMOR FOR AI AGENTS"
echo "  One-line Automated Installer (Linux & macOS)"
echo "================================================================================"
echo -e "${NC}"

# 1. Check for Node.js
if ! command -v node >/dev/null 2>&1; then
    echo -e "${RED}[x] Node.js is not installed.${NC}"
    echo -e "    Hetzer requires Node.js >= 22.13.0."
    echo -e "    Install it via NodeSource or NVM:"
    echo -e "      curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -"
    echo -e "      sudo apt-get install -y nodejs"
    exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//')
MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
MINOR=$(echo "$NODE_VERSION" | cut -d. -f2)

# node:sqlite loads without a flag from 22.13.0 (22.x) and 23.4.0 (23.x).
if [ "$MAJOR" -lt 22 ] || { [ "$MAJOR" -eq 22 ] && [ "$MINOR" -lt 13 ]; } || { [ "$MAJOR" -eq 23 ] && [ "$MINOR" -lt 4 ]; }; then
    echo -e "${RED}[x] Node.js v${NODE_VERSION} is too old.${NC}"
    echo -e "    Hetzer requires Node.js ^22.13.0 or >= 23.4.0, the first releases that load the"
    echo -e "    built-in node:sqlite module without a flag. Install the current 22 or 24 LTS."
    exit 1
fi

# 2. Check for npm
if ! command -v npm >/dev/null 2>&1; then
    echo -e "${RED}[x] npm is not installed.${NC}"
    exit 1
fi

# 3. Install hetzer globally via npm
echo -e "${BLUE}[i] Installing Hetzer CLI globally via npm...${NC}"

NPM_PREFIX=$(npm config get prefix 2>/dev/null || echo "/usr")
if [ -w "$NPM_PREFIX" ] || [ -w "$NPM_PREFIX/lib" ] 2>/dev/null || [ -w "$NPM_PREFIX/bin" ] 2>/dev/null; then
    npm install -g hetzer@latest
else
    if command -v sudo >/dev/null 2>&1; then
        echo -e "${YELLOW}[i] Elevating with sudo for global npm installation...${NC}"
        sudo npm install -g hetzer@latest
    else
        echo -e "${YELLOW}[i] Configuring npm prefix to ~/.npm-global...${NC}"
        mkdir -p "$HOME/.npm-global"
        npm config set prefix "$HOME/.npm-global"
        export PATH="$HOME/.npm-global/bin:$PATH"
        npm install -g hetzer@latest
    fi
fi

# 4. Verify installation & Auto-deploy Universal Skills
if command -v hetzer >/dev/null 2>&1; then
    HETZER_BIN=$(command -v hetzer)
    echo -e "\n${GREEN}${BOLD}[v] Hetzer installed successfully at: ${HETZER_BIN}${NC}\n"
    
    echo -e "${BLUE}[i] Auto-deploying Universal AI Agent Skills...${NC}"
    hetzer skill install || true

    echo -e "\n${GREEN}"
    echo "================================================================================"
    echo "  🎉 HETZER CLI & AGENT SKILLS ARE READY!"
    echo "================================================================================"
    echo -e "${NC}"
    echo "Quickstart Commands:"
    echo "  1. Pre-commit Git Guard  : hetzer hook install"
    echo "  2. Initialize Workspace  : hetzer init"
    echo "  3. Store a Secret        : hetzer creds set <id>   (masked prompt)"
    echo "  4. Doctor Diagnostic     : hetzer doctor"
    echo ""
else
    NPM_BIN="$(npm config get prefix 2>/dev/null)/bin"
    echo -e "${YELLOW}[!] Hetzer was installed, but '${NPM_BIN}' is not in your current PATH.${NC}"
    echo "    Add this to your ~/.bashrc or ~/.zshrc:"
    echo "      export PATH=\"${NPM_BIN}:\$PATH\""
    echo "    Then run: source ~/.bashrc"
fi
