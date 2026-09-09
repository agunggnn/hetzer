# Hetzer: Complete Installation & Setup Guide

> **Target OS**: Ubuntu/Debian, RHEL/CentOS, Windows (WSL2/Native), macOS (Apple Silicon & Intel)  
> **Node.js**: >= 22.5.0  
> **Docker (Optional for Full Stack)**: Engine >= 24.0, Docker Compose >= v2.20  
> **Headless Mode**: no Docker required; the Node CLI consumes resources only while invoked
> **Documentation Type**: Modular Reference & Step-by-Step Tutorial

---

## 📑 Table of Contents

1. [System Requirements](#1-system-requirements)
2. [60-Second Quickstart](#2-60-second-quickstart)
3. [OS-Specific Prerequisites](#3-os-specific-prerequisites)
   - [Ubuntu & Debian Linux](#31-ubuntu--debian-linux)
   - [CentOS, RHEL & Fedora](#32-centos-rhel--fedora)
   - [Windows 10 / 11 (Native & WSL2)](#33-windows-10--11-native--wsl2)
   - [macOS (Apple Silicon & Intel)](#34-macos-apple-silicon--intel)
   - [Cloud VPS (Hetzner, DigitalOcean, AWS EC2)](#35-cloud-vps-hetzner-digitalocean-aws-ec2)
4. [Installation Methods](#4-installation-methods)
   - [Method A: One-Line Script via curl / PowerShell (Fastest)](#method-a-one-line-script-via-curl--powershell-fastest)
   - [Method B: Zero-Install via npx](#method-b-zero-install-via-npx)
   - [Method C: Global CLI via npm (Recommended)](#method-c-global-cli-via-npm-recommended)
   - [Method D: Clone from Source](#method-d-clone-from-source)
5. [Pre-flight Diagnostics (`hetzer doctor`)](#5-pre-flight-diagnostics-hetzer-doctor)
6. [Project Initialization & Secret Setup](#6-project-initialization--secret-setup)
7. [Starting Services & Active Healthchecks](#7-starting-services--active-healthchecks)
8. [Enabling Persistent Memory (Cognee Module)](#8-enabling-persistent-memory-cognee-module)
9. [Updating & Maintenance](#9-updating--maintenance)
10. [Uninstallation & Teardown](#10-uninstallation--teardown)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)

---

## 1. System Requirements

Hetzer is engineered for high density and low memory consumption. It does not require a dedicated GPU.

| Mode | System Profile | RAM Consumption | Docker Required? |
|---|---|---|---|
| **Headless Armor & Skills** | Any machine with Node.js >= 22.5 | **< 10 MiB RAM** | ❌ **No (0 Docker)** |
| **Full Stack (Core + 9Router)** | 1 Core CPU, 1.0 GiB RAM | ~200 MiB active | ✅ Yes (Docker Compose v2) |
| **Full Stack + Cognee Memory**| 2 Cores CPU, 3.0 GiB RAM | ~1.4 GiB active | ✅ Yes (Docker Compose v2) |

---

## 2. 60-Second Quickstart

If your machine has Node.js (>= 22.5), run instantly without permanent installation:

```bash
# 1. Install credential-safety guidance for supported local agents
npx hetzer skill install

# 2. Guard your Git repository from accidental token leaks
npx hetzer hook install

# 3. Store a secret securely in AES-256-GCM Grimoire Vault
npx hetzer creds set openai-api-key
```

If using full stack container services:
```bash
# 4. Initialize and launch services with active healthcheck verification
hetzer init
hetzer up --wait
hetzer tui
```

Your 9Router AI Gateway will immediately be live at `http://127.0.0.1:20140`. Retrieve the generated password anytime with:
```bash
hetzer creds reveal nine-router-initial-password
```

---

## 3. OS-Specific Prerequisites

### 3.1 Ubuntu & Debian Linux

Install Node.js 22.x LTS and Docker Engine:

```bash
# 1. Update packages
sudo apt-get update && sudo apt-get install -y curl ca-certificates gnupg

# 2. Install Node.js 22 LTS
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# 3. Install Docker Engine & Compose plugin (optional for full stack)
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# 4. Grant current user non-root Docker socket access
sudo usermod -aG docker $USER
newgrp docker
```

---

### 3.2 CentOS, RHEL & Fedora

```bash
# 1. Install Node.js 22
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo dnf install -y nodejs

# 2. Install Docker CE
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
newgrp docker
```

---

### 3.3 Windows 10 / 11 (Native & WSL2)

1. **Native Windows**:
   Install Node.js >= 22 via winget or the official installer:
   ```powershell
   winget install OpenJS.NodeJS.LTS
   ```
2. **Optional WSL2 & Docker Desktop (for full stack)**:
   ```powershell
   wsl --install
   ```
   Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/). Ensure "Use the WSL 2 based engine" is checked in Docker settings.

---

### 3.4 macOS (Apple Silicon & Intel)

```bash
# 1. Install Node.js 22
brew install node@22
brew link node@22

# 2. (Optional) Install OrbStack or Docker Desktop for container services
brew install --cask orbstack
```

---

### 3.5 Cloud VPS (Hetzner, DigitalOcean, AWS EC2)

On budget cloud instances (e.g. 1 vCPU, 2GB RAM), configure a swap file to guarantee stability during peak embedding indexing:

```bash
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
```

---

## 4. Installation Methods

### Method A: One-Line Script via curl / PowerShell (Fastest)

**Linux & macOS (curl / bash):**
```bash
curl -fsSL https://raw.githubusercontent.com/agunggnn/hetzer/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/agunggnn/hetzer/main/install.ps1 | iex
```

---

### Method B: Zero-Install via npx

Run any command on-demand without installing globally:
```bash
npx hetzer skill install
npx hetzer hook install
npx hetzer creds list
```

---

### Method C: Global CLI via npm (Recommended)

```bash
npm install -g hetzer
```

Verify the binary is available:
```bash
hetzer --version
```

---

### Method D: Clone from Source (Contributors)

```bash
git clone https://github.com/agunggnn/hetzer.git
cd hetzer
npm test
npm link
```

---

## 5. Pre-flight Diagnostics (`hetzer doctor`)

Before starting containers, run `hetzer doctor` to inspect the host environment:

```bash
hetzer doctor
```

To automatically repair directory permissions or structure:
```bash
hetzer doctor --fix
```

The doctor command checks:
- ✅ Node.js version compatibility (`>= 22.5.0` for built-in `node:sqlite`).
- ✅ Docker Engine daemon liveness.
- ✅ Docker Compose v2 plugin availability.
- ✅ Non-root user permissions for `/var/run/docker.sock`.
- ✅ File permissions on `.env` (`chmod 600` on POSIX systems).
- ✅ Grimoire Vault database connectivity.

---

## 6. Project Initialization & Secret Setup

Run `hetzer init` to create the command plane:

```bash
# Initialize in current directory:
hetzer init

# Or initialize inside a dedicated directory:
hetzer init ./my-hetzer-instance
cd my-hetzer-instance
```

### What Happens During `hetzer init`?
1. Generates `data/hetzer-vault.db` (AES-256-GCM encrypted SQLite database).
2. Generates a secure master key (`HETZER_GRIMOIRE_KEY`) if not already present.
3. Generates a 16-character hexadecimal password for 9Router admin access.
4. Creates `.env` with strict `chmod 600` permissions.
5. Populates `.env` using credential references:
   ```dotenv
   NINE_ROUTER_INITIAL_PASSWORD=secretRef:nine-router-initial-password
   ```

To reveal your 9Router password anytime:
```bash
hetzer creds reveal nine-router-initial-password
```

---

## 7. Starting Services & Active Healthchecks

Start your container services:

```bash
hetzer up --wait
```

The `--wait` flag automatically:
1. Merges active Compose configurations.
2. Injects decrypted credentials ephemerally into container memory.
3. Spawns Docker containers.
4. Actively probes HTTP healthcheck endpoints until `healthy` is reached.
5. Displays a live status table with loopback URLs and ports.

To monitor running services continuously:
```bash
hetzer tui
```

---

## 8. Enabling Persistent Memory (Cognee Module)

Cognee is an optional module that adds graph and vector persistent memory via the Model Context Protocol (MCP).

```bash
# 1. Install the module
hetzer install cognee

# 2. Configure your LLM API key into the Vault
hetzer creds set cognee-llm-api-key

# 3. Launch Cognee
hetzer up --wait cognee

# 4. Register MCP endpoint into .mcp.json
hetzer mcp configure
```

Claude Desktop, Cursor, and Cline can now immediately access memory tools (`remember`, `recall`, `improve`).

---

## 9. Updating & Maintenance

### Update Docker Container Digests
Hetzer pins container digests for cryptographic reproducibility. To fetch updated digests:
```bash
hetzer update
```

### Backup Grimoire Vault
```bash
cp data/hetzer-vault.db data/hetzer-vault.backup.db
cp .env .env.backup
```

---

## 10. Uninstallation & Teardown

```bash
# 1. Stop containers and destroy named Docker volumes:
hetzer down -v

# 2. Remove the project directory:
cd .. && rm -rf hetzer

# 3. Uninstall the global CLI binary:
npm uninstall -g hetzer

# 4. (Optional) Prune unused Docker images:
docker image prune -a
```

---

## 11. Troubleshooting & FAQ

### Q1: `Permission denied while trying to connect to the Docker daemon socket`
**Fix**: Add your user to the `docker` group:
```bash
sudo usermod -aG docker $USER && newgrp docker
```

### Q2: `HTTP 406 Not Acceptable` when calling MCP tools
**Fix**: Ensure your MCP client sends `Accept: application/json, text/event-stream`. The Hetzer MCP bridge handles this automatically.

### Q3: `Container cognee-mcp restarting (ExitCode 1, Health: unhealthy)`
**Fix**: Ensure Docker volume permissions are clean. Hetzer enforces `user: "0:0"` in `docker-compose.cognee.yml`. Run `hetzer up --wait cognee`.

---

*For detailed system architecture, see [docs/architecture.md](docs/architecture.md).*  
*For Model Context Protocol usage, see [docs/mcp-guide.md](docs/mcp-guide.md).*
