# Hetzer: Complete Installation & Setup Guide

> **Target OS**: Ubuntu/Debian, RHEL/CentOS, Windows (WSL2/Native), macOS (Apple Silicon & Intel)  
> **Node.js**: `^22.13.0 || >=23.4.0` (the current 22 or 24 LTS works)  
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
8. [Multi-Container Fleet Ops (Jagdpanzer Delegation)](#8-multi-container-fleet-ops-jagdpanzer-delegation)
9. [Updating & Maintenance](#9-updating--maintenance)
10. [Uninstallation & Teardown](#10-uninstallation--teardown)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)

---

## 1. System Requirements

Hetzer is engineered for high density and low memory consumption. It does not require a dedicated GPU.

| Mode | System Profile | RAM Consumption | Docker Required? |
|---|---|---|---|
| **Headless Armor & Skills** | Any machine with Node.js >= 22.13 | **< 10 MiB RAM** | ❌ **No (0 Docker)** |
| **Full Stack (Core + 9Router)** | 1 Core CPU, 1.0 GiB RAM | ~200 MiB active | ✅ Yes (Docker Compose v2) |
| **Ephemeral Sandbox Isolation** | Docker or Podman engine | Transient (< 50 MiB) | ✅ Optional (`hetzer exec --sandbox`) |

---

## 2. 60-Second Quickstart

If your machine has Node.js (>= 22.13), run instantly without permanent installation:

```bash
# 1. Install credential-safety guidance for supported local agents
npx hetzer skill install

# 2. Guard your Git repository from accidental token leaks
npx hetzer hook install

# 3. Store a secret securely in AES-256-GCM Grimoire Vault
npx hetzer creds set openai-api-key
```

Hetzer no longer starts container stacks. `hetzer up`, `hetzer down` and `hetzer tui` were removed and print a pointer
to [Jagdpanzer](https://github.com/agunggnn/jagdpanzer), which runs multi-container stacks.

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
# or install directly from GitHub repository:
npm install -g git+https://github.com/agunggnn/hetzer.git
# or from the GitHub Packages mirror (needs an npm login to GitHub Packages with a read:packages token):
npm install -g @agunggnn/hetzer --registry=https://npm.pkg.github.com
```

> **Release channel**: `hetzer` on npmjs is the primary package. From 0.6.2 it is staged by the release workflow
> through npm trusted publishing (no npm token is stored in the repository) and becomes public only after a
> maintainer approves it with 2FA. npmjs went from 0.4.5 straight to 0.6.2; 0.5.x to 0.6.1 are on GitHub Releases
> and GitHub Packages only. Run `hetzer --version` after installing and expect 0.6.2 or later.

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
- ✅ Node.js version compatibility (`^22.13.0 || >=23.4.0`, so built-in `node:sqlite` loads without a flag).
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
3. Creates `.env` with strict `chmod 600` permissions.
4. For the fixed list of variable names in `cli/vault/migrate-env.mjs` (`BINDINGS`), moves a plaintext value found in
   `.env` into the vault and leaves a `secretRef:<id>` reference in its place. Other variables are left alone.

`hetzer init` no longer generates gateway passwords: the bundled stack was removed.

---

## 7. Starting Services & Active Healthchecks

This section described `hetzer up --wait` and `hetzer tui`. Both were removed together with the Compose runner; each
now prints a pointer to [Jagdpanzer](https://github.com/agunggnn/jagdpanzer) and exits with code 1. See the next section for what Hetzer still runs.

---

## 8. Multi-Container Fleet Ops (Jagdpanzer Delegation)

Multi-container stack orchestration (databases, persistent memory engines, and multi-service topologies) is cleanly separated from Hetzer and maintained in [**Jagdpanzer**](https://github.com/agunggnn/jagdpanzer).

Hetzer operates strictly as a lightweight single-command runtime armor, stream redactor, and container sandbox:
```bash
# Isolate untrusted commands inside ephemeral containers (mounts the current directory; add --sandbox-mount <dir> to choose another):
hetzer exec --sandbox alpine:latest -- python -c "print('hello')"

# Mediate credentials securely through the HTTP broker:
hetzer exec --allow api-key -- python script.py
```

For persistent cognitive memory pipelines, multi-service Docker Compose clusters, and automated microservice networks, please deploy via [Jagdpanzer](https://github.com/agunggnn/jagdpanzer).

---

## 9. Updating & Maintenance

### Upgrade Hetzer CLI
Hetzer is upgraded through npm. The built-in upgrade manager was removed: `hetzer check-update` and `hetzer upgrade`
only print the command below, and `hetzer version --check` prints the installed version without looking for a newer one.

```bash
# Show the installed version:
hetzer version

# Upgrade Hetzer CLI:
npm install -g hetzer@latest
```

### Update Docker Container Digests (Removed)
`hetzer update <module>` was removed with the module system. Container stacks and their image digests are managed in
[Jagdpanzer](https://github.com/agunggnn/jagdpanzer).

### Backup Grimoire Vault
```bash
cp data/hetzer-vault.db data/hetzer-vault.backup.db
cp .env .env.backup
```

---

## 10. Uninstallation & Teardown

```bash
# 1. Remove the project directory:
cd .. && rm -rf hetzer

# 2. Uninstall the global CLI binary:
npm uninstall -g hetzer

# 3. (Optional) Prune unused Docker images:
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

### Q3: `ERR_CANARY_TRIPWIRE_TRIGGERED (exitCode 43)`
**Fix**: A honeytoken canary (`canary-token`, `canary-*`, or `HETZER_CANARY_TOKEN`) was leaked into a process stream or network call. The subprocess was immediately terminated by Hetzer's tripwire guard. Audit the command payload or script to locate the leaked token reference.

---

*For detailed system architecture, see [docs/architecture.md](docs/architecture.md).*  
*For Model Context Protocol usage, see [docs/mcp-guide.md](docs/mcp-guide.md).*
