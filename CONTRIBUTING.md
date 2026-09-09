# Contributing to Hetzer

## Development Setup

```bash
git clone https://github.com/agunggnn/hetzer.git
cd hetzer
npm ci
```

## Development workflow

Create a branch for every change. Do not develop or commit directly on `main`.

```bash
git switch -c <type>/<short-description>
```

Before opening a pull request, update the package version and every mirrored version field when the merge should produce a release. The main-branch release workflow refuses to move an existing version tag.

## Running Tests

```bash
# Run all tests
npm test

# Run all six empirical security and performance protocols
npm run verify -- --no-write

# Confirm both registry packages can be assembled
npm run build:package

# Run specific test file
node --test cli/core/env.test.mjs
```

## Linting / Checks

```bash
npm run lint
```

This runs `scripts/check.mjs` which validates:
- Module registry schema
- Built-in module definitions
- Compose file references
- Runtime entry points

## Project Structure

```
cli/
  bin/           # CLI entry point (hetzer.js)
  core/          # Core orchestration (env, docker, update, cli, banner, git-hook)
  modules/       # Module registry, resolution, toggle, TUI
  mcp/           # MCP server, protocol, catalog, synthesis
  skills/        # Multi-agent skill installation & rule injection
  vault/         # Encrypted credential vault (SQLite + AES-256-GCM)
  templates/     # Project initialization templates
scripts/
  check.mjs      # Build-time validation
benchmarks/      # Performance benchmarks
.github/workflows/ci.yml
```

## Code Conventions

- Node >=22.5.0 ESM; the vault requires the built-in `node:sqlite` module
- `node:test` for unit tests (`*.test.mjs`)
- `node --test "**/*.test.mjs"` runs all tests
- Zero external dependencies in runtime `cli/` — Node standard library only
- Export functions at top level, not default
- English error messages and logs for all user-facing output

## Adding a New Module

1. Create `cli/modules/<name>/module.json` (see `builtin.json` for schema)
2. Add `docker-compose.yml` beside it if `lifecycle: "compose"`
3. Run `npm run lint` to validate

## Vault Changes

- Credential encryption: AES-256-GCM via `node:crypto` (see `cli/vault/hetzer-vault.mjs`)
- Master key derived via HKDF-SHA256 with salt `hetzer-grimoire-v1`
- Environment variable: `HETZER_GRIMOIRE_KEY`
- `.env` files created by `init` get `chmod 600` (Unix)
- Any `.env` write in `toggle.mjs` also applies `chmod 600`

## CI pipeline

- Feature-branch pushes and pull requests into `main` run static checks, tests, all six empirical protocols, and package builds on Ubuntu, macOS, and Windows.
- `compose-contract` job: Smoke test `hetzer init` + `hetzer doctor` on Ubuntu
- Direct pushes to `main` are not the development path. Protect `main` in GitHub and require the CI jobs before merging.

## Release pipeline

After a pull request is merged, `.github/workflows/release-main.yml` repeats the gates, builds both registry tarballs, creates an immutable annotated `v<package.version>` tag, creates a GitHub Release containing those artifacts, and directly invokes the idempotent scoped GitHub Packages workflow.

Publishing the unscoped npmjs package remains an explicit credentialed operation; the GitHub workflow does not assume access to an npm token.
