# Agent sandbox and decoys

This guide covers the controls added in 0.7.0 for the case where the code or the model you run cannot be trusted:
a backdoored model that tries to read credentials from disk and send them out, a malicious dependency, or a prompt
injection. It explains what each control stops, how to set it up on macOS and Linux, and what stays outside it.

## The problem in one paragraph

`hetzer exec` mediates the credentials it hands out, but the process it starts, and an agent that runs outside it,
still run as your OS user. Such a process can read `~/.ssh`, `~/.aws`, browser profiles, the workspace `.env` and
the vault file, and open any network connection. Hetzer's command checks (`ERR_SENSITIVE_PATH_ACCESS`, the
downloader and reflection guards) match command text; a script that builds a path at run time passes them. The
controls below change what the process can reach instead of what its command line looks like.

## 1. The master key stays outside the workspace

From 0.7.0, `hetzer init` writes the master key to `~/.hetzer/keys/<instance-id>.key` (mode 0600, directory 0700)
and records only the non-secret `HETZER_INSTANCE_ID` in `.env`. Before, the key sat in `.env`, next to
`data/hetzer-vault.db`, so anything that could read the project could decrypt the vault.

- Existing workspaces keep working. `hetzer doctor` warns while the key is still in `.env`; move it with
  `hetzer creds isolate-key`.
- `hetzer init` refuses (`ERR_MASTER_KEY_NOT_FOUND`) to generate a new key over an existing vault whose key it cannot
  find, because the credentials in that vault could not be decrypted with a new one.
- CI and containers can keep supplying `HETZER_GRIMOIRE_KEY` in the environment; nothing is written to disk then.

Boundary: this removes the key from the workspace, not from your account. A process running as your user outside a
sandbox can still read `~/.hetzer/keys`. The sandbox below hides it.

## 2. The sandbox engines

`hetzer exec --sandbox` and `hetzer agent` can use three engines:

| Engine | Needs | Isolation | Network |
|---|---|---|---|
| `docker`, `podman` | A running container engine and an image | Separate file system: only the project is mounted, Hetzer files in it are hidden | Open by default; `--sandbox-network none` closes it. No per-host allowlist |
| `srt` | [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime) (Apache-2.0), installed separately | Host file system with rules: reads of the home directory and Hetzer files denied, the project re-allowed; writes only in the project and a per-run temporary directory | Denied, except hosts listed with `--sandbox-allow-host` |

`srt` uses the operating system's own sandbox: `sandbox-exec` (Seatbelt) on macOS and bubblewrap with seccomp on
Linux. Network access goes through a proxy that srt runs on the host and that only lets listed hosts through. No
daemon, no image and no virtual machine are involved, which makes it the lighter choice on a laptop. Hetzer does not
bundle it, so Hetzer keeps no runtime dependencies; it was written and tested against version 0.0.78.

Engine selection: `--sandbox-engine <auto|docker|podman|srt>` or `HETZER_SANDBOX_ENGINE`. `auto` (the default for
`hetzer exec`) tries Docker, then Podman, then srt. `--sandbox-allow-host`, `--sandbox-allow-read` and
`--sandbox-allow-write` select srt, and an image selects a container engine; asking for both is refused.
`hetzer agent` uses srt unless you name an engine or an image, because the agent is installed on the host rather
than in an image.

### Install srt on macOS

```bash
brew install ripgrep
npm install -g @anthropic-ai/sandbox-runtime@0.0.78
hetzer doctor        # shows "Sandbox (srt) : 0.0.78 [OK]"
```

### Install srt on Linux

```bash
sudo apt-get install -y bubblewrap socat ripgrep     # Debian/Ubuntu
npm install -g @anthropic-ai/sandbox-runtime@0.0.78
# Ubuntu 24.04 restricts unprivileged user namespaces through AppArmor; bubblewrap needs them:
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
hetzer doctor
```

The sysctl change applies to the whole machine until reboot (persist it in `/etc/sysctl.d/` if you accept it).
Read your distribution's notes before relaxing it on a shared host.

### What srt allows, run by run

Hetzer writes a settings file for each run and removes it afterwards:

- **Reads denied:** the home directory, the Hetzer home, and named credential stores even when a broader path is
  re-opened (`~/.ssh`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.gnupg`, `~/.config/gh`,
  `~/.npmrc`, `~/.netrc`, `~/.git-credentials`, `~/.pypirc`, `~/.hetzer`, OS keyrings and browser profiles).
- **Reads re-allowed:** the project (`--sandbox-mount`, default the current directory) and each
  `--sandbox-allow-read` or `--sandbox-allow-write` path. The workspace `.env`, the vault, `.hetzer/`, the audit log
  and the incident log stay hidden inside the project.
- **Writes allowed:** the project (not with `--sandbox-ro`), the run's own temporary directory (`TMPDIR`) and each
  `--sandbox-allow-write` path. The shared `/tmp` is not writable. On Linux a write under the hidden home directory
  lands in an empty in-memory directory and is gone when the command exits.
- **Writes denied inside the project:** files that other tools run later on the host. srt protects `.git/hooks`,
  `.git/config`, shell start-up files, `.mcp.json`, `.vscode/`, `.idea/`, `.claude/commands` and `.claude/agents`
  (Hetzer starts srt from the project so these apply to it); Hetzer adds `.husky`, `.githooks`, `.envrc` and
  `.claude/settings*.json` when they exist.
- **Network:** only the `--sandbox-allow-host` entries (`api.github.com`, `*.npmjs.org`, `registry.npmjs.org:443`).
  No entry means no network.
- **Environment:** `PATH`, `HOME`, locale and terminal names, the run's `TMPDIR`, and the variables Hetzer injected.
  The master key and unrelated host variables are not passed.

Refused on purpose: `--sandbox-allow-read` of a credential store or the Hetzer key directory, and
`--sandbox-allow-write` of the home directory, a directory that contains it, or the Hetzer home (a process could
plant start-up files there). Brokered credentials are refused with srt for now (`ERR_SANDBOX_BROKER_UNSUPPORTED`):
the host broker listens on loopback, which the srt network namespace does not reach.

### Example: a build that may only reach the npm registry

```bash
hetzer exec --sandbox-engine srt --sandbox-allow-host registry.npmjs.org -- npm ci
```

## 3. Running a whole agent in the sandbox: `hetzer agent`

`hetzer exec --sandbox` contains the one command an agent chooses to run through Hetzer. Everything else the agent
does (its own file reads, its shell tool, its web requests) still runs on the host. `hetzer agent` starts the agent
itself inside the sandbox:

```bash
cd ~/projects/my-app
hetzer agent \
  --sandbox-allow-host api.anthropic.com \
  --sandbox-allow-read ~/.local/share/claude \
  --sandbox-allow-write ~/.claude \
  -- claude
```

- The agent sees the project, not your home directory. Its own state directory must be re-opened with
  `--sandbox-allow-write` (Claude Code keeps it in `~/.claude`; Codex in `~/.codex`). A configuration file that the
  agent rewrites in place by renaming a temporary file needs its directory, not only the file.
- The agent's API host must be listed. Which hosts an agent needs depends on its version and settings; srt's proxy
  answers an unlisted host with HTTP 403, and you decide whether to add it. Do not add a host you would not hand your
  code to.
- When the agent binary or its interpreter lives under your home directory (a per-user installer, `nvm`), Hetzer
  reports it before starting (`ERR_SANDBOX_COMMAND_UNREADABLE`) with the directory to pass to
  `--sandbox-allow-read`. Credential stores under that directory stay hidden.
- The session uses the terminal directly, so its output is not redacted. It gets no credential unless `--allow`
  names one; a raw-injection grant (`--allow <id> --allow-raw-unmediated <id>`) prints a warning, because the value
  can then appear on screen. An agent's own API key should come from its own login, not from Hetzer.
- `--host`, `--no-sandbox` and `--broker-policy` are refused. The audit ledger records `SANDBOX_EXEC` with
  `agent: true` at the start and `AGENT_EXIT` with the status and duration at the end.

## 4. Decoys that alert from outside: `hetzer canary plant`

The local canary (`hetzer canary setup`) fires only when something asks Hetzer for it. A scraper that reads files
directly never does. An external canary is a decoy credential issued by a service that alerts you when the
credential is used, wherever that happens: after it has been read and sent out, the attacker's first use of it is
the alert. Hetzer does not create these and makes no network call.

1. Get a decoy from an alerting service, for example an "AWS API key" token from
   [canarytokens.org](https://canarytokens.org) (Thinkst Canary; free, or self-hosted). The service learns when and
   from where the decoy is used; read its privacy terms.
2. Plant it where a scraper would look, in a file that is not tracked by Git:

   ```bash
   hetzer canary plant .env.backup --var AWS_ACCESS_KEY_ID --var AWS_SECRET_ACCESS_KEY --label "canarytokens AWS"
   ```

   Each value is typed at a masked prompt. Hetzer refuses the workspace `.env` (it would move the value into the
   vault and inject it), `data/`, `.hetzer/`, the Hetzer home and any file Git tracks, and adds the bait file to
   `.git/info/exclude` (not `.gitignore`, which is committed and would point at the bait).
3. `hetzer canary list` shows each decoy and whether it is still in place; `hetzer canary remove <id>` deletes only
   the lines that still match. Revoke the decoy at the issuing service as well.

Hetzer keeps only SHA-256 fingerprints of the values, in `~/.hetzer/canaries/`, outside the workspace and hidden by
the sandbox, so the registry does not tell a reader of the workspace which values are decoys.

Boundary: the alert fires when the decoy is **used**, not when it is read, and only through the issuing service. An
attacker who recognises the decoy, or who only collects and never uses credentials, sets off nothing. A decoy inside
the project is readable by the sandboxed agent on purpose; that is where a scraper looks.

## What none of this covers

- Kernel, sandbox-exec, bubblewrap or container-engine vulnerabilities. These are process sandboxes, not virtual
  machines. A separate OS account or a virtual machine is the stronger boundary.
- What you re-open: every `--sandbox-allow-read`, `--sandbox-allow-write` and `--sandbox-allow-host` entry is reachable
  by the sandboxed code. A listed host can receive data; prefer hosts you control or trust.
- The project itself: the sandboxed code can read and change everything else in the project. Hetzer's extra paths
  are denied only when they exist (srt 0.0.78 cannot deny a missing path on Linux), so a new `.claude/settings.json`
  or `.envrc` can be created, and project scripts such as `package.json` `scripts` or a `Makefile` run on the host when you run them.
  Review changes, including new dot-files, before you run project tooling outside the sandbox or commit.
- Processes you start without the sandbox, and a Hetzer that runs on a machine you do not control.

The settings Hetzer generates are checked against a real srt by `cli/vault/srt-sandbox.test.mjs` when srt is
installed, and the network allowlist where CI enables it (`HETZER_SRT_NETWORK_TEST=1`). The evidence protocols are
`VERIFY-SEC-016` to `VERIFY-SEC-019` in [verification-evidence.json](verification-evidence.json).
