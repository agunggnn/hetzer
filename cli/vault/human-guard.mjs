import { spawnSync } from "node:child_process";

// Set only when an agent or pipeline runs the command.
const AGENT_ENV_VARS = [
  ["ANTIGRAVITY_AGENT", "Antigravity Agent runtime detected"],
  ["CLAUDECODE", "Claude Code session detected"],
  ["CLAUDE_CODE_ENTRYPOINT", "Claude Code session detected"],
  ["CLAUDE_CODE", "Claude Code session detected"],
  ["HERMES_AGENT", "Hermes Agent session detected"],
  ["OPENCODE_CLIENT", "OpenCode Agent session detected"],
  ["AGENT_MODE", "Generic Agent Mode detected"],
  ["CI", "Continuous Integration / non-interactive pipeline detected"],
  ["GITHUB_ACTIONS", "GitHub Actions pipeline detected"],
];

// Set in every terminal an editor opens, for a person typing as much as for the editor's own agent.
const EDITOR_ENV_VARS = [
  ["CURSOR_PROJECT_DIR", "Cursor editor terminal detected"],
  ["CURSOR_TRACE_ID", "Cursor editor terminal detected"],
  ["VSCODE_PID", "VS Code editor terminal detected"],
];

const AGENT_PROCESS_NAMES = ["opencode", "antigravity", "agy", "claude", "hermes", "agent", "copilot", "ollama"];
const EDITOR_PROCESS_NAMES = ["cursor", "code", "electron"];

function detectAgentEnv(env = process.env) {
  for (const [k, desc] of AGENT_ENV_VARS) {
    if (env[k]) return { isAgent: true, reason: desc, envVar: k };
  }
  return { isAgent: false };
}

function detectEditorEnv(env = process.env) {
  for (const [k, desc] of EDITOR_ENV_VARS) {
    if (env[k]) return { isEditor: true, reason: desc, envVar: k };
  }
  return { isEditor: false };
}

/** An agent name anywhere in the ancestry wins over an editor name, so an agent started from an editor terminal is an agent. */
export function detectAgentAncestor(names = []) {
  const lowered = names.map((raw) => [String(raw), String(raw).toLowerCase()]);
  const agent = lowered.find(([, n]) => AGENT_PROCESS_NAMES.some((a) => n.includes(a)));
  if (agent) return { isAgent: true, processName: agent[0] };
  const editor = lowered.find(([, n]) => EDITOR_PROCESS_NAMES.some((e) => n.includes(e)));
  if (editor) return { isAgent: false, editorProcess: editor[0] };
  return { isAgent: false };
}

let cachedAncestry = null;

export function checkProcessAncestors({ platform = process.platform, pid = process.pid, run = spawnSync, maxDepth = 5 } = {}) {
  const isDefault = pid === process.pid && platform === process.platform && run === spawnSync && maxDepth === 5;
  if (isDefault && cachedAncestry !== null) {
    return cachedAncestry;
  }
  let result = { isAgent: false };
  try {
    if (platform === "win32") {
      // Use single quotes to avoid JS template issues; PowerShell script built via string concat
      const script = [
        '$current = Get-CimInstance Win32_Process -Filter "ProcessId = ' + Number(pid) + '"',
        'for ($i = 0; $i -lt ' + Number(maxDepth) + '; $i++) {',
        'if (-not $current -or $current.ParentProcessId -le 0) { break }',
        '$current = Get-CimInstance Win32_Process -Filter "ProcessId = $($current.ParentProcessId)"',
        'if ($current) { Write-Output ($current.ProcessId.ToString() + "`t" + $current.Name) }',
        '}',
      ].join('; ');
      const res = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', timeout: 2500, windowsHide: true });
      if (res.status === 0 && res.stdout) {
        const names = res.stdout.split(/\r?\n/).map((line) => line.split('\t').slice(1).join('\t')).filter(Boolean);
        result = detectAgentAncestor(names);
      }
    } else {
      const res = run('ps', ['-axo', 'pid=,ppid=,comm='], { encoding: 'utf8', timeout: 2500, windowsHide: true });
      if (res.status === 0 && res.stdout) {
        const processes = new Map();
        for (const line of res.stdout.split(/\r?\n/)) {
          const m = /^\s*(\d+)\s+(\d+)\s+(.+?)\s*$/.exec(line);
          if (m) processes.set(Number(m[1]), { parentPid: Number(m[2]), name: m[3] });
        }
        const names = [];
        let cur = Number(pid);
        for (let d = 0; d < maxDepth; d += 1) {
          const curInfo = processes.get(cur);
          if (!curInfo || curInfo.parentPid <= 0 || curInfo.parentPid === cur) break;
          const parent = processes.get(curInfo.parentPid);
          if (!parent) break;
          names.push(parent.name);
          cur = curInfo.parentPid;
        }
        result = detectAgentAncestor(names);
      }
    }
  } catch {
    // ignore
  }
  if (isDefault) {
    cachedAncestry = result;
  }
  return result;
}

/**
 * Refuses unless a person at an interactive terminal is running the command. These are heuristics for
 * same-user agents (environment markers and up to five process ancestors), not an OS privilege boundary.
 *
 * Editor terminals (VS Code, Cursor) are refused by default because the editor's own agent runs commands
 * there too. allowEditorTerminal lets input-only operations, where nothing is shown back, run in one; the
 * result's editorTerminal names it so the caller can apply a narrower rule.
 */
export function assertInteractiveHumanSession({ input = process.stdin, env = process.env, ancestor, operation = "'hetzer creds reveal'", allowEditorTerminal = false } = {}) {
  if (!input.isTTY) {
    throw new Error(
      `Access Denied: ${operation} requires a direct human interactive TTY terminal.\n` +
      "Pipes, scripts and agents cannot use this command; run it yourself in a terminal."
    );
  }
  const envCheck = detectAgentEnv(env);
  if (envCheck.isAgent) {
    throw new Error(
      `Access Denied: ${operation} blocked by the credential reveal guard.\n` +
      `Reason: ${envCheck.reason} ($${envCheck.envVar} is set).\n` +
      "Autonomous agents running in YOLO/unrestricted mode cannot extract raw secrets into context.\n" +
      "To execute commands with injected secrets safely, use 'hetzer exec -- <command>'."
    );
  }
  const ancestry = ancestor || checkProcessAncestors();
  if (ancestry.isAgent) {
    throw new Error(
      `Access Denied: ${operation} blocked by the credential reveal guard.\n` +
      `Reason: Agent runtime '${ancestry.processName}' detected in process tree ancestry.\n` +
      "Autonomous agents running in YOLO/unrestricted mode cannot extract raw secrets into context.\n" +
      "To execute commands with injected secrets safely, use 'hetzer exec -- <command>'."
    );
  }
  const editorEnv = detectEditorEnv(env);
  const editorTerminal = editorEnv.isEditor ? editorEnv.reason : ancestry.editorProcess ? `Editor process '${ancestry.editorProcess}' detected in process tree ancestry` : null;
  if (editorTerminal && !allowEditorTerminal) {
    throw new Error(
      `Access Denied: ${operation} blocked by the credential reveal guard.\n` +
      `Reason: ${editorTerminal}${editorEnv.isEditor ? ` ($${editorEnv.envVar} is set)` : ""}.\n` +
      "Editor terminals are refused for this operation because the editor's agent runs commands there too.\n" +
      "If you are a person, run it from a standalone terminal (macOS Terminal, iTerm2, Windows Terminal)."
    );
  }
  return { editorTerminal };
}

export function isAgenticContext({ input = process.stdin, env = process.env } = {}) {
  if (!input.isTTY) return true;
  if (detectAgentEnv(env).isAgent) return true;
  if (detectEditorEnv(env).isEditor) return true;
  const ancestry = checkProcessAncestors();
  return ancestry.isAgent || Boolean(ancestry.editorProcess);
}
