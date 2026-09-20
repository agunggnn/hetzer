import { spawnSync } from "node:child_process";

const AGENT_ENV_VARS = [
  ["ANTIGRAVITY_AGENT", "Antigravity Agent"],
  ["CURSOR_PROJECT_DIR", "Cursor IDE"],
  ["CURSOR_TRACE_ID", "Cursor Agent"],
  ["CLAUDE_CODE", "Claude Code"],
  ["HERMES_AGENT", "Hermes Agent"],
  ["OPENCODE_CLIENT", "OpenCode Agent"],
  ["AGENT_MODE", "Generic Agent Mode"],
  ["CI", "CI pipeline"],
  ["GITHUB_ACTIONS", "GitHub Actions"],
];

const AGENT_PROCESS_NAMES = [
  "opencode", "opencode.exe", "cursor", "cursor.exe", "code", "code.exe",
  "antigravity", "claude", "hermes", "agent", "copilot",
];

function detectAgentEnv(env = process.env) {
  for (const [k, desc] of AGENT_ENV_VARS) if (env[k]) return { isAgent: true, reason: `${desc} ($${k})` };
  return { isAgent: false };
}

export function checkProcessAncestors({ platform = process.platform, pid = process.pid, run = spawnSync, maxDepth = 5 } = {}) {
  try {
    if (platform === "win32") {
      const script = [
        "`$current = Get-CimInstance Win32_Process -Filter `"ProcessId = ${Number(pid)}`"",
        "for (`$i = 0; `$i -lt ${Number(maxDepth)}; `$i++) {",
        "if (-not `$current -or `$current.ParentProcessId -le 0) { break }",
        "`$current = Get-CimInstance Win32_Process -Filter `"ProcessId = `$($current.ParentProcessId)`"",
        "if (`$current) { Write-Output (`$current.ProcessId.ToString() + `"`t`" + `$current.Name) }",
        "}"
      ].join("; ");
      const res = run("powershell", ["-NoProfile","-NonInteractive","-Command", script], { encoding:"utf8", timeout:2500, windowsHide:true });
      if (res.status === 0 && res.stdout) {
        const names = res.stdout.split(/\r?\n/).map(l=>l.split("`t").slice(1).join("`t")).filter(Boolean);
        for (const n of names) if (AGENT_PROCESS_NAMES.some(a=>n.toLowerCase().includes(a))) return { isAgent:true, processName:n };
      }
    } else {
      const res = run("ps", ["-o","ppid,comm","-p", String(pid)], { encoding:"utf8", timeout:1500 });
      // fallback simple
    }
  } catch {}
  return { isAgent:false };
}

function detectAgentAncestor(names) {
  for (const n of names) if (AGENT_PROCESS_NAMES.some(a=>n.toLowerCase().includes(a))) return { isAgent:true, processName:n };
  return { isAgent:false };
}

export function assertInteractiveHumanSession({ input = process.stdin, env = process.env, ancestor, operation = "'vault reveal'" } = {}) {
  if (!input.isTTY) throw new Error(`Access Denied: ${operation} requires a direct human interactive TTY.\nAutonomous agent / non-interactive programmatic secret revelation is blocked.`);
  const envCheck = detectAgentEnv(env);
  if (envCheck.isAgent) throw new Error(`Access Denied: ${operation} blocked.\nReason: ${envCheck.reason} detected.\nUse 'hetzer exec -- <command>' for scoped injection.`);
  const ancestry = ancestor || checkProcessAncestors();
  if (ancestry.isAgent) throw new Error(`Access Denied: ${operation} blocked.\nReason: Agent runtime '${ancestry.processName}' in ancestry.\nUse 'hetzer exec -- <command>'.`);
}

export function isAgenticContext({ env = process.env } = {}) {
  if (!process.stdin.isTTY) return true;
  if (detectAgentEnv(env).isAgent) return true;
  if (checkProcessAncestors().isAgent) return true;
  return false;
}
